"""Watchlists: re-run a multi-source query on a schedule and alert on change
(catalogue block 3).

Each check is an ordinary multi-source run with the cache bypassed. Its
findings are reduced to a fingerprint set of (connector, type, value); the
difference from the previous check becomes an alert. Counts that drift on
their own (followers, members) are left out of the fingerprint so they do not
alert every time. Certificates and domain registrations close to expiry raise
a warning. Checks run only with network access allowed, on identifiers the
operator owns or is authorised to monitor.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from . import intel
from .db import _connection, new_id, record_activity, require_module, setting_bool, utc_now
from .errors import NotFoundError, ValidationError
from .validation import clean_text

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 7 * 24 * 60
MAX_WATCHES = 200
EXPIRY_WARNING_DAYS = 30
# Values that change without anything meaningful happening.
VOLATILE_TYPES = frozenset(
    {
        "member-count", "followers-count", "friends-count", "following-count",
        "invite-expires", "http-response", "created-at", "avatar", "banner",
        "posture-score", "site-unknown",
    }
)
VOLATILE_CONNECTORS = frozenset({"local-workspace", "username-variations", "discord-snowflake"})


def _row(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["baseline"] = bool(item.pop("fingerprint_json"))
    item["warnings"] = json.loads(item.pop("warnings_json") or "[]")
    return item


def _interval(value: object) -> int:
    try:
        minutes = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValidationError("interval_minutes must be an integer") from exc
    if not MIN_INTERVAL_MINUTES <= minutes <= MAX_INTERVAL_MINUTES:
        raise ValidationError(f"interval_minutes must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES}")
    return minutes


def list_watches(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        rows = connection.execute("SELECT * FROM watches ORDER BY created_at DESC").fetchall()
        unread = connection.execute("SELECT COUNT(*) FROM watch_alerts WHERE read = 0").fetchone()[0]
    items = [_row(row) for row in rows]
    return {"items": items, "total": len(items), "unread_alerts": unread}


def create_watch(database: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("send an object")
    unknown = set(payload) - {"value", "label", "interval_minutes"}
    if unknown:
        raise ValidationError(f"unsupported watch fields: {', '.join(sorted(unknown))}")
    detected = intel.detect_artifact(payload.get("value"))
    label = clean_text(payload.get("label", ""), "label", max_length=120)
    interval = _interval(payload.get("interval_minutes", 1440))
    watch_id = new_id()
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        if connection.execute("SELECT COUNT(*) FROM watches").fetchone()[0] >= MAX_WATCHES:
            raise ValidationError(f"at most {MAX_WATCHES} watches")
        if connection.execute(
            "SELECT 1 FROM watches WHERE query_type = ? AND value = ?", (detected["type"], detected["value"])
        ).fetchone():
            raise ValidationError("this identifier is already watched")
        connection.execute(
            """INSERT INTO watches (id, value, query_type, label, interval_minutes, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (watch_id, detected["value"], detected["type"], label, interval, utc_now()),
        )
        record_activity(connection, action="watch-create", target_type="watch", target_id=watch_id,
                        summary=f"Watching {detected['type']} {detected['value'][:120]}")
    return get_watch(database, watch_id)


def get_watch(database: str, watch_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
    if row is None:
        raise NotFoundError("watch not found")
    return _row(row)


def update_watch(database: str, watch_id: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not payload:
        raise ValidationError("send at least one field")
    unknown = set(payload) - {"label", "interval_minutes", "enabled"}
    if unknown:
        raise ValidationError(f"unsupported watch fields: {', '.join(sorted(unknown))}")
    get_watch(database, watch_id)
    changes: dict[str, Any] = {}
    if "label" in payload:
        changes["label"] = clean_text(payload["label"], "label", max_length=120)
    if "interval_minutes" in payload:
        changes["interval_minutes"] = _interval(payload["interval_minutes"])
    if "enabled" in payload:
        if not isinstance(payload["enabled"], bool):
            raise ValidationError("enabled must be true or false")
        changes["enabled"] = int(payload["enabled"])
    with _connection(database) as connection:
        assignments = ", ".join(f"{key} = ?" for key in changes)
        connection.execute(f"UPDATE watches SET {assignments} WHERE id = ?", (*changes.values(), watch_id))
    return get_watch(database, watch_id)


def delete_watch(database: str, watch_id: str) -> None:
    get_watch(database, watch_id)
    with _connection(database) as connection:
        connection.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
        record_activity(connection, action="watch-delete", target_type="watch", target_id=watch_id, summary="Watch removed")


def list_alerts(database: str, *, unread_only: bool = False, limit: int = 100) -> dict[str, Any]:
    query = """SELECT a.*, w.value AS watch_value, w.query_type AS watch_type, w.label AS watch_label
               FROM watch_alerts a JOIN watches w ON w.id = a.watch_id"""
    if unread_only:
        query += " WHERE a.read = 0"
    query += " ORDER BY a.created_at DESC LIMIT ?"
    with _connection(database) as connection:
        rows = connection.execute(query, (max(1, min(limit, 500)),)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["read"] = bool(item["read"])
        item["details"] = json.loads(item.pop("details_json") or "{}")
        items.append(item)
    return {"items": items, "total": len(items)}


def mark_alerts_read(database: str, alert_ids: Any = None) -> int:
    with _connection(database) as connection:
        if alert_ids is None:
            return connection.execute("UPDATE watch_alerts SET read = 1 WHERE read = 0").rowcount
        if not isinstance(alert_ids, list) or not all(isinstance(item, str) for item in alert_ids):
            raise ValidationError("ids must be a list of alert ids")
        marks = ",".join("?" * len(alert_ids)) or "''"
        return connection.execute(f"UPDATE watch_alerts SET read = 1 WHERE id IN ({marks})", alert_ids).rowcount


# ---------------------------------------------------------------------------
# Checking


def _fingerprint(results: list[dict[str, Any]]) -> list[str]:
    keys = {
        f"{item['connector_id']}|{item['result_type']}|{item['value']}"
        for item in results
        if item.get("status") == "ok"
        and item.get("result_type")
        and item["result_type"] not in VOLATILE_TYPES
        and item["connector_id"] not in VOLATILE_CONNECTORS
    }
    return sorted(keys)


def _expiry_warnings(results: list[dict[str, Any]], now: datetime) -> list[str]:
    warnings = []
    for item in results:
        data = item.get("data") or {}
        if item.get("result_type") == "cert-validity" and isinstance(data.get("days_remaining"), int):
            if data["days_remaining"] <= EXPIRY_WARNING_DAYS:
                warnings.append(f"TLS certificate expires in {data['days_remaining']} days")
        if item.get("result_type") == "rdap-event" and data.get("action") == "expiration":
            try:
                when = datetime.fromisoformat(str(item["value"]).replace("Z", "+00:00"))
            except ValueError:
                continue
            days = (when - now).days
            if days <= EXPIRY_WARNING_DAYS:
                warnings.append(f"Domain registration expires in {days} days ({item['value'][:10]})")
    return sorted(set(warnings))


def _add_alert(connection: Any, watch: dict[str, Any], run_id: str, kind: str, summary: str, details: dict[str, Any]) -> str:
    alert_id = new_id()
    connection.execute(
        """INSERT INTO watch_alerts (id, watch_id, run_id, kind, summary, details_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (alert_id, watch["id"], run_id, kind, summary, json.dumps(details), utc_now()),
    )
    return alert_id


def check_watch(database: str, watch_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Run one watch now and record any change. Returns the alerts created."""
    watch = get_watch(database, watch_id)
    with _connection(database) as connection:
        if not setting_bool(connection, "intel.allow_network", False):
            raise ValidationError("watch checks need network access (Settings → allow network)")
        previous_row = connection.execute("SELECT fingerprint_json FROM watches WHERE id = ?", (watch_id,)).fetchone()
    previous = json.loads(previous_row["fingerprint_json"]) if previous_row["fingerprint_json"] else None
    try:
        run = intel.run_query(database, value=f"{_prefix(watch)}{watch['value']}", use_cache=False, wait=True, notify=False)
    except (ValidationError, ValueError) as exc:
        with _connection(database) as connection:
            connection.execute("UPDATE watches SET last_error = ?, last_checked_at = ? WHERE id = ?", (str(exc)[:300], utc_now(), watch_id))
        raise
    results = run.get("results") or []
    current = _fingerprint(results)
    warnings = _expiry_warnings(results, now or datetime.now(timezone.utc))
    created: list[str] = []
    label = watch["label"] or watch["value"]
    messages: list[str] = []
    with _connection(database) as connection:
        if previous is not None:
            added = sorted(set(current) - set(previous))
            removed = sorted(set(previous) - set(current))
            if added or removed:
                summary = f"{label}: {len(added)} new, {len(removed)} gone"
                details = {"added": [_readable(key) for key in added[:200]], "removed": [_readable(key) for key in removed[:200]]}
                created.append(_add_alert(connection, watch, run["id"], "change", summary, details))
                messages.append(summary)
        new_warnings = sorted(set(warnings) - set(watch["warnings"]))
        if new_warnings:
            summary = f"{label}: " + "; ".join(new_warnings)
            created.append(_add_alert(connection, watch, run["id"], "expiry", summary, {"warnings": new_warnings}))
            messages.append(summary)
        connection.execute(
            """UPDATE watches SET fingerprint_json = ?, warnings_json = ?, last_run_id = ?,
                      last_checked_at = ?, last_error = '' WHERE id = ?""",
            (json.dumps(current), json.dumps(warnings), run["id"], utc_now(), watch_id),
        )
    if messages:
        intel.post_webhook(
            database,
            "**GARBAGE watchlist**\n" + "\n".join(f"• {message}" for message in messages),
            {"watch_id": watch_id, "run_id": run["id"], "alerts": created},
            watch_id,
        )
    return {"watch": get_watch(database, watch_id), "run_id": run["id"], "baseline": previous is None, "alerts": created}


def _prefix(watch: dict[str, Any]) -> str:
    """Account types are detected from their prefix; indicators need none."""
    return {
        "discord-id": "discord:", "roblox-user": "roblox:", "username": "user:",
        "telegram": "telegram:", "minecraft": "minecraft:", "steam": "steam:", "topic": "topic:",
        "discord-invite": "https://discord.gg/",
    }.get(watch["query_type"], "")


def _readable(key: str) -> dict[str, str]:
    connector, result_type, value = key.split("|", 2)
    return {"connector": connector, "type": result_type, "value": value}


def due_watches(database: str, now: datetime | None = None) -> list[str]:
    moment = now or datetime.now(timezone.utc)
    due = []
    with _connection(database) as connection:
        rows = connection.execute("SELECT id, interval_minutes, last_checked_at FROM watches WHERE enabled = 1").fetchall()
    for row in rows:
        if not row["last_checked_at"]:
            due.append(row["id"])
            continue
        try:
            last = datetime.fromisoformat(row["last_checked_at"].replace("Z", "+00:00"))
        except ValueError:
            due.append(row["id"])
            continue
        if moment - last >= timedelta(minutes=row["interval_minutes"]):
            due.append(row["id"])
    return due


def run_due(database: str) -> int:
    with _connection(database) as connection:
        if not setting_bool(connection, "intel.allow_network", False):
            return 0
    checked = 0
    for watch_id in due_watches(database):
        try:
            check_watch(database, watch_id)
            checked += 1
        except (ValidationError, NotFoundError):
            continue
    return checked


def start_scheduler(database: str, period_seconds: float = 60.0) -> threading.Event:
    """Check due watches every ``period_seconds`` in a daemon thread."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.wait(period_seconds):
            try:
                run_due(database)
                from .preservation import run_daily_verification

                run_daily_verification(database)
            except Exception as exc:  # noqa: BLE001 - the scheduler must survive any one failure
                with _connection(database) as connection:
                    record_activity(connection, action="watch-scheduler", target_type="watch",
                                    summary=f"Scheduled watch check failed: {str(exc)[:200]}")

    threading.Thread(target=loop, name="watch-scheduler", daemon=True).start()
    return stop
