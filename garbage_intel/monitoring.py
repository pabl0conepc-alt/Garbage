"""Monitoring: saved multi-source queries that re-run on a schedule.

A monitor names an artifact, the sources to ask and an interval (at least
15 minutes). The server's scheduler thread runs due monitors through the
normal orchestrator, so the network, target-contact and key gates, cache,
rate limits and provenance all apply. Each run is compared with the
previous one by (source, result type, value): what appeared and what
disappeared are stored with the run, and a change creates an in-app
notification.

The scheduler only runs while the GARBAGE server is running; a missed slot
runs once when the server is back, not once per missed interval.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import _connection, new_id, record_activity, require_module, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .intel import connectors, detect_artifact, get_run, run_query
from .validation import clean_text

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 30 * 24 * 60
MAX_MONITORS = 200
MAX_DIFF_ITEMS = 500
TICK_SECONDS = 30
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _row(connection: Any, monitor_id: str) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM monitors WHERE id = ?", (monitor_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"monitor not found: {monitor_id}")
    item = dict(row)
    item["connectors"] = json.loads(item.pop("connectors_json") or "[]")
    item["enabled"] = bool(item["enabled"])
    return item


def _validate(value: object, connector_ids: object, interval: object) -> tuple[dict[str, str], list[str], int]:
    artifact = detect_artifact(value)
    known = {item.connector_id: item for item in connectors()}
    if not isinstance(connector_ids, list) or not connector_ids or not all(isinstance(item, str) for item in connector_ids):
        raise ValidationError("choose at least one source")
    unknown = sorted(set(connector_ids) - set(known))
    if unknown:
        raise ValidationError(f"unknown connectors: {', '.join(unknown)}")
    unusable = sorted(item for item in connector_ids if artifact["type"] not in known[item].accepts)
    if unusable:
        raise ValidationError(f"sources that do not accept {artifact['type']}: {', '.join(unusable)}")
    if isinstance(interval, bool) or not isinstance(interval, int) or not MIN_INTERVAL_MINUTES <= interval <= MAX_INTERVAL_MINUTES:
        raise ValidationError(f"interval must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES} minutes")
    return artifact, sorted(set(connector_ids)), interval


def create_monitor(
    database: str,
    *,
    name: object,
    value: object,
    connector_ids: object,
    interval_minutes: object = 1440,
    investigation_id: object = None,
) -> dict[str, Any]:
    label = clean_text(name, "name", max_length=120, required=True)
    artifact, chosen, interval = _validate(value, connector_ids, interval_minutes)
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    monitor_id = new_id()
    now = utc_now()
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        if connection.execute("SELECT COUNT(*) FROM monitors").fetchone()[0] >= MAX_MONITORS:
            raise ValidationError(f"at most {MAX_MONITORS} monitors")
        if case_id and connection.execute("SELECT 1 FROM investigations WHERE id = ?", (case_id,)).fetchone() is None:
            raise NotFoundError(f"investigation not found: {case_id}")
        connection.execute(
            """INSERT INTO monitors (id, name, query_type, query_value, connectors_json, interval_minutes, investigation_id,
                                     enabled, created_at, updated_at, next_run_at, last_run_at, last_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, '', '')""",
            (monitor_id, label, artifact["type"], artifact["value"], json.dumps(chosen), interval, case_id, now, now, now),
        )
        record_activity(connection, action="monitor", target_type="monitor", target_id=monitor_id, investigation_id=case_id,
                        summary=f"Monitor created: {label[:80]} ({artifact['type']} {artifact['value'][:80]}, every {interval} min)")
        return _row(connection, monitor_id)


def update_monitor(database: str, monitor_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    unknown = set(payload) - {"name", "enabled", "interval_minutes", "connectors"}
    if unknown:
        raise ValidationError(f"unsupported monitor fields: {', '.join(sorted(unknown))}")
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        current = _row(connection, monitor_id)
        name = clean_text(payload["name"], "name", max_length=120, required=True) if "name" in payload else current["name"]
        enabled = payload.get("enabled", current["enabled"])
        if not isinstance(enabled, bool):
            raise ValidationError("enabled must be a boolean")
        _, chosen, interval = _validate(current["query_value"], payload.get("connectors", current["connectors"]), payload.get("interval_minutes", current["interval_minutes"]))
        next_run = current["next_run_at"]
        if enabled and not current["enabled"]:
            next_run = utc_now()
        connection.execute(
            """UPDATE monitors SET name = ?, enabled = ?, interval_minutes = ?, connectors_json = ?, next_run_at = ?, updated_at = ?
               WHERE id = ?""",
            (name, 1 if enabled else 0, interval, json.dumps(chosen), next_run, utc_now(), monitor_id),
        )
        return _row(connection, monitor_id)


def delete_monitor(database: str, monitor_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        current = _row(connection, monitor_id)
        connection.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
        record_activity(connection, action="monitor", target_type="monitor", target_id=monitor_id, summary=f"Monitor deleted: {current['name'][:80]}")
    return {"deleted": monitor_id}


def list_monitors(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        ids = [row["id"] for row in connection.execute("SELECT id FROM monitors ORDER BY name, id")]
        items = [_row(connection, monitor_id) for monitor_id in ids]
        unread = connection.execute("SELECT COUNT(*) FROM notifications WHERE read_at = ''").fetchone()[0]
    return {"items": items, "total": len(items), "unread_notifications": unread, "scheduler": SCHEDULER.status()}


def _signature(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found = {}
    for item in run["results"]:
        if item["status"] not in ("ok",) or not item["value"]:
            continue
        key = f"{item['connector_id']}\x1f{item['result_type']}\x1f{item['value']}"
        found[key] = {"connector_id": item["connector_id"], "result_type": item["result_type"], "value": item["value"]}
    return found


def run_monitor(database: str, monitor_id: str, *, trigger: str = "manual") -> dict[str, Any]:
    """Run one monitor now, store the difference from its previous run.

    One run per monitor at a time: a manual run that overlaps the scheduler
    would otherwise diff against the same previous run twice."""
    with _RUNNING_LOCK:
        if monitor_id in _RUNNING:
            raise ConflictError("monitor is already running")
        _RUNNING.add(monitor_id)
    try:
        return _run_monitor(database, monitor_id, trigger)
    finally:
        with _RUNNING_LOCK:
            _RUNNING.discard(monitor_id)


def _run_monitor(database: str, monitor_id: str, trigger: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        monitor = _row(connection, monitor_id)
        previous = connection.execute(
            "SELECT intel_run_id FROM monitor_runs WHERE monitor_id = ? AND status <> 'error' ORDER BY started_at DESC LIMIT 1",
            (monitor_id,),
        ).fetchone()
    started = utc_now()
    try:
        run = run_query(
            database,
            value=monitor["query_value"],
            query_type=monitor["query_type"],
            connector_ids=monitor["connectors"],
            investigation_id=monitor["investigation_id"],
            use_cache=False,
        )
        error = ""
    except Exception as exc:  # noqa: BLE001 - a failing monitor must not stop the scheduler
        run, error = None, str(exc)[:300]
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    baseline = previous is None
    sources = []
    if run is not None:
        current = _signature(run)
        sources = [{"connector_id": item["connector_id"], "status": item["status"]} for item in run["sources"]]
        if previous is not None:
            try:
                before = _signature(get_run(database, previous["intel_run_id"]))
            except NotFoundError:
                before, baseline = {}, True
            # A source that failed this time is not counted as "everything removed".
            failed = {item["connector_id"] for item in run["sources"] if item["status"] not in ("ok", "empty")}
            added = [value for key, value in current.items() if key not in before]
            removed = [value for key, value in before.items() if key not in current and value["connector_id"] not in failed]
    status = "error" if run is None else ("baseline" if baseline else ("changed" if added or removed else "unchanged"))
    finished = utc_now()
    record = {
        "id": new_id(),
        "monitor_id": monitor_id,
        "intel_run_id": run["id"] if run else "",
        "trigger": trigger,
        "status": status,
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added[:MAX_DIFF_ITEMS],
        "removed": removed[:MAX_DIFF_ITEMS],
        "sources": sources,
        "error": error,
        "started_at": started,
        "finished_at": finished,
    }
    next_run = _stamp(datetime.now(timezone.utc) + timedelta(minutes=monitor["interval_minutes"]))
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO monitor_runs (id, monitor_id, intel_run_id, trigger, status, added_count, removed_count,
                                         diff_json, error, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record["id"], monitor_id, record["intel_run_id"], trigger, status, len(added), len(removed),
             json.dumps({"added": record["added"], "removed": record["removed"], "sources": sources}), error, started, finished),
        )
        connection.execute(
            "UPDATE monitors SET last_run_at = ?, last_status = ?, next_run_at = ?, updated_at = ? WHERE id = ?",
            (finished, status, next_run, finished, monitor_id),
        )
        if status in ("changed", "error"):
            title = (f"{monitor['name']}: {len(added)} new, {len(removed)} gone" if status == "changed" else f"{monitor['name']}: the run failed")
            connection.execute(
                "INSERT INTO notifications (id, kind, monitor_id, monitor_run_id, title, body, created_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, '')",
                (new_id(), status, monitor_id, record["id"], title[:200], error or ", ".join(item["value"] for item in added[:5])[:500], finished),
            )
    return record


def monitor_runs(database: str, monitor_id: str, *, limit: int = 30) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "monitoring")
        monitor = _row(connection, monitor_id)
        rows = connection.execute(
            "SELECT * FROM monitor_runs WHERE monitor_id = ? ORDER BY started_at DESC LIMIT ?",
            (monitor_id, max(1, min(200, int(limit)))),
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        diff = json.loads(item.pop("diff_json") or "{}")
        item.update(added=diff.get("added", []), removed=diff.get("removed", []), sources=diff.get("sources", []))
        items.append(item)
    return {"monitor": monitor, "items": items}


def notifications(database: str, *, unread_only: bool = False, limit: int = 50) -> dict[str, Any]:
    with _connection(database) as connection:
        where = "WHERE read_at = ''" if unread_only else ""
        rows = connection.execute(
            f"SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT ?", (max(1, min(200, int(limit))),)
        ).fetchall()
        unread = connection.execute("SELECT COUNT(*) FROM notifications WHERE read_at = ''").fetchone()[0]
    return {"items": [dict(row) for row in rows], "unread": unread}


def mark_read(database: str, notification_ids: object) -> dict[str, Any]:
    with _connection(database) as connection:
        if notification_ids == "all":
            connection.execute("UPDATE notifications SET read_at = ? WHERE read_at = ''", (utc_now(),))
        elif isinstance(notification_ids, list) and all(isinstance(item, str) for item in notification_ids):
            connection.executemany("UPDATE notifications SET read_at = ? WHERE id = ? AND read_at = ''", [(utc_now(), item) for item in notification_ids[:500]])
        else:
            raise ValidationError('ids must be a list of notification ids or "all"')
    return notifications(database, unread_only=True)


def due_monitors(database: str, now: datetime | None = None) -> list[str]:
    moment = _stamp(now or datetime.now(timezone.utc))
    with _connection(database) as connection:
        from .db import module_enabled

        if not module_enabled(connection, "monitoring"):
            return []
        return [row["id"] for row in connection.execute(
            "SELECT id FROM monitors WHERE enabled = 1 AND next_run_at <= ? ORDER BY next_run_at", (moment,)
        )]


class Scheduler:
    """One background thread per server; runs due monitors one at a time."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._database = ""
        self.last_tick = ""
        self.last_error = ""

    def start(self, database: str) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._database = database
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="garbage-monitors", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def tick(self) -> int:
        ran = 0
        for monitor_id in due_monitors(self._database):
            if self._stop.is_set():
                break
            try:
                run_monitor(self._database, monitor_id, trigger="schedule")
                ran += 1
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)[:300]
        self.last_tick = utc_now()
        return ran

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                self.last_error = str(exc)[:300]
            self._stop.wait(TICK_SECONDS)

    def status(self) -> dict[str, Any]:
        return {"running": bool(self._thread and self._thread.is_alive()), "last_tick": self.last_tick, "tick_seconds": TICK_SECONDS, "last_error": self.last_error}


SCHEDULER = Scheduler()
