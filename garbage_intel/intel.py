"""Multi-source intelligence runtime: connector registry, rate limits, cache
and the explicit fan-out of one artifact to every compatible connector.

A connector declares which artifact types it accepts, whether it needs the
network, its rate limit and its cache lifetime. The orchestrator never runs a
network connector unless ``intel.allow_network`` is enabled, records every
result with provenance (connector, source URL, response digest, time) and
keeps a per-connector health record for the source status panel.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from functools import partial
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .db import (
    _connection,
    module_enabled,
    new_id,
    record_activity,
    require_module,
    setting_bool,
    setting_int,
    utc_now,
)
from .errors import NotFoundError, ValidationError
from .intel_keys import get_secret
from .modules.indicator_tools import inspect_value
from .net import NetworkError, NetworkPolicyError
from .validation import clean_text

ARTIFACT_TYPES = (
    "domain",
    "ipv4",
    "ipv6",
    "cidr",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "asn",
    "cve",
)
RESULT_STATUSES = (
    "pending",
    "ok",
    "empty",
    "error",
    "rate-limited",
    "network-disabled",
    "target-contact-disabled",
    "key-missing",
    "module-disabled",
    "unsupported",
)
MAX_FINDINGS_PER_CONNECTOR = 200
MAX_RUNS_LISTED = 100
_CVE = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """One normalised fact returned by a connector."""

    result_type: str
    value: str
    data: dict[str, Any] = field(default_factory=dict)
    source_url: str = ""
    response_sha256: str = ""


@dataclass(frozen=True)
class ConnectorContext:
    database: str
    query_type: str
    query_value: str
    investigation_id: str | None
    # The operator's key for this connector's provider, when it has one.
    api_key: str = ""


ConnectorFunction = Callable[[ConnectorContext], list[Finding]]


@dataclass(frozen=True)
class Connector:
    connector_id: str
    name: str
    description: str
    accepts: tuple[str, ...]
    run: ConnectorFunction
    network: bool = False
    # True when the connector talks to the artifact's own servers (an HTTP
    # request or TLS handshake), not to a third-party registry or archive.
    contacts_target: bool = False
    requires_key: bool = False
    # Provider in garbage_intel.intel_keys; with requires_key False the key is
    # optional and only raises the provider's limits.
    key_id: str = ""
    rate_per_minute: int = 60
    ttl_seconds: int = 0
    source_url: str = ""


class RateLimiter:
    """Token bucket per connector, shared by every request in the process."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def acquire(self, key: str, rate_per_minute: int) -> bool:
        if rate_per_minute <= 0:
            return True
        capacity = float(rate_per_minute)
        refill = capacity / 60.0
        now = self._clock()
        with self._lock:
            tokens, updated = self._buckets.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - updated) * refill)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# Runs started with wait=False execute here, one thread per run.
_BACKGROUND = ThreadPoolExecutor(max_workers=4, thread_name_prefix="intel-run")

_REGISTRY: dict[str, Connector] = {}
_REGISTRY_LOCK = threading.Lock()
RATE_LIMITER = RateLimiter()


def register_connector(connector: Connector) -> Connector:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", connector.connector_id):
        raise ValueError(f"invalid connector id: {connector.connector_id}")
    unknown = set(connector.accepts) - set(ARTIFACT_TYPES)
    if unknown:
        raise ValueError(f"unknown artifact types: {', '.join(sorted(unknown))}")
    with _REGISTRY_LOCK:
        _REGISTRY[connector.connector_id] = connector
    return connector


def unregister_connector(connector_id: str) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.pop(connector_id, None)


def connectors() -> list[Connector]:
    with _REGISTRY_LOCK:
        return sorted(_REGISTRY.values(), key=lambda item: item.connector_id)


_CONNECTOR_MODULES = {"nvd": "nvd-connector", "cisa-kev-local": "cisa-kev"}


def connector_module(connector: Connector) -> str:
    """Registry module that switches this connector on and off ('' for none)."""
    if connector.connector_id in _CONNECTOR_MODULES:
        return _CONNECTOR_MODULES[connector.connector_id]
    return "external-osint-connectors" if connector.network else ""


def _disabled_connectors(connection: Any, selected: list[Connector]) -> set[str]:
    return {
        connector.connector_id
        for connector in selected
        if connector_module(connector)
        and not module_enabled(connection, connector_module(connector))
    }


# ---------------------------------------------------------------------------
# Artifact detection


def detect_artifact(raw: object) -> dict[str, str]:
    """Classify one artifact without contacting any service."""
    value = clean_text(raw, "value", max_length=2000, required=True)
    cve = _CVE.fullmatch(value.strip())
    if cve:
        return {"type": "cve", "value": f"CVE-{cve.group(1)}-{cve.group(2)}", "label": "CVE"}
    try:
        inspection = inspect_value(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    kind = inspection.get("kind", "")
    canonical = inspection.get("canonical", "")
    if kind not in ARTIFACT_TYPES or not canonical:
        raise ValidationError(
            "value is not a supported artifact; use a domain, IP, CIDR, URL, "
            "email, hash, ASN or CVE"
        )
    return {"type": kind, "value": canonical, "label": inspection.get("label", kind)}


# ---------------------------------------------------------------------------
# Cache and source status


def _expires(ttl_seconds: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    return moment.isoformat().replace("+00:00", "Z")


def _cache_get(
    connection: Any, connector_id: str, query_type: str, query_value: str
) -> list[Finding] | None:
    row = connection.execute(
        """SELECT payload_json FROM intel_cache
           WHERE connector_id = ? AND query_type = ? AND query_value = ?
             AND expires_at > ?""",
        (connector_id, query_type, query_value, utc_now()),
    ).fetchone()
    if row is None:
        return None
    try:
        items = json.loads(row["payload_json"])
        return [Finding(**item) for item in items]
    except (TypeError, ValueError):
        return None


def _cache_put(
    connection: Any,
    connector: Connector,
    query_type: str,
    query_value: str,
    findings: list[Finding],
) -> None:
    payload = json.dumps([finding.__dict__ for finding in findings], sort_keys=True)
    connection.execute(
        """INSERT INTO intel_cache
           (connector_id, query_type, query_value, payload_json, fetched_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(connector_id, query_type, query_value) DO UPDATE
           SET payload_json = excluded.payload_json,
               fetched_at = excluded.fetched_at,
               expires_at = excluded.expires_at""",
        (
            connector.connector_id,
            query_type,
            query_value,
            payload,
            utc_now(),
            _expires(connector.ttl_seconds),
        ),
    )


def _record_status(
    connection: Any, connector_id: str, status: str, error: str, latency_ms: int
) -> None:
    success = 1 if status in {"ok", "empty"} else 0
    failure = 1 if status == "error" else 0
    connection.execute(
        """INSERT INTO intel_source_status
           (connector_id, last_status, last_error, last_latency_ms, last_run_at,
            success_count, error_count)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(connector_id) DO UPDATE
           SET last_status = excluded.last_status,
               last_error = excluded.last_error,
               last_latency_ms = excluded.last_latency_ms,
               last_run_at = excluded.last_run_at,
               success_count = intel_source_status.success_count + excluded.success_count,
               error_count = intel_source_status.error_count + excluded.error_count""",
        (connector_id, status, error[:500], latency_ms, utc_now(), success, failure),
    )


def list_connectors(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        network_allowed = setting_bool(connection, "intel.allow_network", False)
        target_allowed = setting_bool(connection, "intel.allow_target_contact", False)
        keys = {row["provider_id"] for row in connection.execute("SELECT provider_id FROM intel_api_keys")}
        status_rows = {
            row["connector_id"]: dict(row)
            for row in connection.execute("SELECT * FROM intel_source_status")
        }
        disabled = _disabled_connectors(connection, connectors())
    items = []
    for connector in connectors():
        status = status_rows.get(connector.connector_id)
        if connector.connector_id in disabled:
            availability = "module-disabled"
        elif connector.network and not network_allowed:
            availability = "network-disabled"
        elif connector.contacts_target and not target_allowed:
            availability = "target-contact-disabled"
        elif connector.requires_key and connector.key_id not in keys:
            availability = "key-missing"
        else:
            availability = "ready"
        items.append(
            {
                "connector_id": connector.connector_id,
                "name": connector.name,
                "description": connector.description,
                "accepts": list(connector.accepts),
                "network": connector.network,
                "requires_key": connector.requires_key,
                "key_id": connector.key_id,
                "key_configured": connector.key_id in keys,
                "contacts_target": connector.contacts_target,
                "rate_per_minute": connector.rate_per_minute,
                "ttl_seconds": connector.ttl_seconds,
                "source_url": connector.source_url,
                "module_id": connector_module(connector),
                "availability": availability,
                "status": status,
            }
        )
    return {
        "network_allowed": network_allowed,
        "target_contact_allowed": target_allowed,
        "items": items,
        "total": len(items),
    }


# ---------------------------------------------------------------------------
# Orchestration


def _run_one(
    connector: Connector, context: ConnectorContext
) -> tuple[str, list[Finding], str, int]:
    started = time.monotonic()
    try:
        findings = connector.run(context)[:MAX_FINDINGS_PER_CONNECTOR]
        status = "ok" if findings else "empty"
        error = ""
    except NetworkPolicyError as exc:
        findings, status, error = [], "error", f"refused by network policy: {exc}"
    except (NetworkError, ValidationError, ValueError) as exc:
        findings, status, error = [], "error", str(exc)
    except Exception:  # noqa: BLE001 - a connector must never break the run
        findings, status, error = [], "error", "connector failed unexpectedly"
    if context.api_key and context.api_key in error:
        error = error.replace(context.api_key, "***")
    return status, findings, error, int((time.monotonic() - started) * 1000)


def run_query(
    database: str,
    *,
    value: object,
    query_type: object = None,
    connector_ids: object = None,
    investigation_id: object = None,
    use_cache: bool = True,
    wait: bool = True,
) -> dict[str, Any]:
    """Fan one artifact out to every compatible connector and persist the run.

    Each source's results are written as soon as that source answers, so a
    caller that passes ``wait=False`` gets the run back at once (sources still
    working are ``pending``) and can poll ``get_run`` for progress.
    """
    detected = detect_artifact(value)
    kind = detected["type"]
    if query_type not in (None, ""):
        if query_type not in ARTIFACT_TYPES:
            raise ValidationError(
                f"query_type must be one of: {', '.join(ARTIFACT_TYPES)}"
            )
        if query_type != kind:
            raise ValidationError(f"value was detected as {kind}, not {query_type}")
    case_id = None
    if investigation_id not in (None, ""):
        if not isinstance(investigation_id, str):
            raise ValidationError("investigation_id must be a string")
        case_id = investigation_id
    selected = connectors()
    if connector_ids not in (None, []):
        if not isinstance(connector_ids, list) or not all(
            isinstance(item, str) for item in connector_ids
        ):
            raise ValidationError("connectors must be a list of connector ids")
        known = {item.connector_id for item in selected}
        unknown = set(connector_ids) - known
        if unknown:
            raise ValidationError(f"unknown connectors: {', '.join(sorted(unknown))}")
        selected = [item for item in selected if item.connector_id in connector_ids]

    run_id = new_id()
    started_at = utc_now()
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        if case_id is not None and connection.execute(
            "SELECT 1 FROM investigations WHERE id = ?", (case_id,)
        ).fetchone() is None:
            raise NotFoundError(f"investigation not found: {case_id}")
        network_allowed = setting_bool(connection, "intel.allow_network", False)
        target_allowed = setting_bool(connection, "intel.allow_target_contact", False)
        workers = setting_int(connection, "intel.max_workers", 4, 1, 16)
        disabled = _disabled_connectors(connection, selected)
        connection.execute(
            """INSERT INTO intel_runs
               (id, investigation_id, query_type, query_value, status,
                connector_count, started_at)
               VALUES (?, ?, ?, ?, 'running', ?, ?)""",
            (run_id, case_id, kind, detected["value"], len(selected), started_at),
        )
        cached: dict[str, list[Finding]] = {}
        if use_cache:
            for connector in selected:
                if connector.ttl_seconds > 0 and kind in connector.accepts:
                    hit = _cache_get(connection, connector.connector_id, kind, detected["value"])
                    if hit is not None:
                        cached[connector.connector_id] = hit

    context = ConnectorContext(database, kind, detected["value"], case_id)
    secrets = {
        connector.key_id: get_secret(database, connector.key_id)
        for connector in selected
        if connector.key_id
    }
    outcomes: dict[str, tuple[str, list[Finding], str, int, bool]] = {}
    runnable: list[Connector] = []
    for connector in selected:
        if kind not in connector.accepts:
            outcomes[connector.connector_id] = ("unsupported", [], "", 0, False)
        elif connector.connector_id in disabled:
            outcomes[connector.connector_id] = ("module-disabled", [], "", 0, False)
        elif connector.connector_id in cached:
            hit = cached[connector.connector_id]
            outcomes[connector.connector_id] = ("ok" if hit else "empty", hit, "", 0, True)
        elif connector.network and not network_allowed:
            outcomes[connector.connector_id] = ("network-disabled", [], "", 0, False)
        elif connector.contacts_target and not target_allowed:
            outcomes[connector.connector_id] = ("target-contact-disabled", [], "", 0, False)
        elif connector.requires_key and not secrets.get(connector.key_id):
            outcomes[connector.connector_id] = ("key-missing", [], "", 0, False)
        elif not RATE_LIMITER.acquire(connector.connector_id, connector.rate_per_minute):
            outcomes[connector.connector_id] = ("rate-limited", [], "", 0, False)
        else:
            runnable.append(connector)

    by_id = {item.connector_id: item for item in selected}
    with _connection(database) as connection:
        for connector_id, outcome in outcomes.items():
            _write_outcome(connection, run_id, by_id[connector_id], outcome, kind, detected["value"], ran=False)
        for connector in runnable:
            _write_outcome(connection, run_id, connector, ("pending", [], "", 0, False), kind, detected["value"], ran=False)

    job = partial(
        _execute, database, run_id, kind, detected["value"], case_id, runnable, context, secrets, workers
    )
    if wait:
        job()
    else:
        _BACKGROUND.submit(job)
    return get_run(database, run_id)


def _write_outcome(
    connection: Any,
    run_id: str,
    connector: Connector,
    outcome: tuple[str, list[Finding], str, int, bool],
    kind: str,
    value: str,
    *,
    ran: bool,
) -> None:
    status, findings, error, elapsed, from_cache = outcome
    if ran:
        _record_status(connection, connector.connector_id, status, error, elapsed)
        if status in {"ok", "empty"} and connector.ttl_seconds > 0:
            _cache_put(connection, connector, kind, value, findings)
    fetched_at = utc_now()
    for finding in findings or [None]:
        connection.execute(
            """INSERT INTO intel_results
               (id, run_id, connector_id, status, cached, result_type, value,
                data_json, source_url, response_sha256, error, elapsed_ms,
                fetched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new_id(),
                run_id,
                connector.connector_id,
                status,
                1 if from_cache else 0,
                finding.result_type if finding else "",
                finding.value if finding else "",
                json.dumps(finding.data if finding else {}, sort_keys=True),
                (finding.source_url if finding else "") or connector.source_url,
                finding.response_sha256 if finding else "",
                error,
                elapsed,
                fetched_at,
            ),
        )


def _finish_run(connection: Any, run_id: str, kind: str, value: str, case_id: str | None) -> None:
    statuses = {
        row["status"]
        for row in connection.execute(
            "SELECT DISTINCT status FROM intel_results WHERE run_id = ?", (run_id,)
        )
    }
    result_count = connection.execute(
        """SELECT COUNT(*) FROM intel_results
           WHERE run_id = ? AND (value <> '' OR result_type <> '')""",
        (run_id,),
    ).fetchone()[0]
    run_status = "completed" if "error" not in statuses else "completed-with-errors"
    connection.execute(
        """UPDATE intel_runs SET status = ?, result_count = ?, finished_at = ?
           WHERE id = ?""",
        (run_status, result_count, utc_now(), run_id),
    )
    record_activity(
        connection,
        action="intel-run",
        target_type="intel_run",
        target_id=run_id,
        investigation_id=case_id,
        summary=f"Multi-source query: {kind} {value[:120]}",
    )


def _execute(
    database: str,
    run_id: str,
    kind: str,
    value: str,
    case_id: str | None,
    runnable: list[Connector],
    context: ConnectorContext,
    secrets: dict[str, str],
    workers: int,
) -> None:
    """Run the connectors and write each one's outcome as it completes."""
    finished: set[str] = set()
    try:
        if runnable:
            with ThreadPoolExecutor(max_workers=min(workers, len(runnable))) as pool:
                futures = {
                    pool.submit(
                        _run_one, connector, replace(context, api_key=secrets.get(connector.key_id, ""))
                    ): connector
                    for connector in runnable
                }
                for future in as_completed(futures):
                    connector = futures[future]
                    status, findings, error, elapsed = future.result()
                    with _connection(database) as connection:
                        connection.execute(
                            "DELETE FROM intel_results WHERE run_id = ? AND connector_id = ? AND status = 'pending'",
                            (run_id, connector.connector_id),
                        )
                        _write_outcome(connection, run_id, connector, (status, findings, error, elapsed, False), kind, value, ran=True)
                    finished.add(connector.connector_id)
    finally:
        with _connection(database) as connection:
            # Anything still pending here was cut short by an unexpected failure.
            connection.execute(
                """UPDATE intel_results SET status = 'error', error = 'the run was interrupted'
                   WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
            _finish_run(connection, run_id, kind, value, case_id)


def recover_interrupted_runs(database: str) -> int:
    """Close runs left 'running' by a previous process (called at startup)."""
    with _connection(database) as connection:
        stale = [row["id"] for row in connection.execute("SELECT id FROM intel_runs WHERE status = 'running'")]
        for run_id in stale:
            connection.execute(
                """UPDATE intel_results SET status = 'error', error = 'the run was interrupted by a restart'
                   WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
            connection.execute(
                "UPDATE intel_runs SET status = 'interrupted', finished_at = ? WHERE id = ?",
                (utc_now(), run_id),
            )
    return len(stale)


def _decode_result(row: Any) -> dict[str, Any]:
    item = dict(row)
    try:
        item["data"] = json.loads(item.pop("data_json") or "{}")
    except ValueError:
        item["data"] = {}
    item["cached"] = bool(item["cached"])
    return item


def get_run(database: str, run_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        run = connection.execute(
            "SELECT * FROM intel_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise NotFoundError(f"intel run not found: {run_id}")
        rows = connection.execute(
            """SELECT * FROM intel_results WHERE run_id = ?
               ORDER BY connector_id, result_type, value""",
            (run_id,),
        ).fetchall()
    results = [_decode_result(row) for row in rows]
    sources: dict[str, dict[str, Any]] = {}
    for item in results:
        entry = sources.setdefault(
            item["connector_id"],
            {
                "connector_id": item["connector_id"],
                "status": item["status"],
                "cached": item["cached"],
                "error": item["error"],
                "elapsed_ms": item["elapsed_ms"],
                "count": 0,
            },
        )
        if item["value"] or item["result_type"]:
            entry["count"] += 1
    ordered = sorted(sources.values(), key=lambda item: item["connector_id"])
    return {
        **dict(run),
        "progress": {
            "total": len(ordered),
            "pending": sum(1 for item in ordered if item["status"] == "pending"),
        },
        "sources": ordered,
        "results": [item for item in results if item["value"] or item["result_type"]],
    }


def list_runs(database: str, *, limit: int = 25) -> dict[str, Any]:
    limit = max(1, min(int(limit), MAX_RUNS_LISTED))
    with _connection(database) as connection:
        require_module(connection, "intel-orchestrator")
        rows = connection.execute(
            "SELECT * FROM intel_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM intel_runs").fetchone()[0]
    return {"items": [dict(row) for row in rows], "total": total}


MAX_OBSERVATION_CHARS = 20_000


def record_run_observation(
    database: str,
    run_id: str,
    *,
    investigation_id: object,
    connector_ids: object = None,
) -> dict[str, Any]:
    """Write a run's findings into a case as one sourced observation.

    The observation text lists every finding with its connector and source URL,
    so the existing indicator extraction and exact-value correlation see it.
    The observation's own reference points back to the run.
    """
    from .store import add_observation

    if not isinstance(investigation_id, str) or not investigation_id:
        raise ValidationError("investigation_id is required")
    run = get_run(database, run_id)
    selected = None
    if connector_ids not in (None, []):
        if not isinstance(connector_ids, list) or not all(
            isinstance(item, str) for item in connector_ids
        ):
            raise ValidationError("connectors must be a list of connector ids")
        selected = set(connector_ids)
    results = [
        item
        for item in run["results"]
        if selected is None or item["connector_id"] in selected
    ]
    if not results:
        raise ValidationError("the run has no findings to record")
    lines = [
        f"Multi-source query {run['query_type']} {run['query_value']} "
        f"(run {run['id']}, {run['started_at']}).",
        "Findings are copied from public sources and have not been independently verified.",
        "Source URLs and response digests are kept in the run record, not in this text,",
        "so connector endpoints are not mistaken for indicators of the case.",
        "",
    ]
    for item in results:
        detail = ", ".join(
            f"{key}={value}"
            for key, value in sorted(item["data"].items())
            if value not in (None, "", [], {})
        )
        line = f"[{item['connector_id']}] {item['result_type']}: {item['value']}"
        if detail:
            line += f" ({detail})"
        lines.append(line)
    content = "\n".join(lines)
    truncated = len(content) > MAX_OBSERVATION_CHARS
    if truncated:
        content = content[: MAX_OBSERVATION_CHARS - 40].rsplit("\n", 1)[0]
        content += "\n[truncated at the observation size limit]"
    observation = add_observation(
        database,
        investigation_id,
        f"Multi-source query: {run['query_value']}"[:300],
        content,
        f"note://garbage/intel-run/{run['id']}",
        "public",
    )
    with _connection(database) as connection:
        connection.execute(
            "UPDATE intel_runs SET investigation_id = ? WHERE id = ? AND investigation_id IS NULL",
            (investigation_id, run["id"]),
        )
    return {"observation": observation, "finding_count": len(results), "truncated": truncated}


PROMOTABLE_TYPES = {
    "dns-a": "ipv4",
    "dns-aaaa": "ipv6",
    "dns-ns": "domain",
    "dns-cname": "domain",
    "dns-mx": "domain",
    "nameserver": "domain",
    "ct-name": "domain",
    "cert-san": "domain",
    "organization": "organization",
    "abuse-contact": "email",
    "archive-capture": "url",
    "http-redirect": "url",
    "lookalike": "domain",
    "asn": "other",
    "as-name": "organization",
    "cidr": "other",
    "hostname": "domain",
    "subdomain": "domain",
    "origin-asn": "other",
    "as-holder": "organization",
    "network-owner": "organization",
    "network-operator": "organization",
    "announced-prefix": "other",
    "malicious-url": "url",
    "final-url": "url",
    "dns-record": "other",
    "website": "url",
    "repository": "url",
    "repo-homepage": "url",
    "fork-of": "url",
    "security-contact-email": "email",
    "security-contact-url": "url",
    "security-policy": "url",
}
MAX_PROMOTIONS = 50


def promotion_value(result_type: str, value: str) -> str:
    """Turn a finding into an entity identifier (MX priority, wildcard, dot)."""
    clean = value.strip()
    if result_type == "dns-mx":
        clean = clean.split()[-1] if clean.split() else ""
    if result_type in {"ct-name", "cert-san"} and clean.startswith("*."):
        clean = clean[2:]
    return clean.rstrip(".")


def promote_results(
    database: str,
    run_id: str,
    *,
    source_entity_id: object,
    items: object,
    investigation_id: object = None,
) -> dict[str, Any]:
    """Pivot step approved by the analyst: selected findings become shared
    entities linked to the source entity by recorded, unverified
    relationships that cite the finding's source."""
    from .entities import (
        _normalize_identifier,
        create_entity,
        create_relationship,
        get_entity,
        link_entity_to_investigation,
    )
    from .errors import ConflictError

    if not isinstance(source_entity_id, str) or not source_entity_id:
        raise ValidationError("source_entity_id is required")
    if not isinstance(items, list) or not items:
        raise ValidationError("items must be a non-empty list")
    if len(items) > MAX_PROMOTIONS:
        raise ValidationError(f"at most {MAX_PROMOTIONS} findings can be promoted at once")
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    get_entity(database, source_entity_id, include_relations=False)
    run = get_run(database, run_id)
    if case_id:
        # The pivot source must be in the case too, or the case graph would
        # show the new entities without the relationships that explain them.
        link_entity_to_investigation(database, case_id, source_entity_id)
    results = {item["id"]: item for item in run["results"]}
    created: list[dict[str, Any]] = []
    reused: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("result_id"), str):
            raise ValidationError("each item needs a result_id")
        finding = results.get(item["result_id"])
        if finding is None:
            raise NotFoundError(f"finding not found in this run: {item['result_id']}")
        entity_type = item.get("entity_type") or PROMOTABLE_TYPES.get(finding["result_type"], "other")
        relationship_type = item.get("relationship_type") or "related-to"
        identifier = promotion_value(finding["result_type"], finding["value"])
        if not identifier or finding["data"].get("null_mx"):
            skipped.append({"result_id": finding["id"], "reason": "finding has no usable identifier"})
            continue
        reference = finding["source_url"]
        if not reference.startswith(("https://", "http://")):
            reference = f"note://garbage/intel-run/{run['id']}"
        description = (
            f"Pivot from {run['query_type']} {run['query_value']} via "
            f"{finding['connector_id']} ({finding['result_type']})."
        )
        try:
            entity = create_entity(
                database,
                entity_type=entity_type,
                name=identifier,
                identifier=identifier,
                description=description,
                source_reference=reference,
                collection_basis="public",
            )
            created.append(entity)
        except ValidationError as exc:
            # One malformed finding (a hostname with an underscore, say)
            # must not abort the rest of the pivot.
            skipped.append({"result_id": finding["id"], "reason": f"invalid identifier: {exc}"})
            continue
        except ConflictError:
            normalized = _normalize_identifier(str(entity_type), identifier)
            with _connection(database) as connection:
                row = connection.execute(
                    "SELECT id FROM entities WHERE entity_type = ? AND identifier = ?",
                    (entity_type, normalized),
                ).fetchone()
            if row is None:
                raise
            entity = get_entity(database, row["id"], include_relations=False)
            reused.append(entity)
        if entity["id"] == source_entity_id:
            skipped.append({"result_id": finding["id"], "reason": "same entity as the pivot source"})
            continue
        if case_id:
            link_entity_to_investigation(database, case_id, entity["id"])
        with _connection(database) as connection:
            duplicate = connection.execute(
                """SELECT id FROM relationships
                   WHERE source_entity_id = ? AND target_entity_id = ?
                     AND relationship_type = ?""",
                (source_entity_id, entity["id"], relationship_type),
            ).fetchone()
        if duplicate is not None:
            skipped.append({"result_id": finding["id"], "reason": "relationship already recorded"})
            continue
        relationships.append(
            create_relationship(
                database,
                source_entity_id=source_entity_id,
                target_entity_id=entity["id"],
                relationship_type=relationship_type,
                description=description,
                source_reference=reference,
                confidence="possible",
                verification_status="not-verified",
                investigation_id=case_id,
            )
        )
    return {
        "created_entities": created,
        "reused_entities": reused,
        "relationships": relationships,
        "skipped": skipped,
    }


# ---------------------------------------------------------------------------
# Built-in local connectors (no network)


def _structure_connector(context: ConnectorContext) -> list[Finding]:
    if context.query_type == "cve":
        match = _CVE.fullmatch(context.query_value)
        return [
            Finding("fact", context.query_value, {"label": "Year", "value": match.group(1)})
        ] if match else []
    inspection = inspect_value(context.query_value)
    findings = [
        Finding("fact", str(fact.get("value", "")), {"label": fact.get("label", "")})
        for fact in inspection.get("facts", [])
    ]
    findings.extend(
        Finding("warning", str(warning), {})
        for warning in inspection.get("warnings", [])
    )
    return findings


def _workspace_connector(context: ConnectorContext) -> list[Finding]:
    from .workspace import inspect_local_indicator

    if context.query_type == "cve":
        return []
    local = inspect_local_indicator(
        context.database,
        value=context.query_value,
        investigation_id=context.investigation_id,
    )["local"]
    findings: list[Finding] = []
    for entity in local["entities"]:
        findings.append(
            Finding(
                "entity",
                entity["name"],
                {
                    "id": entity["id"],
                    "entity_type": entity["entity_type"],
                    "identifier": entity["identifier"],
                    "verification_status": entity["verification_status"],
                },
            )
        )
    for record in local["evidence"]:
        findings.append(
            Finding(
                "evidence",
                record["title"],
                {
                    "id": record["id"],
                    "investigation_id": record["investigation_id"],
                    "sha256": record["sha256"],
                    "integrity_status": record["integrity_status"],
                },
            )
        )
    for analysis in local["file_analyses"]:
        findings.append(
            Finding(
                "file-analysis",
                analysis["file_name"],
                {"id": analysis["id"], "format": analysis["format"], "sha256": analysis["sha256"]},
            )
        )
    indicator = local["indicator"]
    if indicator is not None:
        findings.append(
            Finding(
                "indicator",
                indicator["value"],
                {
                    "type": indicator["type"],
                    "origin_count": indicator.get("origin_count", 0),
                    "verification_status": indicator.get("verification_status", ""),
                },
            )
        )
    for item in local["cooccurring"]:
        findings.append(
            Finding("co-occurrence", item["value"], {"type": item["type"], "count": item["count"]})
        )
    for item in local["lookalikes"].get("items", []):
        findings.append(
            Finding(
                "lookalike",
                item.get("value", ""),
                {key: value for key, value in item.items() if key != "value"},
            )
        )
    return findings


register_connector(
    Connector(
        connector_id="local-structure",
        name="Structural facts",
        description="Syntax, canonical form and structural facts of the artifact; nothing leaves the machine.",
        accepts=ARTIFACT_TYPES,
        run=_structure_connector,
    )
)
register_connector(
    Connector(
        connector_id="local-workspace",
        name="Local workspace",
        description="Exact matches in local entities, evidence, file analyses and indicator index.",
        accepts=tuple(item for item in ARTIFACT_TYPES if item != "cve"),
        run=_workspace_connector,
    )
)

# Public network connectors register themselves on import. Imported last so
# the registry and Finding types above are fully defined.
from .modules import intel_connectors as _intel_connectors  # noqa: E402,F401
from .modules import intel_target_connectors as _intel_target_connectors  # noqa: E402,F401
from .modules import intel_open_connectors as _intel_open_connectors  # noqa: E402,F401
from .modules import intel_keyed_connectors as _intel_keyed_connectors  # noqa: E402,F401
from .modules import intel_org_connectors as _intel_org_connectors  # noqa: E402,F401
