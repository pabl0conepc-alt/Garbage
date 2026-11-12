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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .db import (
    _connection,
    new_id,
    record_activity,
    require_module,
    setting_bool,
    setting_int,
    utc_now,
)
from .errors import NotFoundError, ValidationError
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
    "ok",
    "empty",
    "error",
    "rate-limited",
    "network-disabled",
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


ConnectorFunction = Callable[[ConnectorContext], list[Finding]]


@dataclass(frozen=True)
class Connector:
    connector_id: str
    name: str
    description: str
    accepts: tuple[str, ...]
    run: ConnectorFunction
    network: bool = False
    requires_key: bool = False
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
        status_rows = {
            row["connector_id"]: dict(row)
            for row in connection.execute("SELECT * FROM intel_source_status")
        }
    items = []
    for connector in connectors():
        status = status_rows.get(connector.connector_id)
        if connector.network and not network_allowed:
            availability = "network-disabled"
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
                "rate_per_minute": connector.rate_per_minute,
                "ttl_seconds": connector.ttl_seconds,
                "source_url": connector.source_url,
                "availability": availability,
                "status": status,
            }
        )
    return {"network_allowed": network_allowed, "items": items, "total": len(items)}


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
    return status, findings, error, int((time.monotonic() - started) * 1000)


def run_query(
    database: str,
    *,
    value: object,
    query_type: object = None,
    connector_ids: object = None,
    investigation_id: object = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Fan one artifact out to every compatible connector and persist the run."""
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
        workers = setting_int(connection, "intel.max_workers", 4, 1, 16)
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
    outcomes: dict[str, tuple[str, list[Finding], str, int, bool]] = {}
    runnable: list[Connector] = []
    for connector in selected:
        if kind not in connector.accepts:
            outcomes[connector.connector_id] = ("unsupported", [], "", 0, False)
        elif connector.connector_id in cached:
            hit = cached[connector.connector_id]
            outcomes[connector.connector_id] = ("ok" if hit else "empty", hit, "", 0, True)
        elif connector.network and not network_allowed:
            outcomes[connector.connector_id] = ("network-disabled", [], "", 0, False)
        elif not RATE_LIMITER.acquire(connector.connector_id, connector.rate_per_minute):
            outcomes[connector.connector_id] = ("rate-limited", [], "", 0, False)
        else:
            runnable.append(connector)

    if runnable:
        with ThreadPoolExecutor(max_workers=min(workers, len(runnable))) as pool:
            futures = {
                connector.connector_id: pool.submit(_run_one, connector, context)
                for connector in runnable
            }
            for connector_id, future in futures.items():
                status, findings, error, elapsed = future.result()
                outcomes[connector_id] = (status, findings, error, elapsed, False)

    fetched_at = utc_now()
    by_id = {item.connector_id: item for item in selected}
    result_count = 0
    with _connection(database) as connection:
        for connector_id, (status, findings, error, elapsed, from_cache) in outcomes.items():
            connector = by_id[connector_id]
            if connector in runnable:
                _record_status(connection, connector_id, status, error, elapsed)
                if status in {"ok", "empty"} and connector.ttl_seconds > 0:
                    _cache_put(connection, connector, kind, detected["value"], findings)
            rows = findings or [None]
            for finding in rows:
                if finding is not None:
                    result_count += 1
                connection.execute(
                    """INSERT INTO intel_results
                       (id, run_id, connector_id, status, cached, result_type, value,
                        data_json, source_url, response_sha256, error, elapsed_ms,
                        fetched_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        new_id(),
                        run_id,
                        connector_id,
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
        statuses = {outcome[0] for outcome in outcomes.values()}
        run_status = "completed" if "error" not in statuses else "completed-with-errors"
        connection.execute(
            """UPDATE intel_runs SET status = ?, result_count = ?, finished_at = ?
               WHERE id = ?""",
            (run_status, result_count, fetched_at, run_id),
        )
        record_activity(
            connection,
            action="intel-run",
            target_type="intel_run",
            target_id=run_id,
            investigation_id=case_id,
            summary=f"Multi-source query: {kind} {detected['value'][:120]}",
        )
    return get_run(database, run_id)


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
    return {
        **dict(run),
        "sources": sorted(sources.values(), key=lambda item: item["connector_id"]),
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
