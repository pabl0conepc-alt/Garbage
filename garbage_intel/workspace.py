"""Workspace-level services: modules, settings, activity, indicators, search."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__, native
from .db import (
    MODULE_STATES,
    SCHEMA_VERSION,
    SETTING_SCHEMA,
    VERIFICATION_STATUSES,
    _connection,
    module_enabled,
    record_activity,
    setting_int,
    utc_now,
)
from .platform_support import runtime_diagnostics
from .errors import ConflictError, NotFoundError, ValidationError
from .modules.correlation import correlate_indicators
from .modules.indicator_tools import inspect_value, triage_text
from .modules.indicators import extract_indicators
from .modules.lookalikes import find_domain_lookalikes
from .validation import choice, clean_text, search_pattern


INDICATOR_TYPE_LABELS = {
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "cidr": "CIDR network",
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "username": "Username",
}
_CORE_MODULES = {"module-manager", "settings", "investigations"}


def indicator_types() -> list[dict[str, str]]:
    return [
        {"value": key, "label": label}
        for key, label in INDICATOR_TYPE_LABELS.items()
    ]


def list_modules(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        rows = connection.execute(
            """SELECT module_id, name, description, category, version, state,
                      updated_at
               FROM module_registry
               ORDER BY category, name, module_id"""
        ).fetchall()
    items = [
        {
            **dict(row),
            "enabled": row["state"] == "enabled",
            "toggleable": row["state"] != "planned",
            "core": row["module_id"] in _CORE_MODULES,
        }
        for row in rows
    ]
    return {
        "items": items,
        "states": list(MODULE_STATES),
        "enabled": sum(1 for item in items if item["enabled"]),
        "planned": sum(1 for item in items if item["state"] == "planned"),
    }


def set_module_state(database: str, module_id: str, state: object) -> dict[str, Any]:
    target = choice(state, ("enabled", "disabled", "available"), "module state")
    with _connection(database) as connection:
        row = connection.execute(
            "SELECT module_id, name, state FROM module_registry WHERE module_id = ?",
            (module_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"module not found: {module_id}")
        if row["state"] == "planned":
            raise ConflictError(
                "planned modules are not implemented and cannot be enabled"
            )
        if target != "enabled" and module_id in _CORE_MODULES:
            raise ConflictError(
                f"{row['name']} is a core module and cannot be disabled"
            )
        connection.execute(
            "UPDATE module_registry SET state = ?, updated_at = ? WHERE module_id = ?",
            (target, utc_now(), module_id),
        )
        record_activity(
            connection,
            action="module",
            target_type="module",
            target_id=module_id,
            summary=f"Module {row['name']} set to {target}",
        )
        updated = connection.execute(
            """SELECT module_id, name, description, category, version, state,
                      updated_at
               FROM module_registry WHERE module_id = ?""",
            (module_id,),
        ).fetchone()
    return {
        **dict(updated),
        "enabled": updated["state"] == "enabled",
        "toggleable": updated["state"] != "planned",
        "core": module_id in _CORE_MODULES,
    }


def get_settings(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        stored = {
            row["key"]: row["value"]
            for row in connection.execute(
                "SELECT key, value FROM application_settings"
            )
        }
    values = {
        item["key"]: stored.get(item["key"], item["options"][0])
        for item in SETTING_SCHEMA
    }
    schema = []
    for item in SETTING_SCHEMA:
        entry = {key: value for key, value in item.items() if key != "options"}
        if item["type"] == "integer":
            entry["minimum"] = int(item["options"][0])
            entry["maximum"] = int(item["options"][1])
        else:
            entry["options"] = list(item["options"])
        schema.append(entry)
    return {"values": values, "schema": schema}


def _coerce_setting(entry: dict[str, Any], value: object) -> str:
    key = entry["key"]
    if entry["type"] == "boolean":
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str) and value.strip().lower() in {
            "true",
            "false",
        }:
            return value.strip().lower()
        raise ValidationError(f"{key} must be true or false")
    if entry["type"] == "choice":
        if not isinstance(value, str) or value not in entry["options"]:
            raise ValidationError(
                f"{key} must be one of: {', '.join(entry['options'])}"
            )
        return value
    if entry["type"] == "integer":
        minimum = int(entry["options"][0])
        maximum = int(entry["options"][1])
        try:
            number = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"{key} must be an integer") from exc
        if not minimum <= number <= maximum:
            raise ValidationError(f"{key} must be between {minimum} and {maximum}")
        return str(number)
    raise ValidationError(f"unsupported setting type for {key}")


def update_settings(database: str, payload: dict[str, Any]) -> dict[str, Any]:
    schema = {item["key"]: item for item in SETTING_SCHEMA}
    if not isinstance(payload, dict) or not payload:
        raise ValidationError("provide at least one setting")
    unknown = set(payload) - set(schema)
    if unknown:
        raise ValidationError(f"unknown settings: {', '.join(sorted(unknown))}")
    cleaned = {
        key: _coerce_setting(schema[key], value) for key, value in payload.items()
    }
    with _connection(database) as connection:
        for key, value in cleaned.items():
            connection.execute(
                """INSERT INTO application_settings (key, value, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE
                   SET value = excluded.value, updated_at = excluded.updated_at""",
                (key, value, utc_now()),
            )
        record_activity(
            connection,
            action="settings",
            target_type="settings",
            target_id=",".join(sorted(cleaned)),
            summary=f"Settings updated: {', '.join(sorted(cleaned))}",
        )
    return get_settings(database)


def list_activities(
    database: str,
    *,
    investigation_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    clauses: list[str] = []
    parameters: list[Any] = []
    if investigation_id:
        clauses.append("a.investigation_id = ?")
        parameters.append(investigation_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM activities a {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""SELECT a.id, a.investigation_id, a.actor, a.action,
                       a.target_type, a.target_id, a.summary, a.created_at,
                       i.name AS investigation_name
                FROM activities a
                LEFT JOIN investigations i ON i.id = a.investigation_id
                {where}
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT ? OFFSET ?""",
            [*parameters, limit, offset],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def _indicator_type_for_entity(entity_type: str, identifier: str) -> str | None:
    if entity_type in {"domain", "ipv4", "ipv6", "url", "email", "username"}:
        return entity_type
    if entity_type == "hash":
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(identifier))
    return None


def _indicator_index(
    database: str, investigation_id: str | None = None
) -> dict[str, Any]:
    observation_parameters: list[Any] = []
    observation_filter = ""
    if investigation_id:
        observation_filter = "WHERE o.investigation_id = ?"
        observation_parameters.append(investigation_id)
    with _connection(database) as connection:
        observation_rows = connection.execute(
            f"""SELECT o.id, o.investigation_id, i.name AS investigation_name,
                       o.content, o.source_reference, o.collection_basis,
                       o.observed_at, o.recorded_at
                FROM observations o
                JOIN investigations i ON i.id = o.investigation_id
                {observation_filter}
                ORDER BY o.observed_at, o.recorded_at, o.id
                LIMIT 5000""",
            observation_parameters,
        ).fetchall()
        if investigation_id:
            entity_rows = connection.execute(
                """SELECT e.id, e.entity_type, e.name, e.identifier,
                          e.source_reference, e.verification_status, e.created_at
                   FROM entities e
                   JOIN investigation_entities ie ON ie.entity_id = e.id
                   WHERE ie.investigation_id = ?
                     AND e.identifier <> ''
                   ORDER BY e.created_at, e.id""",
                (investigation_id,),
            ).fetchall()
        else:
            entity_rows = connection.execute(
                """SELECT id, entity_type, name, identifier, source_reference,
                          verification_status, created_at
                   FROM entities WHERE identifier <> ''
                   ORDER BY created_at, id
                   LIMIT 5000"""
            ).fetchall()
        evidence_parameters: list[Any] = []
        evidence_filter = ""
        if investigation_id:
            evidence_filter = "WHERE e.investigation_id = ?"
            evidence_parameters.append(investigation_id)
        evidence_rows = connection.execute(
            f"""SELECT e.id, e.investigation_id, e.title, e.source_reference,
                       e.sha256, e.recorded_at, e.integrity_status,
                       i.name AS investigation_name
                FROM evidence e
                LEFT JOIN investigations i ON i.id = e.investigation_id
                {evidence_filter}
                AND e.sha256 <> ''
                ORDER BY e.recorded_at, e.id
                LIMIT 5000"""
            if investigation_id
            else """SELECT e.id, e.investigation_id, e.title, e.source_reference,
                           e.sha256, e.recorded_at, e.integrity_status,
                           i.name AS investigation_name
                    FROM evidence e
                    LEFT JOIN investigations i ON i.id = e.investigation_id
                    WHERE e.sha256 <> ''
                    ORDER BY e.recorded_at, e.id
                    LIMIT 5000""",
            evidence_parameters,
        ).fetchall()
        assessments = {
            (row["indicator_type"], row["value"]): dict(row)
            for row in connection.execute(
                """SELECT indicator_type, value, verification_status, note,
                          updated_at FROM indicator_assessments"""
            )
        }
        indicator_engine = module_enabled(connection, "indicator-engine")

    findings = (
        extract_indicators(dict(row) for row in observation_rows)
        if indicator_engine
        else []
    )
    correlations = correlate_indicators(findings) if indicator_engine else []
    observation_meta = {row["id"]: row for row in observation_rows}
    case_name = None
    if investigation_id:
        with _connection(database) as connection:
            case_row = connection.execute(
                "SELECT name FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            case_name = case_row["name"] if case_row else None
    index: dict[tuple[str, str], dict[str, Any]] = {}

    def add_origin(kind: str, value: str, origin: dict[str, Any]) -> None:
        key = (kind, value)
        item = index.setdefault(
            key,
            {
                "type": kind,
                "value": value,
                "origins": [],
                "investigations": {},
                "verification_status": "not-verified",
                "assessment_note": "",
            },
        )
        timestamp = str(origin.get("observed_at") or origin.get("recorded_at") or "")
        item["origins"].append(
            {
                "origin_type": origin["origin_type"],
                "origin_id": origin["origin_id"],
                "investigation_id": origin.get("investigation_id"),
                "investigation_name": origin.get("investigation_name"),
                "label": origin.get("label", ""),
                "source_reference": origin.get("source_reference", ""),
                "timestamp": timestamp,
                "verification_status": origin.get("verification_status", "not-verified"),
            }
        )
        if origin.get("investigation_id") and origin.get("investigation_name"):
            item["investigations"][origin["investigation_id"]] = origin[
                "investigation_name"
            ]
        if timestamp:
            if not item.get("first_seen") or timestamp < item["first_seen"]:
                item["first_seen"] = timestamp
            if not item.get("last_seen") or timestamp > item["last_seen"]:
                item["last_seen"] = timestamp

    for finding in findings:
        meta = observation_meta.get(finding["source_observation_id"])
        add_origin(
            finding["type"],
            finding["value"],
            {
                "origin_type": "observation",
                "origin_id": finding["source_observation_id"],
                "investigation_id": meta["investigation_id"] if meta else None,
                "investigation_name": meta["investigation_name"] if meta else None,
                "label": "Observation",
                "source_reference": finding["source_reference"],
                "observed_at": finding["observed_at"],
                "recorded_at": finding["recorded_at"],
            },
        )

    for entity in entity_rows:
        kind = _indicator_type_for_entity(
            entity["entity_type"], entity["identifier"]
        )
        if kind is None:
            continue
        add_origin(
            kind,
            entity["identifier"],
            {
                "origin_type": "entity",
                "origin_id": entity["id"],
                "investigation_id": investigation_id,
                "investigation_name": case_name,
                "label": entity["name"],
                "source_reference": entity["source_reference"],
                "recorded_at": entity["created_at"],
                "verification_status": entity["verification_status"],
            },
        )

    for record in evidence_rows:
        status = (
            "verified"
            if record["integrity_status"] == "verified"
            else "disputed"
            if record["integrity_status"] in {"mismatch", "missing"}
            else "not-verified"
        )
        add_origin(
            "sha256",
            record["sha256"],
            {
                "origin_type": "evidence",
                "origin_id": record["id"],
                "investigation_id": record["investigation_id"],
                "investigation_name": record["investigation_name"],
                "label": record["title"],
                "source_reference": record["source_reference"],
                "recorded_at": record["recorded_at"],
                "verification_status": status,
            },
        )

    items = []
    for item in index.values():
        item["origins"].sort(
            key=lambda origin: (
                origin.get("timestamp") or "",
                origin["origin_type"],
                origin["origin_id"],
            )
        )
        item["origin_count"] = len(item["origins"])
        item["origins"] = item["origins"][:50]
        item["investigations"] = [
            {"id": key, "name": value}
            for key, value in sorted(
                item["investigations"].items(), key=lambda pair: pair[1]
            )
        ]
        assessment = assessments.get((item["type"], item["value"]))
        if assessment:
            item["verification_status"] = assessment["verification_status"]
            item["assessment_note"] = assessment["note"]
        items.append(item)
    items.sort(key=lambda item: (item["type"], item["value"]))
    counts = Counter(item["type"] for item in items)
    return {
        "items": items,
        "total": len(items),
        "counts": dict(counts),
        "extraction_count": len(findings),
        "correlation_count": len(correlations),
        "correlations": correlations[:200],
        "correlations_truncated": len(correlations) > 200,
        "truncated": len(observation_rows) >= 5000,
        "indicator_engine": indicator_engine,
    }


def unified_indicators(
    database: str,
    *,
    investigation_id: str | None = None,
    indicator_type: str | None = None,
    search: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    limit = max(1, min(1000, int(limit)))
    index = _indicator_index(database, investigation_id)
    items = index["items"]
    if indicator_type:
        if indicator_type not in INDICATOR_TYPE_LABELS:
            raise ValidationError(
                f"indicator type must be one of: {', '.join(INDICATOR_TYPE_LABELS)}"
            )
        items = [item for item in items if item["type"] == indicator_type]
    query = search.strip().casefold()
    if query:
        items = [
            item
            for item in items
            if query in item["value"].casefold() or query in item["type"].casefold()
        ]
    total = len(items)
    return {
        **index,
        "items": items[:limit],
        "total": total,
        "limit": limit,
        "types": indicator_types(),
    }


def inspect_local_indicator(
    database: str,
    *,
    value: object,
    investigation_id: str | None = None,
) -> dict[str, Any]:
    """Inspect one value and compare it with local, exact-value records."""
    clean_value = clean_text(value, "indicator value", max_length=2000, required=True)
    inspection = inspect_value(clean_value)
    kind = inspection["kind"]
    canonical = inspection["canonical"]
    index = _indicator_index(database, investigation_id)
    matched = next(
        (
            item
            for item in index["items"]
            if item["type"] == kind and item["value"] == canonical
        ),
        None,
    )
    if matched is not None:
        matched = {**matched, "origins": matched["origins"][:20]}

    entities: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    file_analyses: list[dict[str, Any]] = []
    cooccurring: list[dict[str, Any]] = []
    if canonical:
        with _connection(database) as connection:
            if kind in {"domain", "ipv4", "ipv6", "url", "email", "username"}:
                entity_rows = connection.execute(
                    """SELECT id, entity_type, name, identifier, confidence,
                              verification_status, updated_at
                       FROM entities
                       WHERE lower(identifier) = lower(?)
                       ORDER BY updated_at DESC LIMIT 20""",
                    (canonical,),
                ).fetchall()
                entities = [dict(row) for row in entity_rows]
            if kind in {"md5", "sha1", "sha256"}:
                evidence_rows = connection.execute(
                    """SELECT e.id, e.investigation_id, e.title, e.evidence_type,
                              e.sha256, e.integrity_status, e.recorded_at,
                              i.name AS investigation_name
                       FROM evidence e
                       LEFT JOIN investigations i ON i.id = e.investigation_id
                       WHERE lower(e.sha256) = lower(?)
                       ORDER BY e.recorded_at DESC LIMIT 20""",
                    (canonical,),
                ).fetchall()
                evidence = [dict(row) for row in evidence_rows]
            analysis_rows = connection.execute(
                """SELECT id, investigation_id, file_name, format, sha256, created_at
                   FROM file_analyses
                   WHERE lower(sha256) = lower(?)
                   ORDER BY created_at DESC LIMIT 20""",
                (canonical,),
            ).fetchall()
            file_analyses = [dict(row) for row in analysis_rows]

            if matched is not None:
                observation_ids = [
                    origin["origin_id"]
                    for origin in matched["origins"]
                    if origin["origin_type"] == "observation"
                ]
                if observation_ids:
                    placeholders = ",".join("?" for _ in observation_ids)
                    observation_rows = connection.execute(
                        f"""SELECT id, content, source_reference, collection_basis,
                                  observed_at, recorded_at
                           FROM observations WHERE id IN ({placeholders})
                           LIMIT 50""",
                        observation_ids,
                    ).fetchall()
                    related: dict[tuple[str, str], int] = {}
                    for row in observation_rows:
                        for finding in extract_indicators(
                            [dict(row)], deduplicate=False
                        ):
                            key = (finding["type"], finding["value"])
                            if key == (kind, canonical):
                                continue
                            related[key] = related.get(key, 0) + 1
                    cooccurring = [
                        {"type": kind_value[0], "value": kind_value[1], "count": count}
                        for kind_value, count in sorted(
                            related.items(),
                            key=lambda item: (-item[1], item[0]),
                        )[:8]
                    ]

    lookalikes = {"engine": "none", "items": [], "scanned": 0}
    if kind == "domain":
        candidates = [
            item["value"]
            for item in index["items"]
            if item["type"] == "domain"
        ]
        candidates.extend(
            row["identifier"] for row in entities if row.get("identifier")
        )
        lookalikes = find_domain_lookalikes(canonical, candidates)

    return {
        **inspection,
        "local": {
            "indicator": matched,
            "entities": entities,
            "evidence": evidence,
            "file_analyses": file_analyses,
            "cooccurring": cooccurring,
            "lookalikes": lookalikes,
        },
        "match_count": (
            (1 if matched else 0)
            + len(entities)
            + len(evidence)
            + len(file_analyses)
        ),
        "scope": {
            "investigation_id": investigation_id,
            "indicator_index_total": index["total"],
        },
    }


def triage_indicators(database: str, *, text: object) -> dict[str, Any]:
    """Run the non-persistent text triage tool and expose engine state."""
    with _connection(database) as connection:
        enabled = module_enabled(connection, "indicator-engine")
    if not enabled:
        raise ConflictError("indicator engine is disabled in the module registry")
    return triage_text(text)


def case_coverage(database: str, investigation_id: str) -> dict[str, Any]:
    """Return factual completeness checks for one case, not a risk score."""
    from .store import build_report

    report = build_report(database, investigation_id)
    observations = report["observations"]
    entities = report["entities"]
    evidence = report["evidence"]
    sources = report["sources"]
    relationships = report["relationships"]
    index = _indicator_index(database, investigation_id)

    checks: list[dict[str, Any]] = []

    def add(
        key: str,
        label: str,
        status: str,
        count: int,
        detail: str,
        tab: str,
    ) -> None:
        checks.append(
            {
                "key": key,
                "label": label,
                "status": status,
                "count": count,
                "detail": detail,
                "tab": tab,
            }
        )

    missing_sources = sum(1 for item in observations if not item["source_reference"])
    add(
        "observation-sources",
        "Observations with provenance",
        "attention" if missing_sources else "ok",
        missing_sources,
        (
            f"{missing_sources} observation(s) have no source reference."
            if missing_sources
            else "Every observation carries a source reference."
        ),
        "overview",
    )

    add(
        "entity-links",
        "Linked entities",
        "attention" if not entities else "ok",
        len(entities),
        (
            "Link at least one entity so the case can use the shared registry."
            if not entities
            else f"{len(entities)} entity record(s) linked."
        ),
        "entities",
    )

    unverified_files = sum(
        1 for item in evidence if item.get("integrity_status") != "verified"
    )
    add(
        "evidence-integrity",
        "Evidence integrity",
        "attention" if not evidence or unverified_files else "ok",
        unverified_files if evidence else 0,
        (
            "No evidence is attached to this case."
            if not evidence
            else f"{unverified_files} evidence record(s) are not verified."
            if unverified_files
            else "All stored evidence has a verified digest."
        ),
        "evidence",
    )

    add(
        "source-records",
        "Linked sources",
        "attention" if not sources else "ok",
        len(sources),
        (
            "Register or link a source record for the material used."
            if not sources
            else f"{len(sources)} source record(s) linked."
        ),
        "sources",
    )

    add(
        "relationships",
        "Relationship coverage",
        "info" if not relationships else "ok",
        len(relationships),
        (
            "No entity relationship is recorded yet."
            if not relationships
            else f"{len(relationships)} relationship(s) recorded."
        ),
        "relationships",
    )

    add(
        "indicators",
        "Indicator extraction",
        "info" if not index["total"] else "ok",
        index["total"],
        (
            "No indicator was extracted from the current records."
            if not index["total"]
            else f"{index['total']} unique indicator(s) extracted."
        ),
        "indicators",
    )

    unassessed = sum(
        1 for item in index["items"] if item["verification_status"] == "not-verified"
    )
    add(
        "assessments",
        "Indicator assessments",
        "info" if unassessed else "ok",
        unassessed,
        (
            f"{unassessed} indicator(s) still have no analyst assessment."
            if unassessed
            else "Every extracted indicator has an assessment."
        ),
        "indicators",
    )

    disputed = sum(
        1
        for item in index["items"]
        if item["verification_status"] in {"disputed", "false-positive"}
    )
    add(
        "disputed",
        "Disputed indicators",
        "attention" if disputed else "ok",
        disputed,
        (
            f"{disputed} indicator(s) are disputed or marked false-positive."
            if disputed
            else "No indicator is disputed or marked false-positive."
        ),
        "indicators",
    )

    add(
        "correlations",
        "Cross-source corroboration",
        "info" if not index["correlation_count"] else "ok",
        index["correlation_count"],
        (
            "No exact value appears in more than one observation yet."
            if not index["correlation_count"]
            else f"{index['correlation_count']} value(s) appear in multiple observations."
        ),
        "indicators",
    )

    summary = Counter(check["status"] for check in checks)
    return {
        "investigation_id": investigation_id,
        "checks": checks,
        "summary": {
            "attention": summary["attention"],
            "info": summary["info"],
            "ok": summary["ok"],
            "total": len(checks),
        },
        "disclaimer": (
            "Coverage checks facts present in the case. They do not measure "
            "analytical quality, risk or guilt, and absence of attention items "
            "does not prove completeness."
        ),
    }


def set_indicator_assessment(
    database: str,
    *,
    indicator_type: object,
    value: object,
    verification_status: object,
    note: object = "",
) -> dict[str, Any]:
    kind = choice(indicator_type, tuple(INDICATOR_TYPE_LABELS), "indicator type")
    clean_value = clean_text(value, "indicator value", max_length=2000, required=True)
    status = choice(
        verification_status, VERIFICATION_STATUSES, "verification status"
    )
    clean_note = clean_text(note, "assessment note", max_length=2000)
    with _connection(database) as connection:
        if status == "not-verified" and not clean_note:
            connection.execute(
                """DELETE FROM indicator_assessments
                   WHERE indicator_type = ? AND value = ?""",
                (kind, clean_value),
            )
        else:
            connection.execute(
                """INSERT INTO indicator_assessments
                   (indicator_type, value, verification_status, note, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(indicator_type, value) DO UPDATE
                   SET verification_status = excluded.verification_status,
                       note = excluded.note,
                       updated_at = excluded.updated_at""",
                (kind, clean_value, status, clean_note, utc_now()),
            )
        record_activity(
            connection,
            action="assessment",
            target_type="indicator",
            target_id=f"{kind}:{clean_value}"[:200],
            summary=f"Indicator assessment set to {status}",
        )
    return {
        "indicator_type": kind,
        "value": clean_value,
        "verification_status": status,
        "note": clean_note,
    }


def system_info(database: str) -> dict[str, Any]:
    path = Path(database)
    table_names = (
        "investigations",
        "observations",
        "entities",
        "relationships",
        "evidence",
        "sources",
        "boards",
        "activities",
    )
    with _connection(database) as connection:
        migrations = [
            dict(row)
            for row in connection.execute(
                """SELECT version, description, applied_at
                   FROM schema_migrations ORDER BY version"""
            )
        ]
        counts = {
            name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in table_names
        }
        modules = [
            {"module_id": row["module_id"], "state": row["state"]}
            for row in connection.execute(
                "SELECT module_id, state FROM module_registry ORDER BY module_id"
            )
        ]
    return {
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "database": {
            "name": path.name,
            "file_backed": str(database) != ":memory:",
            "size_bytes": path.stat().st_size if path.is_file() else 0,
        },
        "runtime": runtime_diagnostics(),
        "native": native.native_status(),
        "migrations": migrations,
        "counts": counts,
        "modules": modules,
        "integrations": [
            {
                "module_id": "cisa-kev",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "mode": "explicit manual refresh",
            },
            {
                "module_id": "nvd-connector",
                "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "mode": "explicit multi-source query",
            },
        ],
    }


def overview(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        investigation_counts = {
            row["status"]: row["count"]
            for row in connection.execute(
                """SELECT status, COUNT(*) AS count
                   FROM investigations GROUP BY status"""
            )
        }
        totals = {
            "investigations": sum(investigation_counts.values()),
            "entities": connection.execute(
                "SELECT COUNT(*) FROM entities"
            ).fetchone()[0],
            "evidence": connection.execute(
                "SELECT COUNT(*) FROM evidence"
            ).fetchone()[0],
            "sources": connection.execute(
                "SELECT COUNT(*) FROM sources"
            ).fetchone()[0],
            "observations": connection.execute(
                "SELECT COUNT(*) FROM observations"
            ).fetchone()[0],
            "relationships": connection.execute(
                "SELECT COUNT(*) FROM relationships"
            ).fetchone()[0],
            "boards": connection.execute("SELECT COUNT(*) FROM boards").fetchone()[0],
        }
        collection_basis = {
            row["collection_basis"]: row["count"]
            for row in connection.execute(
                """SELECT collection_basis, COUNT(*) AS count
                   FROM observations GROUP BY collection_basis"""
            )
        }
        recent_investigations = [
            dict(row)
            for row in connection.execute(
                """SELECT i.id, i.name, i.status, i.created_at, i.updated_at,
                          (SELECT COUNT(*) FROM observations o
                           WHERE o.investigation_id = i.id) AS observation_count,
                          (SELECT COUNT(*) FROM evidence e
                           WHERE e.investigation_id = i.id) AS evidence_count,
                          (SELECT COUNT(*) FROM investigation_entities ie
                           WHERE ie.investigation_id = i.id) AS entity_count
                   FROM investigations i
                   ORDER BY i.updated_at DESC, i.created_at DESC
                   LIMIT 6"""
            )
        ]
        module_summary = {
            row["state"]: row["count"]
            for row in connection.execute(
                "SELECT state, COUNT(*) AS count FROM module_registry GROUP BY state"
            )
        }
    recent_activity = list_activities(database, limit=12)["items"]
    index = _indicator_index(database)
    return {
        "totals": {
            **totals,
            "open": investigation_counts.get("open", 0),
            "closed": investigation_counts.get("closed", 0),
            "cancelled": investigation_counts.get("cancelled", 0),
            "unique_indicators": index["total"],
            "correlations": index["correlation_count"],
            "indicator_origins": index["extraction_count"],
        },
        "collection_basis": collection_basis,
        "indicator_mix": index["counts"],
        "indicator_engine": index["indicator_engine"],
        "recent_investigations": recent_investigations,
        "recent_activity": recent_activity,
        "modules": module_summary,
    }


def global_search(database: str, query: str, limit: int | None = None) -> dict[str, Any]:
    with _connection(database) as connection:
        if not module_enabled(connection, "global-search"):
            raise ConflictError("global search is disabled in the module registry")
        default_limit = setting_int(connection, "search.result_limit", 6, 1, 20)
    clean_query = clean_text(query, "query", max_length=200)
    result_limit = max(1, min(20, limit if limit is not None else default_limit))
    if len(clean_query) < 2:
        return {
            "query": clean_query,
            "groups": [],
            "total": 0,
            "limit": result_limit,
            "message": "Enter at least two characters to search.",
        }
    pattern = search_pattern(clean_query)
    groups: list[dict[str, Any]] = []

    def collect(
        key: str,
        label: str,
        count_sql: str,
        item_sql: str,
        parameters: list[Any],
        mapper: Any,
    ) -> None:
        with _connection(database) as connection:
            total = connection.execute(count_sql, parameters).fetchone()[0]
            rows = connection.execute(
                f"{item_sql} LIMIT ?", [*parameters, result_limit]
            ).fetchall()
        groups.append(
            {
                "key": key,
                "label": label,
                "total": total,
                "items": [mapper(row) for row in rows],
            }
        )

    collect(
        "investigations",
        "Investigations",
        """SELECT COUNT(*) FROM investigations
           WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'""",
        """SELECT id, name, status, created_at FROM investigations
           WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
           ORDER BY updated_at DESC, name""",
        [pattern, pattern],
        lambda row: {
            "id": row["id"],
            "title": row["name"],
            "subtitle": f"Investigation · {row['status']}",
            "view": "investigations",
            "investigation_id": row["id"],
        },
    )
    collect(
        "entities",
        "Entities",
        """SELECT COUNT(*) FROM entities
           WHERE name LIKE ? ESCAPE '\\' OR identifier LIKE ? ESCAPE '\\'
              OR description LIKE ? ESCAPE '\\'""",
        """SELECT id, name, entity_type, identifier FROM entities
           WHERE name LIKE ? ESCAPE '\\' OR identifier LIKE ? ESCAPE '\\'
              OR description LIKE ? ESCAPE '\\'
           ORDER BY updated_at DESC, name""",
        [pattern, pattern, pattern],
        lambda row: {
            "id": row["id"],
            "title": row["name"],
            "subtitle": f"{row['entity_type']}"
            + (f" · {row['identifier']}" if row["identifier"] else ""),
            "view": "entities",
            "entity_id": row["id"],
        },
    )
    collect(
        "sources",
        "Sources",
        """SELECT COUNT(*) FROM sources
           WHERE title LIKE ? ESCAPE '\\' OR reference LIKE ? ESCAPE '\\'
              OR description LIKE ? ESCAPE '\\'""",
        """SELECT id, title, category, reference FROM sources
           WHERE title LIKE ? ESCAPE '\\' OR reference LIKE ? ESCAPE '\\'
              OR description LIKE ? ESCAPE '\\'
           ORDER BY updated_at DESC, title""",
        [pattern, pattern, pattern],
        lambda row: {
            "id": row["id"],
            "title": row["title"],
            "subtitle": f"Source · {row['category']}",
            "view": "sources",
            "source_id": row["id"],
        },
    )
    collect(
        "evidence",
        "Evidence",
        """SELECT COUNT(*) FROM evidence
           WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
              OR original_name LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\'""",
        """SELECT id, investigation_id, title, evidence_type, sha256 FROM evidence
           WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
              OR original_name LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\'
           ORDER BY recorded_at DESC""",
        [pattern, pattern, pattern, pattern],
        lambda row: {
            "id": row["id"],
            "title": row["title"],
            "subtitle": f"Evidence · {row['evidence_type']}",
            "view": "evidence",
            "investigation_id": row["investigation_id"],
            "evidence_id": row["id"],
        },
    )
    collect(
        "observations",
        "Observations",
        """SELECT COUNT(*) FROM observations
           WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'""",
        """SELECT o.id, o.investigation_id, o.title, o.observed_at,
                  i.name AS investigation_name
           FROM observations o
           JOIN investigations i ON i.id = o.investigation_id
           WHERE o.title LIKE ? ESCAPE '\\' OR o.content LIKE ? ESCAPE '\\'
           ORDER BY o.observed_at DESC""",
        [pattern, pattern],
        lambda row: {
            "id": row["id"],
            "title": row["title"],
            "subtitle": f"Observation · {row['investigation_name']}",
            "view": "investigations",
            "investigation_id": row["investigation_id"],
        },
    )
    indicator_hits = unified_indicators(database, search=clean_query, limit=result_limit)
    groups.append(
        {
            "key": "indicators",
            "label": "Indicators",
            "total": indicator_hits["total"],
            "items": [
                {
                    "id": f"{item['type']}:{item['value']}",
                    "title": item["value"],
                    "subtitle": f"Indicator · {INDICATOR_TYPE_LABELS[item['type']]}"
                    f" · {item['origin_count']} origin(s)",
                    "view": "indicators",
                    "indicator_type": item["type"],
                }
                for item in indicator_hits["items"]
            ],
        }
    )
    return {
        "query": clean_query,
        "groups": groups,
        "total": sum(group["total"] for group in groups),
        "limit": result_limit,
    }
