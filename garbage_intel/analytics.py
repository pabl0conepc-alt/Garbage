"""Aggregates for the analytics dashboard (plan phase 11).

Counts only: every number here can be traced back to rows the analyst can
open elsewhere in the workspace. Scoped to one investigation when given and to
a trailing window of days for time series.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .db import _connection
from .errors import NotFoundError, ValidationError

PERIODS = (7, 30, 90, 365)


def _days(created_from: datetime, days: int) -> list[str]:
    return [(created_from + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days)]


def workspace_analytics(database: str, *, investigation_id: str | None = None, days: int = 30) -> dict[str, Any]:
    if days not in PERIODS:
        raise ValidationError(f"days must be one of {', '.join(map(str, PERIODS))}")
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=days - 1)
    since = start.strftime("%Y-%m-%dT00:00:00")
    case = investigation_id or None
    with _connection(database) as connection:
        if case and connection.execute("SELECT 1 FROM investigations WHERE id = ?", (case,)).fetchone() is None:
            raise NotFoundError(f"investigation not found: {case}")

        def rows(sql: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
            return [dict(row) for row in connection.execute(sql, parameters)]

        case_filter = "AND investigation_id = ?" if case else ""
        case_args: tuple[Any, ...] = (case,) if case else ()
        entity_scope = (
            "WHERE id IN (SELECT entity_id FROM investigation_entities WHERE investigation_id = ?)" if case else ""
        )

        activity = rows(
            f"""SELECT substr(created_at, 1, 10) AS day, action, COUNT(*) AS count
                FROM activities WHERE created_at >= ? {case_filter}
                GROUP BY day, action""",
            (since, *case_args),
        )
        runs = rows(
            f"""SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS count
                FROM intel_runs WHERE started_at >= ? {case_filter} GROUP BY day""",
            (since, *case_args),
        )
        entity_types = rows(
            f"SELECT entity_type AS key, COUNT(*) AS count FROM entities {entity_scope} GROUP BY entity_type ORDER BY count DESC",
            case_args,
        )
        relationship_types = rows(
            f"""SELECT relationship_type AS key, COUNT(*) AS count FROM relationships
                WHERE 1 = 1 {case_filter} GROUP BY relationship_type ORDER BY count DESC""",
            case_args,
        )
        verification = rows(
            f"""SELECT verification_status AS key, COUNT(*) AS count FROM relationships
                WHERE 1 = 1 {case_filter} GROUP BY verification_status""",
            case_args,
        )
        run_scope = f"WHERE run_id IN (SELECT id FROM intel_runs WHERE investigation_id = ?)" if case else ""
        source_results = rows(
            f"""SELECT connector_id AS key,
                       SUM(CASE WHEN status = 'ok' AND value != '' THEN 1 ELSE 0 END) AS results,
                       COUNT(DISTINCT run_id) AS runs,
                       SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors
                FROM intel_results {run_scope}
                GROUP BY connector_id ORDER BY results DESC""",
            case_args,
        )
        source_status = rows(
            f"""SELECT connector_id AS key, status, COUNT(DISTINCT run_id) AS count
                FROM intel_results {run_scope} GROUP BY connector_id, status""",
            case_args,
        )
        result_types = rows(
            f"""SELECT result_type AS key, COUNT(*) AS count FROM intel_results
                {run_scope + ' AND' if run_scope else 'WHERE'} result_type != ''
                GROUP BY result_type ORDER BY count DESC LIMIT 15""",
            case_args,
        )
        file_formats = rows(
            f"SELECT format AS key, COUNT(*) AS count FROM file_analyses WHERE 1 = 1 {case_filter} GROUP BY format ORDER BY count DESC",
            case_args,
        )
        finding_levels = rows(
            f"""SELECT json_extract(finding.value, '$.level') AS finding_level, COUNT(*) AS count
                FROM file_analyses, json_each(file_analyses.analysis_json, '$.findings') AS finding
                WHERE 1 = 1 {case_filter.replace('investigation_id', 'file_analyses.investigation_id')}
                GROUP BY finding_level""",
            case_args,
        )
        finding_codes = rows(
            f"""SELECT json_extract(finding.value, '$.code') AS finding_code, COUNT(*) AS count
                FROM file_analyses, json_each(file_analyses.analysis_json, '$.findings') AS finding
                WHERE 1 = 1 {case_filter.replace('investigation_id', 'file_analyses.investigation_id')}
                GROUP BY finding_code ORDER BY count DESC LIMIT 12""",
            case_args,
        )
        evidence_types = rows(
            f"SELECT evidence_type AS key, COUNT(*) AS count FROM evidence WHERE 1 = 1 {case_filter} GROUP BY evidence_type ORDER BY count DESC",
            case_args,
        )
        totals = {
            "entities": sum(item["count"] for item in entity_types),
            "relationships": sum(item["count"] for item in relationship_types),
            "observations": connection.execute(f"SELECT COUNT(*) FROM observations WHERE 1 = 1 {case_filter}", case_args).fetchone()[0],
            "evidence": sum(item["count"] for item in evidence_types),
            "intel_runs": connection.execute(f"SELECT COUNT(*) FROM intel_runs WHERE 1 = 1 {case_filter}", case_args).fetchone()[0],
            "intel_results": sum(item["results"] or 0 for item in source_results),
            "file_analyses": sum(item["count"] for item in file_formats),
        }

    labels = _days(start, days)
    actions = sorted({item["action"] for item in activity})
    by_day = {(item["day"], item["action"]): item["count"] for item in activity}
    run_days = {item["day"]: item["count"] for item in runs}
    statuses: dict[str, dict[str, int]] = {}
    for item in source_status:
        statuses.setdefault(item["key"], {})[item["status"]] = item["count"]
    return {
        "investigation_id": case,
        "days": days,
        "since": labels[0],
        "totals": totals,
        "activity": {
            "days": labels,
            "series": [{"key": action, "values": [by_day.get((day, action), 0) for day in labels]} for action in actions],
        },
        "intel_runs_by_day": [run_days.get(day, 0) for day in labels],
        "entity_types": entity_types,
        "relationship_types": relationship_types,
        "relationship_verification": verification,
        "sources": [
            {**item, "results": item["results"] or 0, "errors": item["errors"] or 0, "statuses": statuses.get(item["key"], {})}
            for item in source_results
        ],
        "result_types": result_types,
        "file_formats": file_formats,
        "finding_levels": [{"key": item["finding_level"], "count": item["count"]} for item in finding_levels if item["finding_level"]],
        "finding_codes": [{"key": item["finding_code"], "count": item["count"]} for item in finding_codes if item["finding_code"]],
        "evidence_types": evidence_types,
    }
