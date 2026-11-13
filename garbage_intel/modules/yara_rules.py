"""Workspace YARA rule sets: storage, validation and scanning of analysed files.

Rule sets are compiled on save so syntax errors surface immediately. Enabled
sets run against every new file analysis inside a separate process with a
deadline (see ``yara_engine.run_isolated``).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from ..db import _connection, module_enabled, new_id, record_activity, utc_now
from ..errors import ConflictError, NotFoundError, ValidationError
from ..validation import clean_text
from . import yara_engine

SCAN_TIMEOUT_SECONDS = 20.0


def _row(row: sqlite3.Row, *, with_source: bool = True) -> dict[str, Any]:
    item = {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "enabled": bool(row["enabled"]),
        "rule_count": row["rule_count"],
        "rule_names": [name for name in row["rule_names"].split("\n") if name],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if with_source:
        item["source"] = row["source"]
    return item


def validate_source(source: str) -> yara_engine.RuleSet:
    try:
        return yara_engine.compile_rules(source)
    except yara_engine.YaraError as exc:
        raise ValidationError(f"YARA rule error: {exc}") from exc


def check_source(source: str) -> dict[str, Any]:
    """Compile without storing; report the first error and its line."""
    if not isinstance(source, str):
        raise ValidationError("source must be a string")
    try:
        ruleset = yara_engine.compile_rules(source)
    except yara_engine.YaraError as exc:
        return {"valid": False, "error": str(exc), "line": exc.line, "rules": []}
    return {
        "valid": True,
        "error": "",
        "line": 0,
        "rules": [{"name": rule.name, "tags": rule.tags, "strings": len(rule.strings), "private": rule.private} for rule in ruleset.rules],
    }


def list_rulesets(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        rows = connection.execute("SELECT * FROM yara_rulesets ORDER BY name COLLATE NOCASE").fetchall()
    return {"items": [_row(row, with_source=False) for row in rows], "total": len(rows)}


def get_ruleset(database: str, ruleset_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute("SELECT * FROM yara_rulesets WHERE id = ?", (ruleset_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"rule set not found: {ruleset_id}")
    return _row(row)


def _clean_fields(name: Any, description: Any, source: Any) -> tuple[str, str, str]:
    clean_name = clean_text(name, "name", max_length=120)
    if not clean_name:
        raise ValidationError("name is required")
    clean_description = clean_text(description or "", "description", max_length=1000) or ""
    if not isinstance(source, str) or not source.strip():
        raise ValidationError("source is required")
    return clean_name, clean_description, source


def create_ruleset(database: str, *, name: Any, source: Any, description: Any = "", enabled: Any = True) -> dict[str, Any]:
    clean_name, clean_description, source = _clean_fields(name, description, source)
    compiled = validate_source(source)
    if not isinstance(enabled, bool):
        raise ValidationError("enabled must be a boolean")
    ruleset_id = new_id()
    now = utc_now()
    with _connection(database) as connection:
        try:
            connection.execute(
                """INSERT INTO yara_rulesets
                   (id, name, description, source, enabled, rule_count, rule_names, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ruleset_id, clean_name, clean_description, source, int(enabled), len(compiled.rules),
                 "\n".join(rule.name for rule in compiled.rules), now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"a rule set named '{clean_name}' already exists") from exc
        record_activity(
            connection, action="create", target_type="yara-ruleset", target_id=ruleset_id,
            investigation_id=None, summary=f"YARA rule set created: {clean_name} ({len(compiled.rules)} rules)",
        )
    return get_ruleset(database, ruleset_id)


def update_ruleset(database: str, ruleset_id: str, **fields: Any) -> dict[str, Any]:
    current = get_ruleset(database, ruleset_id)
    name, description, source = _clean_fields(
        fields.get("name", current["name"]), fields.get("description", current["description"]), fields.get("source", current["source"])
    )
    enabled = fields.get("enabled", current["enabled"])
    if not isinstance(enabled, bool):
        raise ValidationError("enabled must be a boolean")
    compiled = validate_source(source)
    with _connection(database) as connection:
        try:
            connection.execute(
                """UPDATE yara_rulesets SET name = ?, description = ?, source = ?, enabled = ?,
                       rule_count = ?, rule_names = ?, updated_at = ? WHERE id = ?""",
                (name, description, source, int(enabled), len(compiled.rules),
                 "\n".join(rule.name for rule in compiled.rules), utc_now(), ruleset_id),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"a rule set named '{name}' already exists") from exc
        record_activity(
            connection, action="update", target_type="yara-ruleset", target_id=ruleset_id,
            investigation_id=None, summary=f"YARA rule set updated: {name}",
        )
    return get_ruleset(database, ruleset_id)


def delete_ruleset(database: str, ruleset_id: str) -> dict[str, Any]:
    current = get_ruleset(database, ruleset_id)
    with _connection(database) as connection:
        connection.execute("DELETE FROM yara_rulesets WHERE id = ?", (ruleset_id,))
        record_activity(
            connection, action="delete", target_type="yara-ruleset", target_id=ruleset_id,
            investigation_id=None, summary=f"YARA rule set deleted: {current['name']}",
        )
    return {"deleted": True, "id": ruleset_id}


def enabled_sources(database: str) -> list[tuple[str, str, str]]:
    with _connection(database) as connection:
        rows = connection.execute(
            "SELECT id, name, source FROM yara_rulesets WHERE enabled = 1 ORDER BY name COLLATE NOCASE"
        ).fetchall()
    return [(row["id"], row["name"], row["source"]) for row in rows]


def scan_with_enabled(database: str, data: bytes) -> dict[str, Any] | None:
    with _connection(database) as connection:
        if not module_enabled(connection, "yara-rules"):
            return None
    sources = enabled_sources(database)
    if not sources:
        return None
    outcome = yara_engine.run_isolated(sources, data, timeout=SCAN_TIMEOUT_SECONDS)
    return {
        "rulesets": outcome["rulesets"],
        "timed_out": outcome["timed_out"],
        "match_count": sum(len(item["matches"]) for item in outcome["rulesets"]),
        "engine": "garbage-yara-subset",
    }


def test_source(source: str, data: bytes) -> dict[str, Any]:
    """Compile and scan one file without storing anything."""
    checked = check_source(source)
    if not checked["valid"]:
        return {**checked, "result": None}
    outcome = yara_engine.run_isolated([("test", "test", source)], data, timeout=SCAN_TIMEOUT_SECONDS)
    ruleset = outcome["rulesets"][0]
    return {**checked, "result": {"matches": ruleset["matches"], "capped_strings": ruleset["capped_strings"], "error": ruleset["error"], "timed_out": outcome["timed_out"]}}
