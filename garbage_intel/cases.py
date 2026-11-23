"""Case lifecycle beyond create/edit: archive, duplicate, and a portable
case package (export and import).

The package (``garbage-case`` v1) carries the case, its status history,
observations, linked entities and relationships, sources, evidence with
metadata, custody log, notes and (optionally) file contents, ATT&CK
techniques and file analyses. A SHA-256 over the canonical JSON of the
content detects any change in transit; evidence files are re-hashed on
import and refused when they do not match their recorded digest.

Import always creates a new case. Entities are reused when one with the
same type and identifier (or name, for name-only types) already exists.
The imported evidence starts a new custody log whose first entries record
the import and keep the original log as received.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from . import __version__, custody
from .db import ENTITY_TYPES, RELATIONSHIP_TYPES, _connection, new_id, record_activity, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .validation import clean_text

FORMAT = "garbage-case"
VERSION = 1
MAX_PACKAGE_FILE_BYTES = 48 * 1024 * 1024
MAX_IMPORT_ITEMS = 20_000


def _case_row(connection: Any, investigation_id: str) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"investigation not found: {investigation_id}")
    return dict(row)


# ---------------------------------------------------------------------------
# Archive and duplicate


def set_archived(database: str, investigation_id: str, archived: bool) -> dict[str, Any]:
    """Archived cases leave the active lists and pickers; nothing is deleted."""
    with _connection(database) as connection:
        case = _case_row(connection, investigation_id)
        stamp = utc_now() if archived else ""
        connection.execute("UPDATE investigations SET archived_at = ?, updated_at = ? WHERE id = ?", (stamp, utc_now(), investigation_id))
        record_activity(
            connection,
            action="archive" if archived else "unarchive",
            target_type="investigation",
            target_id=investigation_id,
            investigation_id=investigation_id,
            summary=f"Investigation {'archived' if archived else 'restored'}: {case['name'][:120]}",
        )
        return dict(connection.execute(
            "SELECT id, name, description, objective, archived_at, created_at, updated_at, status FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone())


def duplicate(database: str, investigation_id: str, *, name: object = None) -> dict[str, Any]:
    """A new open case with the same objective, entities, case relationships,
    sources and techniques. Observations and evidence stay with the original:
    they are records of that case, not a template."""
    with _connection(database) as connection:
        case = _case_row(connection, investigation_id)
        label = clean_text(name, "name", max_length=300) or f"Cópia de {case['name']}"[:300]
        new = new_id()
        now = utc_now()
        connection.execute(
            """INSERT INTO investigations (id, name, description, objective, created_at, status, updated_at)
               VALUES (?, ?, ?, ?, ?, 'open', ?)""",
            (new, label, case["description"], case.get("objective", ""), now, now),
        )
        counts = {}
        counts["entities"] = connection.execute(
            """INSERT INTO investigation_entities (investigation_id, entity_id, added_at)
               SELECT ?, entity_id, ? FROM investigation_entities WHERE investigation_id = ?""",
            (new, now, investigation_id),
        ).rowcount
        relationships = connection.execute(
            "SELECT * FROM relationships WHERE investigation_id = ?", (investigation_id,)
        ).fetchall()
        for row in relationships:
            connection.execute(
                """INSERT INTO relationships
                   (id, investigation_id, source_entity_id, target_entity_id, relationship_type, description,
                    source_reference, confidence, verification_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_id(), new, row["source_entity_id"], row["target_entity_id"], row["relationship_type"], row["description"],
                 row["source_reference"], row["confidence"], row["verification_status"], now, now),
            )
        counts["relationships"] = len(relationships)
        counts["sources"] = connection.execute(
            """INSERT INTO investigation_sources (investigation_id, source_id, added_at)
               SELECT ?, source_id, ? FROM investigation_sources WHERE investigation_id = ?""",
            (new, now, investigation_id),
        ).rowcount
        counts["techniques"] = connection.execute(
            """INSERT INTO case_techniques (id, investigation_id, technique_id, note, source, created_at)
               SELECT lower(hex(randomblob(16))), ?, technique_id, note, source, ? FROM case_techniques WHERE investigation_id = ?""",
            (new, now, investigation_id),
        ).rowcount
        record_activity(
            connection,
            action="create",
            target_type="investigation",
            target_id=new,
            investigation_id=new,
            summary=f"Investigation duplicated from {case['name'][:120]}: {label}",
        )
    return {"id": new, "name": label, "copied": counts}


# ---------------------------------------------------------------------------
# Package export


def _digest(content: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def export_package(database: str, investigation_id: str, *, include_files: bool = True) -> dict[str, Any]:
    from .evidence import _read_stored_file

    with _connection(database) as connection:
        case = _case_row(connection, investigation_id)
        rows = lambda sql, *args: [dict(row) for row in connection.execute(sql, args)]  # noqa: E731
        entities = rows(
            """SELECT e.id, e.entity_type, e.name, e.identifier, e.description, e.source_reference,
                      e.collection_basis, e.confidence, e.verification_status, e.created_at
               FROM entities e JOIN investigation_entities ie ON ie.entity_id = e.id
               WHERE ie.investigation_id = ? ORDER BY e.created_at, e.id""",
            investigation_id,
        )
        entity_ids = {item["id"] for item in entities}
        relationships = [
            row for row in rows(
                """SELECT id, investigation_id, source_entity_id, target_entity_id, relationship_type, description,
                          source_reference, confidence, verification_status, created_at
                   FROM relationships WHERE investigation_id = ? OR investigation_id IS NULL ORDER BY created_at, id""",
                investigation_id,
            )
            if row["source_entity_id"] in entity_ids and row["target_entity_id"] in entity_ids
        ]
        evidence = rows(
            """SELECT id, title, evidence_type, description, source_reference, original_name, stored_name, media_type,
                      size_bytes, sha256, acquired_at, recorded_at, integrity_status
               FROM evidence WHERE investigation_id = ? ORDER BY recorded_at, id""",
            investigation_id,
        )
        package_evidence = []
        total = 0
        for item in evidence:
            events = rows("SELECT * FROM evidence_events WHERE evidence_id = ? ORDER BY sequence", item["id"])
            notes = rows("SELECT body, created_at FROM evidence_notes WHERE evidence_id = ? ORDER BY created_at", item["id"])
            entry = {key: value for key, value in item.items() if key != "stored_name"}
            entry["custody"] = events
            entry["notes"] = notes
            entry["content_base64"] = None
            if include_files and item["stored_name"]:
                try:
                    data = _read_stored_file(database, item["stored_name"])
                except (NotFoundError, OSError):
                    data = None
                if data is not None:
                    total += len(data)
                    if total > MAX_PACKAGE_FILE_BYTES:
                        raise ConflictError("evidence files exceed 48 MiB; export without files")
                    entry["content_base64"] = base64.b64encode(data).decode("ascii")
            package_evidence.append(entry)
        content = {
            "case": {key: case.get(key, "") for key in ("name", "description", "objective", "status", "created_at", "archived_at")},
            "status_events": rows("SELECT status, changed_at FROM investigation_status_events WHERE investigation_id = ? ORDER BY changed_at", investigation_id),
            "observations": rows(
                """SELECT title, content, source_reference, collection_basis, observed_at, recorded_at
                   FROM observations WHERE investigation_id = ? ORDER BY observed_at, recorded_at, id""",
                investigation_id,
            ),
            "entities": entities,
            "relationships": relationships,
            "sources": rows(
                """SELECT s.id, s.title, s.reference, s.category, s.description, s.accessed_at, s.verification_status
                   FROM sources s JOIN investigation_sources ins ON ins.source_id = s.id
                   WHERE ins.investigation_id = ? ORDER BY s.title, s.id""",
                investigation_id,
            ),
            "entity_sources": [
                row for row in rows("SELECT entity_id, source_id FROM entity_sources") if row["entity_id"] in entity_ids
            ],
            "evidence": package_evidence,
            "techniques": rows("SELECT technique_id, note, source, created_at FROM case_techniques WHERE investigation_id = ?", investigation_id),
            "file_analyses": rows(
                "SELECT file_name, format, media_type, size_bytes, sha256, analysis_json, created_at FROM file_analyses WHERE investigation_id = ?",
                investigation_id,
            ),
        }
        for item in package_evidence:
            custody.record(
                connection,
                evidence_id=item["id"],
                investigation_id=investigation_id,
                action="exported",
                sha256=item["sha256"],
                detail=f"Included in a case package{' with its file' if item['content_base64'] else ' (metadata only)'}",
            )
        record_activity(connection, action="export", target_type="investigation", target_id=investigation_id,
                        investigation_id=investigation_id, summary=f"Case package exported: {case['name'][:120]}")
    return {
        "format": FORMAT,
        "version": VERSION,
        "exported_at": utc_now(),
        "generator": f"GARBAGE {__version__}",
        "sha256": _digest(content),
        "content": content,
    }


# ---------------------------------------------------------------------------
# Package import


def _check_package(package: object) -> dict[str, Any]:
    if not isinstance(package, dict) or package.get("format") != FORMAT:
        raise ValidationError("this is not a GARBAGE case package")
    if package.get("version") != VERSION:
        raise ValidationError(f"unsupported case package version: {package.get('version')}")
    content = package.get("content")
    if not isinstance(content, dict) or not isinstance(content.get("case"), dict):
        raise ValidationError("the case package has no content")
    if _digest(content) != package.get("sha256"):
        raise ValidationError("the case package was modified after export (SHA-256 does not match)")
    for key in ("observations", "entities", "relationships", "sources", "entity_sources", "evidence", "techniques", "file_analyses", "status_events"):
        value = content.get(key, [])
        if not isinstance(value, list) or len(value) > MAX_IMPORT_ITEMS:
            raise ValidationError(f"{key} must be a list of at most {MAX_IMPORT_ITEMS} items")
        content.setdefault(key, value)
    return content


def import_package(database: str, package: object, *, commit: bool = False, name: object = None) -> dict[str, Any]:
    from .entities import _normalize_identifier
    from .evidence import _safe_suffix, _write_stored_file

    content = _check_package(package)
    case = content["case"]
    label = clean_text(name, "name", max_length=300) or clean_text(case.get("name"), "name", max_length=300) or "Caso importado"
    problems: list[dict[str, str]] = []
    plan = {"entities_new": 0, "entities_reused": 0, "relationships": 0, "observations": len(content["observations"]),
            "evidence": 0, "evidence_files": 0, "evidence_rejected": 0, "sources": 0, "techniques": 0, "file_analyses": len(content["file_analyses"])}

    def problem(kind: str, key: str, reason: str) -> None:
        if len(problems) < 50:
            problems.append({"kind": kind, "key": str(key)[:120], "reason": reason})

    with _connection(database) as connection:
        entity_map: dict[str, str] = {}
        new_entities = []
        for item in content["entities"]:
            if not isinstance(item, dict) or item.get("entity_type") not in ENTITY_TYPES:
                problem("entity", item.get("id", "") if isinstance(item, dict) else "", "unknown entity type")
                continue
            try:
                identifier = _normalize_identifier(item["entity_type"], str(item.get("identifier") or ""))
            except ValidationError as exc:
                problem("entity", item.get("name", ""), str(exc))
                continue
            row = (
                connection.execute("SELECT id FROM entities WHERE entity_type = ? AND identifier = ?", (item["entity_type"], identifier)).fetchone()
                if identifier
                else connection.execute("SELECT id FROM entities WHERE entity_type = ? AND identifier = '' AND name = ?", (item["entity_type"], str(item.get("name", "")))).fetchone()
            )
            if row:
                entity_map[item["id"]] = row["id"]
                plan["entities_reused"] += 1
            else:
                entity_map[item["id"]] = new_id()
                new_entities.append((entity_map[item["id"]], item, identifier))
                plan["entities_new"] += 1
        relationships = []
        for item in content["relationships"]:
            source, target = entity_map.get(item.get("source_entity_id")), entity_map.get(item.get("target_entity_id"))
            if not source or not target or source == target or item.get("relationship_type") not in RELATIONSHIP_TYPES:
                problem("relationship", item.get("id", ""), "endpoint missing or unknown type")
                continue
            relationships.append((source, target, item))
        plan["relationships"] = len(relationships)
        evidence_plan = []
        for item in content["evidence"]:
            data = None
            if item.get("content_base64"):
                try:
                    data = base64.b64decode(item["content_base64"], validate=True)
                except (ValueError, TypeError):
                    data = b""
                if hashlib.sha256(data).hexdigest() != item.get("sha256"):
                    plan["evidence_rejected"] += 1
                    problem("evidence", item.get("title", ""), "file content does not match its recorded SHA-256")
                    continue
                plan["evidence_files"] += 1
            evidence_plan.append((item, data))
        plan["evidence"] = len(evidence_plan)
        plan["sources"] = len(content["sources"])
        known_techniques = {row["id"] for row in connection.execute("SELECT id FROM attack_techniques")}
        techniques = [item for item in content["techniques"] if item.get("technique_id") in known_techniques]
        for item in content["techniques"]:
            if item.get("technique_id") not in known_techniques:
                problem("technique", item.get("technique_id", ""), "not in the local ATT&CK data; load ATT&CK first")
        plan["techniques"] = len(techniques)
        result = {"committed": False, "name": label, "sha256": package["sha256"], "exported_at": package.get("exported_at", ""),
                  "generator": package.get("generator", ""), "plan": plan, "problems": problems}
        if not commit:
            return result

        now = utc_now()
        case_id = new_id()
        status = case.get("status") if case.get("status") in ("open", "closed", "cancelled") else "open"
        connection.execute(
            """INSERT INTO investigations (id, name, description, objective, created_at, status, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (case_id, label, str(case.get("description", ""))[:20000], str(case.get("objective", ""))[:2000], now, "open", now),
        )
        for event in content["status_events"]:
            connection.execute(
                "INSERT INTO investigation_status_events (id, investigation_id, status, changed_at) VALUES (?, ?, ?, ?)",
                (new_id(), case_id, str(event.get("status", ""))[:20], str(event.get("changed_at", ""))[:40]),
            )
        for entity_id, item, identifier in new_entities:
            connection.execute(
                """INSERT INTO entities (id, entity_type, name, identifier, description, source_reference, collection_basis,
                                         confidence, verification_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entity_id, item["entity_type"], str(item.get("name", ""))[:300], identifier, str(item.get("description", ""))[:5000],
                 str(item.get("source_reference", ""))[:2000], item.get("collection_basis") if item.get("collection_basis") in ("public", "authorized", "user-provided") else "user-provided",
                 item.get("confidence") if item.get("confidence") in ("unconfirmed", "possible", "probable", "confirmed") else "unconfirmed",
                 item.get("verification_status") if item.get("verification_status") in ("not-verified", "verified", "disputed", "false-positive") else "not-verified",
                 now, now),
            )
        for entity_id in set(entity_map.values()):
            connection.execute("INSERT OR IGNORE INTO investigation_entities (investigation_id, entity_id, added_at) VALUES (?, ?, ?)", (case_id, entity_id, now))
        for source, target, item in relationships:
            connection.execute(
                """INSERT OR IGNORE INTO relationships
                   (id, investigation_id, source_entity_id, target_entity_id, relationship_type, description, source_reference,
                    confidence, verification_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_id(), case_id, source, target, item["relationship_type"], str(item.get("description", ""))[:5000],
                 str(item.get("source_reference", ""))[:2000],
                 item.get("confidence") if item.get("confidence") in ("unconfirmed", "possible", "probable", "confirmed") else "unconfirmed",
                 item.get("verification_status") if item.get("verification_status") in ("not-verified", "verified", "disputed", "false-positive") else "not-verified",
                 now, now),
            )
        for item in content["observations"]:
            basis = item.get("collection_basis") if item.get("collection_basis") in ("public", "authorized", "user-provided") else "user-provided"
            connection.execute(
                """INSERT INTO observations (id, investigation_id, title, content, source_reference, collection_basis, observed_at, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (new_id(), case_id, str(item.get("title", ""))[:300], str(item.get("content", ""))[:200_000],
                 str(item.get("source_reference", ""))[:2000], basis, str(item.get("observed_at") or now), now),
            )
        source_map = {}
        for item in content["sources"]:
            row = connection.execute("SELECT id FROM sources WHERE title = ? AND reference = ?", (str(item.get("title", "")), str(item.get("reference", "")))).fetchone()
            source_id = row["id"] if row else new_id()
            if not row:
                connection.execute(
                    """INSERT INTO sources (id, title, reference, category, description, accessed_at, verification_status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (source_id, str(item.get("title", ""))[:300] or "Fonte importada", str(item.get("reference", ""))[:2000], str(item.get("category", "other"))[:40],
                     str(item.get("description", ""))[:5000], str(item.get("accessed_at") or now), str(item.get("verification_status", "not-verified"))[:20], now, now),
                )
            source_map[item.get("id")] = source_id
            connection.execute("INSERT OR IGNORE INTO investigation_sources (investigation_id, source_id, added_at) VALUES (?, ?, ?)", (case_id, source_id, now))
        for link in content["entity_sources"]:
            entity_id, source_id = entity_map.get(link.get("entity_id")), source_map.get(link.get("source_id"))
            if entity_id and source_id:
                connection.execute("INSERT OR IGNORE INTO entity_sources (entity_id, source_id, added_at) VALUES (?, ?, ?)", (entity_id, source_id, now))
        written = []
        try:
            for item, data in evidence_plan:
                evidence_id = new_id()
                stored = f"{evidence_id}{_safe_suffix(str(item.get('original_name', '')))}" if data else ""
                if data:
                    _write_stored_file(database, stored, data)
                    written.append(stored)
                connection.execute(
                    """INSERT INTO evidence (id, investigation_id, title, evidence_type, description, source_reference, original_name,
                                             stored_name, media_type, size_bytes, sha256, acquired_at, recorded_at, integrity_status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (evidence_id, case_id, str(item.get("title", ""))[:300], str(item.get("evidence_type", "file"))[:20],
                     str(item.get("description", ""))[:5000], str(item.get("source_reference", ""))[:2000], str(item.get("original_name", ""))[:300],
                     stored, str(item.get("media_type", "application/octet-stream"))[:200], len(data) if data else int(item.get("size_bytes") or 0),
                     str(item.get("sha256", ""))[:64], str(item.get("acquired_at") or now), now, "verified" if data else "unverified"),
                )
                original = item.get("custody") if isinstance(item.get("custody"), list) else []
                custody.record(
                    connection, evidence_id=evidence_id, investigation_id=case_id, action="imported", sha256=str(item.get("sha256", "")),
                    detail=(f"Imported from case package {package['sha256'][:16]} ({package.get('generator', '')}); "
                            + ("file re-hashed and matches" if data else "metadata only, no file in the package")
                            + f"; original evidence id {item.get('id', '')}; original log {len(original)} event(s)"),
                )
                if original:
                    custody.record(
                        connection, evidence_id=evidence_id, investigation_id=case_id, action="imported-history", sha256=str(item.get("sha256", "")),
                        detail=json.dumps(original[:200], ensure_ascii=False)[:20_000], actor="system",
                    )
                for note in item.get("notes") or []:
                    if isinstance(note, dict) and note.get("body"):
                        connection.execute(
                            "INSERT INTO evidence_notes (id, evidence_id, body, created_at) VALUES (?, ?, ?, ?)",
                            (new_id(), evidence_id, str(note["body"])[:5000], str(note.get("created_at") or now)),
                        )
        except Exception:
            from .evidence import remove_stored_files

            remove_stored_files(database, written)
            raise
        for item in techniques:
            connection.execute(
                "INSERT OR IGNORE INTO case_techniques (id, investigation_id, technique_id, note, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (new_id(), case_id, item["technique_id"], str(item.get("note", ""))[:1000], str(item.get("source", "analyst"))[:20], now),
            )
        for item in content["file_analyses"]:
            analysis_id = new_id()
            try:
                analysis = json.loads(item.get("analysis_json") or "{}")
            except ValueError:
                analysis = {}
            analysis.update(analysis_id=analysis_id, investigation_id=case_id)
            connection.execute(
                """INSERT INTO file_analyses (id, investigation_id, file_name, format, media_type, size_bytes, sha256, analysis_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (analysis_id, case_id, str(item.get("file_name", ""))[:300], str(item.get("format", ""))[:64], str(item.get("media_type", ""))[:200],
                 int(item.get("size_bytes") or 0), str(item.get("sha256", ""))[:64], json.dumps(analysis, ensure_ascii=False), str(item.get("created_at") or now)),
            )
        if status != "open":
            connection.execute("UPDATE investigations SET status = ? WHERE id = ?", (status, case_id))
        record_activity(connection, action="import", target_type="investigation", target_id=case_id, investigation_id=case_id,
                        summary=f"Case package imported: {label[:120]} ({package['sha256'][:16]})")
    result.update(committed=True, id=case_id)
    return result
