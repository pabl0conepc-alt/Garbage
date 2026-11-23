"""Investigation ledger, provenance records, timelines and archives.

Existing functions keep their original contracts. The canonical workspace
records (entities, relationships, evidence, sources, boards) live in sibling
modules but are read here to build one integrated investigation report.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .db import (
    COLLECTION_BASES,
    INVESTIGATION_STATUSES,
    MAX_ARCHIVE_BYTES,
    _connection,
    initialize,
    module_enabled,
    new_id,
    normalize_timestamp,
    record_activity,
    required_text,
    setting_bool,
    utc_now,
)
from .errors import ConflictError, NotFoundError, ValidationError
from .modules.correlation import correlate_indicators
from .modules.indicators import extract_indicators


def _required_text(value: str, field: str) -> str:
    return required_text(value, field)


def backup_sqlite_database(
    source: str | Path, destination: str | Path
) -> dict[str, Any]:
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("source database must be an existing regular file")

    source_path = source_path.resolve()
    if destination_path.resolve() == source_path:
        raise ValueError("backup destination must differ from the source database")
    if destination_path.exists() or destination_path.is_symlink():
        raise FileExistsError(f"backup destination already exists: {destination_path}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=destination_path.parent,
    )
    os.close(descriptor)
    try:
        source_uri = f"{source_path.as_uri()}?mode=ro"
        source_connection = None
        destination_connection = None
        try:
            source_connection = sqlite3.connect(source_uri, uri=True)
            destination_connection = sqlite3.connect(temporary_name)
            source_connection.backup(destination_connection)
        except sqlite3.Error as exc:
            raise ValueError(f"could not back up database: {exc}") from exc
        finally:
            if destination_connection is not None:
                destination_connection.close()
            if source_connection is not None:
                source_connection.close()
        os.link(temporary_name, destination_path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass

    return {
        "source_database": str(source_path),
        "backup": str(destination_path),
        "created": True,
    }


def build_archive(database: str | Path) -> dict[str, Any]:
    path = Path(database)
    if path.is_symlink() or not path.is_file():
        raise ValueError("source database must be an existing regular file")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            investigation_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(investigations)")
            }
            status_expression = (
                "status" if "status" in investigation_columns else "'open'"
            )
            investigations = connection.execute(
                f"""SELECT id, name, description, created_at,
                           {status_expression} AS status
                    FROM investigations ORDER BY created_at, id"""
            ).fetchall()
            status_table = connection.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type = 'table' AND name = 'investigation_status_events'"""
            ).fetchone()
            status_events = (
                connection.execute(
                    """SELECT id, investigation_id, status, changed_at
                       FROM investigation_status_events
                       ORDER BY changed_at, id"""
                ).fetchall()
                if status_table
                else []
            )
            observations = connection.execute(
                """SELECT id, investigation_id, title, content,
                          source_reference, collection_basis, observed_at,
                          recorded_at
                   FROM observations ORDER BY observed_at, recorded_at, id"""
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValueError(f"could not read database for backup: {exc}") from exc
    return {
        "format": "garbage-evidence-archive",
        "schema_version": 1,
        "exported_at": utc_now(),
        "investigations": [dict(row) for row in investigations],
        "observations": [dict(row) for row in observations],
        "status_events": [dict(row) for row in status_events],
    }


def create_json_backup(
    database: str | Path, destination: str | Path
) -> dict[str, Any]:
    destination_path = Path(destination)
    if destination_path.exists() or destination_path.is_symlink():
        raise FileExistsError(f"backup destination already exists: {destination_path}")
    archive = build_archive(database)
    document = json.dumps(archive, ensure_ascii=False, indent=2) + "\n"
    encoded_document = document.encode("utf-8")
    if len(encoded_document) > MAX_ARCHIVE_BYTES:
        raise ValueError("JSON archive exceeds the 10 MiB import limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=destination_path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded_document)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary_name, destination_path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return {
        "backup": str(destination_path),
        "format": "garbage-evidence-archive",
        "schema_version": 1,
        "investigations": len(archive["investigations"]),
        "observations": len(archive["observations"]),
        "status_events": len(archive["status_events"]),
        "created": True,
    }


def import_archive(database: str | Path, archive: object) -> dict[str, Any]:
    if not isinstance(archive, dict) or set(archive) != {
        "format",
        "schema_version",
        "exported_at",
        "investigations",
        "observations",
        "status_events",
    }:
        raise ValueError("archive must match the supported JSON archive schema")
    if archive["format"] != "garbage-evidence-archive":
        raise ValueError("unsupported archive format")
    if type(archive["schema_version"]) is not int or archive["schema_version"] != 1:
        raise ValueError("unsupported archive schema version")
    if not isinstance(archive["exported_at"], str):
        raise ValueError("archive exported_at must be a timestamp string")
    normalize_timestamp(archive["exported_at"])
    investigations = archive["investigations"]
    observations = archive["observations"]
    status_events = archive["status_events"]
    if (
        not isinstance(investigations, list)
        or not isinstance(observations, list)
        or not isinstance(status_events, list)
    ):
        raise ValueError("archive records must be arrays")

    investigation_fields = {"id", "name", "description", "created_at", "status"}
    observation_fields = {
        "id",
        "investigation_id",
        "title",
        "content",
        "source_reference",
        "collection_basis",
        "observed_at",
        "recorded_at",
    }
    clean_investigations: list[dict[str, str]] = []
    seen_investigation_ids: set[str] = set()
    for item in investigations:
        if not isinstance(item, dict) or set(item) != investigation_fields:
            raise ValueError("archive contains an invalid investigation record")
        if any(not isinstance(item[field], str) for field in investigation_fields):
            raise ValueError("investigation fields must be strings")
        if not item["id"].strip() or not item["name"].strip():
            raise ValueError("investigation id and name must not be empty")
        if item["status"] not in INVESTIGATION_STATUSES:
            raise ValueError("archive contains an invalid investigation status")
        if item["id"] in seen_investigation_ids:
            raise ValueError("archive contains duplicate investigation ids")
        seen_investigation_ids.add(item["id"])
        clean_investigations.append(
            {
                **item,
                "name": item["name"].strip(),
                "description": item["description"].strip(),
                "created_at": normalize_timestamp(item["created_at"]),
            }
        )

    clean_observations: list[dict[str, str]] = []
    seen_observation_ids: set[str] = set()
    for item in observations:
        if not isinstance(item, dict) or set(item) != observation_fields:
            raise ValueError("archive contains an invalid observation record")
        if any(not isinstance(item[field], str) for field in observation_fields):
            raise ValueError("observation fields must be strings")
        if any(
            not item[field].strip()
            for field in (
                "id",
                "investigation_id",
                "title",
                "content",
                "source_reference",
            )
        ):
            raise ValueError("observation required fields must not be empty")
        if item["collection_basis"] not in COLLECTION_BASES:
            raise ValueError("archive contains an invalid collection basis")
        if item["investigation_id"] not in seen_investigation_ids:
            raise ValueError("archive observation references a missing investigation")
        if item["id"] in seen_observation_ids:
            raise ValueError("archive contains duplicate observation ids")
        seen_observation_ids.add(item["id"])
        clean_observations.append(
            {
                **item,
                "title": item["title"].strip(),
                "content": item["content"].strip(),
                "source_reference": item["source_reference"].strip(),
                "observed_at": normalize_timestamp(item["observed_at"]),
                "recorded_at": normalize_timestamp(item["recorded_at"]),
            }
        )

    status_event_fields = {"id", "investigation_id", "status", "changed_at"}
    clean_status_events: list[dict[str, str]] = []
    seen_status_event_ids: set[str] = set()
    for item in status_events:
        if not isinstance(item, dict) or set(item) != status_event_fields:
            raise ValueError("archive contains an invalid status event")
        if any(not isinstance(item[field], str) for field in status_event_fields):
            raise ValueError("status event fields must be strings")
        if (
            not item["id"].strip()
            or item["investigation_id"] not in seen_investigation_ids
            or item["status"] not in INVESTIGATION_STATUSES
        ):
            raise ValueError("archive contains an invalid status event")
        if item["id"] in seen_status_event_ids:
            raise ValueError("archive contains duplicate status event ids")
        seen_status_event_ids.add(item["id"])
        clean_status_events.append(
            {**item, "changed_at": normalize_timestamp(item["changed_at"])}
        )

    initialize(database)
    try:
        with _connection(database) as connection:
            connection.executemany(
                """INSERT INTO investigations
                   (id, name, description, created_at, status, updated_at)
                   VALUES (:id, :name, :description, :created_at, :status,
                           :created_at)""",
                clean_investigations,
            )
            connection.executemany(
                """INSERT INTO observations
                   (id, investigation_id, title, content, source_reference,
                    collection_basis, observed_at, recorded_at)
                   VALUES (:id, :investigation_id, :title, :content,
                           :source_reference, :collection_basis, :observed_at,
                           :recorded_at)""",
                clean_observations,
            )
            connection.executemany(
                """INSERT INTO investigation_status_events
                   (id, investigation_id, status, changed_at)
                   VALUES (:id, :investigation_id, :status, :changed_at)""",
                clean_status_events,
            )
            for item in clean_investigations:
                record_activity(
                    connection,
                    action="import",
                    target_type="investigation",
                    target_id=item["id"],
                    investigation_id=item["id"],
                    summary=f"Investigation imported from archive: {item['name']}",
                )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"archive conflicts with existing records: {exc}") from exc
    return {
        "imported": True,
        "investigations": len(clean_investigations),
        "observations": len(clean_observations),
        "status_events": len(clean_status_events),
    }


def create_investigation(
    database: str | Path, name: str, description: str = "", objective: str = ""
) -> dict[str, Any]:
    name = _required_text(name, "name")
    investigation = {
        "id": new_id(),
        "name": name,
        "description": description.strip(),
        "objective": objective.strip()[:2000],
        "archived_at": "",
        "created_at": utc_now(),
        "status": "open",
        "updated_at": utc_now(),
    }
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO investigations
               (id, name, description, objective, created_at, status, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                investigation["id"],
                investigation["name"],
                investigation["description"],
                investigation["objective"],
                investigation["created_at"],
                investigation["status"],
                investigation["updated_at"],
            ),
        )
        record_activity(
            connection,
            action="create",
            target_type="investigation",
            target_id=investigation["id"],
            investigation_id=investigation["id"],
            summary=f"Investigation created: {investigation['name']}",
        )
    return investigation


def list_investigations(database: str | Path) -> list[dict[str, Any]]:
    with _connection(database) as connection:
        rows = connection.execute(
            """SELECT i.id, i.name, i.description, i.objective, i.archived_at,
                      i.created_at, i.updated_at, i.status,
                      (SELECT COUNT(*) FROM observations o
                       WHERE o.investigation_id = i.id) AS observation_count,
                      (SELECT COUNT(*) FROM investigation_entities ie
                       WHERE ie.investigation_id = i.id) AS entity_count,
                      (SELECT COUNT(*) FROM evidence e
                       WHERE e.investigation_id = i.id) AS evidence_count,
                      (SELECT COUNT(*) FROM investigation_sources ins
                       WHERE ins.investigation_id = i.id) AS source_count
               FROM investigations i ORDER BY i.created_at, i.id"""
        ).fetchall()
    return [dict(row) for row in rows]


def get_investigation(database: str | Path, investigation_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute(
            """SELECT id, name, description, objective, archived_at, created_at, updated_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"investigation not found: {investigation_id}")
    return dict(row)


def update_investigation(
    database: str | Path,
    investigation_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    status: str | None = None,
    objective: str | None = None,
) -> dict[str, Any]:
    if name is None and description is None and status is None and objective is None:
        raise ValidationError("at least one of name, description, objective or status is required")
    if name is not None:
        name = _required_text(name, "name")
    if status is not None and status not in INVESTIGATION_STATUSES:
        raise ValidationError(
            f"status must be one of: {', '.join(INVESTIGATION_STATUSES)}"
        )
    with _connection(database) as connection:
        current = connection.execute(
            "SELECT id, name, status FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if current is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        now = utc_now()
        next_name = name if name is not None else current["name"]
        next_status = status if status is not None else current["status"]
        connection.execute(
            "UPDATE investigations SET name = ?, status = ?, updated_at = ? WHERE id = ?",
            (next_name, next_status, now, investigation_id),
        )
        if description is not None:
            connection.execute(
                "UPDATE investigations SET description = ? WHERE id = ?",
                (description.strip(), investigation_id),
            )
        if objective is not None:
            connection.execute(
                "UPDATE investigations SET objective = ? WHERE id = ?",
                (objective.strip()[:2000], investigation_id),
            )
        if status is not None and status != current["status"]:
            connection.execute(
                """INSERT INTO investigation_status_events
                   (id, investigation_id, status, changed_at)
                   VALUES (?, ?, ?, ?)""",
                (new_id(), investigation_id, status, now),
            )
            record_activity(
                connection,
                action="status",
                target_type="investigation",
                target_id=investigation_id,
                investigation_id=investigation_id,
                summary=f"Investigation status changed to {status}",
            )
        elif name is not None or description is not None or objective is not None:
            record_activity(
                connection,
                action="update",
                target_type="investigation",
                target_id=investigation_id,
                investigation_id=investigation_id,
                summary=f"Investigation details updated: {next_name}",
            )
        row = connection.execute(
            """SELECT id, name, description, objective, archived_at, created_at, updated_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
    return dict(row)


def delete_investigation(
    database: str | Path, investigation_id: str, *, force: bool = False
) -> dict[str, Any]:
    with _connection(database) as connection:
        investigation = connection.execute(
            "SELECT id, name FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        counts = {
            "observations": connection.execute(
                "SELECT COUNT(*) FROM observations WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()[0],
            "evidence": connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()[0],
            "relationships": connection.execute(
                "SELECT COUNT(*) FROM relationships WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()[0],
            "entities": connection.execute(
                """SELECT COUNT(*) FROM investigation_entities
                   WHERE investigation_id = ?""",
                (investigation_id,),
            ).fetchone()[0],
            "sources": connection.execute(
                """SELECT COUNT(*) FROM investigation_sources
                   WHERE investigation_id = ?""",
                (investigation_id,),
            ).fetchone()[0],
        }
        if not force and (counts["evidence"] or counts["relationships"]):
            raise ConflictError(
                "investigation has dependent records "
                f"({counts['evidence']} evidence, {counts['relationships']} "
                "relationships); pass force=true to delete the investigation with "
                "its own records. Shared entities and sources are never deleted."
            )
        stored_names = [
            row["stored_name"]
            for row in connection.execute(
                """SELECT stored_name FROM evidence
                   WHERE investigation_id = ? AND stored_name <> ''""",
                (investigation_id,),
            )
        ]
        name = investigation["name"]
        from .custody import record as custody_record

        for evidence in connection.execute(
            "SELECT id, sha256, title FROM evidence WHERE investigation_id = ?", (investigation_id,)
        ).fetchall():
            custody_record(
                connection,
                evidence_id=evidence["id"],
                investigation_id=investigation_id,
                action="deleted",
                sha256=evidence["sha256"],
                detail=f"Deleted with investigation '{name}'",
            )
        connection.execute(
            "DELETE FROM investigations WHERE id = ?", (investigation_id,)
        )
        record_activity(
            connection,
            action="delete",
            target_type="investigation",
            target_id=investigation_id,
            investigation_id=investigation_id,
            summary=f"Investigation deleted: {name}",
        )
    removed_files = 0
    if stored_names:
        from .evidence import remove_stored_files

        removed_files = remove_stored_files(database, stored_names)
    return {
        "deleted": True,
        "investigation_id": investigation_id,
        "name": name,
        "removed": counts,
        "removed_files": removed_files,
        "shared_entities_preserved": True,
        "shared_sources_preserved": True,
    }


def set_investigation_status(
    database: str | Path, investigation_id: str, status: str
) -> dict[str, Any]:
    if status not in INVESTIGATION_STATUSES:
        raise ValidationError(
            f"status must be one of: {', '.join(INVESTIGATION_STATUSES)}"
        )
    with _connection(database) as connection:
        current = connection.execute(
            "SELECT status FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if current is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        if current["status"] != status:
            changed_at = utc_now()
            connection.execute(
                """UPDATE investigations
                   SET status = ?, updated_at = ? WHERE id = ?""",
                (status, changed_at, investigation_id),
            )
            connection.execute(
                """INSERT INTO investigation_status_events
                   (id, investigation_id, status, changed_at)
                   VALUES (?, ?, ?, ?)""",
                (new_id(), investigation_id, status, changed_at),
            )
            record_activity(
                connection,
                action="status",
                target_type="investigation",
                target_id=investigation_id,
                investigation_id=investigation_id,
                summary=f"Investigation status changed to {status}",
            )
        row = connection.execute(
            """SELECT id, name, description, objective, archived_at, created_at, updated_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
    return dict(row)


def add_observation(
    database: str | Path,
    investigation_id: str,
    title: str,
    content: str,
    source_reference: str,
    collection_basis: str,
    observed_at: str | None = None,
) -> dict[str, Any]:
    title = _required_text(title, "title")
    content = _required_text(content, "content")
    source_reference = _required_text(source_reference, "source reference")
    if collection_basis not in COLLECTION_BASES:
        raise ValidationError(
            f"collection basis must be one of: {', '.join(COLLECTION_BASES)}"
        )

    observation = {
        "id": new_id(),
        "investigation_id": _required_text(investigation_id, "investigation id"),
        "title": title,
        "content": content,
        "source_reference": source_reference,
        "collection_basis": collection_basis,
        "observed_at": normalize_timestamp(observed_at),
        "recorded_at": utc_now(),
    }
    with _connection(database) as connection:
        cursor = connection.execute(
            """INSERT INTO observations (
                   id, investigation_id, title, content, source_reference,
                   collection_basis, observed_at, recorded_at
               )
               SELECT ?, ?, ?, ?, ?, ?, ?, ?
               FROM investigations
               WHERE id = ? AND status = 'open'""",
            (*observation.values(), observation["investigation_id"]),
        )
        if cursor.rowcount == 0:
            investigation = connection.execute(
                "SELECT status FROM investigations WHERE id = ?",
                (observation["investigation_id"],),
            ).fetchone()
            if investigation is None:
                raise NotFoundError(
                    f"investigation not found: {observation['investigation_id']}"
                )
            raise ConflictError(
                f"investigation is {investigation['status']}; "
                "reopen it before adding evidence"
            )
        connection.execute(
            """UPDATE investigations SET updated_at = ? WHERE id = ?""",
            (observation["recorded_at"], observation["investigation_id"]),
        )
        record_activity(
            connection,
            action="observation",
            target_type="observation",
            target_id=observation["id"],
            investigation_id=observation["investigation_id"],
            summary=f"Observation recorded: {observation['title']}",
        )
    return observation


def _linked_entities(
    connection: sqlite3.Connection, investigation_id: str
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT e.id, e.entity_type, e.name, e.identifier, e.description,
                  e.source_reference, e.collection_basis, e.confidence,
                  e.verification_status, e.created_at, e.updated_at,
                  ie.added_at AS linked_at
           FROM entities e
           JOIN investigation_entities ie ON ie.entity_id = e.id
           WHERE ie.investigation_id = ?
           ORDER BY e.entity_type, e.name, e.id""",
        (investigation_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _linked_relationships(
    connection: sqlite3.Connection, investigation_id: str
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT r.id, r.investigation_id, r.source_entity_id,
                  r.target_entity_id, r.relationship_type, r.description,
                  r.source_reference, r.confidence, r.verification_status,
                  r.created_at, r.updated_at,
                  source.name AS source_name, source.entity_type AS source_type,
                  target.name AS target_name, target.entity_type AS target_type
           FROM relationships r
           JOIN entities source ON source.id = r.source_entity_id
           JOIN entities target ON target.id = r.target_entity_id
           WHERE r.investigation_id = ?
              OR (
                r.source_entity_id IN (
                    SELECT entity_id FROM investigation_entities
                    WHERE investigation_id = ?
                )
                AND r.target_entity_id IN (
                    SELECT entity_id FROM investigation_entities
                    WHERE investigation_id = ?
                )
              )
           ORDER BY r.created_at, r.id""",
        (investigation_id, investigation_id, investigation_id),
    ).fetchall()
    return [dict(row) for row in rows]


def _linked_evidence(
    connection: sqlite3.Connection, investigation_id: str
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT id, investigation_id, title, evidence_type, description,
                  source_reference, original_name, media_type, size_bytes, sha256,
                  acquired_at, recorded_at, integrity_status, image_format,
                  image_width, image_height
           FROM evidence WHERE investigation_id = ?
           ORDER BY recorded_at, id""",
        (investigation_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _linked_sources(
    connection: sqlite3.Connection, investigation_id: str
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT s.id, s.title, s.reference, s.category, s.description,
                  s.accessed_at, s.verification_status, s.created_at,
                  s.updated_at, ins.added_at AS linked_at
           FROM sources s
           JOIN investigation_sources ins ON ins.source_id = s.id
           WHERE ins.investigation_id = ?
           ORDER BY s.category, s.title, s.id""",
        (investigation_id,),
    ).fetchall()
    return [dict(row) for row in rows]


LEGACY_SECTIONS = ("summary", "entities", "relationships", "evidence", "sources", "observations", "indicators", "correlations", "limitations")


def build_report(database: str | Path, investigation_id: str, sections: tuple[str, ...] | None = None) -> dict[str, Any]:
    """The case report. ``sections`` (see report_sections.SECTIONS) chooses
    what is rendered; the default keeps the original set."""
    with _connection(database) as connection:
        investigation = connection.execute(
            """SELECT id, name, description, objective, archived_at, created_at, updated_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        observations = connection.execute(
            """SELECT id, title, content, source_reference, collection_basis,
                      observed_at, recorded_at
               FROM observations
               WHERE investigation_id = ?
               ORDER BY observed_at, recorded_at, id""",
            (investigation_id,),
        ).fetchall()
        entities = _linked_entities(connection, investigation_id)
        relationships = _linked_relationships(connection, investigation_id)
        evidence = _linked_evidence(connection, investigation_id)
        sources = _linked_sources(connection, investigation_id)
        indicator_engine = module_enabled(connection, "indicator-engine")
        include_limitations = setting_bool(
            connection, "report.include_limitations", True
        )
        include_raw_observations = setting_bool(
            connection, "report.include_raw_observations", True
        )

    observation_records = [dict(row) for row in observations]
    indicator_findings = (
        extract_indicators(observation_records) if indicator_engine else []
    )
    correlations = (
        correlate_indicators(indicator_findings) if indicator_engine else []
    )
    limitations = [
        "Observations are user-entered and have not been independently verified.",
        "This tool records evidence; it does not collect data from external services.",
        "Indicator matches are pattern-based and have not been reputation-checked.",
    ]
    if not include_limitations:
        limitations = []
    if relationships:
        limitations.append(
            "Relationships are analyst-entered and keep the verification status "
            "recorded for each link."
        )
    if evidence:
        limitations.append(
            "Evidence digests confirm file identity; they do not establish "
            "authenticity, origin or intent."
        )
    if not indicator_engine:
        limitations.append(
            "The indicator engine is disabled in the module registry; indicators "
            "and correlations were not computed."
        )
    chosen = tuple(sections) if sections is not None else LEGACY_SECTIONS
    extras: dict[str, Any] = {}
    if any(name in chosen for name in ("methodology", "techniques", "custody", "graph")):
        from . import report_sections

        if "methodology" in chosen:
            extras["methodology"] = report_sections.methodology(str(database), investigation_id)
        if "techniques" in chosen:
            extras["techniques"] = report_sections.techniques(str(database), investigation_id)
        if "custody" in chosen:
            extras["custody"] = report_sections.custody_summary(str(database), evidence)
        if "graph" in chosen:
            extras["graph_svg"] = report_sections.graph_svg(entities, relationships)
    return {
        "sections": list(chosen),
        **extras,
        "investigation": dict(investigation),
        "observations": observation_records,
        "indicators": indicator_findings,
        "correlations": correlations,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "sources": sources,
        "limitations": limitations,
        "options": {
            "include_limitations": include_limitations,
            "include_raw_observations": include_raw_observations,
            "indicator_engine": indicator_engine,
        },
        "metadata": {
            "generated_at": utc_now(),
            "schema_version": 2,
            "record_classes": {
                "observations": "Analyst-recorded observation, not independently verified",
                "evidence": "Hashed file or reference provided by the analyst",
                "relationships": "Analyst-entered link with a verification status",
                "sources": "Consulted source with an access timestamp",
            },
        },
    }


def build_timeline(database: str | Path, investigation_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        investigation = connection.execute(
            """SELECT id, name, description, created_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        observations = connection.execute(
            """SELECT id, title, source_reference, collection_basis,
                      observed_at, recorded_at
               FROM observations
               WHERE investigation_id = ?
               ORDER BY observed_at, recorded_at, id""",
            (investigation_id,),
        ).fetchall()
        status_events = connection.execute(
            """SELECT id, status, changed_at
               FROM investigation_status_events
               WHERE investigation_id = ?
               ORDER BY changed_at, id""",
            (investigation_id,),
        ).fetchall()
        entity_links = connection.execute(
            """SELECT ie.entity_id, ie.added_at, e.name, e.entity_type
               FROM investigation_entities ie
               JOIN entities e ON e.id = ie.entity_id
               WHERE ie.investigation_id = ?""",
            (investigation_id,),
        ).fetchall()
        evidence_records = connection.execute(
            """SELECT id, title, recorded_at FROM evidence
               WHERE investigation_id = ?""",
            (investigation_id,),
        ).fetchall()
        source_links = connection.execute(
            """SELECT ins.source_id, ins.added_at, s.title
               FROM investigation_sources ins
               JOIN sources s ON s.id = ins.source_id
               WHERE ins.investigation_id = ?""",
            (investigation_id,),
        ).fetchall()
        relationship_records = connection.execute(
            """SELECT id, relationship_type, created_at FROM relationships
               WHERE investigation_id = ?""",
            (investigation_id,),
        ).fetchall()

    investigation = dict(investigation)
    events: list[dict[str, Any]] = [
        {
            "type": "investigation_created",
            "occurred_at": investigation["created_at"],
            "recorded_at": investigation["created_at"],
            "title": "Investigation created",
            "status": "open",
        }
    ]
    events.extend(
        {
            "type": "observation",
            "occurred_at": observation["observed_at"],
            "recorded_at": observation["recorded_at"],
            "title": observation["title"],
            "source_reference": observation["source_reference"],
            "collection_basis": observation["collection_basis"],
            "observation_id": observation["id"],
        }
        for observation in observations
    )
    events.extend(
        {
            "type": "status_changed",
            "occurred_at": event["changed_at"],
            "recorded_at": event["changed_at"],
            "title": f"Investigation status changed to {event['status']}",
            "status": event["status"],
            "status_event_id": event["id"],
        }
        for event in status_events
    )
    events.extend(
        {
            "type": "entity_linked",
            "occurred_at": link["added_at"],
            "recorded_at": link["added_at"],
            "title": f"Entity linked: {link['name']}",
            "entity_id": link["entity_id"],
            "entity_type": link["entity_type"],
        }
        for link in entity_links
    )
    events.extend(
        {
            "type": "evidence_added",
            "occurred_at": record["recorded_at"],
            "recorded_at": record["recorded_at"],
            "title": f"Evidence added: {record['title']}",
            "evidence_id": record["id"],
        }
        for record in evidence_records
    )
    events.extend(
        {
            "type": "source_linked",
            "occurred_at": link["added_at"],
            "recorded_at": link["added_at"],
            "title": f"Source linked: {link['title']}",
            "source_id": link["source_id"],
        }
        for link in source_links
    )
    events.extend(
        {
            "type": "relationship_recorded",
            "occurred_at": record["created_at"],
            "recorded_at": record["created_at"],
            "title": f"Relationship recorded: {record['relationship_type']}",
            "relationship_id": record["id"],
        }
        for record in relationship_records
    )
    events.sort(
        key=lambda event: (event["occurred_at"], event["recorded_at"], event["type"])
    )
    return {"investigation": investigation, "events": events}


def report_json(database: str | Path, investigation_id: str) -> str:
    return json.dumps(
        build_report(database, investigation_id), ensure_ascii=False, indent=2
    )
