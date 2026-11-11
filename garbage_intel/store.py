"""Local SQLite storage for investigations and sourced observations."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .modules.indicators import extract_indicators
from .modules.correlation import correlate_indicators


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    collection_basis TEXT NOT NULL CHECK (
        collection_basis IN ('public', 'authorized', 'user-provided')
    ),
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS observations_investigation_time
    ON observations(investigation_id, observed_at, recorded_at);

CREATE TABLE IF NOT EXISTS investigation_status_events (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed', 'cancelled')),
    changed_at TEXT NOT NULL
);
"""

COLLECTION_BASES = ("public", "authorized", "user-provided")
INVESTIGATION_STATUSES = ("open", "closed", "cancelled")
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value: str | None) -> str:
    if value is None:
        return utc_now()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_text(value: str, field: str) -> str:
    if not value.strip():
        raise ValueError(f"{field} must not be empty")
    return value.strip()


def connect(database: str | Path) -> sqlite3.Connection:
    path = Path(database)
    if str(database) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection(database: str | Path) -> Iterator[sqlite3.Connection]:
    connection = connect(database)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize(database: str | Path) -> None:
    with _connection(database) as connection:
        connection.executescript(SCHEMA)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(investigations)")
        }
        if "status" not in columns:
            connection.execute(
                """ALTER TABLE investigations
                   ADD COLUMN status TEXT NOT NULL DEFAULT 'open'"""
            )


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
                   (id, name, description, created_at, status)
                   VALUES (:id, :name, :description, :created_at, :status)""",
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
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"archive conflicts with existing records: {exc}") from exc
    return {
        "imported": True,
        "investigations": len(clean_investigations),
        "observations": len(clean_observations),
        "status_events": len(clean_status_events),
    }


def create_investigation(
    database: str | Path, name: str, description: str = ""
) -> dict[str, Any]:
    name = _required_text(name, "name")
    investigation = {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": description.strip(),
        "created_at": utc_now(),
        "status": "open",
    }
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO investigations
               (id, name, description, created_at, status)
               VALUES (?, ?, ?, ?, ?)""",
            (
                investigation["id"],
                investigation["name"],
                investigation["description"],
                investigation["created_at"],
                investigation["status"],
            ),
        )
    return investigation


def list_investigations(database: str | Path) -> list[dict[str, Any]]:
    with _connection(database) as connection:
        rows = connection.execute(
            """SELECT id, name, description, created_at, status
               FROM investigations ORDER BY created_at, id"""
        ).fetchall()
    return [dict(row) for row in rows]


def set_investigation_status(
    database: str | Path, investigation_id: str, status: str
) -> dict[str, Any]:
    if status not in INVESTIGATION_STATUSES:
        raise ValueError(
            f"status must be one of: {', '.join(INVESTIGATION_STATUSES)}"
        )
    with _connection(database) as connection:
        current = connection.execute(
            "SELECT status FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if current is None:
            raise ValueError(f"investigation not found: {investigation_id}")
        if current["status"] != status:
            changed_at = utc_now()
            connection.execute(
                "UPDATE investigations SET status = ? WHERE id = ?",
                (status, investigation_id),
            )
            connection.execute(
                """INSERT INTO investigation_status_events
                   (id, investigation_id, status, changed_at)
                   VALUES (?, ?, ?, ?)""",
                (str(uuid.uuid4()), investigation_id, status, changed_at),
            )
        row = connection.execute(
            """SELECT id, name, description, created_at, status
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
        raise ValueError(
            f"collection basis must be one of: {', '.join(COLLECTION_BASES)}"
        )

    observation = {
        "id": str(uuid.uuid4()),
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
                raise ValueError(
                    f"investigation not found: {observation['investigation_id']}"
                )
            raise ValueError(
                f"investigation is {investigation['status']}; "
                "reopen it before adding evidence"
            )
    return observation


def build_report(database: str | Path, investigation_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        investigation = connection.execute(
            """SELECT id, name, description, created_at, status
               FROM investigations WHERE id = ?""",
            (investigation_id,),
        ).fetchone()
        if investigation is None:
            raise ValueError(f"investigation not found: {investigation_id}")
        observations = connection.execute(
            """SELECT id, title, content, source_reference, collection_basis,
                      observed_at, recorded_at
               FROM observations
               WHERE investigation_id = ?
               ORDER BY observed_at, recorded_at, id""",
            (investigation_id,),
        ).fetchall()

    indicator_findings = extract_indicators(dict(row) for row in observations)
    return {
        "investigation": dict(investigation),
        "observations": [dict(row) for row in observations],
        "indicators": indicator_findings,
        "correlations": correlate_indicators(indicator_findings),
        "limitations": [
            "Observations are user-entered and have not been independently verified.",
            "This tool records evidence; it does not collect data from external services.",
            "Indicator matches are pattern-based and have not been reputation-checked.",
        ],
    }


def build_timeline(database: str | Path, investigation_id: str) -> dict[str, Any]:
    report = build_report(database, investigation_id)
    investigation = report["investigation"]
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
        for observation in report["observations"]
    )
    with _connection(database) as connection:
        status_events = connection.execute(
            """SELECT id, status, changed_at
               FROM investigation_status_events
               WHERE investigation_id = ?
               ORDER BY changed_at, id""",
            (investigation_id,),
        ).fetchall()
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
    events.sort(key=lambda event: (event["occurred_at"], event["recorded_at"], event["type"]))
    return {"investigation": investigation, "events": events}


def report_json(database: str | Path, investigation_id: str) -> str:
    return json.dumps(
        build_report(database, investigation_id), ensure_ascii=False, indent=2
    )
