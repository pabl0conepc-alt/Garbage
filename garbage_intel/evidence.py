"""Evidence records with hash preservation, safe storage and image metadata.

Uploaded bytes are written under a generated internal name inside an evidence
directory owned by the workspace. Original names are only display metadata and
never used as filesystem paths. Files are never executed; non-image downloads
are served as attachments.
"""

from __future__ import annotations

import mimetypes
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from .db import (
    EVIDENCE_TYPES,
    _connection,
    new_id,
    normalize_timestamp,
    record_activity,
    utc_now,
)
from .errors import ConflictError, NotFoundError, ValidationError
from .modules.imaging import inspect_image, sha256_hex
from .validation import choice, clean_text, safe_reference, search_pattern


MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BODY_BYTES = 6 * 1024 * 1024
_SUFFIX = re.compile(r"^\.[a-z0-9]{1,10}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

_EVIDENCE_COLUMNS = """id, investigation_id, title, evidence_type, description,
    source_reference, original_name, media_type, size_bytes, sha256,
    acquired_at, recorded_at, integrity_status, image_format, image_width,
    image_height"""


def storage_directory(database: str | Path) -> Path:
    if str(database) == ":memory:":
        raise ValidationError("file evidence requires a file-backed database")
    return Path(database).parent / "evidence"


def _safe_suffix(original_name: str) -> str:
    suffix = Path(original_name).suffix.lower()
    return suffix if _SUFFIX.fullmatch(suffix) else ""


def _stored_path(database: str | Path, stored_name: str) -> Path:
    if not stored_name or Path(stored_name).name != stored_name:
        raise ValidationError("invalid stored evidence name")
    directory = storage_directory(database).resolve()
    path = (directory / stored_name).resolve()
    if path.parent != directory:
        raise ValidationError("invalid stored evidence path")
    return path


def _write_stored_file(database: str | Path, stored_name: str, data: bytes) -> None:
    directory = storage_directory(database)
    directory.mkdir(parents=True, exist_ok=True)
    path = _stored_path(database, stored_name)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_stored_file(database: str | Path, stored_name: str) -> bytes:
    path = _stored_path(database, stored_name)
    if path.is_symlink() or not path.is_file():
        raise NotFoundError("stored evidence file is missing")
    with path.open("rb") as source:
        return source.read(MAX_EVIDENCE_BYTES + 1)


def _public_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    record.pop("stored_name", None)
    record["has_file"] = bool(record.pop("_has_file", False))
    return record


def add_evidence(
    database: str,
    investigation_id: str,
    *,
    title: object,
    evidence_type: object = "file",
    description: object = "",
    source_reference: object = "",
    original_name: object = "",
    data: bytes | None = None,
    sha256: object = "",
    acquired_at: object = None,
    analyze_image: bool = True,
) -> dict[str, Any]:
    clean_title = clean_text(title, "title", max_length=300, required=True)
    kind = choice(evidence_type, EVIDENCE_TYPES, "evidence type")
    clean_description = clean_text(description, "description", max_length=10000)
    reference = safe_reference(source_reference, "source reference")
    clean_name = Path(clean_text(original_name, "original name", max_length=300)).name
    acquired = normalize_timestamp(
        clean_text(acquired_at, "acquisition time", max_length=100) or None
    )
    if data is not None:
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError("evidence content must be bytes")
        data = bytes(data)
        if not data:
            raise ValidationError("evidence file must not be empty")
        if len(data) > MAX_EVIDENCE_BYTES:
            raise ValidationError("evidence file exceeds the 4 MiB limit")
    else:
        data = None
        if kind in {"file", "image"} and not reference:
            raise ValidationError(
                "provide file content, or a source reference for a reference-only record"
            )

    digest_value = clean_text(sha256, "sha256", max_length=64).lower()
    if digest_value and not _SHA256.fullmatch(digest_value):
        raise ValidationError("sha256 must be a 64 character hexadecimal digest")

    image = inspect_image(data) if data and analyze_image else None
    if kind == "image" and data and analyze_image and image is None:
        raise ValidationError("uploaded file is not a recognised image format")
    if data is not None:
        digest_value = sha256_hex(data)
    elif not digest_value and not reference:
        raise ValidationError("provide sha256 or a source reference")

    media_type = "application/octet-stream"
    if image is not None:
        media_type = str(image["media_type"])
    elif clean_name:
        guessed, _ = mimetypes.guess_type(clean_name, strict=False)
        if guessed:
            media_type = guessed

    evidence_id = new_id()
    stored_name = f"{evidence_id}{_safe_suffix(clean_name)}" if data else ""
    now = utc_now()
    with _connection(database) as connection:
        investigation = connection.execute(
            "SELECT status FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        if investigation["status"] != "open":
            raise ConflictError(
                f"investigation is {investigation['status']}; "
                "reopen it before adding evidence"
            )
        if data is not None:
            _write_stored_file(database, stored_name, data)
        try:
            connection.execute(
                """INSERT INTO evidence
                   (id, investigation_id, title, evidence_type, description,
                    source_reference, original_name, stored_name, media_type,
                    size_bytes, sha256, acquired_at, recorded_at,
                    integrity_status, image_format, image_width, image_height)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id,
                    investigation_id,
                    clean_title,
                    kind,
                    clean_description,
                    reference,
                    clean_name,
                    stored_name,
                    media_type,
                    len(data) if data is not None else 0,
                    digest_value,
                    acquired,
                    now,
                    "unverified",
                    str(image["format"]) if image else None,
                    int(image["width"]) if image else None,
                    int(image["height"]) if image else None,
                ),
            )
            connection.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (now, investigation_id),
            )
            record_activity(
                connection,
                action="evidence",
                target_type="evidence",
                target_id=evidence_id,
                investigation_id=investigation_id,
                summary=f"Evidence added: {clean_title}",
            )
        except sqlite3.Error:
            if stored_name:
                try:
                    _stored_path(database, stored_name).unlink()
                except OSError:
                    pass
            raise
    return get_evidence(database, evidence_id)


def list_evidence(
    database: str,
    *,
    investigation_id: str | None = None,
    evidence_type: str | None = None,
    search: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    clauses: list[str] = []
    parameters: list[Any] = []
    if investigation_id:
        clauses.append("e.investigation_id = ?")
        parameters.append(investigation_id)
    if evidence_type:
        clauses.append("e.evidence_type = ?")
        parameters.append(choice(evidence_type, EVIDENCE_TYPES, "evidence type"))
    if search.strip():
        clauses.append(
            "(e.title LIKE ? ESCAPE '\\' OR e.description LIKE ? ESCAPE '\\' "
            "OR e.original_name LIKE ? ESCAPE '\\' OR e.sha256 LIKE ? ESCAPE '\\')"
        )
        pattern = search_pattern(search.strip())
        parameters.extend([pattern, pattern, pattern, pattern])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM evidence e {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""SELECT {_EVIDENCE_COLUMNS},
                       CASE WHEN stored_name <> '' THEN 1 ELSE 0 END AS _has_file,
                       (SELECT name FROM investigations i
                        WHERE i.id = e.investigation_id) AS investigation_name
                FROM evidence e {where}
                ORDER BY e.recorded_at DESC, e.id
                LIMIT ? OFFSET ?""",
            [*parameters, limit, offset],
        ).fetchall()
    return {
        "items": [_public_row(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "evidence_types": list(EVIDENCE_TYPES),
    }


def get_evidence(database: str, evidence_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute(
            f"""SELECT {_EVIDENCE_COLUMNS}, stored_name,
                       CASE WHEN stored_name <> '' THEN 1 ELSE 0 END AS _has_file,
                       (SELECT name FROM investigations i
                        WHERE i.id = e.investigation_id) AS investigation_name
                FROM evidence e WHERE e.id = ?""",
            (evidence_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"evidence not found: {evidence_id}")
    return _public_row(row)


def verify_evidence(database: str, evidence_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute(
            "SELECT id, stored_name, sha256 FROM evidence WHERE id = ?",
            (evidence_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"evidence not found: {evidence_id}")
    if not row["stored_name"]:
        raise ConflictError("evidence has no stored file to verify")
    checked_at = utc_now()
    try:
        data = _read_stored_file(database, row["stored_name"])
        computed = sha256_hex(data)
        status = "verified" if computed == row["sha256"] else "mismatch"
        matches = computed == row["sha256"]
    except (NotFoundError, OSError):
        computed = ""
        status = "missing"
        matches = False
    with _connection(database) as connection:
        connection.execute(
            "UPDATE evidence SET integrity_status = ? WHERE id = ?",
            (status, evidence_id),
        )
        record_activity(
            connection,
            action="verify",
            target_type="evidence",
            target_id=evidence_id,
            summary=f"Evidence integrity checked: {status}",
        )
    return {
        "evidence": get_evidence(database, evidence_id),
        "computed_sha256": computed,
        "matches": matches,
        "integrity_status": status,
        "checked_at": checked_at,
    }


def read_evidence_file(
    database: str, evidence_id: str
) -> tuple[bytes, str, str, bool]:
    with _connection(database) as connection:
        row = connection.execute(
            """SELECT stored_name, media_type, original_name, image_format
               FROM evidence WHERE id = ?""",
            (evidence_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"evidence not found: {evidence_id}")
    if not row["stored_name"]:
        raise ConflictError("evidence has no stored file")
    data = _read_stored_file(database, row["stored_name"])
    return (
        data,
        row["media_type"] or "application/octet-stream",
        row["original_name"] or "evidence.bin",
        bool(row["image_format"]),
    )


def delete_evidence(database: str, evidence_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute(
            "SELECT id, title, stored_name FROM evidence WHERE id = ?",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"evidence not found: {evidence_id}")
        connection.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        record_activity(
            connection,
            action="delete",
            target_type="evidence",
            target_id=evidence_id,
            summary=f"Evidence deleted: {row['title']}",
        )
    removed = 0
    if row["stored_name"]:
        try:
            _stored_path(database, row["stored_name"]).unlink()
            removed = 1
        except (OSError, ValidationError):
            removed = 0
    return {
        "deleted": True,
        "evidence_id": evidence_id,
        "title": row["title"],
        "removed_files": removed,
    }


def remove_stored_files(database: str | Path, stored_names: list[str]) -> int:
    removed = 0
    for stored_name in stored_names:
        try:
            _stored_path(database, stored_name).unlink()
            removed += 1
        except (FileNotFoundError, OSError, ValidationError):
            continue
    return removed
