"""Reusable source registry linked to investigations and entities."""

from __future__ import annotations

from typing import Any

from .db import (
    SOURCE_CATEGORIES,
    VERIFICATION_STATUSES,
    _connection,
    new_id,
    normalize_timestamp,
    record_activity,
    utc_now,
)
from .errors import ConflictError, NotFoundError, ValidationError
from .validation import choice, clean_text, safe_reference, search_pattern


def source_categories() -> list[dict[str, str]]:
    return [
        {"value": category, "label": category.replace("-", " ").title()}
        for category in SOURCE_CATEGORIES
    ]


def _source_row(database: str, source_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute(
            """SELECT id, title, reference, category, description, accessed_at,
                      verification_status, created_at, updated_at
               FROM sources WHERE id = ?""",
            (source_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"source not found: {source_id}")
    return dict(row)


def create_source(
    database: str,
    *,
    title: object,
    reference: object = "",
    category: object = "other",
    description: object = "",
    accessed_at: object = None,
    verification_status: object = "not-verified",
) -> dict[str, Any]:
    clean_title = clean_text(title, "title", max_length=300, required=True)
    clean_reference = safe_reference(reference, "reference", required=True)
    clean_category = choice(category, SOURCE_CATEGORIES, "source category")
    clean_description = clean_text(description, "description", max_length=10000)
    verification = choice(
        verification_status, VERIFICATION_STATUSES, "verification status"
    )
    accessed = normalize_timestamp(
        clean_text(accessed_at, "access time", max_length=100) or None
    )
    source_id = new_id()
    now = utc_now()
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO sources
               (id, title, reference, category, description, accessed_at,
                verification_status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                source_id,
                clean_title,
                clean_reference,
                clean_category,
                clean_description,
                accessed,
                verification,
                now,
                now,
            ),
        )
        record_activity(
            connection,
            action="create",
            target_type="source",
            target_id=source_id,
            summary=f"Source registered: {clean_title}",
        )
    return _source_row(database, source_id)


def list_sources(
    database: str,
    *,
    search: str = "",
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    clauses: list[str] = []
    parameters: list[Any] = []
    if category:
        clauses.append("s.category = ?")
        parameters.append(choice(category, SOURCE_CATEGORIES, "source category"))
    if search.strip():
        clauses.append(
            "(s.title LIKE ? ESCAPE '\\' OR s.reference LIKE ? ESCAPE '\\' "
            "OR s.description LIKE ? ESCAPE '\\')"
        )
        pattern = search_pattern(search.strip())
        parameters.extend([pattern, pattern, pattern])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM sources s {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""SELECT s.id, s.title, s.reference, s.category, s.description,
                       s.accessed_at, s.verification_status, s.created_at,
                       s.updated_at,
                       (SELECT COUNT(*) FROM investigation_sources ins
                        WHERE ins.source_id = s.id) AS investigation_count,
                       (SELECT COUNT(*) FROM entity_sources es
                        WHERE es.source_id = s.id) AS entity_count
                FROM sources s {where}
                ORDER BY s.updated_at DESC, s.title, s.id
                LIMIT ? OFFSET ?""",
            [*parameters, limit, offset],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "categories": source_categories(),
    }


def get_source(database: str, source_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        source = _source_row(database, source_id)
        investigations = [
            dict(row)
            for row in connection.execute(
                """SELECT i.id, i.name, i.status, ins.added_at
                   FROM investigations i
                   JOIN investigation_sources ins ON ins.investigation_id = i.id
                   WHERE ins.source_id = ?
                   ORDER BY ins.added_at DESC""",
                (source_id,),
            )
        ]
        entities = [
            dict(row)
            for row in connection.execute(
                """SELECT e.id, e.name, e.entity_type, es.added_at
                   FROM entities e
                   JOIN entity_sources es ON es.entity_id = e.id
                   WHERE es.source_id = ?
                   ORDER BY e.name, e.id""",
                (source_id,),
            )
        ]
    return {**source, "investigations": investigations, "entities": entities}


def update_source(database: str, source_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "title",
        "reference",
        "category",
        "description",
        "accessed_at",
        "verification_status",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ValidationError(f"unsupported source fields: {', '.join(sorted(unknown))}")
    if not payload:
        raise ValidationError("no source fields were provided")
    current = _source_row(database, source_id)
    title = (
        clean_text(payload["title"], "title", max_length=300, required=True)
        if "title" in payload
        else current["title"]
    )
    reference = (
        safe_reference(payload["reference"], "reference", required=True)
        if "reference" in payload
        else current["reference"]
    )
    category = (
        choice(payload["category"], SOURCE_CATEGORIES, "source category")
        if "category" in payload
        else current["category"]
    )
    description = (
        clean_text(payload["description"], "description", max_length=10000)
        if "description" in payload
        else current["description"]
    )
    accessed = current["accessed_at"]
    if "accessed_at" in payload:
        accessed = normalize_timestamp(
            clean_text(payload["accessed_at"], "access time", max_length=100) or None
        )
    verification = (
        choice(
            payload["verification_status"],
            VERIFICATION_STATUSES,
            "verification status",
        )
        if "verification_status" in payload
        else current["verification_status"]
    )
    with _connection(database) as connection:
        connection.execute(
            """UPDATE sources
               SET title = ?, reference = ?, category = ?, description = ?,
                   accessed_at = ?, verification_status = ?, updated_at = ?
               WHERE id = ?""",
            (
                title,
                reference,
                category,
                description,
                accessed,
                verification,
                utc_now(),
                source_id,
            ),
        )
        record_activity(
            connection,
            action="update",
            target_type="source",
            target_id=source_id,
            summary=f"Source updated: {title}",
        )
    return _source_row(database, source_id)


def delete_source(database: str, source_id: str) -> dict[str, Any]:
    current = _source_row(database, source_id)
    with _connection(database) as connection:
        connection.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        record_activity(
            connection,
            action="delete",
            target_type="source",
            target_id=source_id,
            summary=f"Source deleted: {current['title']}",
        )
    return {"deleted": True, "source_id": source_id, "title": current["title"]}


def link_source_to_investigation(
    database: str, investigation_id: str, source_id: str
) -> dict[str, Any]:
    _source_row(database, source_id)
    with _connection(database) as connection:
        investigation = connection.execute(
            "SELECT id FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        cursor = connection.execute(
            """INSERT OR IGNORE INTO investigation_sources
               (investigation_id, source_id, added_at) VALUES (?, ?, ?)""",
            (investigation_id, source_id, utc_now()),
        )
        created = cursor.rowcount > 0
        if created:
            record_activity(
                connection,
                action="link",
                target_type="source",
                target_id=source_id,
                investigation_id=investigation_id,
                summary="Source linked to investigation",
            )
    return {
        "linked": True,
        "already_linked": not created,
        "investigation_id": investigation_id,
        "source_id": source_id,
    }


def unlink_source_from_investigation(
    database: str, investigation_id: str, source_id: str
) -> dict[str, Any]:
    with _connection(database) as connection:
        cursor = connection.execute(
            """DELETE FROM investigation_sources
               WHERE investigation_id = ? AND source_id = ?""",
            (investigation_id, source_id),
        )
        if cursor.rowcount == 0:
            raise NotFoundError("source is not linked to this investigation")
        record_activity(
            connection,
            action="unlink",
            target_type="source",
            target_id=source_id,
            investigation_id=investigation_id,
            summary="Source unlinked from investigation",
        )
    return {"unlinked": True}


def link_source_to_entity(database: str, entity_id: str, source_id: str) -> dict[str, Any]:
    _source_row(database, source_id)
    with _connection(database) as connection:
        if connection.execute(
            "SELECT 1 FROM entities WHERE id = ?", (entity_id,)
        ).fetchone() is None:
            raise NotFoundError(f"entity not found: {entity_id}")
        cursor = connection.execute(
            """INSERT OR IGNORE INTO entity_sources
               (entity_id, source_id, added_at) VALUES (?, ?, ?)""",
            (entity_id, source_id, utc_now()),
        )
        created = cursor.rowcount > 0
        if created:
            record_activity(
                connection,
                action="link",
                target_type="source",
                target_id=source_id,
                summary="Source linked to entity",
            )
    return {
        "linked": True,
        "already_linked": not created,
        "entity_id": entity_id,
        "source_id": source_id,
    }


def unlink_source_from_entity(
    database: str, entity_id: str, source_id: str
) -> dict[str, Any]:
    with _connection(database) as connection:
        cursor = connection.execute(
            "DELETE FROM entity_sources WHERE entity_id = ? AND source_id = ?",
            (entity_id, source_id),
        )
        if cursor.rowcount == 0:
            raise ConflictError("source is not linked to this entity")
        record_activity(
            connection,
            action="unlink",
            target_type="source",
            target_id=source_id,
            summary="Source unlinked from entity",
        )
    return {"unlinked": True}
