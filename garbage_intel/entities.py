"""Canonical entity registry and the shared relationship engine.

Entities and relationships are the single source of truth used by the entity
manager, the investigation board and the relationship graph. Nothing in this
module invents relationships: every record is analyst-entered and carries its
provenance and verification status.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from .db import (
    COLLECTION_BASES,
    CONFIDENCE_LEVELS,
    ENTITY_TYPE_LABELS,
    ENTITY_TYPES,
    IOC_ENTITY_TYPES,
    RELATIONSHIP_TYPE_LABELS,
    RELATIONSHIP_TYPES,
    VERIFICATION_STATUSES,
    _connection,
    new_id,
    normalize_timestamp,
    record_activity,
    utc_now,
)
from . import native
from .errors import ConflictError, NotFoundError, ValidationError
from .modules.indicators import canonical_ip_address
from .validation import (
    choice,
    clean_text,
    optional_choice,
    safe_reference,
    search_pattern,
)

MAX_ENTITY_FIELDS = 20000
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_USERNAME = re.compile(r"^[A-Za-z0-9._\-]{1,100}$")


def entity_types() -> list[dict[str, str]]:
    return [
        {"value": entity_type, "label": ENTITY_TYPE_LABELS[entity_type]}
        for entity_type in ENTITY_TYPES
    ]


def relationship_types() -> list[dict[str, str]]:
    return [
        {"value": value, "label": RELATIONSHIP_TYPE_LABELS[value]}
        for value in RELATIONSHIP_TYPES
    ]


def _normalize_identifier(entity_type: str, identifier: str) -> str:
    if not identifier:
        return ""
    value = identifier.strip()
    if entity_type == "domain":
        value = value.lower().rstrip(".")
        if not _DOMAIN.fullmatch(value):
            raise ValidationError("identifier must be a valid domain name")
    elif entity_type == "ipv4":
        try:
            value = str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError as exc:
            raise ValidationError("identifier must be a valid IPv4 address") from exc
    elif entity_type == "ipv6":
        try:
            value = canonical_ip_address(value)
        except ValueError as exc:
            raise ValidationError("identifier must be a valid IPv6 address") from exc
    elif entity_type == "email":
        value = value.lower()
        if not _EMAIL.fullmatch(value):
            raise ValidationError("identifier must be a valid email address")
    elif entity_type == "url":
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValidationError("identifier must be an http or https URL")
    elif entity_type == "hash":
        if not _HASH.fullmatch(value):
            raise ValidationError(
                "identifier must be a 32, 40 or 64 character hexadecimal hash"
            )
        value = value.lower()
    elif entity_type == "username":
        value = value.lstrip("@")
        if not _USERNAME.fullmatch(value):
            raise ValidationError(
                "identifier must be 1-100 characters of letters, digits, . _ or -"
            )
    return value[:2000]


def _entity_row(connection: sqlite3.Connection, entity_id: str) -> dict[str, Any]:
    row = connection.execute(
        """SELECT id, entity_type, name, identifier, description,
                  source_reference, collection_basis, confidence,
                  verification_status, created_at, updated_at
           FROM entities WHERE id = ?""",
        (entity_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"entity not found: {entity_id}")
    return dict(row)


def create_entity(
    database: str,
    *,
    entity_type: object,
    name: object = "",
    identifier: object = "",
    description: object = "",
    source_reference: object = "",
    collection_basis: object = "user-provided",
    confidence: object = "unconfirmed",
    verification_status: object = "not-verified",
) -> dict[str, Any]:
    kind = choice(entity_type, ENTITY_TYPES, "entity type")
    clean_name = clean_text(name, "name", max_length=300)
    raw_identifier = clean_text(identifier, "identifier", max_length=2000)
    normalized = _normalize_identifier(kind, raw_identifier)
    if not clean_name and not normalized:
        raise ValidationError("provide a name or an identifier")
    if not clean_name:
        clean_name = normalized
    description_text = clean_text(description, "description", max_length=MAX_ENTITY_FIELDS)
    reference = safe_reference(source_reference, "source reference")
    basis = choice(collection_basis, COLLECTION_BASES, "collection basis")
    confidence_value = choice(confidence, CONFIDENCE_LEVELS, "confidence")
    verification = choice(
        verification_status, VERIFICATION_STATUSES, "verification status"
    )
    now = utc_now()
    entity_id = new_id()
    with _connection(database) as connection:
        if normalized:
            existing = connection.execute(
                """SELECT id, name FROM entities
                   WHERE entity_type = ? AND identifier = ?""",
                (kind, normalized),
            ).fetchone()
            if existing is not None:
                raise ConflictError(
                    f"entity already exists: {existing['name']} ({existing['id']})"
                )
        try:
            connection.execute(
                """INSERT INTO entities
                   (id, entity_type, name, identifier, description,
                    source_reference, collection_basis, confidence,
                    verification_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entity_id,
                    kind,
                    clean_name,
                    normalized,
                    description_text,
                    reference,
                    basis,
                    confidence_value,
                    verification,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "an entity with this type and identifier already exists"
            ) from exc
        record_activity(
            connection,
            action="create",
            target_type="entity",
            target_id=entity_id,
            summary=f"Entity registered: {clean_name} ({ENTITY_TYPE_LABELS[kind]})",
        )
    return get_entity(database, entity_id, include_relations=False)


def list_entities(
    database: str,
    *,
    entity_type: str | None = None,
    search: str = "",
    investigation_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    clauses: list[str] = []
    parameters: list[Any] = []
    if entity_type:
        clauses.append("e.entity_type = ?")
        parameters.append(choice(entity_type, ENTITY_TYPES, "entity type"))
    if investigation_id:
        clauses.append(
            """e.id IN (
                SELECT entity_id FROM investigation_entities
                WHERE investigation_id = ?
            )"""
        )
        parameters.append(investigation_id)
    if search.strip():
        clauses.append(
            "(e.name LIKE ? ESCAPE '\\' OR e.identifier LIKE ? ESCAPE '\\' "
            "OR e.description LIKE ? ESCAPE '\\')"
        )
        pattern = search_pattern(search.strip())
        parameters.extend([pattern, pattern, pattern])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM entities e {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""SELECT e.id, e.entity_type, e.name, e.identifier, e.description,
                       e.source_reference, e.collection_basis, e.confidence,
                       e.verification_status, e.created_at, e.updated_at,
                       (SELECT COUNT(*) FROM investigation_entities ie
                        WHERE ie.entity_id = e.id) AS investigation_count,
                       (SELECT COUNT(*) FROM relationships r
                        WHERE r.source_entity_id = e.id
                           OR r.target_entity_id = e.id) AS relationship_count
                FROM entities e
                {where}
                ORDER BY e.updated_at DESC, e.name, e.id
                LIMIT ? OFFSET ?""",
            [*parameters, limit, offset],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "entity_types": entity_types(),
    }


def get_entity(
    database: str, entity_id: str, *, include_relations: bool = True
) -> dict[str, Any]:
    with _connection(database) as connection:
        entity = _entity_row(connection, entity_id)
        investigations = [
            dict(row)
            for row in connection.execute(
                """SELECT i.id, i.name, i.status, ie.added_at
                   FROM investigations i
                   JOIN investigation_entities ie ON ie.investigation_id = i.id
                   WHERE ie.entity_id = ?
                   ORDER BY ie.added_at DESC""",
                (entity_id,),
            )
        ]
        sources = [
            dict(row)
            for row in connection.execute(
                """SELECT s.id, s.title, s.reference, s.category,
                          s.verification_status, es.added_at
                   FROM sources s
                   JOIN entity_sources es ON es.source_id = s.id
                   WHERE es.entity_id = ?
                   ORDER BY s.title, s.id""",
                (entity_id,),
            )
        ]
        relationships: list[dict[str, Any]] = []
        if include_relations:
            relationships = [
                dict(row)
                for row in connection.execute(
                    """SELECT r.id, r.investigation_id, r.source_entity_id,
                              r.target_entity_id, r.relationship_type,
                              r.description, r.source_reference, r.confidence,
                              r.verification_status, r.created_at,
                              CASE WHEN r.source_entity_id = ?
                                   THEN 'outgoing' ELSE 'incoming' END AS direction,
                              other.id AS other_id, other.name AS other_name,
                              other.entity_type AS other_type
                       FROM relationships r
                       JOIN entities other ON other.id = CASE
                            WHEN r.source_entity_id = ?
                            THEN r.target_entity_id ELSE r.source_entity_id END
                       WHERE r.source_entity_id = ? OR r.target_entity_id = ?
                       ORDER BY r.created_at DESC, r.id""",
                    (entity_id, entity_id, entity_id, entity_id),
                )
            ]
    return {
        **entity,
        "investigations": investigations,
        "sources": sources,
        "relationships": relationships,
    }


def update_entity(database: str, entity_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "entity_type",
        "name",
        "identifier",
        "description",
        "source_reference",
        "collection_basis",
        "confidence",
        "verification_status",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ValidationError(f"unsupported entity fields: {', '.join(sorted(unknown))}")
    if not payload:
        raise ValidationError("no entity fields were provided")
    with _connection(database) as connection:
        current = _entity_row(connection, entity_id)
        kind = (
            choice(payload["entity_type"], ENTITY_TYPES, "entity type")
            if "entity_type" in payload
            else current["entity_type"]
        )
        name = (
            clean_text(payload["name"], "name", max_length=300)
            if "name" in payload
            else current["name"]
        )
        raw_identifier = (
            clean_text(payload["identifier"], "identifier", max_length=2000)
            if "identifier" in payload
            else current["identifier"]
        )
        identifier = _normalize_identifier(kind, raw_identifier)
        if not name and not identifier:
            raise ValidationError("provide a name or an identifier")
        if not name:
            name = identifier
        description = (
            clean_text(payload["description"], "description", max_length=MAX_ENTITY_FIELDS)
            if "description" in payload
            else current["description"]
        )
        reference = (
            safe_reference(payload["source_reference"], "source reference")
            if "source_reference" in payload
            else current["source_reference"]
        )
        basis = (
            choice(payload["collection_basis"], COLLECTION_BASES, "collection basis")
            if "collection_basis" in payload
            else current["collection_basis"]
        )
        confidence = (
            choice(payload["confidence"], CONFIDENCE_LEVELS, "confidence")
            if "confidence" in payload
            else current["confidence"]
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
        if identifier:
            duplicate = connection.execute(
                """SELECT id FROM entities
                   WHERE entity_type = ? AND identifier = ? AND id <> ?""",
                (kind, identifier, entity_id),
            ).fetchone()
            if duplicate is not None:
                raise ConflictError("another entity already uses this identifier")
        try:
            connection.execute(
                """UPDATE entities
                   SET entity_type = ?, name = ?, identifier = ?, description = ?,
                       source_reference = ?, collection_basis = ?, confidence = ?,
                       verification_status = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    kind,
                    name,
                    identifier,
                    description,
                    reference,
                    basis,
                    confidence,
                    verification,
                    utc_now(),
                    entity_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "another entity already uses this type and identifier"
            ) from exc
        record_activity(
            connection,
            action="update",
            target_type="entity",
            target_id=entity_id,
            summary=f"Entity updated: {name}",
        )
    return get_entity(database, entity_id, include_relations=False)


def delete_entity(database: str, entity_id: str, *, force: bool = False) -> dict[str, Any]:
    with _connection(database) as connection:
        entity = _entity_row(connection, entity_id)
        relationship_count = connection.execute(
            """SELECT COUNT(*) FROM relationships
               WHERE source_entity_id = ? OR target_entity_id = ?""",
            (entity_id, entity_id),
        ).fetchone()[0]
        if relationship_count and not force:
            raise ConflictError(
                f"entity has {relationship_count} relationships; pass force=true to "
                "delete the entity and its relationship records"
            )
        if force:
            connection.execute(
                """DELETE FROM relationships
                   WHERE source_entity_id = ? OR target_entity_id = ?""",
                (entity_id, entity_id),
            )
        connection.execute("DELETE FROM entities WHERE id = ?", (entity_id,))
        record_activity(
            connection,
            action="delete",
            target_type="entity",
            target_id=entity_id,
            summary=f"Entity deleted: {entity['name']}",
        )
    return {
        "deleted": True,
        "entity_id": entity_id,
        "name": entity["name"],
        "removed_relationships": relationship_count if force else 0,
    }


def link_entity_to_investigation(
    database: str, investigation_id: str, entity_id: str
) -> dict[str, Any]:
    with _connection(database) as connection:
        investigation = connection.execute(
            "SELECT id, name FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        entity = _entity_row(connection, entity_id)
        cursor = connection.execute(
            """INSERT OR IGNORE INTO investigation_entities
               (investigation_id, entity_id, added_at) VALUES (?, ?, ?)""",
            (investigation_id, entity_id, utc_now()),
        )
        created = cursor.rowcount > 0
        if created:
            record_activity(
                connection,
                action="link",
                target_type="entity",
                target_id=entity_id,
                investigation_id=investigation_id,
                summary=f"Entity linked to investigation: {entity['name']}",
            )
    return {
        "linked": True,
        "already_linked": not created,
        "investigation_id": investigation_id,
        "entity_id": entity_id,
    }


def unlink_entity_from_investigation(
    database: str, investigation_id: str, entity_id: str
) -> dict[str, Any]:
    with _connection(database) as connection:
        cursor = connection.execute(
            """DELETE FROM investigation_entities
               WHERE investigation_id = ? AND entity_id = ?""",
            (investigation_id, entity_id),
        )
        if cursor.rowcount == 0:
            raise NotFoundError("entity is not linked to this investigation")
        record_activity(
            connection,
            action="unlink",
            target_type="entity",
            target_id=entity_id,
            investigation_id=investigation_id,
            summary="Entity unlinked from investigation",
        )
    return {"unlinked": True, "investigation_id": investigation_id, "entity_id": entity_id}


def _relationship_row(
    connection: sqlite3.Connection, relationship_id: str
) -> dict[str, Any]:
    row = connection.execute(
        """SELECT r.id, r.investigation_id, r.source_entity_id,
                  r.target_entity_id, r.relationship_type, r.description,
                  r.source_reference, r.confidence, r.verification_status,
                  r.created_at, r.updated_at,
                  source.name AS source_name, source.entity_type AS source_type,
                  target.name AS target_name, target.entity_type AS target_type
           FROM relationships r
           JOIN entities source ON source.id = r.source_entity_id
           JOIN entities target ON target.id = r.target_entity_id
           WHERE r.id = ?""",
        (relationship_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"relationship not found: {relationship_id}")
    return dict(row)


def create_relationship(
    database: str,
    *,
    source_entity_id: object,
    target_entity_id: object,
    relationship_type: object,
    description: object = "",
    source_reference: object = "",
    confidence: object = "unconfirmed",
    verification_status: object = "not-verified",
    investigation_id: object = None,
) -> dict[str, Any]:
    source_id = clean_text(source_entity_id, "source entity", max_length=100, required=True)
    target_id = clean_text(target_entity_id, "target entity", max_length=100, required=True)
    if source_id == target_id:
        raise ValidationError("a relationship requires two different entities")
    kind = choice(relationship_type, RELATIONSHIP_TYPES, "relationship type")
    description_text = clean_text(description, "description", max_length=5000)
    reference = safe_reference(source_reference, "source reference")
    confidence_value = choice(confidence, CONFIDENCE_LEVELS, "confidence")
    verification = choice(
        verification_status, VERIFICATION_STATUSES, "verification status"
    )
    context = (
        clean_text(investigation_id, "investigation id", max_length=100)
        if investigation_id
        else None
    )
    relationship_id = new_id()
    now = utc_now()
    with _connection(database) as connection:
        for entity_id, label in ((source_id, "source"), (target_id, "target")):
            if connection.execute(
                "SELECT 1 FROM entities WHERE id = ?", (entity_id,)
            ).fetchone() is None:
                raise NotFoundError(f"{label} entity not found: {entity_id}")
        if context:
            if connection.execute(
                "SELECT 1 FROM investigations WHERE id = ?", (context,)
            ).fetchone() is None:
                raise NotFoundError(f"investigation not found: {context}")
        try:
            connection.execute(
                """INSERT INTO relationships
                   (id, investigation_id, source_entity_id, target_entity_id,
                    relationship_type, description, source_reference, confidence,
                    verification_status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    relationship_id,
                    context,
                    source_id,
                    target_id,
                    kind,
                    description_text,
                    reference,
                    confidence_value,
                    verification,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "an identical relationship already exists for this investigation"
            ) from exc
        record_activity(
            connection,
            action="create",
            target_type="relationship",
            target_id=relationship_id,
            investigation_id=context,
            summary=f"Relationship recorded: {kind}",
        )
        result = _relationship_row(connection, relationship_id)
    return result


def list_relationships(
    database: str,
    *,
    investigation_id: str | None = None,
    entity_id: str | None = None,
    relationship_type: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    limit = max(1, min(1000, int(limit)))
    clauses: list[str] = []
    parameters: list[Any] = []
    if investigation_id:
        clauses.append("r.investigation_id = ?")
        parameters.append(investigation_id)
    if entity_id:
        clauses.append("(r.source_entity_id = ? OR r.target_entity_id = ?)")
        parameters.extend([entity_id, entity_id])
    if relationship_type:
        clauses.append("r.relationship_type = ?")
        parameters.append(
            choice(relationship_type, RELATIONSHIP_TYPES, "relationship type")
        )
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        rows = connection.execute(
            f"""SELECT r.id, r.investigation_id, r.source_entity_id,
                       r.target_entity_id, r.relationship_type, r.description,
                       r.source_reference, r.confidence, r.verification_status,
                       r.created_at, r.updated_at,
                       source.name AS source_name,
                       source.entity_type AS source_type,
                       target.name AS target_name,
                       target.entity_type AS target_type
                FROM relationships r
                JOIN entities source ON source.id = r.source_entity_id
                JOIN entities target ON target.id = r.target_entity_id
                {where}
                ORDER BY r.created_at DESC, r.id
                LIMIT ?""",
            [*parameters, limit],
        ).fetchall()
    return [dict(row) for row in rows]


def update_relationship(
    database: str, relationship_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    allowed = {
        "relationship_type",
        "description",
        "source_reference",
        "confidence",
        "verification_status",
        "investigation_id",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ValidationError(
            f"unsupported relationship fields: {', '.join(sorted(unknown))}"
        )
    if not payload:
        raise ValidationError("no relationship fields were provided")
    with _connection(database) as connection:
        current = _relationship_row(connection, relationship_id)
        kind = (
            choice(payload["relationship_type"], RELATIONSHIP_TYPES, "relationship type")
            if "relationship_type" in payload
            else current["relationship_type"]
        )
        description = (
            clean_text(payload["description"], "description", max_length=5000)
            if "description" in payload
            else current["description"]
        )
        reference = (
            safe_reference(payload["source_reference"], "source reference")
            if "source_reference" in payload
            else current["source_reference"]
        )
        confidence = (
            choice(payload["confidence"], CONFIDENCE_LEVELS, "confidence")
            if "confidence" in payload
            else current["confidence"]
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
        context = current["investigation_id"]
        if "investigation_id" in payload:
            context = (
                clean_text(
                    payload["investigation_id"],
                    "investigation id",
                    max_length=100,
                )
                if payload["investigation_id"]
                else None
            )
            if context and connection.execute(
                "SELECT 1 FROM investigations WHERE id = ?", (context,)
            ).fetchone() is None:
                raise NotFoundError(f"investigation not found: {context}")
        try:
            connection.execute(
                """UPDATE relationships
                   SET investigation_id = ?, relationship_type = ?,
                       description = ?, source_reference = ?, confidence = ?,
                       verification_status = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    context,
                    kind,
                    description,
                    reference,
                    confidence,
                    verification,
                    utc_now(),
                    relationship_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "an identical relationship already exists for this investigation"
            ) from exc
        record_activity(
            connection,
            action="update",
            target_type="relationship",
            target_id=relationship_id,
            investigation_id=context,
            summary=f"Relationship updated: {kind}",
        )
        return _relationship_row(connection, relationship_id)


def delete_relationship(database: str, relationship_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        current = _relationship_row(connection, relationship_id)
        connection.execute("DELETE FROM relationships WHERE id = ?", (relationship_id,))
        record_activity(
            connection,
            action="delete",
            target_type="relationship",
            target_id=relationship_id,
            investigation_id=current["investigation_id"],
            summary="Relationship deleted",
        )
    return {"deleted": True, "relationship_id": relationship_id}


def graph_payload(
    database: str,
    *,
    investigation_id: str | None = None,
    entity_type: str | None = None,
    search: str = "",
) -> dict[str, Any]:
    clauses: list[str] = []
    parameters: list[Any] = []
    if investigation_id:
        clauses.append(
            """e.id IN (
                SELECT entity_id FROM investigation_entities
                WHERE investigation_id = ?
            )"""
        )
        parameters.append(investigation_id)
    if entity_type:
        clauses.append("e.entity_type = ?")
        parameters.append(choice(entity_type, ENTITY_TYPES, "entity type"))
    if search.strip():
        clauses.append("(e.name LIKE ? ESCAPE '\\' OR e.identifier LIKE ? ESCAPE '\\')")
        pattern = search_pattern(search.strip())
        parameters.extend([pattern, pattern])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        if investigation_id:
            investigation = connection.execute(
                "SELECT id, name, status FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
            if investigation is None:
                raise NotFoundError(f"investigation not found: {investigation_id}")
            investigation_payload = dict(investigation)
        else:
            investigation = None
            investigation_payload = None
        nodes = [
            dict(row)
            for row in connection.execute(
                f"""SELECT e.id, e.entity_type, e.name, e.identifier,
                           e.description, e.verification_status, e.confidence
                    FROM entities e {where}
                    ORDER BY e.name, e.id
                    LIMIT 500""",
                parameters,
            )
        ]
        node_ids = {node["id"] for node in nodes}
        if node_ids:
            placeholders = ",".join("?" for _ in node_ids)
            edges = [
                dict(row)
                for row in connection.execute(
                    f"""SELECT r.id, r.source_entity_id, r.target_entity_id,
                               r.relationship_type, r.description,
                               r.verification_status, r.confidence,
                               r.investigation_id
                        FROM relationships r
                        WHERE r.source_entity_id IN ({placeholders})
                          AND r.target_entity_id IN ({placeholders})
                        ORDER BY r.created_at, r.id
                        LIMIT 1000""",
                    [*node_ids, *node_ids],
                )
            ]
        else:
            edges = []
    return {
        "investigation": investigation_payload,
        "nodes": nodes,
        "edges": edges,
        "metrics": native.graph_metrics(nodes, edges),
        "entity_types": entity_types(),
        "relationship_types": relationship_types(),
    }


def list_ioc_entities(database: str, limit: int = 500) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in IOC_ENTITY_TYPES)
    with _connection(database) as connection:
        rows = connection.execute(
            f"""SELECT id, entity_type, name, identifier, source_reference,
                       verification_status, created_at, updated_at
                FROM entities
                WHERE entity_type IN ({placeholders}) AND identifier <> ''
                ORDER BY updated_at DESC LIMIT ?""",
            [*IOC_ENTITY_TYPES, max(1, min(1000, int(limit)))],
        ).fetchall()
    return [dict(row) for row in rows]
