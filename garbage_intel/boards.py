"""Persisted investigation board state.

The board stores only layout and presentation. Each entity element references
the shared entity registry, and any connection that represents a real link
references the shared relationship record so the graph, board and entity
manager cannot drift apart.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from typing import Any

from .db import (
    BOARD_ELEMENT_KINDS,
    BOARD_LAYERS,
    ENTITY_LAYER,
    RELATIONSHIP_TYPES,
    _connection,
    new_id,
    record_activity,
    utc_now,
)
from .errors import ConflictError, NotFoundError, ValidationError
from .validation import choice, clean_text


_IDENTIFIER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
DEFAULT_LAYERS = {layer: True for layer in BOARD_LAYERS}
MAX_ELEMENTS = 2000
MAX_CONNECTIONS = 4000
_LAYER_FOR_KIND = {"note": "notes", "text": "notes", "group": "groups"}


def _number(
    value: object,
    field: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValidationError(f"{field} must be finite")
    if not minimum <= number <= maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}")
    return number


def _existing_board(
    connection: sqlite3.Connection, investigation_id: str
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM boards WHERE investigation_id = ?", (investigation_id,)
    ).fetchone()


def _ensure_board(database: str, investigation_id: str, *, create: bool) -> sqlite3.Row:
    with _connection(database) as connection:
        investigation = connection.execute(
            "SELECT id, name FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if investigation is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        board = _existing_board(connection, investigation_id)
        if board is None and create:
            board_id = new_id()
            now = utc_now()
            connection.execute(
                """INSERT INTO boards
                   (id, investigation_id, name, viewport_x, viewport_y, zoom,
                    layers, revision, created_at, updated_at)
                   VALUES (?, ?, ?, 0, 0, 1, ?, 0, ?, ?)""",
                (
                    board_id,
                    investigation_id,
                    f"{investigation['name']} board",
                    json.dumps(DEFAULT_LAYERS),
                    now,
                    now,
                ),
            )
            board = _existing_board(connection, investigation_id)
        if board is None:
            raise NotFoundError("investigation board not found")
        return board


def _serialize_board(board: sqlite3.Row) -> dict[str, Any]:
    try:
        stored_layers = json.loads(board["layers"])
    except (TypeError, ValueError):
        stored_layers = {}
    layers = dict(DEFAULT_LAYERS)
    if isinstance(stored_layers, dict):
        for layer in BOARD_LAYERS:
            if isinstance(stored_layers.get(layer), bool):
                layers[layer] = stored_layers[layer]
    return {
        "id": board["id"],
        "investigation_id": board["investigation_id"],
        "name": board["name"],
        "viewport": {
            "x": board["viewport_x"],
            "y": board["viewport_y"],
            "zoom": board["zoom"],
        },
        "layers": layers,
        "revision": board["revision"],
        "created_at": board["created_at"],
        "updated_at": board["updated_at"],
    }


def get_board(database: str, investigation_id: str) -> dict[str, Any]:
    board = _ensure_board(database, investigation_id, create=True)
    with _connection(database) as connection:
        elements = [
            dict(row)
            for row in connection.execute(
                """SELECT be.id, be.board_id, be.element_kind, be.entity_id,
                          be.label, be.content, be.x, be.y, be.width, be.height,
                          be.layer, be.z_index, be.created_at, be.updated_at,
                          e.name AS entity_name,
                          e.entity_type AS entity_type,
                          e.identifier AS entity_identifier,
                          e.verification_status AS entity_verification
                   FROM board_elements be
                   LEFT JOIN entities e ON e.id = be.entity_id
                   WHERE be.board_id = ?
                   ORDER BY be.z_index, be.created_at, be.id""",
                (board["id"],),
            )
        ]
        connections = [
            dict(row)
            for row in connection.execute(
                """SELECT bc.id, bc.board_id, bc.source_element_id,
                          bc.target_element_id, bc.relationship_id, bc.label,
                          bc.connection_type, bc.created_at,
                          r.verification_status AS relationship_verification,
                          r.relationship_type AS relationship_type
                   FROM board_connections bc
                   LEFT JOIN relationships r ON r.id = bc.relationship_id
                   WHERE bc.board_id = ?
                   ORDER BY bc.created_at, bc.id""",
                (board["id"],),
            )
        ]
    payload = _serialize_board(board)
    payload["element_count"] = len(elements)
    payload["connection_count"] = len(connections)
    return {"board": payload, "elements": elements, "connections": connections}


def _validate_elements(
    connection: sqlite3.Connection, elements: object
) -> list[dict[str, Any]]:
    if not isinstance(elements, list):
        raise ValidationError("elements must be an array")
    if len(elements) > MAX_ELEMENTS:
        raise ValidationError(f"a board is limited to {MAX_ELEMENTS} elements")
    cleaned: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in elements:
        if not isinstance(item, dict):
            raise ValidationError("each element must be an object")
        identifier = item.get("id") or f"el-{new_id()}"
        if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
            raise ValidationError("element id must be 1-64 safe characters")
        if identifier in seen_ids:
            raise ValidationError(f"duplicate board element id: {identifier}")
        seen_ids.add(identifier)
        kind = choice(item.get("element_kind"), BOARD_ELEMENT_KINDS, "element kind")
        entity_id = item.get("entity_id")
        entity_row = None
        if kind == "entity":
            if not isinstance(entity_id, str) or not entity_id.strip():
                raise ValidationError("entity elements require an entity id")
            entity_row = connection.execute(
                """SELECT id, name, entity_type FROM entities WHERE id = ?""",
                (entity_id.strip(),),
            ).fetchone()
            if entity_row is None:
                raise NotFoundError(f"entity not found: {entity_id}")
            default_label = entity_row["name"]
            default_layer = ENTITY_LAYER.get(entity_row["entity_type"], "other")
        else:
            if entity_id:
                raise ValidationError("only entity elements may reference an entity")
            default_label = ""
            default_layer = _LAYER_FOR_KIND[kind]
        layer = item.get("layer") or default_layer
        if layer not in BOARD_LAYERS:
            raise ValidationError(f"unknown board layer: {layer}")
        cleaned.append(
            {
                "id": identifier,
                "element_kind": kind,
                "entity_id": entity_row["id"] if entity_row else None,
                "label": clean_text(
                    item.get("label", default_label),
                    "element label",
                    max_length=300,
                    default=default_label,
                ),
                "content": clean_text(
                    item.get("content"),
                    "element content",
                    max_length=5000,
                ),
                "x": _number(
                    item.get("x"), "element x", default=0, minimum=-1e6, maximum=1e6
                ),
                "y": _number(
                    item.get("y"), "element y", default=0, minimum=-1e6, maximum=1e6
                ),
                "width": _number(
                    item.get("width"),
                    "element width",
                    default=220,
                    minimum=80,
                    maximum=1200,
                ),
                "height": _number(
                    item.get("height"),
                    "element height",
                    default=120,
                    minimum=60,
                    maximum=800,
                ),
                "layer": layer,
                "z_index": int(
                    _number(
                        item.get("z_index"),
                        "element z-index",
                        default=0,
                        minimum=0,
                        maximum=10000,
                    )
                ),
            }
        )
    return cleaned


def _validate_connections(
    connection: sqlite3.Connection,
    connections: object,
    elements: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(connections, list):
        raise ValidationError("connections must be an array")
    if len(connections) > MAX_CONNECTIONS:
        raise ValidationError(
            f"a board is limited to {MAX_CONNECTIONS} connections"
        )
    by_id = {element["id"]: element for element in elements}
    cleaned: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str, str, str]] = set()
    seen_relationships: set[str] = set()
    for item in connections:
        if not isinstance(item, dict):
            raise ValidationError("each connection must be an object")
        identifier = item.get("id") or f"cn-{new_id()}"
        if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
            raise ValidationError("connection id must be 1-64 safe characters")
        if identifier in seen_ids:
            raise ValidationError(f"duplicate board connection id: {identifier}")
        seen_ids.add(identifier)
        source = item.get("source_element_id")
        target = item.get("target_element_id")
        if source not in by_id or target not in by_id:
            raise ValidationError("connections must reference board elements")
        if source == target:
            raise ValidationError("a connection requires two different elements")
        connection_type = choice(
            item.get("connection_type") or "connected-to",
            RELATIONSHIP_TYPES,
            "connection type",
        )
        label = clean_text(item.get("label"), "connection label", max_length=300)
        relationship_id = item.get("relationship_id") or None
        if relationship_id is not None:
            if not isinstance(relationship_id, str):
                raise ValidationError("relationship id must be a string")
            relationship = connection.execute(
                """SELECT id, source_entity_id, target_entity_id
                   FROM relationships WHERE id = ?""",
                (relationship_id,),
            ).fetchone()
            if relationship is None:
                raise NotFoundError(f"relationship not found: {relationship_id}")
            if relationship_id in seen_relationships:
                raise ValidationError(
                    "a relationship can only be represented once on a board"
                )
            source_entity = by_id[source]["entity_id"]
            target_entity = by_id[target]["entity_id"]
            if {source_entity, target_entity} != {
                relationship["source_entity_id"],
                relationship["target_entity_id"],
            }:
                raise ValidationError(
                    "the connection must join the entities of the referenced "
                    "relationship"
                )
            seen_relationships.add(relationship_id)
        pair = (source, target, connection_type, label)
        reverse = (target, source, connection_type, label)
        if pair in seen_pairs or reverse in seen_pairs:
            raise ValidationError("duplicate board connection")
        seen_pairs.add(pair)
        cleaned.append(
            {
                "id": identifier,
                "source_element_id": source,
                "target_element_id": target,
                "relationship_id": relationship_id,
                "label": label,
                "connection_type": connection_type,
            }
        )
    return cleaned


def save_board(database: str, investigation_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("board state must be an object")
    board = _ensure_board(database, investigation_id, create=True)
    revision = payload.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise ValidationError("revision must be an integer")
    if revision != board["revision"]:
        raise ConflictError(
            f"board revision conflict: expected {board['revision']} but received "
            f"{revision}; reload the board and retry"
        )
    if "elements" not in payload or "connections" not in payload:
        raise ValidationError("board state requires elements and connections")
    viewport = payload.get("viewport") or {}
    if not isinstance(viewport, dict):
        raise ValidationError("viewport must be an object")
    viewport_x = _number(
        viewport.get("x"), "viewport x", default=board["viewport_x"], minimum=-1e6, maximum=1e6
    )
    viewport_y = _number(
        viewport.get("y"), "viewport y", default=board["viewport_y"], minimum=-1e6, maximum=1e6
    )
    zoom = _number(
        viewport.get("zoom"), "zoom", default=board["zoom"], minimum=0.2, maximum=3
    )
    layers = payload.get("layers", {})
    if not isinstance(layers, dict):
        raise ValidationError("layers must be an object")
    unknown_layers = set(layers) - set(BOARD_LAYERS)
    if unknown_layers:
        raise ValidationError(
            f"unknown board layers: {', '.join(sorted(unknown_layers))}"
        )
    for key, value in layers.items():
        if not isinstance(value, bool):
            raise ValidationError(f"layer {key} must be a boolean")
    clean_layers = dict(DEFAULT_LAYERS)
    clean_layers.update(layers)
    name = (
        clean_text(payload["name"], "board name", max_length=200)
        if "name" in payload
        else board["name"]
    )
    if not name:
        raise ValidationError("board name must not be empty")

    with _connection(database) as connection:
        elements = _validate_elements(connection, payload["elements"])
        connections = _validate_connections(
            connection, payload["connections"], elements
        )
        existing = {
            row["id"]: row["created_at"]
            for row in connection.execute(
                "SELECT id, created_at FROM board_elements WHERE board_id = ?",
                (board["id"],),
            )
        }
        now = utc_now()
        structure_changed = (
            len(elements) != len(existing)
            or name != board["name"]
            or any(element["id"] not in existing for element in elements)
        )
        connection.execute(
            "DELETE FROM board_connections WHERE board_id = ?", (board["id"],)
        )
        connection.execute(
            "DELETE FROM board_elements WHERE board_id = ?", (board["id"],)
        )
        try:
            connection.executemany(
                """INSERT INTO board_elements
                   (id, board_id, element_kind, entity_id, label, content, x, y,
                    width, height, layer, z_index, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        element["id"],
                        board["id"],
                        element["element_kind"],
                        element["entity_id"],
                        element["label"],
                        element["content"],
                        element["x"],
                        element["y"],
                        element["width"],
                        element["height"],
                        element["layer"],
                        element["z_index"],
                        existing.get(element["id"], now),
                        now,
                    )
                    for element in elements
                ],
            )
            connection.executemany(
                """INSERT INTO board_connections
                   (id, board_id, source_element_id, target_element_id,
                    relationship_id, label, connection_type, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        connection_row["id"],
                        board["id"],
                        connection_row["source_element_id"],
                        connection_row["target_element_id"],
                        connection_row["relationship_id"],
                        connection_row["label"],
                        connection_row["connection_type"],
                        now,
                    )
                    for connection_row in connections
                ],
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("board state violates a stored reference") from exc
        connection.execute(
            """UPDATE boards
               SET name = ?, viewport_x = ?, viewport_y = ?, zoom = ?,
                   layers = ?, revision = revision + 1, updated_at = ?
               WHERE id = ?""",
            (
                name,
                viewport_x,
                viewport_y,
                zoom,
                json.dumps(clean_layers),
                now,
                board["id"],
            ),
        )
        if structure_changed:
            record_activity(
                connection,
                action="board",
                target_type="board",
                target_id=board["id"],
                investigation_id=investigation_id,
                summary="Investigation board layout saved",
            )
    return get_board(database, investigation_id)
