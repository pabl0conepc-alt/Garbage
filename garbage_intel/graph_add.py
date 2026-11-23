"""The search screen's "+" button: put a result on the graph.

The searched artifact and the chosen finding become entities joined by a
relationship. Values that are infrastructure (domain, IP, URL, e-mail, hash,
CVE, company) keep their type, so transforms work on them; anything else is
recorded as an "other" entity whose description keeps the label, hint and
sources the result box showed. Pressing "+" twice reuses what is there.
"""

from __future__ import annotations

from typing import Any

from .db import _connection
from .entities import (
    _normalize_identifier,
    create_entity,
    create_relationship,
    get_entity,
    link_entity_to_investigation,
)
from .errors import ConflictError, ValidationError
from .intel import detect_artifact, get_run
from .validation import clean_text

ENTITY_FOR = {
    "domain": "domain",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "url": "url",
    "email": "email",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "cve": "ioc",
    "cnpj": "organization",
}
TYPE_LABELS = {
    "asn": "ASN",
    "cidr": "Rede CIDR",
    "cpf": "CPF",
    "phone": "Telefone",
    "location": "Endereço",
}


def _typed(value: str) -> tuple[str, str]:
    """(entity type, identifier) for a value, or ("other", "")."""
    try:
        detected = detect_artifact(value)
    except ValidationError:
        return "other", ""
    kind = ENTITY_FOR.get(detected["type"])
    if not kind or kind == "organization":
        return "other", ""
    try:
        return kind, _normalize_identifier(kind, detected["value"])
    except ValidationError:
        return "other", ""


def _find(database: str, entity_type: str, identifier: str, name: str, description: str) -> str | None:
    with _connection(database) as connection:
        if identifier:
            row = connection.execute(
                "SELECT id FROM entities WHERE entity_type = ? AND identifier = ?", (entity_type, identifier)
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT id FROM entities WHERE entity_type = ? AND identifier = '' AND name = ? AND description = ?",
                (entity_type, name, description),
            ).fetchone()
    return row["id"] if row else None


def _ensure(database: str, *, entity_type: str, name: str, identifier: str, description: str) -> tuple[str, bool]:
    found = _find(database, entity_type, identifier, name, description)
    if found:
        return found, False
    entity = create_entity(
        database,
        entity_type=entity_type,
        name=name[:300],
        identifier=identifier,
        description=description,
        source_reference="note://pesquisa-multifonte",
        collection_basis="public",
    )
    return entity["id"], True


def _link_case(database: str, investigation_id: str | None, entity_id: str) -> None:
    if not investigation_id:
        return
    try:
        link_entity_to_investigation(database, investigation_id, entity_id)
    except ConflictError:
        pass


def _related(database: str, first: str, second: str) -> bool:
    with _connection(database) as connection:
        return (
            connection.execute(
                """SELECT 1 FROM relationships
                   WHERE (source_entity_id = ? AND target_entity_id = ?)
                      OR (source_entity_id = ? AND target_entity_id = ?)""",
                (first, second, second, first),
            ).fetchone()
            is not None
        )


def _text(item: dict[str, Any], key: str, limit: int = 500) -> str:
    value = item.get(key)
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(part) for part in value[:20])
    return clean_text(str(value), key, max_length=limit)


def add_to_graph(database: str, *, run_id: object, item: object = None, investigation_id: object = None) -> dict[str, Any]:
    if not isinstance(run_id, str) or not run_id:
        raise ValidationError("run_id is required")
    run = get_run(database, run_id)
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else run.get("investigation_id") or None
    dossier = run.get("dossier") or {}
    query_type, query_value = run["query_type"], run["query_value"]

    root_type = ENTITY_FOR.get(query_type, "other")
    if root_type == "organization":
        root_name = dossier.get("title") or query_value
    else:
        root_name = query_value
    root_id, root_created = _ensure(
        database,
        entity_type=root_type,
        name=root_name,
        identifier=query_value if root_type != "ioc" else query_value.upper(),
        description=TYPE_LABELS.get(query_type, "") if root_type == "other" else (dossier.get("subtitle") or "")[:2000],
    )
    _link_case(database, case_id, root_id)
    result: dict[str, Any] = {"root_id": root_id, "entity_id": root_id, "investigation_id": case_id, "created": root_created}
    if item is None:
        return result
    if not isinstance(item, dict):
        raise ValidationError("item must be an object")

    value = _text(item, "value", 300)
    if not value:
        raise ValidationError("item value is required")
    label = _text(item, "label", 120)
    section = _text(item, "section", 120)
    entity_type, identifier = _typed(_text(item, "pivot_value", 300) or value)
    lines = [
        label,
        _text(item, "hint", 500),
        _text(item, "meta", 200),
        f"Fontes: {_text(item, 'sources')}" if item.get("sources") else "",
        f"Seção: {section}" if section else "",
        f"Encontrado pesquisando {query_value}",
    ]
    description = "\n".join(line for line in lines if line)
    entity_id, created = _ensure(
        database,
        entity_type=entity_type,
        name=identifier or value,
        identifier=identifier,
        description=description if entity_type == "other" else "\n".join(lines[1:]).strip(),
    )
    _link_case(database, case_id, entity_id)
    if entity_id != root_id and not _related(database, root_id, entity_id):
        create_relationship(
            database,
            source_entity_id=root_id,
            target_entity_id=entity_id,
            relationship_type="related-to",
            description=section or label,
            investigation_id=case_id,
        )
    result.update(entity_id=entity_id, created=created, entity=get_entity(database, entity_id, include_relations=False))
    return result
