"""Graph import from GraphML or JSON (GARBAGE, Cytoscape, D3 or Gephi style).

The analyst brings a graph built elsewhere. Every node becomes an entity (or
reuses the existing entity with the same type and identifier) and every edge a
relationship, recorded as user-provided, unconfirmed and not verified, citing
the imported file by digest. A preview reports exactly what a commit would
do; nothing is written until the analyst confirms.

GraphML is parsed with ElementTree after rejecting any DTD, so entity
expansion and external entities never reach the parser.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ElementTree
from typing import Any

from .db import (
    ENTITY_TYPES,
    RELATIONSHIP_TYPES,
    _connection,
    new_id,
    record_activity,
    require_module,
    utc_now,
)
from .errors import NotFoundError, ValidationError
from .intel import detect_artifact

MAX_IMPORT_BYTES = 8 * 1024 * 1024
MAX_IMPORT_NODES = 2000
MAX_IMPORT_EDGES = 5000
MAX_REPORTED_PROBLEMS = 50

_GRAPHML_NS = "{http://graphml.graphdrawing.org/xmlns}"

# Types used by other tools, mapped onto the entity registry.
TYPE_SYNONYMS = {
    "ip": "ipv4",
    "ipaddress": "ipv4",
    "ipv4address": "ipv4",
    "ipv6address": "ipv6",
    "dnsname": "domain",
    "hostname": "domain",
    "website": "domain",
    "fqdn": "domain",
    "emailaddress": "email",
    "mail": "email",
    "company": "organization",
    "org": "organization",
    "as": "other",
    "asn": "other",
    "netblock": "other",
    "cidr": "other",
    "phrase": "other",
    "alias": "username",
    "account": "username",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "filehash": "hash",
    "document": "file",
    "indicator": "ioc",
    "cve": "other",
}
RELATIONSHIP_SYNONYMS = {
    "resolves-to": "hosted-on",
    "resolves": "hosted-on",
    "a-record": "hosted-on",
    "hosted": "hosted-on",
    "member-of": "belongs-to",
    "part-of": "belongs-to",
    "registered-by": "belongs-to",
    "links-to": "references",
    "redirects-to": "references",
    "mentions": "references",
    "contacts": "communicates-with",
    "talks-to": "communicates-with",
    "uses-nameserver": "uses",
    "mx": "uses",
    "ns": "uses",
    "owned-by": "belongs-to",
    "related": "related-to",
}
_ARTIFACT_ENTITY = {
    "domain": "domain",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "url": "url",
    "email": "email",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
}


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    text = text.rsplit(".", 1)[-1] if text.startswith("maltego.") else text
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def entity_type_for(raw_type: object, value: str) -> str:
    slug = _slug(raw_type).replace("-", "")
    if slug in ENTITY_TYPES:
        return slug
    if slug in TYPE_SYNONYMS:
        mapped = TYPE_SYNONYMS[slug]
        if mapped == "ipv4" and ":" in value:
            return "ipv6"
        return mapped
    if value:
        try:
            detected = detect_artifact(value)
        except ValidationError:
            return "other"
        return _ARTIFACT_ENTITY.get(detected["type"], "other")
    return "other"


def relationship_type_for(raw: object) -> str:
    slug = _slug(raw)
    if slug in RELATIONSHIP_TYPES:
        return slug
    return RELATIONSHIP_SYNONYMS.get(slug, "related-to")


def _first(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _node(raw_id: str, attributes: dict[str, Any]) -> dict[str, Any]:
    name = _first(attributes, "name", "label", "title", "value", "identifier") or raw_id
    identifier = _first(attributes, "identifier", "value")
    kind = entity_type_for(_first(attributes, "entity_type", "type", "kind", "category"), identifier or name)
    if not identifier and kind in _ARTIFACT_ENTITY.values():
        identifier = name
    return {
        "key": raw_id,
        "entity_type": kind,
        "name": name[:300],
        "identifier": identifier[:2000],
        "description": _first(attributes, "description", "notes")[:5000],
    }


def _edge(source: str, target: str, attributes: dict[str, Any]) -> dict[str, Any]:
    label = _first(attributes, "relationship_type", "type", "label", "relation", "name")
    kind = relationship_type_for(label)
    description = _first(attributes, "description")
    if label and _slug(label) != kind:
        description = (f"Imported relationship: {label}. " + description).strip()
    return {"source": source, "target": target, "relationship_type": kind, "description": description[:5000]}


def parse_graphml(text: str) -> dict[str, list[dict[str, Any]]]:
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise ValidationError("GraphML with a DTD or entities is not accepted")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValidationError(f"the GraphML file could not be parsed: {exc}") from exc
    keys: dict[str, str] = {}
    for key in root.iter(f"{_GRAPHML_NS}key"):
        keys[key.get("id", "")] = key.get("attr.name") or key.get("id", "")
    graph = root.find(f"{_GRAPHML_NS}graph")
    if graph is None:
        raise ValidationError("the GraphML file has no graph element")

    def data(element: Any) -> dict[str, str]:
        values = {}
        for item in element.findall(f"{_GRAPHML_NS}data"):
            name = keys.get(item.get("key", ""), item.get("key", ""))
            values[name.strip().lower().replace(" ", "_")] = "".join(item.itertext()).strip()
        return values

    nodes = [_node(node.get("id", ""), data(node)) for node in graph.iter(f"{_GRAPHML_NS}node")]
    edges = [
        _edge(edge.get("source", ""), edge.get("target", ""), data(edge))
        for edge in graph.iter(f"{_GRAPHML_NS}edge")
    ]
    return {"nodes": nodes, "edges": edges}


def parse_json(text: str) -> dict[str, list[dict[str, Any]]]:
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ValidationError("the JSON file could not be parsed") from exc
    if isinstance(payload, dict) and isinstance(payload.get("elements"), (dict, list)):
        elements = payload["elements"]  # Cytoscape
        if isinstance(elements, dict):
            raw_nodes, raw_edges = elements.get("nodes", []), elements.get("edges", [])
        else:
            raw_nodes = [item for item in elements if isinstance(item, dict) and "source" not in (item.get("data") or {})]
            raw_edges = [item for item in elements if isinstance(item, dict) and "source" in (item.get("data") or {})]
    elif isinstance(payload, dict):
        raw_nodes = payload.get("nodes", [])
        raw_edges = payload.get("edges", payload.get("links", []))
    else:
        raise ValidationError("the JSON file must be an object with nodes and edges")
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ValidationError("nodes and edges must be lists")

    def flat(item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise ValidationError("every node and edge must be an object")
        merged = dict(item.get("attributes") or {}) if isinstance(item.get("attributes"), dict) else {}
        merged.update({key: value for key, value in item.items() if key not in ("data", "attributes")})
        if isinstance(item.get("data"), dict):
            merged.update(item["data"])
        return merged

    nodes = []
    for item in raw_nodes:
        fields = flat(item)
        nodes.append(_node(_first(fields, "id", "key"), fields))
    edges = []
    for item in raw_edges:
        fields = flat(item)
        source = fields.get("source", fields.get("source_entity_id", ""))
        target = fields.get("target", fields.get("target_entity_id", ""))
        # D3 force graphs may already hold node objects here.
        source = source.get("id", "") if isinstance(source, dict) else source
        target = target.get("id", "") if isinstance(target, dict) else target
        edges.append(_edge(str(source), str(target), fields))
    return {"nodes": nodes, "edges": edges}


def parse_graph(content: object, file_format: object) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(content, str) or not content.strip():
        raise ValidationError("content must be the text of the graph file")
    if len(content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValidationError(f"graph files are limited to {MAX_IMPORT_BYTES // (1024 * 1024)} MiB")
    if file_format not in ("graphml", "json"):
        raise ValidationError("format must be graphml or json")
    parsed = parse_graphml(content) if file_format == "graphml" else parse_json(content)
    if not parsed["nodes"]:
        raise ValidationError("the graph has no nodes")
    if len(parsed["nodes"]) > MAX_IMPORT_NODES:
        raise ValidationError(f"at most {MAX_IMPORT_NODES} nodes can be imported at once")
    if len(parsed["edges"]) > MAX_IMPORT_EDGES:
        raise ValidationError(f"at most {MAX_IMPORT_EDGES} edges can be imported at once")
    return parsed


def import_graph(
    database: str,
    *,
    content: object,
    file_format: object,
    file_name: object = "",
    investigation_id: object = None,
    commit: bool = False,
) -> dict[str, Any]:
    """Preview (default) or commit the import of one graph file."""
    from .entities import _normalize_identifier

    parsed = parse_graph(content, file_format)
    digest = hashlib.sha256(str(content).encode("utf-8")).hexdigest()
    name = str(file_name or f"graph.{file_format}")[:200]
    reference = f"note://garbage/graph-import/{digest[:16]}"
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    problems: list[dict[str, str]] = []
    resolved: dict[str, dict[str, Any]] = {}
    planned: dict[tuple[str, str, str], dict[str, Any]] = {}
    counts = {"new_entities": 0, "existing_entities": 0, "invalid_nodes": 0, "new_relationships": 0, "existing_relationships": 0, "skipped_edges": 0}
    types: dict[str, int] = {}

    def problem(kind: str, key: str, reason: str) -> None:
        if len(problems) < MAX_REPORTED_PROBLEMS:
            problems.append({"kind": kind, "key": key, "reason": reason})

    with _connection(database) as connection:
        require_module(connection, "entities")
        require_module(connection, "relationships")
        if case_id and connection.execute("SELECT 1 FROM investigations WHERE id = ?", (case_id,)).fetchone() is None:
            raise NotFoundError(f"investigation not found: {case_id}")
        for node in parsed["nodes"]:
            if not node["key"] or node["key"] in resolved:
                counts["invalid_nodes"] += 1
                problem("node", node["key"], "missing or repeated node id")
                continue
            try:
                identifier = _normalize_identifier(node["entity_type"], node["identifier"])
            except ValidationError as exc:
                counts["invalid_nodes"] += 1
                problem("node", node["key"], str(exc))
                continue
            if identifier:
                row = connection.execute(
                    "SELECT id FROM entities WHERE entity_type = ? AND identifier = ?",
                    (node["entity_type"], identifier),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT id FROM entities WHERE entity_type = ? AND identifier = '' AND name = ?",
                    (node["entity_type"], node["name"]),
                ).fetchone()
            signature = (node["entity_type"], identifier, "" if identifier else node["name"])
            if row is not None:
                entity = {"id": row["id"], "new": False}
                counts["existing_entities"] += 1
            elif signature in planned:
                entity = planned[signature]
            else:
                entity = {"id": new_id(), "new": True, **node, "identifier": identifier}
                planned[signature] = entity
                counts["new_entities"] += 1
                types[node["entity_type"]] = types.get(node["entity_type"], 0) + 1
            resolved[node["key"]] = entity

        edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        seen: set[tuple[str, str, str]] = set()
        for edge in parsed["edges"]:
            source = resolved.get(edge["source"])
            target = resolved.get(edge["target"])
            if source is None or target is None:
                counts["skipped_edges"] += 1
                problem("edge", f"{edge['source']} → {edge['target']}", "an endpoint is missing or invalid")
                continue
            if source["id"] == target["id"]:
                counts["skipped_edges"] += 1
                problem("edge", f"{edge['source']} → {edge['target']}", "both ends are the same entity")
                continue
            key = (source["id"], target["id"], edge["relationship_type"])
            if key in seen:
                counts["skipped_edges"] += 1
                continue
            seen.add(key)
            existing = None
            if not source["new"] and not target["new"]:
                existing = connection.execute(
                    """SELECT 1 FROM relationships WHERE source_entity_id = ? AND target_entity_id = ?
                       AND relationship_type = ? AND COALESCE(investigation_id, '') = COALESCE(?, '')""",
                    (*key, case_id),
                ).fetchone()
            if existing is not None:
                counts["existing_relationships"] += 1
                continue
            edges[key] = edge
            counts["new_relationships"] += 1

        result = {
            "committed": False,
            "file_name": name,
            "sha256": digest,
            "format": file_format,
            "nodes": len(parsed["nodes"]),
            "edges": len(parsed["edges"]),
            "counts": counts,
            "new_by_type": types,
            "problems": problems,
            "investigation_id": case_id,
        }
        if not commit:
            return result

        now = utc_now()
        description = f"Imported from {name} (sha256 {digest[:16]})."
        connection.executemany(
            """INSERT INTO entities
               (id, entity_type, name, identifier, description, source_reference,
                collection_basis, confidence, verification_status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'user-provided', 'unconfirmed', 'not-verified', ?, ?)""",
            [
                (item["id"], item["entity_type"], item["name"], item["identifier"],
                 (item["description"] + "\n" + description).strip(), reference, now, now)
                for item in planned.values()
            ],
        )
        connection.executemany(
            """INSERT OR IGNORE INTO relationships
               (id, investigation_id, source_entity_id, target_entity_id, relationship_type,
                description, source_reference, confidence, verification_status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'unconfirmed', 'not-verified', ?, ?)""",
            [
                (new_id(), case_id, source, target, kind, (edge["description"] + " " + description).strip(), reference, now, now)
                for (source, target, kind), edge in edges.items()
            ],
        )
        if case_id:
            connection.executemany(
                "INSERT OR IGNORE INTO investigation_entities (investigation_id, entity_id, added_at) VALUES (?, ?, ?)",
                [(case_id, item["id"], now) for item in {entity["id"]: entity for entity in resolved.values()}.values()],
            )
        record_activity(
            connection,
            action="import",
            target_type="graph",
            target_id=digest[:16],
            investigation_id=case_id,
            summary=f"Graph imported: {name[:120]}, {counts['new_entities']} entities, {counts['new_relationships']} relationships",
        )
    result["committed"] = True
    return result
