"""Transforms: one entity in, connector query, new linked entities out.

A transform is a connector seen from the graph. It declares which entity
types it takes, which result types it can turn into new entities and with
which relationship, and it runs through the same orchestrator as the
multi-source search (gates, cache, rate limits, provenance). Every run is
logged per transform with its parameters, the source outcome, the entities it
created or reused and how long it took, so each entity keeps an enrichment
history.

Person, username and profile entities are never transform inputs: the
platform does not collect data about people automatically.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .db import _connection, new_id, record_activity, require_module, utc_now
from .errors import NotFoundError, ValidationError
from .intel import (
    PROMOTABLE_TYPES,
    connectors,
    detect_artifact,
    list_connectors,
    promote_results,
    run_query,
)

PERSONAL_TYPES = frozenset({"person", "username", "profile"})
MAX_HISTORY = 100

# Result types each connector can turn into entities. Connectors not listed
# only enrich: their findings stay in the run and the entity's history.
TRANSFORM_OUTPUTS: dict[str, tuple[str, ...]] = {
    "dns-doh": ("dns-a", "dns-aaaa", "dns-cname", "dns-mx", "dns-ns"),
    "cymru-asn": ("asn", "as-name"),
    "rdap": ("nameserver", "organization", "abuse-contact", "cidr"),
    "crtsh": ("ct-name",),
    "wayback": ("archive-capture",),
    "shodan-internetdb": ("hostname",),
    "ripestat": ("origin-asn", "as-holder", "announced-prefix", "abuse-contact"),
    "peeringdb": ("network-operator",),
    "ipinfo": ("network-owner", "hostname"),
    "certspotter": ("subdomain",),
    "virustotal": ("network-owner", "final-url"),
    "shodan": ("hostname",),
    "urlhaus": ("malicious-url",),
    "tls-certificate": ("cert-san",),
    "web-fingerprint": ("http-redirect",),
    "local-workspace": ("lookalike",),
    "github": ("website", "repository", "repo-homepage", "fork-of"),
    "security-txt": ("security-contact-email", "security-contact-url", "security-policy"),
    "typosquat": ("typosquat",),
}

# Relationship recorded from the input entity to each new entity.
RELATIONSHIP_FOR_RESULT: dict[str, str] = {
    "dns-a": "hosted-on",
    "dns-aaaa": "hosted-on",
    "dns-cname": "references",
    "dns-mx": "uses",
    "dns-ns": "uses",
    "nameserver": "uses",
    "asn": "belongs-to",
    "origin-asn": "belongs-to",
    "as-name": "belongs-to",
    "as-holder": "belongs-to",
    "network-owner": "belongs-to",
    "network-operator": "belongs-to",
    "organization": "belongs-to",
    "cidr": "belongs-to",
    "announced-prefix": "belongs-to",
    "abuse-contact": "associated-with",
    "archive-capture": "references",
    "http-redirect": "references",
    "final-url": "references",
    "malicious-url": "related-to",
    "ct-name": "related-to",
    "cert-san": "related-to",
    "subdomain": "related-to",
    "hostname": "related-to",
    "lookalike": "related-to",
    "website": "references",
    "repository": "owns",
    "repo-homepage": "references",
    "fork-of": "derived-from",
    "security-contact-email": "associated-with",
    "security-contact-url": "associated-with",
    "security-policy": "references",
    "typosquat": "related-to",
}

PARAMETERS = (
    {"key": "use_cache", "type": "boolean", "default": True},
    {"key": "promote", "type": "boolean", "default": True},
    {"key": "max_new_entities", "type": "integer", "default": 25, "minimum": 1, "maximum": 50},
)


def entity_artifact(entity: dict[str, Any]) -> dict[str, str]:
    """The artifact a transform queries for this entity."""
    kind = entity["entity_type"]
    if kind in PERSONAL_TYPES:
        raise ValidationError(
            "transforms do not run on people, usernames or profiles"
        )
    raw = (entity.get("identifier") or "").strip()
    if not raw and kind not in {"organization", "file", "image"}:
        raw = (entity.get("name") or "").strip()
    if not raw:
        raise ValidationError("the entity has no identifier a transform can query")
    try:
        detected = detect_artifact(raw)
    except ValidationError as exc:
        raise ValidationError(
            "the entity's identifier is not a domain, IP, CIDR, URL, email, hash, ASN or CVE"
        ) from exc
    expected = {
        "domain": {"domain"},
        "ipv4": {"ipv4"},
        "ipv6": {"ipv6"},
        "email": {"email"},
        "url": {"url"},
        "hash": {"md5", "sha1", "sha256"},
        "file": {"md5", "sha1", "sha256"},
        "image": {"md5", "sha1", "sha256"},
    }.get(kind)
    if expected is not None and detected["type"] not in expected:
        raise ValidationError(
            f"the identifier was read as {detected['type']}, which does not match the entity type {kind}"
        )
    return {"type": detected["type"], "value": detected["value"]}


def _estimates(connection: Any) -> dict[str, dict[str, int]]:
    """Mean and count of real (uncached) source durations per connector."""
    rows = connection.execute(
        """SELECT connector_id, AVG(elapsed_ms) AS mean_ms, COUNT(*) AS samples
           FROM (SELECT run_id, connector_id, MAX(elapsed_ms) AS elapsed_ms
                 FROM intel_results
                 WHERE cached = 0 AND status IN ('ok', 'empty')
                 GROUP BY run_id, connector_id)
           GROUP BY connector_id"""
    ).fetchall()
    return {
        row["connector_id"]: {"mean_ms": int(row["mean_ms"] or 0), "samples": row["samples"]}
        for row in rows
    }


def _describe(connector: Any, availability: dict[str, Any], estimate: dict[str, int] | None) -> dict[str, Any]:
    outputs = TRANSFORM_OUTPUTS.get(connector.connector_id, ())
    return {
        "transform_id": connector.connector_id,
        "name": connector.name,
        "description": connector.description,
        "kind": "pivot" if outputs else "enrichment",
        "inputs": list(connector.accepts),
        "outputs": [
            {
                "result_type": result_type,
                "entity_type": PROMOTABLE_TYPES.get(result_type, "other"),
                "relationship_type": RELATIONSHIP_FOR_RESULT.get(result_type, "related-to"),
            }
            for result_type in outputs
        ],
        "network": connector.network,
        "contacts_target": connector.contacts_target,
        "requires_key": connector.requires_key,
        "availability": availability.get("availability", "ready"),
        "rate_per_minute": connector.rate_per_minute,
        "ttl_seconds": connector.ttl_seconds,
        "estimate_ms": estimate["mean_ms"] if estimate else None,
        "estimate_samples": estimate["samples"] if estimate else 0,
        "source_url": connector.source_url,
    }


def list_transforms(database: str, *, entity_id: str | None = None) -> dict[str, Any]:
    """Every transform, or the ones that accept this entity."""
    from .entities import get_entity

    artifact = None
    reason = ""
    if entity_id:
        entity = get_entity(database, entity_id, include_relations=False)
        try:
            artifact = entity_artifact(entity)
        except ValidationError as exc:
            reason = str(exc)
    with _connection(database) as connection:
        require_module(connection, "transforms")
        estimates = _estimates(connection)
    availability = {item["connector_id"]: item for item in list_connectors(database)["items"]}
    items = [
        _describe(connector, availability.get(connector.connector_id, {}), estimates.get(connector.connector_id))
        for connector in connectors()
        if artifact is None or artifact["type"] in connector.accepts
    ]
    if entity_id and artifact is None:
        items = []
    return {
        "artifact": artifact,
        "unsupported_reason": reason,
        "parameters": list(PARAMETERS),
        "items": items,
        "total": len(items),
    }


def _parameters(raw: object) -> dict[str, Any]:
    if raw in (None, ""):
        raw = {}
    if not isinstance(raw, dict):
        raise ValidationError("parameters must be an object")
    known = {item["key"]: item for item in PARAMETERS}
    unknown = set(raw) - set(known)
    if unknown:
        raise ValidationError(f"unknown transform parameters: {', '.join(sorted(unknown))}")
    values: dict[str, Any] = {}
    for key, spec in known.items():
        value = raw.get(key, spec["default"])
        if spec["type"] == "boolean":
            if not isinstance(value, bool):
                raise ValidationError(f"{key} must be a boolean")
        else:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValidationError(f"{key} must be an integer")
            if not spec["minimum"] <= value <= spec["maximum"]:
                raise ValidationError(f"{key} must be between {spec['minimum']} and {spec['maximum']}")
        values[key] = value
    return values


def run_transforms(
    database: str,
    *,
    entity_id: object,
    transform_ids: object,
    investigation_id: object = None,
    parameters: object = None,
) -> dict[str, Any]:
    """Run the selected transforms on one entity and log each of them."""
    from .entities import get_entity

    if not isinstance(entity_id, str) or not entity_id:
        raise ValidationError("entity_id is required")
    if not isinstance(transform_ids, list) or not transform_ids or not all(
        isinstance(item, str) for item in transform_ids
    ):
        raise ValidationError("transforms must be a non-empty list of transform ids")
    if len(set(transform_ids)) > 30:
        raise ValidationError("at most 30 transforms run at once")
    options = _parameters(parameters)
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    with _connection(database) as connection:
        require_module(connection, "transforms")
    entity = get_entity(database, entity_id, include_relations=False)
    artifact = entity_artifact(entity)
    registry = {item.connector_id: item for item in connectors()}
    unknown = set(transform_ids) - set(registry)
    if unknown:
        raise ValidationError(f"unknown transforms: {', '.join(sorted(unknown))}")
    selected = sorted(set(transform_ids))
    incompatible = [item for item in selected if artifact["type"] not in registry[item].accepts]
    if incompatible:
        raise ValidationError(
            f"transforms that do not accept {artifact['type']}: {', '.join(incompatible)}"
        )

    started_at = utc_now()
    clock = time.monotonic()
    run = run_query(
        database,
        value=artifact["value"],
        query_type=artifact["type"],
        connector_ids=selected,
        investigation_id=case_id,
        use_cache=options["use_cache"],
    )
    query_ms = int((time.monotonic() - clock) * 1000)
    sources = {item["connector_id"]: item for item in run["sources"]}
    by_connector: dict[str, list[dict[str, Any]]] = {}
    for result in run["results"]:
        by_connector.setdefault(result["connector_id"], []).append(result)

    budget = options["max_new_entities"]
    logs: list[dict[str, Any]] = []
    for transform_id in selected:
        source = sources.get(transform_id, {"status": "unsupported", "cached": False, "error": "", "elapsed_ms": 0, "count": 0})
        events: list[dict[str, Any]] = [
            {"event": "input", "type": artifact["type"], "value": artifact["value"], "at": started_at},
            {
                "event": "source",
                "status": source["status"],
                "cached": source["cached"],
                "count": source["count"],
                "elapsed_ms": source["elapsed_ms"],
                "error": source["error"],
            },
        ]
        outputs = set(TRANSFORM_OUTPUTS.get(transform_id, ()))
        candidates = [
            result
            for result in by_connector.get(transform_id, [])
            if result["result_type"] in outputs and result["value"]
        ]
        promotion = {"created_entities": [], "reused_entities": [], "relationships": [], "skipped": []}
        clock = time.monotonic()
        if options["promote"] and candidates:
            chosen = candidates[:budget]
            if len(candidates) > len(chosen):
                events.append({"event": "limit", "kept": len(chosen), "found": len(candidates)})
            if chosen:
                promotion = promote_results(
                    database,
                    run["id"],
                    source_entity_id=entity_id,
                    investigation_id=case_id,
                    items=[
                        {
                            "result_id": result["id"],
                            "entity_type": PROMOTABLE_TYPES.get(result["result_type"], "other"),
                            "relationship_type": RELATIONSHIP_FOR_RESULT.get(result["result_type"], "related-to"),
                        }
                        for result in chosen
                    ],
                )
                budget -= len(chosen)
        elif candidates:
            events.append({"event": "not-promoted", "count": len(candidates)})
        if options["promote"] and candidates:
            events.append(
                {
                    "event": "promoted",
                    "created": len(promotion["created_entities"]),
                    "reused": len(promotion["reused_entities"]),
                    "relationships": len(promotion["relationships"]),
                    "skipped": len(promotion["skipped"]),
                }
            )
        duration = source["elapsed_ms"] + int((time.monotonic() - clock) * 1000)
        record = {
            "id": new_id(),
            "transform_id": transform_id,
            "entity_id": entity_id,
            "investigation_id": case_id,
            "intel_run_id": run["id"],
            "status": source["status"],
            "result_count": source["count"],
            "created_count": len(promotion["created_entities"]),
            "reused_count": len(promotion["reused_entities"]),
            "relationship_count": len(promotion["relationships"]),
            "parameters": options,
            "log": events,
            "duration_ms": duration,
            "started_at": started_at,
            "finished_at": utc_now(),
            "created_entities": [
                {"id": item["id"], "entity_type": item["entity_type"], "name": item["name"]}
                for item in promotion["created_entities"]
            ],
        }
        logs.append(record)

    with _connection(database) as connection:
        for record in logs:
            connection.execute(
                """INSERT INTO transform_runs
                   (id, transform_id, entity_id, investigation_id, intel_run_id, status,
                    result_count, created_count, reused_count, relationship_count,
                    parameters_json, log_json, duration_ms, started_at, finished_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"],
                    record["transform_id"],
                    record["entity_id"],
                    record["investigation_id"],
                    record["intel_run_id"],
                    record["status"],
                    record["result_count"],
                    record["created_count"],
                    record["reused_count"],
                    record["relationship_count"],
                    json.dumps(record["parameters"], sort_keys=True),
                    json.dumps(record["log"], sort_keys=True),
                    record["duration_ms"],
                    record["started_at"],
                    record["finished_at"],
                ),
            )
        record_activity(
            connection,
            action="transform",
            target_type="entity",
            target_id=entity_id,
            investigation_id=case_id,
            summary=(
                f"Transforms on {artifact['type']} {artifact['value'][:120]}: "
                f"{len(logs)} run, {sum(item['created_count'] for item in logs)} new entities"
            ),
        )
    return {
        "entity_id": entity_id,
        "artifact": artifact,
        "intel_run_id": run["id"],
        "parameters": options,
        "query_ms": query_ms,
        "items": logs,
        "created_count": sum(item["created_count"] for item in logs),
        "relationship_count": sum(item["relationship_count"] for item in logs),
    }


def entity_history(database: str, entity_id: str, *, limit: int = 50) -> dict[str, Any]:
    """Enrichment history of one entity, newest first."""
    limit = max(1, min(int(limit), MAX_HISTORY))
    with _connection(database) as connection:
        require_module(connection, "transforms")
        if connection.execute("SELECT 1 FROM entities WHERE id = ?", (entity_id,)).fetchone() is None:
            raise NotFoundError(f"entity not found: {entity_id}")
        rows = connection.execute(
            """SELECT * FROM transform_runs WHERE entity_id = ?
               ORDER BY started_at DESC, transform_id LIMIT ?""",
            (entity_id, limit),
        ).fetchall()
        total = connection.execute(
            "SELECT COUNT(*) FROM transform_runs WHERE entity_id = ?", (entity_id,)
        ).fetchone()[0]
    items = []
    for row in rows:
        item = dict(row)
        item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
        item["log"] = json.loads(item.pop("log_json") or "[]")
        items.append(item)
    return {"items": items, "total": total}

