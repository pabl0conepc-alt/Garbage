"""Automatic infrastructure pivot from a graph node.

From a domain it asks DNS for its addresses, mail and name servers; from an
IP it asks for the reverse name, the routing AS and the names that pointed
to it recently (passive DNS). Each answer becomes an entity linked to the
node it came from, and with depth 2 the new domains and IPs are expanded
once more. Fan-out per node and the total of new nodes are capped so a CDN
address does not flood the graph.

Only passive sources are used (public resolvers, routing data, passive DNS);
the node's own servers are never contacted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .entities import _normalize_identifier, create_relationship, get_entity
from .errors import ValidationError
from .graph_add import _ensure, _link_case, _related
from .intel import run_query

DOMAIN_SOURCES = ["dns-doh"]
IP_SOURCES = ["cymru-asn", "ipinfo", "mnemonic-pdns"]
MAX_FANOUT = 8
MAX_NEW = 40
RECENT_DAYS = 365


def _value(entity: dict[str, Any]) -> str:
    return (entity.get("identifier") or entity.get("name") or "").strip().lower().rstrip(".")


def _neighbours(database: str, kind: str, value: str, case_id: str | None) -> list[tuple[str, str, str, str]]:
    """(entity type, value, relationship type, why) found for one node."""
    sources = DOMAIN_SOURCES if kind == "domain" else IP_SOURCES
    run = run_query(database, value=value, connector_ids=sources, investigation_id=case_id, wait=True)
    found: list[tuple[str, str, str, str]] = []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)).strftime("%Y-%m-%d")
    for result in run.get("results") or []:
        if result.get("status") not in ("ok", None):
            continue
        result_type = result["result_type"]
        raw = str(result.get("value") or "").strip().rstrip(".")
        data = result.get("data") or {}
        if result_type == "dns-a":
            found.append(("ipv4", raw, "hosted-on", "DNS A"))
        elif result_type == "dns-aaaa":
            found.append(("ipv6", raw, "hosted-on", "DNS AAAA"))
        elif result_type == "dns-cname":
            found.append(("domain", raw, "references", "DNS CNAME"))
        elif result_type == "dns-mx" and not data.get("null_mx"):
            found.append(("domain", raw.split()[-1].rstrip("."), "uses", "servidor de e-mail (MX)"))
        elif result_type == "dns-ns":
            found.append(("domain", raw, "uses", "servidor de nomes (NS)"))
        elif result_type == "asn":
            found.append(("other", raw.upper(), "belongs-to", "sistema autônomo que anuncia o IP"))
        elif result_type == "hostname":
            found.append(("domain", raw.lower(), "associated-with", "nome reverso"))
        elif result_type == "pdns-name" and str(data.get("last_seen") or "") >= cutoff:
            found.append(("domain", raw.lower(), "associated-with", f"DNS passivo até {data.get('last_seen')}"))
    unique: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    for item in found:
        if item[1] and item[1] != value:
            unique.setdefault((item[0], item[1]), item)
    return list(unique.values())


def expand(database: str, *, entity_id: object, depth: object = 1, investigation_id: object = None) -> dict[str, Any]:
    if not isinstance(entity_id, str) or not entity_id:
        raise ValidationError("entity_id is required")
    if depth not in (1, 2):
        raise ValidationError("depth must be 1 or 2")
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    start = get_entity(database, entity_id, include_relations=False)
    if start["entity_type"] not in ("domain", "ipv4", "ipv6"):
        raise ValidationError("the automatic pivot starts from a domain or an IP")
    _link_case(database, case_id, start["id"])
    frontier = [(start["id"], start["entity_type"], _value(start))]
    seen = {start["id"]}
    created: list[str] = []
    reused: list[str] = []
    links = 0
    skipped = 0
    for level in range(depth):
        next_frontier = []
        for node_id, kind, value in frontier:
            for entity_type, neighbour, relationship, why in _neighbours(database, kind, value, case_id)[:MAX_FANOUT]:
                if len(created) >= MAX_NEW:
                    skipped += 1
                    continue
                try:
                    identifier = _normalize_identifier(entity_type, neighbour) if entity_type != "other" else neighbour
                except ValidationError:
                    continue
                target_id, is_new = _ensure(
                    database,
                    entity_type=entity_type,
                    name=identifier,
                    identifier=identifier,
                    description="Sistema autônomo" if entity_type == "other" else "",
                )
                (created if is_new else reused).append(target_id)
                _link_case(database, case_id, target_id)
                if target_id != node_id and not _related(database, node_id, target_id):
                    create_relationship(
                        database,
                        source_entity_id=node_id,
                        target_entity_id=target_id,
                        relationship_type=relationship,
                        description=f"Pivô automático: {why}",
                        investigation_id=case_id,
                    )
                    links += 1
                if target_id not in seen and entity_type in ("domain", "ipv4", "ipv6"):
                    seen.add(target_id)
                    next_frontier.append((target_id, entity_type, identifier))
        frontier = next_frontier
    return {
        "entity_id": start["id"],
        "created": len(set(created)),
        "reused": len(set(reused)),
        "relationships": links,
        "skipped": skipped,
        "new_ids": sorted(set(created)),
    }
