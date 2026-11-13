"""Investigation export in CTI exchange formats (plan phase 8): STIX 2.1
bundles, MISP events and a CSV of indicators.

Exports carry what the case records, with its uncertainty: verification
status and confidence travel in descriptions and comments, indicators are
typed "unknown" rather than "malicious", and MISP's to_ids flag is set only
for verified records. Entities about people (person, username, profile) are
left out by default; the export says so.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .db import _connection
from .errors import ValidationError
from .store import build_report

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # STIX 2.1 section 2.9
GARBAGE_NAMESPACE = uuid.UUID("6d1c2f43-7d1e-5f9a-9e53-3f0a52f1c7a1")
# Standard TLP 1.0 marking definitions from the STIX 2.1 specification.
TLP = {
    "white": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "2017-01-20T00:00:00.000Z"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "2017-01-20T00:00:00.000Z"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "2017-01-20T00:00:00.000Z"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "2017-01-20T00:00:00.000Z"),
}
PERSONAL_TYPES = {"person", "username", "profile"}
_HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _stix_time(value: str | None) -> str:
    if not value:
        value = datetime.now(timezone.utc).isoformat()
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        moment = datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _sco_id(kind: str, contributing: dict[str, Any]) -> str:
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, canonical)}"


def _sdo_id(kind: str, key: str) -> str:
    """Stable across exports (so re-imports deduplicate) but shaped as the
    UUIDv4 the specification recommends for domain and relationship objects."""
    digest = uuid.uuid5(GARBAGE_NAMESPACE, f"{kind}:{key}")
    return f"{kind}--{uuid.UUID(bytes=digest.bytes, version=4)}"


def _escape_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _hash_name(value: str) -> str | None:
    return _HASH_NAMES.get(len(value)) if re.fullmatch(r"[0-9a-fA-F]+", value or "") else None


def _observable(entity_type: str, value: str) -> tuple[dict[str, Any], str] | None:
    """STIX cyber-observable for an entity, plus its indicator pattern."""
    value = (value or "").strip()
    if not value:
        return None
    if entity_type == "domain":
        sco = {"type": "domain-name", "value": value.lower()}
        return sco, f"[domain-name:value = '{_escape_pattern(sco['value'])}']"
    if entity_type in ("ipv4", "ipv6"):
        kind = f"{entity_type}-addr"
        return {"type": kind, "value": value}, f"[{kind}:value = '{_escape_pattern(value)}']"
    if entity_type == "url":
        return {"type": "url", "value": value}, f"[url:value = '{_escape_pattern(value)}']"
    if entity_type == "email":
        return {"type": "email-addr", "value": value.lower()}, f"[email-addr:value = '{_escape_pattern(value.lower())}']"
    if entity_type in ("hash", "file") and _hash_name(value):
        algorithm = _hash_name(value)
        return {"type": "file", "hashes": {algorithm: value.lower()}}, f"[file:hashes.'{algorithm}' = '{value.lower()}']"
    return None


def _case_extras(database: str, investigation_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with _connection(database) as connection:
        files = [dict(row) for row in connection.execute(
            "SELECT id, file_name, format, sha256, tlsh, ssdeep, analysis_json, created_at FROM file_analyses WHERE investigation_id = ?",
            (investigation_id,),
        )]
        try:
            techniques = [dict(row) for row in connection.execute(
                """SELECT c.technique_id, c.note, c.created_at, t.name, t.url FROM case_techniques c
                   LEFT JOIN attack_techniques t ON t.id = c.technique_id WHERE c.investigation_id = ?""",
                (investigation_id,),
            )]
        except Exception:  # noqa: BLE001 - ATT&CK tables are optional
            techniques = []
    return files, techniques


def build_stix(database: str, investigation_id: str, *, tlp: str = "amber", include_personal: bool = False) -> dict[str, Any]:
    if tlp not in TLP:
        raise ValidationError("tlp must be white, green, amber or red")
    report = build_report(database, investigation_id)
    files, techniques = _case_extras(database, investigation_id)
    case = report["investigation"]
    now = _stix_time(None)
    marking_id, marking_created = TLP[tlp]
    identity_id = _sdo_id("identity", "garbage-workstation")
    common = {"spec_version": "2.1", "created_by_ref": identity_id, "object_marking_refs": [marking_id]}
    objects: dict[str, dict[str, Any]] = {}
    entity_refs: dict[str, str] = {}
    skipped: list[str] = []

    def add(item: dict[str, Any]) -> str:
        objects.setdefault(item["id"], item)
        return item["id"]

    add({"type": "marking-definition", "spec_version": "2.1", "id": marking_id, "created": marking_created, "definition_type": "tlp", "name": f"TLP:{tlp.upper()}", "definition": {"tlp": tlp}})
    add({"type": "identity", "spec_version": "2.1", "id": identity_id, "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z", "name": "GARBAGE workstation export", "identity_class": "system"})

    for entity in report["entities"]:
        kind = entity["entity_type"]
        if kind in PERSONAL_TYPES and not include_personal:
            skipped.append(kind)
            continue
        created = _stix_time(entity.get("created_at"))
        description = f"Verification: {entity.get('verification_status')}; confidence: {entity.get('confidence')}."
        found = _observable(kind, entity.get("identifier") or entity.get("name"))
        if found:
            sco, pattern = found
            contributing = {key: value for key, value in sco.items() if key != "type"}
            sco_id = _sco_id(sco["type"], contributing)
            add({**sco, "spec_version": "2.1", "id": sco_id, "object_marking_refs": [marking_id]})
            entity_refs[entity["id"]] = sco_id
            indicator_id = _sdo_id("indicator", f"{investigation_id}:{sco_id}")
            add({
                **common, "type": "indicator", "id": indicator_id, "created": created, "modified": created,
                "name": entity.get("name") or entity.get("identifier"), "description": description,
                "indicator_types": ["unknown"], "pattern": pattern, "pattern_type": "stix", "valid_from": created,
            })
            add({
                **common, "type": "relationship", "id": _sdo_id("relationship", f"{indicator_id}:based-on:{sco_id}"),
                "created": created, "modified": created, "relationship_type": "based-on", "source_ref": indicator_id, "target_ref": sco_id,
            })
        elif kind == "organization":
            org_id = _sdo_id("identity", f"org:{entity['id']}")
            add({**common, "type": "identity", "id": org_id, "created": created, "modified": created, "name": entity.get("name") or entity.get("identifier"), "identity_class": "organization", "description": description})
            entity_refs[entity["id"]] = org_id
        else:
            skipped.append(kind)

    for relationship in report["relationships"]:
        source = entity_refs.get(relationship["source_entity_id"])
        target = entity_refs.get(relationship["target_entity_id"])
        if not source or not target:
            continue
        created = _stix_time(relationship.get("created_at"))
        add({
            **common, "type": "relationship", "id": _sdo_id("relationship", relationship["id"]), "created": created, "modified": created,
            "relationship_type": relationship["relationship_type"], "source_ref": source, "target_ref": target,
            "description": f"Analyst-recorded association. Verification: {relationship.get('verification_status')}; confidence: {relationship.get('confidence')}. "
            + (relationship.get("description") or ""),
        })

    for analysis in files:
        hashes = {"SHA-256": analysis["sha256"]}
        try:
            payload = json.loads(analysis["analysis_json"])
            hashes.update({"MD5": payload["hashes"]["md5"], "SHA-1": payload["hashes"]["sha1"]})
        except (ValueError, KeyError, TypeError):
            pass
        if analysis.get("tlsh"):
            hashes["TLSH"] = analysis["tlsh"][2:] if analysis["tlsh"].startswith("T1") else analysis["tlsh"]
        if analysis.get("ssdeep"):
            hashes["SSDEEP"] = analysis["ssdeep"]
        file_id = _sco_id("file", {"hashes": hashes, "name": analysis["file_name"]})
        add({"type": "file", "spec_version": "2.1", "id": file_id, "name": analysis["file_name"], "hashes": hashes, "object_marking_refs": [marking_id]})

    for technique in techniques:
        created = _stix_time(technique.get("created_at"))
        pattern_id = _sdo_id("attack-pattern", technique["technique_id"])
        add({
            **common, "type": "attack-pattern", "id": pattern_id, "created": created, "modified": created,
            "name": technique.get("name") or technique["technique_id"], "description": technique.get("note") or "Linked by the analyst to this investigation.",
            "external_references": [{"source_name": "mitre-attack", "external_id": technique["technique_id"], **({"url": technique["url"]} if technique.get("url") else {})}],
        })

    report_id = _sdo_id("report", investigation_id)
    content_refs = [item_id for item_id, item in objects.items() if item["type"] not in ("marking-definition",) and item_id != identity_id]
    for observation in report["observations"]:
        created = _stix_time(observation.get("recorded_at"))
        add({
            **common, "type": "note", "id": _sdo_id("note", observation["id"]), "created": created, "modified": created,
            "abstract": observation.get("title") or "Observation", "content": observation.get("content") or "",
            "object_refs": [report_id],
        })
    note_refs = [item_id for item_id, item in objects.items() if item["type"] == "note"]
    add({
        **common, "type": "report", "id": report_id, "created": _stix_time(case.get("created_at")), "modified": now,
        "name": case["name"], "description": (case.get("description") or "")
        + " Exported from GARBAGE. Associations are analyst assessments with their recorded verification status, not attribution.",
        "report_types": ["threat-report"], "published": now, "object_refs": (content_refs + note_refs) or [identity_id],
    })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects.values())}
    return {"bundle": bundle, "skipped": sorted(set(skipped)), "tlp": tlp}


# ---------------------------------------------------------------------------
# MISP

_MISP_TYPES = {
    "domain": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email", "Payload delivery"),
}


def build_misp(database: str, investigation_id: str, *, tlp: str = "amber", include_personal: bool = False) -> dict[str, Any]:
    if tlp not in TLP:
        raise ValidationError("tlp must be white, green, amber or red")
    report = build_report(database, investigation_id)
    files, techniques = _case_extras(database, investigation_id)
    case = report["investigation"]
    attributes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def attribute(kind: str, category: str, value: str, comment: str, verified: bool) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        attributes.append({
            "uuid": str(uuid.uuid5(GARBAGE_NAMESPACE, f"misp:{investigation_id}:{kind}:{value}")),
            "type": kind, "category": category, "value": value, "to_ids": verified, "comment": comment[:250],
            "distribution": "5",
        })

    for entity in report["entities"]:
        kind = entity["entity_type"]
        if kind in PERSONAL_TYPES and not include_personal:
            continue
        value = (entity.get("identifier") or entity.get("name") or "").strip()
        comment = f"verification: {entity.get('verification_status')}; confidence: {entity.get('confidence')}"
        verified = entity.get("verification_status") == "verified"
        if kind in _MISP_TYPES:
            misp_type, category = _MISP_TYPES[kind]
            attribute(misp_type, category, value.lower() if kind in ("domain", "email") else value, comment, verified)
        elif kind in ("hash", "file") and _hash_name(value):
            attribute(_hash_name(value).lower().replace("-", ""), "Payload delivery", value.lower(), comment, verified)
        elif kind == "organization":
            attribute("text", "Other", value, f"organization; {comment}", False)
    for analysis in files:
        attribute("filename|sha256", "Payload delivery", f"{analysis['file_name']}|{analysis['sha256']}", "file analysed statically in GARBAGE", False)
        if analysis.get("ssdeep"):
            attribute("ssdeep", "Payload delivery", analysis["ssdeep"], f"similarity digest of {analysis['file_name']}", False)
        if analysis.get("tlsh"):
            attribute("tlsh", "Payload delivery", analysis["tlsh"], f"similarity digest of {analysis['file_name']}", False)
    tags = [{"name": f"tlp:{tlp}"}]
    for technique in techniques:
        if technique.get("name"):
            tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{technique["name"]} - {technique["technique_id"]}"'})
    return {
        "Event": {
            "uuid": str(uuid.uuid5(GARBAGE_NAMESPACE, f"misp-event:{investigation_id}")),
            "info": case["name"],
            "date": (case.get("created_at") or datetime.now(timezone.utc).isoformat())[:10],
            "threat_level_id": "4",
            "analysis": "2" if case.get("status") == "closed" else "1",
            "distribution": "0",
            "published": False,
            "Tag": tags,
            "Attribute": attributes,
        }
    }


# ---------------------------------------------------------------------------
# CSV of indicators

def _cell(value: Any) -> str:
    text = str(value if value is not None else "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def build_ioc_csv(database: str, investigation_id: str, *, include_personal: bool = False) -> str:
    report = build_report(database, investigation_id)
    files, _ = _case_extras(database, investigation_id)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "origin", "verification", "confidence", "recorded_at", "context"])
    seen: set[tuple[str, str]] = set()

    def row(kind: str, value: str, origin: str, verification: str, confidence: str, recorded: str, context: str) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        writer.writerow([_cell(item) for item in (kind, value, origin, verification, confidence, recorded, context)])

    for entity in report["entities"]:
        if entity["entity_type"] in PERSONAL_TYPES and not include_personal:
            continue
        if entity["entity_type"] in ("domain", "ipv4", "ipv6", "url", "email", "hash", "file"):
            row(entity["entity_type"], entity.get("identifier") or entity.get("name"), "entity", entity.get("verification_status", ""), entity.get("confidence", ""), entity.get("created_at", ""), entity.get("name", ""))
    for indicator in report["indicators"]:
        row(indicator["type"], indicator["value"], "observation", indicator.get("verification_status", ""), "", indicator.get("recorded_at", ""), (indicator.get("context") or "")[:200])
    for analysis in files:
        row("sha256", analysis["sha256"], "file-analysis", "", "", analysis.get("created_at", ""), analysis["file_name"])
    return buffer.getvalue()
