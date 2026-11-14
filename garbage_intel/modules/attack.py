"""Offline MITRE ATT&CK (plan phase 8).

An explicit refresh downloads the official Enterprise ATT&CK STIX bundle from
mitre-attack/attack-stix-data and keeps a compact copy in the workspace:
tactics, techniques, groups, software, mitigations and the "uses" and
"mitigates" relationships between them. Nothing is fetched implicitly.

Analysts link techniques to an investigation by hand, or accept suggestions
derived from file-analysis findings and from technique IDs that intelligence
sources (OTX) returned in the case's runs. A suggestion states its reason; it
is a lead for the analyst, not an attribution of behaviour.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from .. import net
from ..db import _connection, new_id, record_activity, utc_now
from ..errors import ConflictError, NotFoundError, ValidationError
from ..net import FetchResult, NetworkError
from ..validation import clean_text

FETCH: Callable[..., FetchResult] = net.fetch
INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
HOSTS = ("raw.githubusercontent.com",)
MAX_BUNDLE_BYTES = 96 * 1024 * 1024
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_GROUP_ID = re.compile(r"^G\d{4}$")
_SOFTWARE_ID = re.compile(r"^S\d{4}$")

# Static file findings -> techniques they are consistent with.
FINDING_TECHNIQUES: dict[str, tuple[tuple[str, str], ...]] = {
    "vba-macros": (("T1059.005", "VBA macro code is present"),),
    "vba-autoexec": (("T1204.002", "macros run automatically when the document is opened"),),
    "pdf-active-content": (("T1204.002", "the PDF declares JavaScript or a launch action"),),
    "lnk-command": (("T1204.002", "a shortcut launches a script host or downloader"), ("T1059", "the shortcut invokes a command interpreter")),
    "lnk-padded-arguments": (("T1027", "shortcut arguments are hidden behind whitespace"),),
    "iso-executable-content": (("T1553.005", "executables are delivered inside a disc image"),),
    "rtf-equation-editor": (("T1203", "an Equation Editor object is embedded"),),
    "rtf-remote-template": (("T1221", "the document references a remote template"),),
    "rtf-dde": (("T1559.002", "a DDE field is present"),),
    "rtf-package": (("T1204.002", "a packaged file is embedded in the document"),),
    "msi-custom-actions": (("T1218.007", "the installer declares custom actions"),),
    "embedded-executable": (("T1027.009", "executable headers are embedded in another file"),),
    "high-entropy": (("T1027.002", "high entropy is consistent with packing"),),
}
# VBA keyword categories -> techniques.
KEYWORD_TECHNIQUES: dict[str, tuple[str, str]] = {
    "scripting": ("T1059.001", "macro source mentions PowerShell or another interpreter"),
    "network": ("T1105", "macro source can download content"),
    "obfuscation": ("T1027", "macro source uses obfuscation helpers"),
    "native": ("T1106", "macro source declares native API calls"),
    "process": ("T1059", "macro source starts processes"),
}


class AttackError(ValueError):
    """The ATT&CK bundle could not be fetched or parsed."""


def _external_id(item: dict[str, Any]) -> tuple[str, str]:
    for reference in item.get("external_references") or []:
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"]), str(reference.get("url") or "")
    return "", ""


def _summary(text: Any, limit: int = 700) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", str(text or ""))
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    first = text.strip().split("\n\n", 1)[0]
    return first[:limit].strip()


def parse_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Reduce a STIX bundle to the tables the workspace keeps."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise AttackError("not a STIX bundle")
    by_stix: dict[str, str] = {}
    tactics, techniques, objects, relations = [], [], [], []
    version = ""
    # The matrix object lists tactics in the official left-to-right order.
    order: dict[str, int] = {}
    for item in bundle.get("objects") or []:
        if isinstance(item, dict) and item.get("type") == "x-mitre-matrix" and not item.get("revoked"):
            order = {ref: position for position, ref in enumerate(item.get("tactic_refs") or [])}
            break
    for item in bundle.get("objects") or []:
        if not isinstance(item, dict) or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        kind = item.get("type")
        if kind == "x-mitre-collection":
            version = str(item.get("x_mitre_version") or version)
            continue
        external, url = _external_id(item)
        if not external:
            continue
        by_stix[item.get("id", "")] = external
        if kind == "x-mitre-tactic":
            tactics.append(
                {
                    "id": external,
                    "shortname": item.get("x_mitre_shortname", ""),
                    "name": item.get("name", ""),
                    "description": _summary(item.get("description"), 400),
                    "url": url,
                    "position": order.get(item.get("id", ""), 100 + len(tactics)),
                }
            )
        elif kind == "attack-pattern":
            phases = [phase.get("phase_name", "") for phase in item.get("kill_chain_phases") or [] if phase.get("kill_chain_name") == "mitre-attack"]
            techniques.append(
                {
                    "id": external,
                    "name": item.get("name", ""),
                    "tactics": ",".join(phases),
                    "platforms": ",".join(item.get("x_mitre_platforms") or []),
                    "is_subtechnique": 1 if item.get("x_mitre_is_subtechnique") else 0,
                    "description": _summary(item.get("description")),
                    "detection": _summary(item.get("x_mitre_detection"), 500),
                    "url": url,
                }
            )
        elif kind in ("intrusion-set", "malware", "tool", "course-of-action"):
            objects.append(
                {
                    "id": external,
                    "kind": {"intrusion-set": "group", "malware": "software", "tool": "software", "course-of-action": "mitigation"}[kind],
                    "name": item.get("name", ""),
                    "aliases": ",".join(alias for alias in (item.get("aliases") or item.get("x_mitre_aliases") or []) if alias != item.get("name"))[:500],
                    "description": _summary(item.get("description"), 500),
                    "url": url,
                }
            )
    for item in bundle.get("objects") or []:
        if not isinstance(item, dict) or item.get("type") != "relationship" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        if item.get("relationship_type") not in ("uses", "mitigates"):
            continue
        source = by_stix.get(item.get("source_ref", ""))
        target = by_stix.get(item.get("target_ref", ""))
        # Relations to techniques, plus which software a group uses (actor profiles).
        if source and target and (_TECHNIQUE_ID.match(target) or (_GROUP_ID.match(source) and _SOFTWARE_ID.match(target))):
            relations.append({"source_id": source, "target_id": target, "kind": item["relationship_type"]})
    if not techniques or not tactics:
        raise AttackError("the bundle has no techniques or tactics")
    unique_relations = {(item["source_id"], item["target_id"], item["kind"]): item for item in relations}
    return {"version": version, "tactics": tactics, "techniques": techniques, "objects": objects, "relations": list(unique_relations.values())}


def store(database: str, parsed: dict[str, Any], *, source_url: str, sha256: str) -> dict[str, Any]:
    with _connection(database) as connection:
        for table in ("attack_relations", "attack_objects", "attack_techniques", "attack_tactics"):
            connection.execute(f"DELETE FROM {table}")
        connection.executemany(
            "INSERT INTO attack_tactics (id, shortname, name, description, url, position) VALUES (:id, :shortname, :name, :description, :url, :position)",
            parsed["tactics"],
        )
        connection.executemany(
            """INSERT INTO attack_techniques (id, name, tactics, platforms, is_subtechnique, description, detection, url)
               VALUES (:id, :name, :tactics, :platforms, :is_subtechnique, :description, :detection, :url)""",
            parsed["techniques"],
        )
        connection.executemany(
            "INSERT OR REPLACE INTO attack_objects (id, kind, name, aliases, description, url) VALUES (:id, :kind, :name, :aliases, :description, :url)",
            parsed["objects"],
        )
        connection.executemany(
            "INSERT INTO attack_relations (source_id, target_id, kind) VALUES (:source_id, :target_id, :kind)",
            parsed["relations"],
        )
        connection.execute("DELETE FROM attack_meta")
        connection.execute(
            "INSERT INTO attack_meta (domain, version, source_url, sha256, fetched_at) VALUES ('enterprise', ?, ?, ?, ?)",
            (parsed["version"], source_url, sha256, utc_now()),
        )
        record_activity(
            connection, action="refresh", target_type="attack", target_id="enterprise", investigation_id=None,
            summary=f"MITRE ATT&CK refreshed: version {parsed['version']}, {len(parsed['techniques'])} techniques",
        )
    return status(database)


def refresh(database: str) -> dict[str, Any]:
    try:
        index_result = FETCH(INDEX_URL, allowed_hosts=HOSTS, max_bytes=2 * 1024 * 1024, timeout=30)
        index = json.loads(index_result.body.decode("utf-8"))
        collection = next(item for item in index.get("collections", []) if item.get("name") == "Enterprise ATT&CK")
        latest = collection["versions"][0]["url"]
    except (NetworkError, ValueError, StopIteration, KeyError, IndexError) as exc:
        raise AttackError(f"could not read the ATT&CK index: {exc}") from exc
    if not str(latest).startswith("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"):
        raise AttackError("the ATT&CK index points outside mitre-attack/attack-stix-data")
    try:
        result = FETCH(latest, allowed_hosts=HOSTS, max_bytes=MAX_BUNDLE_BYTES, timeout=180)
    except NetworkError as exc:
        raise AttackError(f"could not download the ATT&CK bundle: {exc}") from exc
    if result.status != 200:
        raise AttackError(f"the ATT&CK bundle answered HTTP {result.status}")
    try:
        bundle = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttackError("the ATT&CK bundle is not valid JSON") from exc
    return store(database, parse_bundle(bundle), source_url=latest, sha256=result.sha256)


def status(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        meta = connection.execute("SELECT * FROM attack_meta").fetchone()
        counts = {
            "tactics": connection.execute("SELECT COUNT(*) FROM attack_tactics").fetchone()[0],
            "techniques": connection.execute("SELECT COUNT(*) FROM attack_techniques WHERE is_subtechnique = 0").fetchone()[0],
            "subtechniques": connection.execute("SELECT COUNT(*) FROM attack_techniques WHERE is_subtechnique = 1").fetchone()[0],
            "groups": connection.execute("SELECT COUNT(*) FROM attack_objects WHERE kind = 'group'").fetchone()[0],
            "software": connection.execute("SELECT COUNT(*) FROM attack_objects WHERE kind = 'software'").fetchone()[0],
            "mitigations": connection.execute("SELECT COUNT(*) FROM attack_objects WHERE kind = 'mitigation'").fetchone()[0],
        }
    return {"loaded": meta is not None, **(dict(meta) if meta else {}), "counts": counts}


def _require_loaded(connection: Any) -> None:
    if connection.execute("SELECT 1 FROM attack_meta").fetchone() is None:
        raise NotFoundError("ATT&CK has not been downloaded yet; refresh it first")


def matrix(database: str, *, investigation_id: str | None = None) -> dict[str, Any]:
    with _connection(database) as connection:
        _require_loaded(connection)
        tactics = {row["shortname"]: dict(row) for row in connection.execute("SELECT * FROM attack_tactics ORDER BY position, name")}
        techniques = [dict(row) for row in connection.execute("SELECT id, name, tactics, is_subtechnique, platforms FROM attack_techniques ORDER BY name")]
        linked: dict[str, int] = {}
        if investigation_id:
            for row in connection.execute(
                "SELECT technique_id, COUNT(*) AS count FROM case_techniques WHERE investigation_id = ? GROUP BY technique_id",
                (investigation_id,),
            ):
                linked[row["technique_id"]] = row["count"]
        usage = {row["target_id"]: row["count"] for row in connection.execute(
            "SELECT target_id, COUNT(*) AS count FROM attack_relations WHERE kind = 'uses' GROUP BY target_id"
        )}
    subtechniques: dict[str, list[dict[str, Any]]] = {}
    for item in techniques:
        if item["is_subtechnique"]:
            subtechniques.setdefault(item["id"].split(".")[0], []).append(item)
    columns = []
    for shortname in tactics:
        cells = []
        for item in techniques:
            if item["is_subtechnique"] or shortname not in item["tactics"].split(","):
                continue
            subs = sorted(subtechniques.get(item["id"], []), key=lambda sub: sub["id"])
            sub_linked = sum(1 for sub in subs if sub["id"] in linked)
            cells.append(
                {
                    "id": item["id"],
                    "name": item["name"],
                    "linked": item["id"] in linked,
                    "linked_subtechniques": sub_linked,
                    "subtechniques": [{"id": sub["id"], "name": sub["name"], "linked": sub["id"] in linked} for sub in subs],
                    "used_by": usage.get(item["id"], 0),
                }
            )
        columns.append({**tactics[shortname], "techniques": cells})
    return {"tactics": columns, "linked_count": len(linked), "investigation_id": investigation_id}


def technique(database: str, technique_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        _require_loaded(connection)
        row = connection.execute("SELECT * FROM attack_techniques WHERE id = ?", (technique_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"technique not found: {technique_id}")
        related = [
            dict(item)
            for item in connection.execute(
                """SELECT o.id, o.kind, o.name, o.aliases, o.url, r.kind AS relation
                   FROM attack_relations r JOIN attack_objects o ON o.id = r.source_id
                   WHERE r.target_id = ? ORDER BY o.kind, o.name""",
                (technique_id,),
            )
        ]
        cases = [
            dict(item)
            for item in connection.execute(
                """SELECT c.investigation_id, i.name AS investigation_name, c.note, c.source, c.created_at
                   FROM case_techniques c JOIN investigations i ON i.id = c.investigation_id
                   WHERE c.technique_id = ? ORDER BY c.created_at DESC""",
                (technique_id,),
            )
        ]
        parent = technique_id.split(".")[0]
        family = [dict(item) for item in connection.execute(
            "SELECT id, name FROM attack_techniques WHERE id = ? OR id LIKE ? ORDER BY id", (parent, f"{parent}.%")
        )]
    return {
        **dict(row),
        "tactics": [item for item in row["tactics"].split(",") if item],
        "platforms": [item for item in row["platforms"].split(",") if item],
        "groups": [item for item in related if item["kind"] == "group"],
        "software": [item for item in related if item["kind"] == "software"],
        "mitigations": [item for item in related if item["kind"] == "mitigation"],
        "family": family,
        "cases": cases,
    }


def search(database: str, query: str, limit: int = 30) -> dict[str, Any]:
    text = clean_text(query, "query", max_length=100) or ""
    if not text:
        return {"items": []}
    pattern = f"%{text}%"
    with _connection(database) as connection:
        _require_loaded(connection)
        rows = connection.execute(
            """SELECT id, name, 'technique' AS kind FROM attack_techniques WHERE id LIKE ? OR name LIKE ?
               UNION ALL
               SELECT id, name, kind FROM attack_objects WHERE id LIKE ? OR name LIKE ? OR aliases LIKE ?
               LIMIT ?""",
            (f"{text.upper()}%", pattern, f"{text.upper()}%", pattern, pattern, max(1, min(100, limit))),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


def link(database: str, investigation_id: str, technique_id: Any, *, note: Any = "", source: str = "analyst") -> dict[str, Any]:
    if not isinstance(technique_id, str) or not _TECHNIQUE_ID.match(technique_id):
        raise ValidationError("technique_id must look like T1059 or T1059.001")
    clean_note = clean_text(note or "", "note", max_length=1000) or ""
    with _connection(database) as connection:
        _require_loaded(connection)
        if connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        row = connection.execute("SELECT name FROM attack_techniques WHERE id = ?", (technique_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"technique not found: {technique_id}")
        if connection.execute(
            "SELECT 1 FROM case_techniques WHERE investigation_id = ? AND technique_id = ?", (investigation_id, technique_id)
        ).fetchone():
            raise ConflictError(f"{technique_id} is already linked to this investigation")
        connection.execute(
            "INSERT INTO case_techniques (id, investigation_id, technique_id, note, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (new_id(), investigation_id, technique_id, clean_note, source[:40], utc_now()),
        )
        record_activity(
            connection, action="link", target_type="attack-technique", target_id=technique_id, investigation_id=investigation_id,
            summary=f"ATT&CK technique linked: {technique_id} {row['name']}",
        )
    return case_techniques(database, investigation_id)


def unlink(database: str, investigation_id: str, technique_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        removed = connection.execute(
            "DELETE FROM case_techniques WHERE investigation_id = ? AND technique_id = ?", (investigation_id, technique_id)
        ).rowcount
        if removed:
            record_activity(
                connection, action="delete", target_type="attack-technique", target_id=technique_id, investigation_id=investigation_id,
                summary=f"ATT&CK technique unlinked: {technique_id}",
            )
    return case_techniques(database, investigation_id)


def case_techniques(database: str, investigation_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        rows = connection.execute(
            """SELECT c.technique_id AS id, t.name, t.tactics, c.note, c.source, c.created_at
               FROM case_techniques c LEFT JOIN attack_techniques t ON t.id = c.technique_id
               WHERE c.investigation_id = ? ORDER BY c.technique_id""",
            (investigation_id,),
        ).fetchall()
    return {"investigation_id": investigation_id, "items": [dict(row) for row in rows]}


def suggestions(database: str, investigation_id: str) -> dict[str, Any]:
    """Techniques consistent with the case's file findings and source results."""
    found: dict[str, dict[str, Any]] = {}

    def add(technique_id: str, reason: str, origin: str) -> None:
        entry = found.setdefault(technique_id, {"id": technique_id, "reasons": [], "origins": set()})
        if reason not in entry["reasons"] and len(entry["reasons"]) < 6:
            entry["reasons"].append(reason)
        entry["origins"].add(origin)

    with _connection(database) as connection:
        _require_loaded(connection)
        for row in connection.execute(
            "SELECT file_name, analysis_json FROM file_analyses WHERE investigation_id = ?", (investigation_id,)
        ):
            try:
                analysis = json.loads(row["analysis_json"])
            except ValueError:
                continue
            for finding in analysis.get("findings") or []:
                for technique_id, reason in FINDING_TECHNIQUES.get(finding.get("code"), ()):
                    add(technique_id, f"{row['file_name']}: {reason}", "file-analysis")
            projects = (analysis.get("structure") or {}).get("vba") or ((analysis.get("structure") or {}).get("compound") or {}).get("vba") or []
            for project in projects:
                for module in project.get("modules") or []:
                    for category in module.get("suspicious") or {}:
                        if category in KEYWORD_TECHNIQUES:
                            technique_id, reason = KEYWORD_TECHNIQUES[category]
                            add(technique_id, f"{row['file_name']}: {reason}", "file-analysis")
        for row in connection.execute(
            """SELECT DISTINCT r.value, r.connector_id, ru.query_value FROM intel_results r
               JOIN intel_runs ru ON ru.id = r.run_id
               WHERE ru.investigation_id = ? AND r.result_type = 'attack-technique'""",
            (investigation_id,),
        ):
            if _TECHNIQUE_ID.match(row["value"]):
                add(row["value"], f"{row['connector_id']} lists it for {row['query_value']}", "intel-source")
        linked = {row["technique_id"] for row in connection.execute(
            "SELECT technique_id FROM case_techniques WHERE investigation_id = ?", (investigation_id,)
        )}
        names = {row["id"]: row["name"] for row in connection.execute(
            f"SELECT id, name FROM attack_techniques WHERE id IN ({','.join('?' for _ in found) or 'NULL'})", list(found)
        )}
    items = [
        {**entry, "origins": sorted(entry["origins"]), "name": names.get(entry["id"], ""), "linked": entry["id"] in linked}
        for entry in found.values()
        if entry["id"] in names
    ]
    items.sort(key=lambda item: (item["linked"], item["id"]))
    return {"investigation_id": investigation_id, "items": items}

