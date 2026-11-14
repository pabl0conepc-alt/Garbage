"""Threat-actor profiles from the offline ATT&CK data.

A profile is what MITRE publishes about a group: aliases, the techniques and
software it is reported to use, and, derived from those, the mitigations that
cover most of its techniques and how many local Sigma rules detect each one.

Case overlap ranks groups by the techniques they share with a case. Shared
techniques are weighted by rarity (a technique used by few groups says more
than one used by most), but overlap is a lead for the analyst, never an
attribution: many groups share tradecraft and techniques are public.
"""

from __future__ import annotations

import math
import re
from typing import Any

from ..db import _connection
from ..errors import NotFoundError, ValidationError
from ..validation import clean_text
from .attack import _require_loaded
from .sigma import counts_for

GROUP_ID = re.compile(r"^G\d{4}$")
# Below this many case techniques the ranking is mostly ties.
WEAK_BELOW = 5
OVERLAP_CAVEAT = (
    "Technique overlap is not attribution: groups share tradecraft, techniques are public "
    "and MITRE lists only what has been reported."
)


def groups(database: str, *, query: str = "", limit: int = 200) -> dict[str, Any]:
    text = clean_text(query or "", "query", max_length=100) or ""
    pattern = f"%{text}%"
    with _connection(database) as connection:
        _require_loaded(connection)
        rows = connection.execute(
            """SELECT o.id, o.name, o.aliases, o.url,
                      (SELECT COUNT(*) FROM attack_relations r
                         WHERE r.source_id = o.id AND r.kind = 'uses' AND r.target_id LIKE 'T%') AS technique_count,
                      (SELECT COUNT(*) FROM attack_relations r
                         WHERE r.source_id = o.id AND r.kind = 'uses' AND r.target_id LIKE 'S%') AS software_count
               FROM attack_objects o
               WHERE o.kind = 'group' AND (? = '' OR o.id LIKE ? OR o.name LIKE ? OR o.aliases LIKE ?)
               ORDER BY technique_count DESC, o.name
               LIMIT ?""",
            (text, f"{text.upper()}%", pattern, pattern, max(1, min(500, limit))),
        ).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM attack_objects WHERE kind = 'group'").fetchone()[0]
    return {
        "items": [{**dict(row), "aliases": _aliases(row["aliases"])} for row in rows],
        "total": total,
    }


def group(database: str, group_id: str) -> dict[str, Any]:
    if not GROUP_ID.match(group_id or ""):
        raise ValidationError("group id must look like G0016")
    with _connection(database) as connection:
        _require_loaded(connection)
        row = connection.execute("SELECT * FROM attack_objects WHERE id = ? AND kind = 'group'", (group_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"group not found: {group_id}")
        techniques = [
            dict(item)
            for item in connection.execute(
                """SELECT t.id, t.name, t.tactics, t.is_subtechnique, t.url
                   FROM attack_relations r JOIN attack_techniques t ON t.id = r.target_id
                   WHERE r.source_id = ? AND r.kind = 'uses' ORDER BY t.id""",
                (group_id,),
            )
        ]
        software = [
            dict(item)
            for item in connection.execute(
                """SELECT o.id, o.name, o.aliases, o.url,
                          (SELECT COUNT(*) FROM attack_relations s WHERE s.source_id = o.id AND s.kind = 'uses') AS technique_count
                   FROM attack_relations r JOIN attack_objects o ON o.id = r.target_id
                   WHERE r.source_id = ? AND r.kind = 'uses' AND o.kind = 'software' ORDER BY o.name""",
                (group_id,),
            )
        ]
        software_known = connection.execute(
            "SELECT 1 FROM attack_relations WHERE source_id LIKE 'G%' AND target_id LIKE 'S%' LIMIT 1"
        ).fetchone() is not None
        technique_ids = [item["id"] for item in techniques]
        # A mitigation counts for a technique when MITRE maps it to the
        # technique itself or to its parent.
        lookup = sorted(set(technique_ids) | {item.split(".")[0] for item in technique_ids})
        covered: dict[str, set[str]] = {}
        details: dict[str, dict[str, Any]] = {}
        if lookup:
            for item in connection.execute(
                f"""SELECT o.id, o.name, o.url, r.target_id
                    FROM attack_relations r JOIN attack_objects o ON o.id = r.source_id
                    WHERE r.kind = 'mitigates' AND r.target_id IN ({",".join("?" for _ in lookup)})""",
                lookup,
            ):
                details[item["id"]] = {"id": item["id"], "name": item["name"], "url": item["url"]}
                for technique_id in technique_ids:
                    if item["target_id"] in (technique_id, technique_id.split(".")[0]):
                        covered.setdefault(item["id"], set()).add(technique_id)
        mitigations = sorted(
            ({**details[key], "covered": len(value), "techniques": sorted(value)} for key, value in covered.items()),
            key=lambda item: (-item["covered"], item["name"]),
        )[:15]
        tactic_names = {item["shortname"]: item["name"] for item in connection.execute("SELECT shortname, name FROM attack_tactics")}
        tactic_order = [item["shortname"] for item in connection.execute("SELECT shortname FROM attack_tactics ORDER BY position, name")]
        cases = [
            dict(item)
            for item in connection.execute(
                f"""SELECT c.investigation_id, i.name AS investigation_name, COUNT(*) AS shared
                    FROM case_techniques c JOIN investigations i ON i.id = c.investigation_id
                    WHERE c.technique_id IN ({",".join("?" for _ in technique_ids) or "NULL"})
                    GROUP BY c.investigation_id ORDER BY shared DESC, i.name""",
                technique_ids,
            )
        ]
    sigma = counts_for(database, technique_ids)
    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for item in techniques:
        entry = {**item, "sigma_rules": sigma.get(item["id"], 0)}
        for tactic in [name for name in item["tactics"].split(",") if name] or ["other"]:
            by_tactic.setdefault(tactic, []).append(entry)
    ordered = [name for name in tactic_order if name in by_tactic] + [name for name in by_tactic if name not in tactic_order]
    return {
        "id": row["id"],
        "name": row["name"],
        "aliases": _aliases(row["aliases"]),
        "description": row["description"],
        "url": row["url"],
        "technique_count": len(techniques),
        "tactics": [{"shortname": name, "name": tactic_names.get(name, name), "techniques": by_tactic[name]} for name in ordered],
        "software": [{**item, "aliases": _aliases(item["aliases"])} for item in software],
        "software_known": software_known,
        "mitigations": mitigations,
        "detection": {
            "techniques_with_rules": sum(1 for item in technique_ids if sigma.get(item)),
            "techniques": len(technique_ids),
        },
        "cases": cases,
    }


def case_overlap(database: str, investigation_id: str, *, limit: int = 10) -> dict[str, Any]:
    """Groups ranked by the techniques they share with the case."""
    with _connection(database) as connection:
        _require_loaded(connection)
        if connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            raise NotFoundError(f"investigation not found: {investigation_id}")
        case = {row["technique_id"] for row in connection.execute(
            "SELECT technique_id FROM case_techniques WHERE investigation_id = ?", (investigation_id,)
        )}
        uses: dict[str, set[str]] = {}
        for row in connection.execute(
            """SELECT r.source_id, r.target_id FROM attack_relations r
               JOIN attack_objects o ON o.id = r.source_id
               WHERE r.kind = 'uses' AND o.kind = 'group' AND r.target_id LIKE 'T%'"""
        ):
            uses.setdefault(row["source_id"], set()).add(row["target_id"])
        names = {row["id"]: (row["name"], row["aliases"], row["url"]) for row in connection.execute(
            "SELECT id, name, aliases, url FROM attack_objects WHERE kind = 'group'"
        )}
        technique_names = {row["id"]: row["name"] for row in connection.execute(
            f"SELECT id, name FROM attack_techniques WHERE id IN ({','.join('?' for _ in case) or 'NULL'})", sorted(case)
        )}
    if not case:
        return {"investigation_id": investigation_id, "case_techniques": 0, "weak": True, "items": [], "caveat": OVERLAP_CAVEAT}
    total_groups = max(1, len(uses))
    used_by: dict[str, int] = {}
    for techniques in uses.values():
        for technique in techniques:
            used_by[technique] = used_by.get(technique, 0) + 1

    def weight(technique: str) -> float:
        # Rarer techniques say more; a sub-technique also inherits its parent's use.
        seen = used_by.get(technique, 0) or used_by.get(technique.split(".")[0], 0)
        return math.log((total_groups + 1) / (seen + 1)) + 1

    def covers(techniques: set[str], wanted: str) -> bool:
        """Same technique, its parent, or one of its sub-techniques."""
        parent = wanted.split(".")[0]
        return wanted in techniques or parent in techniques or any(item.startswith(f"{wanted}.") for item in techniques)

    possible = sum(weight(item) for item in case)
    ranked = []
    for group_id, techniques in uses.items():
        shared = sorted(item for item in case if covers(techniques, item))
        if not shared:
            continue
        name, aliases, url = names.get(group_id, (group_id, "", ""))
        ranked.append(
            {
                "id": group_id,
                "name": name,
                "aliases": _aliases(aliases),
                "url": url,
                "shared": [{"id": item, "name": technique_names.get(item, ""), "exact": item in techniques} for item in shared],
                "shared_count": len(shared),
                "group_technique_count": len(techniques),
                # A match only through the technique family counts half.
                "score": round(sum(weight(item) * (1 if item in techniques else 0.5) for item in shared) / possible, 3),
            }
        )
    # Ties go to the group whose known repertoire the case matches most closely.
    ranked.sort(key=lambda item: (-item["score"], -item["shared_count"], item["group_technique_count"], item["name"]))
    return {
        "investigation_id": investigation_id,
        "case_techniques": len(case),
        "weak": len(case) < WEAK_BELOW,
        "items": ranked[: max(1, min(50, limit))],
        "caveat": OVERLAP_CAVEAT,
    }


def _aliases(raw: str) -> list[str]:
    return [item for item in (raw or "").split(",") if item]
