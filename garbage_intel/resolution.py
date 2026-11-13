"""Entity resolution: candidate duplicates at three levels, analyst decides.

* **exact**: both entities name the same artifact once canonicalised (an IPv4
  registered as ``ipv4`` and again as ``ioc``; a file and a hash entity with
  the same SHA-256).
* **probable**: the values differ only in ways that rarely change what they
  point to (``www.`` prefix, URL scheme or trailing slash, organisation legal
  suffix and punctuation).
* **weak**: similar but plausibly different (same domain label under another
  suffix, organisation names that are close but not equal).

Nothing is merged automatically. A merge moves relationships, case links,
sources and board elements to the kept entity, records the merged entity as an
alias and is written to the activity log. A pair marked distinct is not
proposed again. Person, username and profile entities are left out: the
platform does not correlate identities.
"""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .db import _connection, new_id, record_activity, require_module, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .intel import detect_artifact
from .validation import clean_text

LEVELS = ("exact", "probable", "weak")
PERSONAL_TYPES = frozenset({"person", "username", "profile"})
MAX_ENTITIES = 5000
MAX_FUZZY_ORGANIZATIONS = 1500
MAX_CANDIDATES = 300
WEAK_NAME_RATIO = 0.86

_LEGAL_SUFFIXES = frozenset(
    "inc incorporated llc ltd limited ltda sa s a ag gmbh corp corporation co "
    "company plc bv nv srl spa sas sarl oy ab as kk me eireli epp pty".split()
)
# Second-level registries where the registrable name sits one label deeper.
_MULTI_LABEL_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk com.br net.br org.br gov.br com.au net.au org.au "
    "co.jp co.nz co.za com.mx com.ar com.tr co.in co.kr com.cn com.hk com.sg".split()
)


def _artifact_key(entity: dict[str, Any]) -> tuple[str, str] | None:
    raw = (entity["identifier"] or "").strip()
    if not raw and entity["entity_type"] in {"domain", "ipv4", "ipv6", "email", "url", "hash", "ioc", "other"}:
        raw = (entity["name"] or "").strip()
    if not raw:
        return None
    try:
        detected = detect_artifact(raw)
    except ValidationError:
        return None
    kind = "hash" if detected["type"] in {"md5", "sha1", "sha256"} else detected["type"]
    return kind, detected["value"]


def organization_key(name: str) -> str:
    """Lower-case, accent-free organisation name without legal suffixes."""
    text = unicodedata.normalize("NFKD", name)
    text = "".join(char for char in text if not unicodedata.combining(char)).lower()
    words = re.findall(r"[a-z0-9]+", text)
    while words and words[-1] in _LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def registrable_parts(domain: str) -> tuple[str, str]:
    """(label, suffix) of a domain, e.g. ('example', 'com.br')."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return labels[0], ""


def _url_key(value: str) -> str:
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = parts.port
    if port and port not in (80, 443):
        host = f"{host}:{port}"
    path = parts.path.rstrip("/")
    return urlunsplit(("", host, path, parts.query, ""))


def pair_key(first: str, second: str) -> str:
    return "|".join(sorted((first, second)))


def _summary(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entity["id"],
        "entity_type": entity["entity_type"],
        "name": entity["name"],
        "identifier": entity["identifier"],
        "verification_status": entity["verification_status"],
        "relationship_count": entity.get("relationship_count", 0),
        "case_count": entity.get("case_count", 0),
    }


def find_candidates(
    database: str, *, investigation_id: str | None = None, level: str | None = None
) -> dict[str, Any]:
    if level not in (None, "") and level not in LEVELS:
        raise ValidationError(f"level must be one of: {', '.join(LEVELS)}")
    with _connection(database) as connection:
        require_module(connection, "entity-resolution")
        params: list[Any] = []
        scope = ""
        if investigation_id:
            if connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
                raise NotFoundError(f"investigation not found: {investigation_id}")
            scope = "AND e.id IN (SELECT entity_id FROM investigation_entities WHERE investigation_id = ?)"
            params.append(investigation_id)
        rows = connection.execute(
            f"""SELECT e.id, e.entity_type, e.name, e.identifier, e.verification_status,
                       (SELECT COUNT(*) FROM relationships r
                        WHERE r.source_entity_id = e.id OR r.target_entity_id = e.id) AS relationship_count,
                       (SELECT COUNT(*) FROM investigation_entities ie
                        WHERE ie.entity_id = e.id) AS case_count
                FROM entities e
                WHERE e.entity_type NOT IN ('person', 'username', 'profile') {scope}
                ORDER BY e.created_at, e.id
                LIMIT ?""",
            (*params, MAX_ENTITIES + 1),
        ).fetchall()
        dismissed = {
            row["pair_key"]
            for row in connection.execute(
                "SELECT pair_key FROM resolution_decisions WHERE decision = 'distinct'"
            )
        }
    entities = [dict(row) for row in rows[:MAX_ENTITIES]]
    truncated = len(rows) > MAX_ENTITIES

    found: dict[str, dict[str, Any]] = {}

    def propose(first: dict[str, Any], second: dict[str, Any], rank: str, rule: str, detail: dict[str, Any]) -> None:
        if first["id"] == second["id"]:
            return
        key = pair_key(first["id"], second["id"])
        if key in dismissed:
            return
        current = found.get(key)
        if current is not None and LEVELS.index(current["level"]) <= LEVELS.index(rank):
            return
        found[key] = {
            "pair_key": key,
            "level": rank,
            "rule": rule,
            "detail": detail,
            "entities": [_summary(first), _summary(second)],
        }

    by_artifact: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entity in entities:
        artifact = _artifact_key(entity)
        if artifact is not None:
            entity["_artifact"] = artifact
            by_artifact.setdefault(artifact, []).append(entity)
    for (kind, value), group in by_artifact.items():
        for index, first in enumerate(group):
            for second in group[index + 1:]:
                propose(first, second, "exact", "same-artifact", {"artifact_type": kind, "value": value})

    domains: dict[str, list[dict[str, Any]]] = {}
    labels: dict[str, list[dict[str, Any]]] = {}
    urls: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        artifact = entity.get("_artifact")
        if artifact is None:
            continue
        kind, value = artifact
        if kind == "domain":
            bare = value[4:] if value.startswith("www.") else value
            domains.setdefault(bare, []).append(entity)
            label, suffix = registrable_parts(bare)
            if suffix and bare == f"{label}.{suffix}":
                labels.setdefault(label, []).append(entity)
        elif kind == "url":
            urls.setdefault(_url_key(value), []).append(entity)
    for bare, group in domains.items():
        for index, first in enumerate(group):
            for second in group[index + 1:]:
                if first["_artifact"][1] != second["_artifact"][1]:
                    propose(first, second, "probable", "www-prefix", {"domain": bare})
    for key, group in urls.items():
        for index, first in enumerate(group):
            for second in group[index + 1:]:
                if first["_artifact"][1] != second["_artifact"][1]:
                    propose(first, second, "probable", "url-variant", {"normalized": key})
    for label, group in labels.items():
        if len(label) < 4:
            continue  # short labels collide by chance across suffixes
        for index, first in enumerate(group):
            for second in group[index + 1:]:
                propose(
                    first,
                    second,
                    "weak",
                    "same-label-other-suffix",
                    {"label": label, "values": [first["_artifact"][1], second["_artifact"][1]]},
                )

    organizations = [entity for entity in entities if entity["entity_type"] == "organization"]
    keyed: dict[str, list[dict[str, Any]]] = {}
    for entity in organizations:
        key = organization_key(entity["name"])
        if key:
            entity["_org"] = key
            keyed.setdefault(key, []).append(entity)
    for key, group in keyed.items():
        for index, first in enumerate(group):
            for second in group[index + 1:]:
                rank = "exact" if first["name"].strip().casefold() == second["name"].strip().casefold() else "probable"
                propose(first, second, rank, "organization-name", {"normalized": key})
    fuzzy = [entity for entity in organizations if entity.get("_org")][:MAX_FUZZY_ORGANIZATIONS]
    for index, first in enumerate(fuzzy):
        for second in fuzzy[index + 1:]:
            if first["_org"] == second["_org"]:
                continue
            if abs(len(first["_org"]) - len(second["_org"])) > max(len(first["_org"]), len(second["_org"])) // 3:
                continue
            ratio = SequenceMatcher(None, first["_org"], second["_org"]).ratio()
            if ratio >= WEAK_NAME_RATIO:
                propose(first, second, "weak", "similar-organization-name", {"ratio": round(ratio, 3)})

    items = sorted(
        found.values(),
        key=lambda item: (LEVELS.index(item["level"]), item["rule"], item["pair_key"]),
    )
    counts = {rank: sum(1 for item in items if item["level"] == rank) for rank in LEVELS}
    if level:
        items = [item for item in items if item["level"] == level]
    return {
        "items": items[:MAX_CANDIDATES],
        "total": len(items),
        "counts": counts,
        "scanned": len(entities),
        "truncated": truncated,
        "dismissed": len(dismissed),
    }


def dismiss_pair(database: str, first: object, second: object, *, note: object = "", level: object = "", rule: object = "") -> dict[str, Any]:
    if not isinstance(first, str) or not isinstance(second, str) or not first or not second or first == second:
        raise ValidationError("two different entity ids are required")
    note_text = clean_text(note, "note", max_length=1000)
    with _connection(database) as connection:
        require_module(connection, "entity-resolution")
        for entity_id in (first, second):
            if connection.execute("SELECT 1 FROM entities WHERE id = ?", (entity_id,)).fetchone() is None:
                raise NotFoundError(f"entity not found: {entity_id}")
        key = pair_key(first, second)
        connection.execute(
            """INSERT INTO resolution_decisions
               (pair_key, entity_a, entity_b, decision, level, rule, note, decided_at)
               VALUES (?, ?, ?, 'distinct', ?, ?, ?, ?)
               ON CONFLICT(pair_key) DO UPDATE SET decision = 'distinct',
                   note = excluded.note, decided_at = excluded.decided_at""",
            (key, *sorted((first, second)), str(level)[:20], str(rule)[:60], note_text, utc_now()),
        )
        record_activity(
            connection,
            action="resolution",
            target_type="entity",
            target_id=first,
            summary="Entity pair marked as distinct",
        )
    return {"pair_key": key, "decision": "distinct"}


def merge_entities(
    database: str, *, keep_id: object, merge_id: object, note: object = "", level: object = ""
) -> dict[str, Any]:
    """Fold ``merge_id`` into ``keep_id``; the merged entity becomes an alias."""
    from .entities import get_entity

    if not isinstance(keep_id, str) or not isinstance(merge_id, str) or not keep_id or not merge_id:
        raise ValidationError("keep_id and merge_id are required")
    if keep_id == merge_id:
        raise ValidationError("an entity cannot be merged into itself")
    note_text = clean_text(note, "note", max_length=1000)
    level_text = level if level in LEVELS else ""
    with _connection(database) as connection:
        require_module(connection, "entity-resolution")
        rows = {
            row["id"]: dict(row)
            for row in connection.execute(
                "SELECT * FROM entities WHERE id IN (?, ?)", (keep_id, merge_id)
            )
        }
        for entity_id in (keep_id, merge_id):
            if entity_id not in rows:
                raise NotFoundError(f"entity not found: {entity_id}")
        keep, merged = rows[keep_id], rows[merge_id]
        if (keep["entity_type"] in PERSONAL_TYPES) != (merged["entity_type"] in PERSONAL_TYPES):
            raise ConflictError("a person, username or profile can only be merged with the same kind of entity")
        moved = {"relationships": 0, "dropped_relationships": 0, "cases": 0, "sources": 0, "board_elements": 0, "transform_runs": 0}
        # A relationship between the two would become a self-loop.
        moved["dropped_relationships"] += connection.execute(
            """DELETE FROM relationships
               WHERE (source_entity_id = ? AND target_entity_id = ?)
                  OR (source_entity_id = ? AND target_entity_id = ?)""",
            (keep_id, merge_id, merge_id, keep_id),
        ).rowcount
        for column, other in (("source_entity_id", "target_entity_id"), ("target_entity_id", "source_entity_id")):
            for row in connection.execute(
                f"SELECT id, {other} AS other, relationship_type, investigation_id FROM relationships WHERE {column} = ?",
                (merge_id,),
            ).fetchall():
                duplicate = connection.execute(
                    f"""SELECT 1 FROM relationships
                        WHERE {column} = ? AND {other} = ? AND relationship_type = ?
                          AND COALESCE(investigation_id, '') = COALESCE(?, '')""",
                    (keep_id, row["other"], row["relationship_type"], row["investigation_id"]),
                ).fetchone()
                if duplicate is not None:
                    connection.execute("DELETE FROM relationships WHERE id = ?", (row["id"],))
                    moved["dropped_relationships"] += 1
                else:
                    connection.execute(
                        f"UPDATE relationships SET {column} = ?, updated_at = ? WHERE id = ?",
                        (keep_id, utc_now(), row["id"]),
                    )
                    moved["relationships"] += 1
        moved["cases"] = connection.execute(
            """INSERT OR IGNORE INTO investigation_entities (investigation_id, entity_id, added_at)
               SELECT investigation_id, ?, added_at FROM investigation_entities WHERE entity_id = ?""",
            (keep_id, merge_id),
        ).rowcount
        moved["sources"] = connection.execute(
            """INSERT OR IGNORE INTO entity_sources (entity_id, source_id, added_at)
               SELECT ?, source_id, added_at FROM entity_sources WHERE entity_id = ?""",
            (keep_id, merge_id),
        ).rowcount
        moved["board_elements"] = connection.execute(
            "UPDATE board_elements SET entity_id = ? WHERE entity_id = ?", (keep_id, merge_id)
        ).rowcount
        moved["transform_runs"] = connection.execute(
            "UPDATE transform_runs SET entity_id = ? WHERE entity_id = ?", (keep_id, merge_id)
        ).rowcount
        connection.execute(
            "UPDATE entity_aliases SET entity_id = ? WHERE entity_id = ?", (keep_id, merge_id)
        )
        connection.execute(
            """INSERT INTO entity_aliases
               (id, entity_id, entity_type, name, identifier, merged_from_id, level, note, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (new_id(), keep_id, merged["entity_type"], merged["name"], merged["identifier"], merge_id, level_text, note_text, utc_now()),
        )
        connection.execute("DELETE FROM investigation_entities WHERE entity_id = ?", (merge_id,))
        connection.execute("DELETE FROM entity_sources WHERE entity_id = ?", (merge_id,))
        connection.execute("DELETE FROM entities WHERE id = ?", (merge_id,))
        connection.execute("UPDATE entities SET updated_at = ? WHERE id = ?", (utc_now(), keep_id))
        connection.execute(
            """INSERT INTO resolution_decisions
               (pair_key, entity_a, entity_b, decision, level, rule, note, decided_at)
               VALUES (?, ?, ?, 'merged', ?, '', ?, ?)
               ON CONFLICT(pair_key) DO UPDATE SET decision = 'merged',
                   note = excluded.note, decided_at = excluded.decided_at""",
            (pair_key(keep_id, merge_id), *sorted((keep_id, merge_id)), level_text, note_text, utc_now()),
        )
        record_activity(
            connection,
            action="resolution",
            target_type="entity",
            target_id=keep_id,
            summary=f"Entity merged: {merged['name'][:120]} into {keep['name'][:120]}",
        )
    return {"entity": get_entity(database, keep_id), "aliases": entity_aliases(database, keep_id)["items"], "moved": moved}


def entity_aliases(database: str, entity_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        rows = connection.execute(
            "SELECT * FROM entity_aliases WHERE entity_id = ? ORDER BY created_at DESC", (entity_id,)
        ).fetchall()
    return {"items": [dict(row) for row in rows], "total": len(rows)}
