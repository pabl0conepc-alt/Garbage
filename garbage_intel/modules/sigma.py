"""Sigma detection rules from the SigmaHQ release, indexed by ATT&CK technique.

``refresh`` downloads the core rule package of the latest SigmaHQ release
(one explicit request, hosts pinned) and stores each rule's catalogue fields
and its full YAML text. The rules are SigmaHQ's, under the Detection Rule
License 1.1, which asks for attribution: the interface shows it with every
rule. Nothing here converts or runs a rule; they are reference material for
the techniques linked to a case.

The YAML reader handles the subset Sigma rule headers use: top-level scalars
(plain, quoted, block ``|``/``>``), lists of scalars and one level of nested
mapping. The ``detection`` block is kept as text.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from typing import Any, Callable

from .. import net
from ..db import _connection, record_activity, require_module, utc_now
from ..errors import NotFoundError
from ..net import FetchResult, NetworkError

FETCH: Callable[..., FetchResult] = net.fetch
RELEASE_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip"
HOSTS = ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
MAX_ZIP_BYTES = 16 * 1024 * 1024
MAX_RULE_BYTES = 256 * 1024
LICENSE = "Detection Rule License (DRL) 1.1, SigmaHQ and rule authors"
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_KEY = re.compile(r"^([A-Za-z_][\w-]*):(?:\s+(.*))?$")


class SigmaError(Exception):
    pass


def _scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        inner = text[1:-1]
        return inner.replace("''", "'") if text[0] == "'" else inner.replace('\\"', '"').replace("\\\\", "\\")
    return re.sub(r"\s+#.*$", "", text)


def parse_rule(text: str) -> dict[str, Any]:
    """Top-level fields of a Sigma rule (see the module docstring)."""
    lines = text.replace("\r\n", "\n").split("\n")
    result: dict[str, Any] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _KEY.match(line)
        if not match:
            index += 1
            continue
        key, rest = match.group(1), (match.group(2) or "").strip()
        index += 1
        block: list[str] = []
        while index < len(lines) and (not lines[index].strip() or lines[index][:1].isspace() or lines[index].startswith("- ")):
            block.append(lines[index])
            index += 1
        while block and not block[-1].strip():
            block.pop()
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            indent = min((len(item) - len(item.lstrip()) for item in block if item.strip()), default=0)
            content = [item[indent:] for item in block]
            result[key] = "\n".join(content) if rest.startswith("|") else re.sub(r"(?<!\n)\n(?!\n)", " ", "\n".join(content))
        elif rest:
            result[key] = _scalar(rest)
        elif block and block[0].lstrip().startswith("- "):
            items = []
            for item in block:
                stripped = item.strip()
                if stripped.startswith("- ") and ":" not in stripped[2:].split(" #")[0].replace("://", ""):
                    items.append(_scalar(stripped[2:]))
                elif stripped.startswith("- "):
                    items.append(_scalar(stripped[2:]))
            result[key] = items
        elif block:
            nested: dict[str, Any] = {}
            indent = len(block[0]) - len(block[0].lstrip())
            for item in block:
                if len(item) - len(item.lstrip()) != indent:
                    continue
                inner = _KEY.match(item.strip())
                # Nested block scalars (logsource "definition: |") are not
                # catalogue fields; they stay in the rule text.
                if inner and inner.group(2) and inner.group(2).strip() not in ("|", ">", "|-", ">-"):
                    nested[inner.group(1)] = _scalar(inner.group(2))
            result[key] = nested
            result[f"{key}__text"] = "\n".join(block)
        else:
            result[key] = ""
    return result


def techniques(tags: list[str]) -> list[str]:
    found = []
    for tag in tags:
        match = _TECHNIQUE_TAG.match(str(tag).strip())
        if match:
            found.append(match.group(1).upper())
    return sorted(set(found))


def _row(path: str, text: str) -> tuple[Any, ...] | None:
    fields = parse_rule(text)
    rule_id = str(fields.get("id", "")).strip()
    title = str(fields.get("title", "")).strip()
    if not rule_id or not title:
        return None
    tags = [str(tag) for tag in fields.get("tags") or [] if isinstance(tag, str)]
    logsource = fields.get("logsource") if isinstance(fields.get("logsource"), dict) else {}
    return (
        rule_id[:100],
        title[:300],
        str(fields.get("status", ""))[:20],
        str(fields.get("level", ""))[:20],
        str(fields.get("description", ""))[:4000],
        ",".join(tags)[:2000],
        ",".join(techniques(tags)),
        str(logsource.get("product", ""))[:60],
        str(logsource.get("category", ""))[:80],
        str(logsource.get("service", ""))[:80],
        json.dumps([str(item)[:500] for item in fields.get("references") or []][:30]),
        json.dumps([str(item)[:300] for item in fields.get("falsepositives") or []][:20]),
        str(fields.get("date", ""))[:20],
        str(fields.get("modified", ""))[:20],
        path[:300],
        text[:MAX_RULE_BYTES],
    )


def load_package(database: str, data: bytes, *, version: str, source_url: str) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SigmaError("the Sigma package is not a valid zip") from exc
    rows = []
    for info in archive.infolist():
        if not info.filename.endswith((".yml", ".yaml")) or info.file_size > MAX_RULE_BYTES or info.filename.startswith(("/", "..")):
            continue
        row = _row(info.filename, archive.read(info).decode("utf-8", "replace"))
        if row:
            rows.append(row)
    if not rows:
        raise SigmaError("the Sigma package contains no rules")
    with _connection(database) as connection:
        connection.execute("DELETE FROM sigma_rules")
        connection.executemany(
            """INSERT OR REPLACE INTO sigma_rules
               (id, title, status, level, description, tags, techniques, product, category, service,
                references_json, falsepositives_json, date, modified, path, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        connection.execute("DELETE FROM sigma_meta")
        connection.execute(
            "INSERT INTO sigma_meta (version, source_url, sha256, rule_count, fetched_at) VALUES (?, ?, ?, ?, ?)",
            (version, source_url, hashlib.sha256(data).hexdigest(), len(rows), utc_now()),
        )
        record_activity(connection, action="sigma", target_type="sigma", summary=f"Sigma rules refreshed: {version}, {len(rows)} rules")
    return status(database)


def refresh(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "sigma-rules")
    try:
        result = FETCH(RELEASE_URL, allowed_hosts=HOSTS, max_bytes=MAX_ZIP_BYTES, timeout=120.0)
    except NetworkError as exc:
        raise SigmaError(f"the Sigma package could not be downloaded: {exc}") from exc
    if result.status != 200:
        raise SigmaError(f"the Sigma package could not be downloaded (HTTP {result.status})")
    if not (result.final_url.startswith("https://github.com/SigmaHQ/sigma/") or "release-asset" in result.final_url or any(hop.startswith("https://github.com/SigmaHQ/sigma/releases/download/") for hop in result.redirects)):
        raise SigmaError("the Sigma package came from an unexpected location")
    version = ""
    for hop in [*result.redirects, result.final_url]:
        match = re.search(r"/releases/download/([\w.-]+)/", hop)
        if match:
            version = match.group(1)
    return load_package(database, result.body, version=version or "unknown", source_url=RELEASE_URL)


def status(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "sigma-rules")
        meta = connection.execute("SELECT * FROM sigma_meta LIMIT 1").fetchone()
        levels = {row["level"]: row["total"] for row in connection.execute("SELECT level, COUNT(*) AS total FROM sigma_rules GROUP BY level")}
        mapped = connection.execute("SELECT COUNT(*) FROM sigma_rules WHERE techniques <> ''").fetchone()[0]
    return {"loaded": meta is not None, **(dict(meta) if meta else {}), "levels": levels, "with_techniques": mapped, "license": LICENSE}


def _decode(row: Any, full: bool = False) -> dict[str, Any]:
    item = dict(row)
    item["tags"] = [tag for tag in item["tags"].split(",") if tag]
    item["techniques"] = [tag for tag in item["techniques"].split(",") if tag]
    item["references"] = json.loads(item.pop("references_json") or "[]")
    item["falsepositives"] = json.loads(item.pop("falsepositives_json") or "[]")
    if not full:
        item.pop("raw", None)
    return item


def search(
    database: str,
    *,
    technique: str | None = None,
    query: str = "",
    level: str | None = None,
    product: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    clauses, params = [], []
    if technique:
        clauses.append("(',' || techniques || ',') LIKE ?")
        params.append(f"%,{technique.upper()}%")
    if level:
        clauses.append("level = ?")
        params.append(level)
    if product:
        clauses.append("product = ?")
        params.append(product)
    if query:
        clauses.append("(title LIKE ? OR description LIKE ? OR tags LIKE ?)")
        params += [f"%{query}%"] * 3
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connection(database) as connection:
        require_module(connection, "sigma-rules")
        total = connection.execute(f"SELECT COUNT(*) FROM sigma_rules {where}", params).fetchone()[0]
        rows = connection.execute(
            f"""SELECT id, title, status, level, description, tags, techniques, product, category, service,
                       references_json, falsepositives_json, date, modified, path
                FROM sigma_rules {where}
                ORDER BY CASE level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, title
                LIMIT ?""",
            (*params, max(1, min(500, int(limit)))),
        ).fetchall()
        products = [row[0] for row in connection.execute("SELECT DISTINCT product FROM sigma_rules WHERE product <> '' ORDER BY product")]
    return {"items": [_decode(row) for row in rows], "total": total, "products": products, "license": LICENSE}


def get_rule(database: str, rule_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "sigma-rules")
        row = connection.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"Sigma rule not found: {rule_id}")
    return {**_decode(row, full=True), "license": LICENSE}


def counts_for(database: str, technique_ids: list[str]) -> dict[str, int]:
    """Number of Sigma rules per technique (sub-techniques count separately)."""
    if not technique_ids:
        return {}
    with _connection(database) as connection:
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'sigma_rules'").fetchone() is None:
            return {}
        rows = connection.execute("SELECT techniques FROM sigma_rules WHERE techniques <> ''").fetchall()
    wanted = set(technique_ids)
    counts: dict[str, int] = {}
    for row in rows:
        for technique in row["techniques"].split(","):
            if technique in wanted:
                counts[technique] = counts.get(technique, 0) + 1
    return counts
