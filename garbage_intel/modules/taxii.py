"""TAXII 2.1 client: discovery, API roots, collections and paged object pulls.

The analyst registers a server by its discovery URL (with HTTP Basic
credentials when the server needs them). Every request goes through the
SSRF-safe ``net.fetch``, restricted to that server's host. Pulled STIX
objects are stored as received; indicators can then be written into a case
as an observation, so the indicator engine extracts and correlates them.
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any, Callable
from urllib.parse import urlencode, urljoin, urlsplit

from .. import net
from ..db import _connection, new_id, record_activity, require_module, utc_now
from ..errors import NotFoundError, ValidationError
from ..net import FetchResult, NetworkError
from ..validation import clean_text

FETCH: Callable[..., FetchResult] = net.fetch
SLEEP: Callable[[float], None] = time.sleep
RETRIES = 2
RETRY_DELAY_SECONDS = 2.0
ACCEPT = "application/taxii+json;version=2.1"
PAGE_SIZE = 500
MAX_PULL_OBJECTS = 20_000
MAX_ROOTS = 50
_COLLECTION_ID = re.compile(r"[A-Za-z0-9._:-]{1,200}")
_COMPARISON = re.compile(r"\[\s*([a-z0-9-]+):([A-Za-z0-9_.'\[\]-]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]")
_OBSERVABLE_PATHS = {
    "domain-name:value", "ipv4-addr:value", "ipv6-addr:value", "url:value", "email-addr:value",
    "file:hashes.MD5", "file:hashes.'SHA-1'", "file:hashes.'SHA-256'", "file:hashes.SHA1", "file:hashes.SHA256",
}


def _server_row(connection: Any, server_id: str) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM taxii_servers WHERE id = ?", (server_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"TAXII server not found: {server_id}")
    return dict(row)


def _public(server: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": server["id"],
        "name": server["name"],
        "discovery_url": server["discovery_url"],
        "has_credentials": bool(server["username"]),
        "created_at": server["created_at"],
        "last_pull_at": server.get("last_pull_at") or "",
    }


def _request(server: dict[str, Any], url: str) -> Any:
    host = urlsplit(server["discovery_url"]).hostname or ""
    headers = {"Accept": ACCEPT}
    if server["username"]:
        token = base64.b64encode(f"{server['username']}:{server['password']}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    result = FETCH(url, headers=headers, allowed_hosts=(host,), max_bytes=32 * 1024 * 1024, timeout=60.0)
    for _ in range(RETRIES):
        # Gateways in front of TAXII servers drop the odd page under load.
        if result.status not in (502, 503, 504):
            break
        SLEEP(RETRY_DELAY_SECONDS)
        result = FETCH(url, headers=headers, allowed_hosts=(host,), max_bytes=32 * 1024 * 1024, timeout=60.0)
    if result.status in (401, 403):
        raise NetworkError(f"the TAXII server refused the credentials (HTTP {result.status})")
    if result.status == 404:
        raise NetworkError("the TAXII server answered HTTP 404")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        return json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


def add_server(database: str, *, name: object, discovery_url: object, username: object = "", password: object = "") -> dict[str, Any]:
    label = clean_text(name, "name", max_length=120, required=True)
    url = clean_text(discovery_url, "discovery URL", max_length=500, required=True)
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValidationError("the discovery URL must be an https URL")
    user = clean_text(username, "username", max_length=200)
    secret = str(password or "")[:500]
    if bool(user) != bool(secret):
        raise ValidationError("give both username and password, or neither")
    server_id = new_id()
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        connection.execute(
            """INSERT INTO taxii_servers (id, name, discovery_url, username, password, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (server_id, label, url, user, secret, utc_now()),
        )
        record_activity(connection, action="taxii", target_type="taxii_server", target_id=server_id, summary=f"TAXII server added: {label}")
        return _public(_server_row(connection, server_id))


def list_servers(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        rows = [dict(row) for row in connection.execute("SELECT * FROM taxii_servers ORDER BY name")]
        counts = {
            row["server_id"]: row["total"]
            for row in connection.execute("SELECT server_id, COUNT(*) AS total FROM taxii_objects GROUP BY server_id")
        }
    return {"items": [{**_public(row), "object_count": counts.get(row["id"], 0)} for row in rows]}


def delete_server(database: str, server_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        server = _server_row(connection, server_id)
        connection.execute("DELETE FROM taxii_objects WHERE server_id = ?", (server_id,))
        connection.execute("DELETE FROM taxii_pulls WHERE server_id = ?", (server_id,))
        connection.execute("DELETE FROM taxii_servers WHERE id = ?", (server_id,))
        record_activity(connection, action="taxii", target_type="taxii_server", target_id=server_id, summary=f"TAXII server removed: {server['name']}")
    return {"deleted": server_id}


def discover(database: str, server_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        server = _server_row(connection, server_id)
    data = _request(server, server["discovery_url"])
    if not isinstance(data, dict):
        raise NetworkError("the discovery document is not an object")
    roots = []
    for root in (data.get("api_roots") or [])[:MAX_ROOTS]:
        if isinstance(root, str):
            roots.append(urljoin(server["discovery_url"], root.rstrip("/") + "/"))
    default = data.get("default")
    default_url = urljoin(server["discovery_url"], default.rstrip("/") + "/") if isinstance(default, str) else (roots[0] if roots else "")
    return {
        "title": str(data.get("title", ""))[:200],
        "description": str(data.get("description", ""))[:1000],
        "default": default_url,
        "api_roots": roots,
    }


def _check_root(server: dict[str, Any], api_root: object) -> str:
    if not isinstance(api_root, str) or not api_root.startswith("https://"):
        raise ValidationError("api_root must be an https URL from discovery")
    if urlsplit(api_root).hostname != urlsplit(server["discovery_url"]).hostname:
        raise ValidationError("api_root must be on the server's host")
    return api_root if api_root.endswith("/") else api_root + "/"


def collections(database: str, server_id: str, api_root: object) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        server = _server_row(connection, server_id)
    root = _check_root(server, api_root)
    data = _request(server, urljoin(root, "collections/"))
    items = []
    for item in (data or {}).get("collections") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            items.append(
                {
                    "id": item["id"][:200],
                    "title": str(item.get("title", ""))[:200],
                    "description": str(item.get("description", ""))[:2000],
                    "can_read": bool(item.get("can_read")),
                    "can_write": bool(item.get("can_write")),
                }
            )
    return {"api_root": root, "items": items}


def _object_name(item: dict[str, Any]) -> str:
    for key in ("name", "value", "pattern", "id"):
        if isinstance(item.get(key), str) and item[key]:
            return item[key][:300]
    return ""


def pull(
    database: str,
    server_id: str,
    *,
    api_root: object,
    collection_id: object,
    added_after: object = None,
    object_types: object = None,
    max_objects: object = 5000,
) -> dict[str, Any]:
    """Fetch a collection's objects page by page (``next``) and store them."""
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        server = _server_row(connection, server_id)
    root = _check_root(server, api_root)
    if not isinstance(collection_id, str) or not _COLLECTION_ID.fullmatch(collection_id):
        raise ValidationError("collection_id is not a valid collection identifier")
    if isinstance(max_objects, bool) or not isinstance(max_objects, int) or not 1 <= max_objects <= MAX_PULL_OBJECTS:
        raise ValidationError(f"max_objects must be between 1 and {MAX_PULL_OBJECTS}")
    query: dict[str, str] = {"limit": str(PAGE_SIZE)}
    if added_after not in (None, ""):
        if not isinstance(added_after, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z", added_after):
            raise ValidationError("added_after must be a UTC timestamp like 2026-01-01T00:00:00Z")
        query["added_after"] = added_after
    if object_types not in (None, [], ""):
        if not isinstance(object_types, list) or not all(isinstance(item, str) and re.fullmatch(r"[a-z0-9-]{1,60}", item) for item in object_types):
            raise ValidationError("object_types must be a list of STIX type names")
        query["match[type]"] = ",".join(object_types)
    base = urljoin(root, f"collections/{collection_id}/objects/")
    pull_id = new_id()
    started = utc_now()
    stored = 0
    pages = 0
    counts: dict[str, int] = {}
    error = ""
    try:
        cursor = None
        while stored < max_objects:
            page_query = dict(query, **({"next": cursor} if cursor else {}))
            envelope = _request(server, f"{base}?{urlencode(page_query)}")
            pages += 1
            objects = [item for item in (envelope or {}).get("objects") or [] if isinstance(item, dict) and isinstance(item.get("id"), str)]
            objects = objects[: max_objects - stored]
            with _connection(database) as connection:
                for item in objects:
                    kind = str(item.get("type", ""))[:60]
                    counts[kind] = counts.get(kind, 0) + 1
                    connection.execute(
                        """INSERT INTO taxii_objects
                           (server_id, collection_id, object_id, type, name, pattern, modified, raw_json, fetched_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(server_id, collection_id, object_id) DO UPDATE SET
                               type = excluded.type, name = excluded.name, pattern = excluded.pattern,
                               modified = excluded.modified, raw_json = excluded.raw_json, fetched_at = excluded.fetched_at""",
                        (
                            server_id,
                            collection_id,
                            item["id"][:200],
                            kind,
                            _object_name(item),
                            str(item.get("pattern", ""))[:4000],
                            str(item.get("modified", ""))[:40],
                            json.dumps(item, sort_keys=True)[:200_000],
                            utc_now(),
                        ),
                    )
            stored += len(objects)
            cursor = envelope.get("next") if isinstance(envelope, dict) and envelope.get("more") else None
            if not cursor or not objects:
                break
    except NetworkError as exc:
        error = str(exc)
    status = "error" if error and not stored else ("partial" if error else "completed")
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO taxii_pulls (id, server_id, collection_id, started_at, finished_at, object_count, page_count, status, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pull_id, server_id, collection_id, started, utc_now(), stored, pages, status, error[:500]),
        )
        connection.execute("UPDATE taxii_servers SET last_pull_at = ? WHERE id = ?", (utc_now(), server_id))
        record_activity(connection, action="taxii", target_type="taxii_server", target_id=server_id, summary=f"TAXII pull: {stored} objects from {collection_id[:80]}")
    if status == "error":
        raise NetworkError(error)
    return {"id": pull_id, "status": status, "error": error, "object_count": stored, "page_count": pages, "by_type": counts}


def list_objects(
    database: str,
    *,
    server_id: str | None = None,
    collection_id: str | None = None,
    object_type: str | None = None,
    search: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    clauses, params = [], []
    for column, value in (("server_id", server_id), ("collection_id", collection_id), ("type", object_type)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if search:
        clauses.append("(name LIKE ? ESCAPE '\\' OR pattern LIKE ? ESCAPE '\\' OR object_id LIKE ? ESCAPE '\\')")
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [pattern, pattern, pattern]
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit = max(1, min(500, int(limit)))
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        total = connection.execute(f"SELECT COUNT(*) FROM taxii_objects {where}", params).fetchone()[0]
        types = {row["type"]: row["total"] for row in connection.execute(f"SELECT type, COUNT(*) AS total FROM taxii_objects {where} GROUP BY type", params)}
        rows = connection.execute(
            f"""SELECT server_id, collection_id, object_id, type, name, pattern, modified, fetched_at
                FROM taxii_objects {where} ORDER BY modified DESC, object_id LIMIT ? OFFSET ?""",
            (*params, limit, max(0, int(offset))),
        ).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "types": types}


def get_object(database: str, server_id: str, collection_id: str, object_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        row = connection.execute(
            "SELECT raw_json FROM taxii_objects WHERE server_id = ? AND collection_id = ? AND object_id = ?",
            (server_id, collection_id, object_id),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"TAXII object not found: {object_id}")
    return json.loads(row["raw_json"])


def pattern_values(pattern: str) -> list[tuple[str, str]]:
    """(observable path, value) for each equality comparison in a STIX pattern."""
    values = []
    for kind, path, value in _COMPARISON.findall(pattern or ""):
        key = f"{kind}:{path}"
        if key in _OBSERVABLE_PATHS:
            values.append((key, value.replace("\\'", "'").replace("\\\\", "\\")))
    return values


def indicators_to_case(database: str, *, investigation_id: object, server_id: object, collection_id: object, object_ids: object) -> dict[str, Any]:
    """Write the observables of selected STIX indicators into a case."""
    from ..store import add_observation

    if not isinstance(investigation_id, str) or not investigation_id:
        raise ValidationError("investigation_id is required")
    if not isinstance(object_ids, list) or not object_ids or len(object_ids) > 500 or not all(isinstance(item, str) for item in object_ids):
        raise ValidationError("object_ids must be a list of 1 to 500 STIX ids")
    with _connection(database) as connection:
        require_module(connection, "taxii-feeds")
        server = _server_row(connection, str(server_id))
        marks = ",".join("?" * len(object_ids))
        rows = connection.execute(
            f"""SELECT object_id, name, pattern, raw_json FROM taxii_objects
                WHERE server_id = ? AND collection_id = ? AND type = 'indicator' AND object_id IN ({marks})""",
            (server["id"], collection_id, *object_ids),
        ).fetchall()
    lines = [
        f"STIX indicators from TAXII server {server['name']}, collection {collection_id}.",
        "Copied as published by the feed; not independently verified. The feed's address",
        "is kept in the reference, not in this text, so it is not taken for an indicator.",
        "",
    ]
    observables = 0
    for row in rows:
        values = pattern_values(row["pattern"])
        if not values:
            continue
        lines.append(f"Indicator {row['object_id']}: {row['name']}")
        for path, value in values:
            lines.append(f"  {path} = {value}")
            observables += 1
    if not observables:
        raise ValidationError("the selected objects have no simple observable patterns")
    observation = add_observation(
        database,
        investigation_id,
        f"TAXII indicators: {server['name']}"[:300],
        "\n".join(lines)[:20_000],
        f"note://garbage/taxii/{server['id']}/{collection_id}"[:500],
        "public",
    )
    return {"observation": observation, "indicator_count": len(rows), "observable_count": observables}
