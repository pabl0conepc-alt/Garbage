"""Local plugins: transforms written by the analyst, run in a child process.

A plugin is a folder in the plugins directory (``GARBAGE_PLUGINS_DIR``, or
``plugins`` next to the database) with ``plugin.json`` and Python code
exposing ``run(ctx)``. The manifest declares what the plugin accepts, what it
returns and which permissions it needs: the hosts it may fetch, how many
requests, how long it may run and how much it may answer. Nothing runs until
the analyst approves that exact code and those permissions; any change to a
file or a permission sends the plugin back to unapproved.

An approved plugin becomes a connector (``plugin-<id>``) and therefore a
transform, under the same network and target-contact gates as the built-in
sources. Each run is a fresh ``python -I`` process with a time limit, a
memory cap on POSIX, a minimal environment and no direct sockets; every
request goes through the host's SSRF-safe fetcher restricted to the declared
hosts. This isolates mistakes and bounds runaway code. It is not a sandbox
against hostile code: only install plugins you have read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pkgutil
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import net
from .db import ENTITY_TYPES, RELATIONSHIP_TYPES, _connection, record_activity, require_module, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .intel import (
    ARTIFACT_TYPES,
    Connector,
    ConnectorContext,
    Finding,
    connectors,
    register_connector,
    unregister_connector,
)
from .net import NetworkError, NetworkPolicyError

FETCH: Callable[..., net.FetchResult] = net.fetch
MANIFEST = "plugin.json"
_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,40}")
_RESULT_TYPE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
PERSONAL_TYPES = frozenset({"person", "username", "profile"})
MAX_FINDINGS = 200
MAX_PLUGIN_FILES = 50
MAX_PLUGIN_BYTES = 2 * 1024 * 1024
DEFAULTS = {"network": [], "contacts_target": False, "max_requests": 10, "timeout_seconds": 20, "max_output_kb": 256}
LIMITS = {"max_requests": 50, "timeout_seconds": 60, "max_output_kb": 1024}

_LOCK = threading.Lock()
_LOADED: dict[str, dict[str, Any]] = {}


def plugins_dir(database: str) -> Path:
    configured = os.environ.get("GARBAGE_PLUGINS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(database).expanduser().resolve().parent / "plugins"


def connector_id(plugin_id: str) -> str:
    return f"plugin-{plugin_id}"


# ---------------------------------------------------------------------------
# Manifest


def validate_manifest(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("the manifest must be a JSON object")
    unknown = set(raw) - {"id", "name", "version", "description", "author", "entry", "accepts", "outputs", "permissions"}
    if unknown:
        raise ValidationError(f"unknown manifest fields: {', '.join(sorted(unknown))}")
    plugin_id = raw.get("id")
    if not isinstance(plugin_id, str) or not _ID.fullmatch(plugin_id):
        raise ValidationError("id must be 2-41 lowercase letters, digits or hyphens")
    texts = {}
    for key, limit, required in (("name", 80, True), ("version", 20, True), ("description", 300, True), ("author", 80, False)):
        value = raw.get(key, "")
        if not isinstance(value, str) or (required and not value.strip()) or len(value) > limit:
            raise ValidationError(f"{key} must be text of at most {limit} characters")
        texts[key] = value.strip()
    entry = raw.get("entry", "main.py")
    if not isinstance(entry, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}\.py", entry):
        raise ValidationError("entry must be a .py file name in the plugin folder")
    accepts = raw.get("accepts")
    if not isinstance(accepts, list) or not accepts or not set(accepts) <= set(ARTIFACT_TYPES):
        raise ValidationError(f"accepts must list artifact types among: {', '.join(ARTIFACT_TYPES)}")
    outputs = []
    for item in raw.get("outputs") or []:
        if not isinstance(item, dict) or not _RESULT_TYPE.fullmatch(str(item.get("result_type", ""))):
            raise ValidationError("each output needs a result_type of lowercase letters, digits or hyphens")
        entity_type = item.get("entity_type")
        if entity_type is not None and (entity_type not in ENTITY_TYPES or entity_type in PERSONAL_TYPES):
            raise ValidationError("output entity_type must be a non-personal entity type")
        relationship = item.get("relationship_type", "related-to")
        if relationship not in RELATIONSHIP_TYPES:
            raise ValidationError("output relationship_type is not a known relationship type")
        outputs.append({"result_type": item["result_type"], "entity_type": entity_type, "relationship_type": relationship})
    permissions = dict(DEFAULTS)
    declared = raw.get("permissions") or {}
    if not isinstance(declared, dict) or set(declared) - set(DEFAULTS):
        raise ValidationError(f"permissions may only hold: {', '.join(DEFAULTS)}")
    hosts = declared.get("network", [])
    if not isinstance(hosts, list) or not all(isinstance(host, str) and _HOST.fullmatch(host.lower()) for host in hosts) or len(hosts) > 10:
        raise ValidationError("permissions.network must list up to 10 host names")
    permissions["network"] = sorted({host.lower() for host in hosts})
    contacts = declared.get("contacts_target", False)
    if not isinstance(contacts, bool):
        raise ValidationError("permissions.contacts_target must be true or false")
    permissions["contacts_target"] = contacts
    for key, ceiling in LIMITS.items():
        value = declared.get(key, DEFAULTS[key])
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
            raise ValidationError(f"permissions.{key} must be between 1 and {ceiling}")
        permissions[key] = value
    return {"id": plugin_id, **texts, "entry": entry, "accepts": sorted(set(accepts)), "outputs": outputs, "permissions": permissions}


def _code_digest(folder: Path, manifest_bytes: bytes) -> str:
    """SHA-256 over the manifest and every .py file, in name order."""
    digest = hashlib.sha256(b"manifest\0" + manifest_bytes)
    files = sorted(path for path in folder.rglob("*.py") if "__pycache__" not in path.parts)
    if len(files) > MAX_PLUGIN_FILES:
        raise ValidationError(f"a plugin may hold at most {MAX_PLUGIN_FILES} Python files")
    total = 0
    for path in files:
        data = path.read_bytes()
        total += len(data)
        if total > MAX_PLUGIN_BYTES:
            raise ValidationError("plugin code exceeds 2 MiB")
        digest.update(b"\0" + str(path.relative_to(folder)).encode() + b"\0" + data)
    return digest.hexdigest()


def discover(database: str) -> list[dict[str, Any]]:
    """Every folder in the plugins directory with its manifest or its error."""
    root = plugins_dir(database)
    found = []
    if not root.is_dir():
        return found
    for folder in sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith((".", "_")))[:100]:
        item: dict[str, Any] = {"folder": folder.name, "path": str(folder)}
        try:
            manifest_bytes = (folder / MANIFEST).read_bytes()
            manifest = validate_manifest(json.loads(manifest_bytes.decode("utf-8")))
            if not (folder / manifest["entry"]).is_file():
                raise ValidationError(f"entry file {manifest['entry']} is missing")
            item.update(manifest=manifest, sha256=_code_digest(folder, manifest_bytes), error="")
        except FileNotFoundError:
            item.update(manifest=None, sha256="", error="plugin.json is missing")
        except (ValueError, ValidationError) as exc:
            item.update(manifest=None, sha256="", error=str(exc)[:300])
        found.append(item)
    return found


# ---------------------------------------------------------------------------
# Registry and approval


def list_plugins(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "plugins")
        approvals = {row["id"]: dict(row) for row in connection.execute("SELECT * FROM plugin_registry")}
    items = []
    for item in discover(database):
        manifest = item["manifest"]
        approval = approvals.get(manifest["id"]) if manifest else None
        if item["error"]:
            state = "invalid"
        elif not approval or not approval["enabled"]:
            state = "disabled"
        elif approval["approved_sha256"] != item["sha256"]:
            state = "changed"
        else:
            state = "enabled"
        items.append(
            {
                **item,
                "id": manifest["id"] if manifest else item["folder"],
                "state": state,
                "loaded": bool(manifest) and manifest["id"] in _LOADED,
                "approved_at": approval["approved_at"] if approval else "",
                "last_error": approval["last_error"] if approval else "",
            }
        )
    return {"directory": str(plugins_dir(database)), "items": items, "isolation": "separate python -I process, time and memory limits, brokered network; not a sandbox for hostile code"}


def _find(database: str, plugin_id: str) -> dict[str, Any]:
    for item in discover(database):
        if item["manifest"] and item["manifest"]["id"] == plugin_id:
            return item
    raise NotFoundError(f"plugin not found: {plugin_id}")


def enable(database: str, plugin_id: str, *, sha256: object) -> dict[str, Any]:
    """Approve the plugin's current code and permissions and load it.

    ``sha256`` must be the digest the analyst reviewed, so code that changed
    between listing and approval is not approved by accident."""
    item = _find(database, plugin_id)
    if item["error"]:
        raise ConflictError(f"the plugin is invalid: {item['error']}")
    if sha256 != item["sha256"]:
        raise ConflictError("the plugin changed since it was listed; review it again")
    manifest = item["manifest"]
    if connector_id(plugin_id) in {connector.connector_id for connector in connectors()} and plugin_id not in _LOADED:
        raise ConflictError("a built-in connector already uses this id")
    with _connection(database) as connection:
        require_module(connection, "plugins")
        connection.execute(
            """INSERT INTO plugin_registry (id, enabled, approved_sha256, approved_manifest_json, approved_at, last_error)
               VALUES (?, 1, ?, ?, ?, '')
               ON CONFLICT(id) DO UPDATE SET enabled = 1, approved_sha256 = excluded.approved_sha256,
                   approved_manifest_json = excluded.approved_manifest_json, approved_at = excluded.approved_at, last_error = ''""",
            (plugin_id, item["sha256"], json.dumps(manifest, sort_keys=True), utc_now()),
        )
        record_activity(connection, action="plugin", target_type="plugin", target_id=plugin_id,
                        summary=f"Plugin approved: {manifest['name']} {manifest['version']} ({item['sha256'][:12]})")
    _load(database, item)
    return list_plugins(database)


def disable(database: str, plugin_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "plugins")
        updated = connection.execute("UPDATE plugin_registry SET enabled = 0 WHERE id = ?", (plugin_id,)).rowcount
        if updated:
            record_activity(connection, action="plugin", target_type="plugin", target_id=plugin_id, summary=f"Plugin disabled: {plugin_id}")
    _unload(plugin_id)
    return list_plugins(database)


def load_approved(database: str) -> list[str]:
    """Register every approved, unchanged plugin (called at startup)."""
    try:
        listing = list_plugins(database)
    except Exception:  # noqa: BLE001 - a broken plugins folder must not stop the server
        return []
    loaded = []
    for item in listing["items"]:
        if item["state"] == "enabled":
            _load(database, item)
            loaded.append(item["id"])
        elif item["manifest"]:
            _unload(item["manifest"]["id"])
    return loaded


def _load(database: str, item: dict[str, Any]) -> None:
    manifest = item["manifest"]
    permissions = manifest["permissions"]
    folder = Path(item["path"])
    approved = item["sha256"]

    def run(context: ConnectorContext) -> list[Finding]:
        # Re-check at run time: a file edited after approval must not run.
        current = next((entry for entry in discover(database) if entry["manifest"] and entry["manifest"]["id"] == manifest["id"]), None)
        if current is None or current["sha256"] != approved:
            raise NetworkError("the plugin changed after approval; approve it again")
        return execute(manifest, folder, context.query_type, context.query_value)

    with _LOCK:
        _LOADED[manifest["id"]] = {"manifest": manifest, "sha256": approved}
    register_connector(
        Connector(
            connector_id(manifest["id"]),
            manifest["name"],
            manifest["description"],
            tuple(manifest["accepts"]),
            run,
            network=bool(permissions["network"]),
            contacts_target=permissions["contacts_target"],
            rate_per_minute=30,
            source_url="",
        )
    )


def _unload(plugin_id: str) -> None:
    with _LOCK:
        known = _LOADED.pop(plugin_id, None)
    if known is not None:
        unregister_connector(connector_id(plugin_id))


def outputs_for(transform_id: str) -> list[dict[str, Any]]:
    """Declared outputs of a loaded plugin connector (empty otherwise)."""
    if not transform_id.startswith("plugin-"):
        return []
    with _LOCK:
        known = _LOADED.get(transform_id[len("plugin-"):])
    return known["manifest"]["outputs"] if known else []


# ---------------------------------------------------------------------------
# Execution


def _runner_source() -> str:
    data = pkgutil.get_data("garbage_intel", "plugin_runner.py")
    if data is None:
        raise NetworkError("the plugin runner is missing from the installation")
    return data.decode("utf-8")


def _environment() -> dict[str, str]:
    keep = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _broker(manifest: dict[str, Any], request: dict[str, Any], used: int) -> dict[str, Any]:
    permissions = manifest["permissions"]
    if not permissions["network"]:
        return {"id": request.get("id"), "error": "this plugin declared no network access"}
    if used > permissions["max_requests"]:
        return {"id": request.get("id"), "error": f"request limit of {permissions['max_requests']} reached"}
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    headers = {str(key)[:100]: str(value)[:1000] for key, value in list(headers.items())[:20]
               if str(key).lower() not in {"host", "cookie", "authorization", "proxy-authorization"}}
    try:
        result = FETCH(
            str(request.get("url", "")),
            headers=headers,
            allowed_hosts=tuple(permissions["network"]),
            max_bytes=permissions["max_output_kb"] * 1024 * 4,
            timeout=min(30.0, float(permissions["timeout_seconds"])),
        )
    except (NetworkError, NetworkPolicyError) as exc:
        return {"id": request.get("id"), "error": str(exc)[:300]}
    return {
        "id": request.get("id"),
        "status": result.status,
        "headers": dict(result.headers),
        "final_url": result.final_url,
        "body_base64": base64.b64encode(result.body).decode("ascii"),
    }


def _clean_findings(manifest: dict[str, Any], raw: Any) -> list[Finding]:
    if not isinstance(raw, list):
        raise NetworkError("the plugin returned no list of findings")
    findings = []
    for item in raw[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        result_type = str(item.get("result_type", ""))
        value = item.get("value")
        if not _RESULT_TYPE.fullmatch(result_type) or not isinstance(value, (str, int, float)):
            continue
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        encoded = json.dumps(data, default=str)
        if len(encoded) > 8000:
            data = {"note": "data omitted: over 8000 bytes"}
        source = str(item.get("source_url", ""))
        if not source.startswith(("https://", "http://")):
            source = ""
        findings.append(Finding(result_type, str(value)[:2000], json.loads(json.dumps(data, default=str)), source[:500]))
    return findings


def execute(manifest: dict[str, Any], folder: Path, query_type: str, query_value: str) -> list[Finding]:
    """Run the plugin once in a child process and return its findings."""
    permissions = manifest["permissions"]
    timeout = permissions["timeout_seconds"]
    limit = permissions["max_output_kb"] * 1024
    process = subprocess.Popen(
        [sys.executable, "-I", "-X", "utf8", "-c", _runner_source()],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(folder),
        env=_environment(),
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def reader() -> None:
        assert process.stdout is not None
        received = 0
        for line in process.stdout:
            received += len(line)
            if received > limit * 2:
                lines.put('{"op": "error", "message": "output limit exceeded"}')
                break
            lines.put(line)
        lines.put(None)

    def drain_stderr() -> None:
        assert process.stderr is not None
        for _ in process.stderr:
            pass  # plugin prints are discarded; they must not fill the pipe

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=drain_stderr, daemon=True).start()
    deadline = time.monotonic() + timeout
    requests = 0
    try:
        assert process.stdin is not None
        process.stdin.write(json.dumps({"plugin_dir": str(folder), "entry": manifest["entry"], "input": {"type": query_type, "value": query_value}, "timeout": timeout}) + "\n")
        process.stdin.flush()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NetworkError(f"the plugin did not finish within {timeout} s")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                raise NetworkError("the plugin exited without a result")
            try:
                message = json.loads(line)
            except ValueError as exc:
                raise NetworkError("the plugin broke the protocol") from exc
            operation = message.get("op") if isinstance(message, dict) else None
            if operation == "fetch":
                requests += 1
                process.stdin.write(json.dumps(_broker(manifest, message, requests)) + "\n")
                process.stdin.flush()
            elif operation == "result":
                return _clean_findings(manifest, message.get("findings"))
            elif operation == "error":
                raise NetworkError(f"the plugin failed: {str(message.get('message', ''))[:300]}")
            else:
                raise NetworkError("the plugin broke the protocol")
    except BrokenPipeError as exc:
        raise NetworkError("the plugin exited without a result") from exc
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
