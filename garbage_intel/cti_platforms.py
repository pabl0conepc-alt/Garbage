"""Two-way exchange with the analyst's own MISP and OpenCTI.

Each platform is one server: its address lives in the settings table and
its API key with the other API keys (never returned). An internal server may
be on a private address or a non-standard port when the analyst says so;
requests still go only to that host, and cloud metadata (link-local)
addresses stay refused.

* **Send a case**: MISP gets the case's MISP event (created, or updated when
  it already exists); OpenCTI gets each observable and a report that holds
  them, with a stable STIX id so sending again updates the same report.
* **Look up**: in the multi-source search, a value is searched in each
  configured platform (events or observables that contain it).
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable
from urllib.parse import urlsplit

from . import net
from .cti_export import GARBAGE_NAMESPACE, build_misp
from .db import _connection, record_activity, setting_value, utc_now
from .errors import NotFoundError, ValidationError
from .intel import Connector, ConnectorContext, Finding, register_connector
from .intel_keys import get_secret, set_key, delete_key
from .net import FetchResult, NetworkError
from .store import get_investigation

FETCH: Callable[..., FetchResult] = net.fetch
KINDS = {"misp": "MISP", "opencti": "OpenCTI"}
LOOKUP_TYPES = ("domain", "ipv4", "ipv6", "url", "email", "md5", "sha1", "sha256", "cve")
OPENCTI_TYPES = {
    "domain": ("Domain-Name", "DomainName"),
    "ip-dst": ("IPv4-Addr", "IPv4Addr"),
    "url": ("Url", "Url"),
    "email": ("Email-Addr", "EmailAddr"),
}
HASH_TYPES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def _kind(kind: str) -> str:
    if kind not in KINDS:
        raise NotFoundError(f"unknown platform: {kind}")
    return kind


def _config(database: str, kind: str) -> dict[str, Any]:
    with _connection(database) as connection:
        url = setting_value(connection, f"{kind}.url", "")
        private = setting_value(connection, f"{kind}.private", "false") == "true"
        last = setting_value(connection, f"{kind}.last_check", "")
    return {"url": url, "private": private, "last_check": last}


def _save_setting(connection: Any, key: str, value: str) -> None:
    connection.execute(
        """INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
        (key, value, utc_now()),
    )


def status(database: str) -> dict[str, Any]:
    items = {}
    for kind, name in KINDS.items():
        config = _config(database, kind)
        key = get_secret(database, kind)
        items[kind] = {
            "kind": kind,
            "name": name,
            "url": config["url"],
            "private": config["private"],
            "configured": bool(config["url"] and key),
            "key_hint": f"…{key[-4:]}" if len(key) >= 8 else "",
            "last_check": config["last_check"],
        }
    return {"items": items}


def configure(database: str, kind: str, *, url: object, private: object = False, key: object = None) -> dict[str, Any]:
    kind = _kind(kind)
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("url is required")
    url = url.strip().rstrip("/")
    allow_private = private is True
    try:
        net.validate_url(url + "/", allowed_hosts=[(urlsplit(url).hostname or "").lower()], allow_http=allow_private, allow_private=allow_private)
    except net.NetworkPolicyError as exc:
        raise ValidationError(f"{KINDS[kind]} address refused: {exc}") from exc
    if urlsplit(url).query or urlsplit(url).fragment:
        raise ValidationError("url must not carry a query or fragment")
    if key not in (None, ""):
        set_key(database, kind, key)
    with _connection(database) as connection:
        _save_setting(connection, f"{kind}.url", url)
        _save_setting(connection, f"{kind}.private", "true" if allow_private else "false")
        record_activity(connection, action="settings", target_type="cti-platform", target_id=kind, summary=f"{KINDS[kind]} server set: {url}")
    return status(database)["items"][kind]


def remove(database: str, kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    delete_key(database, kind)
    with _connection(database) as connection:
        connection.execute("DELETE FROM application_settings WHERE key IN (?, ?, ?)", (f"{kind}.url", f"{kind}.private", f"{kind}.last_check"))
    return {"kind": kind, "deleted": True}


# ---------------------------------------------------------------------------
# Transport


def _request(database: str, kind: str, path: str, *, payload: Any = None, method: str = "GET") -> tuple[int, Any]:
    config = _config(database, kind)
    key = get_secret(database, kind)
    if not config["url"] or not key:
        raise ValidationError(f"configure {KINDS[kind]} (address and API key) first")
    host = (urlsplit(config["url"]).hostname or "").lower()
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    headers.update({"Authorization": key} if kind == "misp" else {"Authorization": f"Bearer {key}"})
    try:
        result = FETCH(
            config["url"] + path,
            method=method,
            headers=headers,
            body=json.dumps(payload).encode("utf-8") if payload is not None else None,
            allowed_hosts=(host,),
            allow_http=config["private"],
            allow_private=config["private"],
            max_bytes=16 * 1024 * 1024,
            timeout=60.0,
        )
    except NetworkError as exc:
        raise NetworkError(str(exc).replace(key, "***")) from exc
    try:
        data = json.loads(result.body.decode("utf-8")) if result.body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = None
    if result.status in (401, 403) and not (kind == "misp" and _misp_exists(data)):
        raise NetworkError(f"{KINDS[kind]} refused the API key (HTTP {result.status})")
    return result.status, data


def _graphql(database: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    status_code, data = _request(database, "opencti", "/graphql", payload={"query": query, "variables": variables}, method="POST")
    if status_code >= 400 or not isinstance(data, dict):
        raise NetworkError(f"OpenCTI answered HTTP {status_code}")
    if data.get("errors"):
        message = str((data["errors"][0] or {}).get("message", "error"))[:300]
        raise NetworkError(f"OpenCTI: {message}")
    return data.get("data") or {}


def _misp_exists(data: Any) -> bool:
    text = json.dumps(data or {}).lower()
    return "already exists" in text or "event already" in text


def check(database: str, kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    if kind == "misp":
        status_code, data = _request(database, kind, "/servers/getVersion")
        if status_code >= 400 or not isinstance(data, dict):
            raise NetworkError(f"MISP answered HTTP {status_code}")
        version = str(data.get("version", ""))
    else:
        version = str((_graphql(database, "query { about { version } }", {}).get("about") or {}).get("version", ""))
    with _connection(database) as connection:
        _save_setting(connection, f"{kind}.last_check", utc_now())
    return {"kind": kind, "ok": True, "version": version[:40]}


# ---------------------------------------------------------------------------
# Sending a case


def _push_record(database: str, kind: str, investigation_id: str, remote_id: str, count: int, link: str) -> None:
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO cti_pushes (platform, investigation_id, remote_id, link, object_count, pushed_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(platform, investigation_id) DO UPDATE SET remote_id = excluded.remote_id, link = excluded.link,
                   object_count = excluded.object_count, pushed_at = excluded.pushed_at""",
            (kind, investigation_id, remote_id, link, count, utc_now()),
        )
        record_activity(
            connection, action="export", target_type="cti-platform", target_id=kind, investigation_id=investigation_id,
            summary=f"Case sent to {KINDS[kind]}: {count} object(s)",
        )


def pushes(database: str, investigation_id: str) -> dict[str, Any]:
    get_investigation(database, investigation_id)
    with _connection(database) as connection:
        rows = [dict(row) for row in connection.execute("SELECT * FROM cti_pushes WHERE investigation_id = ? ORDER BY platform", (investigation_id,))]
    return {"items": rows}


def _push_misp(database: str, investigation_id: str, tlp: str) -> dict[str, Any]:
    event = build_misp(database, investigation_id, tlp=tlp)
    event_uuid = event["Event"]["uuid"]
    status_code, data = _request(database, "misp", "/events/add", payload=event, method="POST")
    if status_code >= 400 and _misp_exists(data):
        status_code, data = _request(database, "misp", f"/events/edit/{event_uuid}", payload=event, method="POST")
    if status_code >= 400 or not isinstance(data, dict):
        message = (data or {}).get("message") if isinstance(data, dict) else ""
        raise NetworkError(f"MISP answered HTTP {status_code}" + (f": {str(message)[:200]}" if message else ""))
    remote = (data.get("Event") or {}).get("id") or event_uuid
    link = f"{_config(database, 'misp')['url']}/events/view/{remote}"
    count = len(event["Event"]["Attribute"])
    _push_record(database, "misp", investigation_id, str(remote), count, link)
    return {"kind": "misp", "remote_id": str(remote), "link": link, "objects": count}


_OBSERVABLE = """mutation Add($type: String!, $description: String, $DomainName: DomainNameAddInput, $IPv4Addr: IPv4AddrAddInput,
  $IPv6Addr: IPv6AddrAddInput, $Url: UrlAddInput, $EmailAddr: EmailAddrAddInput, $StixFile: StixFileAddInput) {
  stixCyberObservableAdd(type: $type, x_opencti_description: $description, DomainName: $DomainName, IPv4Addr: $IPv4Addr,
    IPv6Addr: $IPv6Addr, Url: $Url, EmailAddr: $EmailAddr, StixFile: $StixFile) { id }
}"""
_REPORT = """mutation Report($input: ReportAddInput!) { reportAdd(input: $input) { id } }"""


def _push_opencti(database: str, investigation_id: str, tlp: str) -> dict[str, Any]:
    event = build_misp(database, investigation_id, tlp=tlp)["Event"]
    case = get_investigation(database, investigation_id)
    ids: list[str] = []
    for attribute in event["Attribute"]:
        kind, value = attribute["type"], attribute["value"]
        variables: dict[str, Any] = {"description": attribute.get("comment", "")[:250]}
        if kind in HASH_TYPES:
            variables.update(type="StixFile", StixFile={"hashes": [{"algorithm": HASH_TYPES[kind], "hash": value}]})
        elif kind in OPENCTI_TYPES:
            stix_type, field = OPENCTI_TYPES[kind]
            if kind == "ip-dst" and ":" in value:
                stix_type, field = "IPv6-Addr", "IPv6Addr"
            variables.update(type=stix_type, **{field: {"value": value}})
        else:
            continue
        added = _graphql(database, _OBSERVABLE, variables).get("stixCyberObservableAdd") or {}
        if added.get("id"):
            ids.append(added["id"])
    # The case's creation time keeps the report's identity stable across sends.
    published = case.get("created_at") or utc_now()
    report = _graphql(
        database,
        _REPORT,
        {
            "input": {
                "stix_id": f"report--{uuid.uuid5(GARBAGE_NAMESPACE, f'opencti-report:{investigation_id}')}",
                "name": case["name"],
                "description": (case.get("objective") or case.get("description") or "Caso enviado pelo GARBAGE.")[:4000],
                "published": published,
                "report_types": ["threat-report"],
                "objects": ids,
            }
        },
    ).get("reportAdd") or {}
    remote = str(report.get("id") or "")
    if not remote:
        raise NetworkError("OpenCTI did not return the report")
    link = f"{_config(database, 'opencti')['url']}/dashboard/analyses/reports/{remote}"
    _push_record(database, "opencti", investigation_id, remote, len(ids), link)
    return {"kind": "opencti", "remote_id": remote, "link": link, "objects": len(ids)}


def push_case(database: str, kind: str, investigation_id: str, *, tlp: object = "amber") -> dict[str, Any]:
    kind = _kind(kind)
    get_investigation(database, investigation_id)
    if not isinstance(tlp, str):
        raise ValidationError("tlp must be text")
    return _push_misp(database, investigation_id, tlp) if kind == "misp" else _push_opencti(database, investigation_id, tlp)


# ---------------------------------------------------------------------------
# Lookups in the multi-source search


def _misp_lookup(context: ConnectorContext) -> list[Finding]:
    status_code, data = _request(context.database, "misp", "/attributes/restSearch", payload={
        "returnFormat": "json", "value": context.query_value, "limit": 100, "includeEventTags": True,
    }, method="POST")
    if status_code >= 400:
        raise NetworkError(f"MISP answered HTTP {status_code}")
    attributes = ((data or {}).get("response") or {}).get("Attribute") or [] if isinstance(data, dict) else []
    base = _config(context.database, "misp")["url"]
    events: dict[str, dict[str, Any]] = {}
    for attribute in attributes:
        event = attribute.get("Event") or {}
        event_id = str(attribute.get("event_id") or event.get("id") or "")
        if not event_id:
            continue
        item = events.setdefault(event_id, {
            "info": str(event.get("info") or f"evento {event_id}")[:300],
            "date": str(event.get("date") or "")[:10],
            "threat_level": str(event.get("threat_level_id") or ""),
            "link": f"{base}/events/view/{event_id}",
            "attribute_types": set(),
            "to_ids": False,
            "tags": set(),
        })
        item["attribute_types"].add(str(attribute.get("type") or ""))
        item["to_ids"] = item["to_ids"] or bool(attribute.get("to_ids"))
        for tag in (attribute.get("Tag") or []) + (event.get("Tag") or []):
            if isinstance(tag, dict) and tag.get("name"):
                item["tags"].add(str(tag["name"])[:80])
    return [
        Finding("misp-event", item["info"], {**item, "attribute_types": sorted(item["attribute_types"]), "tags": sorted(item["tags"])[:15], "event_id": event_id})
        for event_id, item in events.items()
    ][:50]


_LOOKUP = """query Lookup($search: String) {
  stixCyberObservables(search: $search, first: 10) { edges { node {
    id entity_type observable_value created_at x_opencti_score
    objectLabel { value }
    indicators(first: 5) { edges { node { name valid_from x_opencti_score } } }
    reports(first: 5) { edges { node { id name published } } }
  } } }
}"""


def _opencti_lookup(context: ConnectorContext) -> list[Finding]:
    data = _graphql(context.database, _LOOKUP, {"search": context.query_value})
    base = _config(context.database, "opencti")["url"]
    findings = []
    for edge in ((data.get("stixCyberObservables") or {}).get("edges") or []):
        node = edge.get("node") or {}
        value = str(node.get("observable_value") or "")
        if value.lower() != context.query_value.lower():
            continue
        reports = [item["node"] for item in ((node.get("reports") or {}).get("edges") or []) if item.get("node")]
        indicators = [item["node"] for item in ((node.get("indicators") or {}).get("edges") or []) if item.get("node")]
        findings.append(Finding("opencti-observable", f"{node.get('entity_type', '')} {value}"[:300], {
            "score": node.get("x_opencti_score"),
            "labels": [label.get("value") for label in node.get("objectLabel") or [] if label.get("value")][:15],
            "created": str(node.get("created_at") or "")[:10],
            "indicators": [str(item.get("name") or "")[:200] for item in indicators],
            "link": f"{base}/dashboard/observations/observables/{node.get('id', '')}",
        }))
        for report in reports:
            findings.append(Finding("opencti-report", str(report.get("name") or "")[:300], {
                "published": str(report.get("published") or "")[:10],
                "link": f"{base}/dashboard/analyses/reports/{report.get('id', '')}",
            }))
    return findings


for _connector in (
    Connector("misp", "MISP", "Events of your own MISP that contain the value (attribute search).",
              LOOKUP_TYPES, _misp_lookup, network=True, requires_key=True, key_id="misp", rate_per_minute=60, ttl_seconds=900),
    Connector("opencti", "OpenCTI", "Observables of your own OpenCTI with the value: score, labels, indicators and reports.",
              LOOKUP_TYPES[:-1], _opencti_lookup, network=True, requires_key=True, key_id="opencti", rate_per_minute=60, ttl_seconds=900),
):
    register_connector(_connector)
