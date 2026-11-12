"""Public, keyless intelligence connectors (plan phase 2).

Every connector is passive: it queries a public registry, resolver or archive
about the artifact and never touches the artifact's own infrastructure.
All requests go through ``garbage_intel.net.fetch`` (SSRF-safe, bounded) and
every finding keeps the source URL and the SHA-256 of the raw response.

Privacy rule: RDAP contact data is reduced to organisation-level roles
(registrar, abuse, sponsoring organisation). Registrant, administrative and
technical vCards are never stored, even when a registry still publishes them.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError

# Indirection so tests can replay recorded responses without a network.
FETCH: Callable[..., FetchResult] = net.fetch

DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_HOSTS = ("cloudflare-dns.com",)
RDAP_BOOTSTRAP = "https://rdap.org"
CRTSH_URL = "https://crt.sh/"
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
EPSS_URL = "https://api.first.org/data/v1/epss"
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
_ORG_ROLES = {"registrar", "abuse", "sponsor", "reseller", "noc"}
# On RIR network and autnum objects the registrant is the address holder, an
# organisation; on domain objects it can be a natural person and is dropped.
_NETWORK_ROLES = _ORG_ROLES | {"registrant"}


def _get_json(
    url: str,
    *,
    hosts: tuple[str, ...] | None = None,
    headers: dict[str, str] | None = None,
    max_bytes: int = 2 * 1024 * 1024,
    timeout: float = 15.0,
) -> tuple[Any, FetchResult]:
    result = FETCH(
        url,
        headers={"Accept": "application/json", **(headers or {})},
        allowed_hosts=hosts,
        max_bytes=max_bytes,
        timeout=timeout,
    )
    if result.status == 404:
        return None, result
    if result.status == 429:
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        return json.loads(result.body.decode("utf-8")), result
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


def _host_of(context: ConnectorContext) -> str:
    if context.query_type == "domain":
        return context.query_value
    if context.query_type == "email":
        return context.query_value.rsplit("@", 1)[-1]
    if context.query_type == "url":
        host = (urlsplit(context.query_value).hostname or "").rstrip(".")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
    return ""


# ---------------------------------------------------------------------------
# DNS over HTTPS


def doh_query(name: str, record_type: str) -> tuple[list[str], FetchResult]:
    url = f"{DOH_URL}?name={quote(name, safe='')}&type={record_type}"
    data, result = _get_json(
        url, hosts=DOH_HOSTS, headers={"Accept": "application/dns-json"}
    )
    if not isinstance(data, dict):
        return [], result
    wanted = DNS_TYPES[record_type]
    answers = [
        str(item.get("data", "")).strip()
        for item in data.get("Answer") or []
        if isinstance(item, dict) and item.get("type") == wanted
    ]
    return [answer for answer in answers if answer], result


def _dns_connector(context: ConnectorContext) -> list[Finding]:
    host = _host_of(context)
    if not host:
        return []
    findings: list[Finding] = []
    record_types = ("MX",) if context.query_type == "email" else (
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"
    )
    for record_type in record_types:
        answers, result = doh_query(host, record_type)
        for answer in answers:
            data: dict[str, Any] = {"record": record_type, "name": host}
            if record_type == "TXT":
                value = answer.strip('"')
            elif record_type == "MX" and answer.split()[-1:] == ["."]:
                value = answer
                data["null_mx"] = True  # RFC 7505: the domain accepts no mail
            else:
                value = answer.rstrip(".")
            if record_type == "TXT" and value.lower().startswith("v=spf1"):
                data["policy"] = "spf"
            findings.append(
                Finding(f"dns-{record_type.lower()}", value, data, result.final_url, result.sha256)
            )
    if context.query_type != "email":
        answers, result = doh_query(f"_dmarc.{host}", "TXT")
        for answer in answers:
            value = answer.strip('"')
            if value.lower().startswith("v=dmarc1"):
                findings.append(
                    Finding("dns-dmarc", value, {"record": "TXT", "name": f"_dmarc.{host}"}, result.final_url, result.sha256)
                )
    return findings


# ---------------------------------------------------------------------------
# Team Cymru IP-to-ASN (queried as DNS TXT over HTTPS)


def _cymru_origin_name(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
    nibbles = parsed.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _cymru_fields(answer: str) -> list[str]:
    return [part.strip() for part in answer.strip('"').split("|")]


def _cymru_connector(context: ConnectorContext) -> list[Finding]:
    findings: list[Finding] = []
    if context.query_type in {"ipv4", "ipv6"}:
        answers, result = doh_query(_cymru_origin_name(context.query_value), "TXT")
        asns: list[str] = []
        for answer in answers:
            fields = _cymru_fields(answer)
            if len(fields) < 5:
                continue
            for asn in fields[0].split():
                asns.append(asn)
                findings.append(
                    Finding(
                        "asn",
                        f"AS{asn}",
                        {
                            "prefix": fields[1],
                            "country": fields[2],
                            "registry": fields[3],
                            "allocated": fields[4],
                        },
                        result.final_url,
                        result.sha256,
                    )
                )
        targets = list(dict.fromkeys(asns))[:3]
    elif context.query_type == "asn":
        targets = [context.query_value.upper().removeprefix("AS")]
    else:
        return []
    for asn in targets:
        answers, result = doh_query(f"AS{asn}.asn.cymru.com", "TXT")
        for answer in answers:
            fields = _cymru_fields(answer)
            if len(fields) >= 5:
                findings.append(
                    Finding(
                        "as-name",
                        fields[4],
                        {"asn": f"AS{asn}", "country": fields[1], "registry": fields[2], "allocated": fields[3]},
                        result.final_url,
                        result.sha256,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# RDAP (registration data, organisation level only)


def _vcard_name(entity: dict[str, Any]) -> str:
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return ""
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
            if isinstance(item[3], str) and item[3].strip():
                return item[3].strip()
    return ""


def _vcard_emails(entity: dict[str, Any]) -> list[str]:
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return []
    return [
        item[3].strip()
        for item in card[1]
        if isinstance(item, list) and len(item) >= 4 and item[0] == "email"
        and isinstance(item[3], str) and item[3].strip()
    ]


def _org_entities(
    entities: object, allowed_roles: set[str], depth: int = 0
) -> list[tuple[str, str, list[str]]]:
    found: list[tuple[str, str, list[str]]] = []
    if not isinstance(entities, list) or depth > 3:
        return found
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = {role for role in entity.get("roles") or [] if isinstance(role, str)}
        kept = sorted(roles & allowed_roles)
        if kept:
            name = _vcard_name(entity)
            emails = _vcard_emails(entity) if "abuse" in kept else []
            if name or emails:
                found.append((",".join(kept), name, emails))
        found.extend(_org_entities(entity.get("entities"), allowed_roles, depth + 1))
    return found


def _rdap_path(context: ConnectorContext) -> str:
    kind, value = context.query_type, context.query_value
    if kind == "domain":
        return f"/domain/{quote(value)}"
    if kind in {"ipv4", "ipv6"}:
        return f"/ip/{quote(value, safe=':')}"
    if kind == "cidr":
        return f"/ip/{quote(value, safe=':/')}"
    if kind == "asn":
        return f"/autnum/{value.upper().removeprefix('AS')}"
    return ""


def _rdap_connector(context: ConnectorContext) -> list[Finding]:
    path = _rdap_path(context)
    if not path:
        return []
    data, result = _get_json(
        RDAP_BOOTSTRAP + path,
        headers={"Accept": "application/rdap+json, application/json"},
    )
    if not isinstance(data, dict):
        return []
    source, digest = result.final_url, result.sha256
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(result_type: str, value: object, extra: dict[str, Any] | None = None) -> None:
        if not isinstance(value, (str, int)) or not str(value).strip():
            return
        key = (result_type, str(value).strip(), json.dumps(extra or {}, sort_keys=True))
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(result_type, key[1], extra or {}, source, digest))

    add("rdap-handle", data.get("handle"), {"object": data.get("objectClassName", "")})
    add("rdap-name", data.get("ldhName") or data.get("name"))
    for status in data.get("status") or []:
        add("rdap-status", status)
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") != "last update of RDAP database":
            add("rdap-event", event.get("eventDate"), {"action": event.get("eventAction", "")})
    for nameserver in data.get("nameservers") or []:
        if isinstance(nameserver, dict):
            add("nameserver", str(nameserver.get("ldhName", "")).lower().rstrip("."))
    roles = _NETWORK_ROLES if data.get("objectClassName") in {"ip network", "autnum"} else _ORG_ROLES
    for role, name, emails in _org_entities(data.get("entities"), roles):
        if name:
            add("organization", name, {"role": role})
        for email in emails:
            add("abuse-contact", email, {"role": role})
    if "startAddress" in data:
        add("ip-range", f"{data.get('startAddress')} - {data.get('endAddress')}", {
            "type": data.get("type", ""),
            "country": data.get("country", ""),
        })
    for cidr in data.get("cidr0_cidrs") or []:
        if isinstance(cidr, dict):
            prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
            if prefix:
                add("cidr", f"{prefix}/{cidr.get('length')}")
    if "startAutnum" in data:
        add("asn-range", f"AS{data.get('startAutnum')} - AS{data.get('endAutnum')}", {
            "country": data.get("country", ""),
        })
    secure = data.get("secureDNS")
    if isinstance(secure, dict) and "delegationSigned" in secure:
        add("dnssec", "signed" if secure.get("delegationSigned") else "unsigned")
    return findings


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)


def _crtsh_connector(context: ConnectorContext) -> list[Finding]:
    host = _host_of(context)
    if not host:
        return []
    url = f"{CRTSH_URL}?q={quote('%.' + host, safe='')}&output=json&exclude=expired"
    data, result = _get_json(url, hosts=("crt.sh",), max_bytes=16 * 1024 * 1024, timeout=45.0)
    if not isinstance(data, list):
        return []
    names: dict[str, dict[str, Any]] = {}
    issuers: dict[str, int] = {}
    suffix = "." + host.lower()
    for row in data:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name", ""))
        issuers[issuer] = issuers.get(issuer, 0) + 1
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lower().rstrip(".")
            if not name or not (name == host.lower() or name.endswith(suffix)):
                continue
            entry = names.setdefault(
                name,
                {"certificates": 0, "first_seen": row.get("not_before", ""), "last_seen": row.get("not_before", "")},
            )
            entry["certificates"] += 1
            seen = str(row.get("not_before", ""))
            if seen and (not entry["first_seen"] or seen < entry["first_seen"]):
                entry["first_seen"] = seen
            if seen > str(entry["last_seen"]):
                entry["last_seen"] = seen
    findings = [
        Finding("ct-name", name, {**meta, "wildcard": name.startswith("*.")}, result.final_url, result.sha256)
        for name, meta in sorted(names.items(), key=lambda item: (-item[1]["certificates"], item[0]))
    ]
    findings.extend(
        Finding("ct-issuer", issuer, {"certificates": count}, result.final_url, result.sha256)
        for issuer, count in sorted(issuers.items(), key=lambda item: -item[1])[:10]
        if issuer
    )
    return findings


# ---------------------------------------------------------------------------
# Internet Archive CDX


def _wayback_connector(context: ConnectorContext) -> list[Finding]:
    target = context.query_value if context.query_type == "url" else _host_of(context)
    if not target:
        return []
    url = (
        f"{WAYBACK_CDX}?url={quote(target, safe='')}&output=json&limit=200"
        "&fl=timestamp,original,statuscode,mimetype,digest&collapse=digest"
    )
    data, result = _get_json(url, hosts=("web.archive.org",), timeout=30.0)
    if not isinstance(data, list) or len(data) < 2:
        return []
    header, rows = data[0], data[1:]
    if not isinstance(header, list):
        return []
    captures = [dict(zip(header, row)) for row in rows if isinstance(row, list)]
    if not captures:
        return []
    timestamps = sorted(str(item.get("timestamp", "")) for item in captures)
    findings = [
        Finding(
            "archive-summary",
            f"{len(captures)} distinct captures",
            {"first": timestamps[0], "last": timestamps[-1], "limited_to": 200},
            result.final_url,
            result.sha256,
        )
    ]
    for item in captures[-25:]:
        stamp = str(item.get("timestamp", ""))
        original = str(item.get("original", ""))
        findings.append(
            Finding(
                "archive-capture",
                f"https://web.archive.org/web/{stamp}/{original}",
                {
                    "timestamp": stamp,
                    "status": item.get("statuscode", ""),
                    "mimetype": item.get("mimetype", ""),
                    "digest": item.get("digest", ""),
                },
                result.final_url,
                result.sha256,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# FIRST EPSS and local CISA KEV


def _epss_connector(context: ConnectorContext) -> list[Finding]:
    data, result = _get_json(f"{EPSS_URL}?cve={quote(context.query_value)}", hosts=("api.first.org",))
    if not isinstance(data, dict):
        return []
    findings = []
    for row in data.get("data") or []:
        if not isinstance(row, dict) or row.get("cve") != context.query_value:
            continue
        try:
            score = float(row.get("epss", ""))
            percentile = float(row.get("percentile", ""))
        except (TypeError, ValueError):
            continue
        findings.append(
            Finding(
                "epss",
                f"{score:.4f}",
                {"percentile": round(percentile, 4), "date": row.get("date", ""), "model_version": data.get("version", "")},
                result.final_url,
                result.sha256,
            )
        )
    return findings


def _kev_connector(context: ConnectorContext) -> list[Finding]:
    from .cisa_kev import CisaKevError, list_cached

    try:
        cached = list_cached(context.database, search=context.query_value, limit=5)
    except CisaKevError:
        return [
            Finding(
                "notice",
                "Local KEV catalogue has not been refreshed",
                {"meaning": "absence from this result says nothing about KEV status"},
            )
        ]
    findings = []
    for item in cached.get("items") or []:
        if item.get("cve_id") != context.query_value:
            continue
        findings.append(
            Finding(
                "kev-entry",
                item["cve_id"],
                {
                    "vendor_project": item.get("vendor_project", ""),
                    "product": item.get("product", ""),
                    "vulnerability_name": item.get("vulnerability_name", ""),
                    "date_added": item.get("date_added", ""),
                    "due_date": item.get("due_date", ""),
                    "ransomware_use": item.get("ransomware_use", ""),
                },
                cached.get("source_url", ""),
                cached.get("sha256", ""),
            )
        )
    return findings


CONNECTORS = (
    Connector(
        connector_id="dns-doh",
        name="DNS (DNS over HTTPS)",
        description="A, AAAA, CNAME, MX, NS, TXT, CAA, SPF and DMARC records through Cloudflare's public resolver. The resolver sees the queried name.",
        accepts=("domain", "url", "email"),
        run=_dns_connector,
        network=True,
        rate_per_minute=120,
        ttl_seconds=3600,
        source_url=DOH_URL,
    ),
    Connector(
        connector_id="cymru-asn",
        name="Team Cymru IP-to-ASN",
        description="Origin ASN, announced prefix, country, registry and AS name for an IP or ASN, via DNS TXT records.",
        accepts=("ipv4", "ipv6", "asn"),
        run=_cymru_connector,
        network=True,
        rate_per_minute=60,
        ttl_seconds=86400,
        source_url="https://www.team-cymru.com/ip-asn-mapping",
    ),
    Connector(
        connector_id="rdap",
        name="RDAP registration data",
        description="Registry status, dates, nameservers, ranges and organisation-level contacts (registrar, abuse). Personal registrant data is not kept.",
        accepts=("domain", "ipv4", "ipv6", "cidr", "asn"),
        run=_rdap_connector,
        network=True,
        rate_per_minute=30,
        ttl_seconds=86400,
        source_url=RDAP_BOOTSTRAP,
    ),
    Connector(
        connector_id="crtsh",
        name="Certificate Transparency (crt.sh)",
        description="Names seen in unexpired certificates for the domain and its subdomains, with issuers.",
        accepts=("domain", "url", "email"),
        run=_crtsh_connector,
        network=True,
        rate_per_minute=10,
        ttl_seconds=86400,
        source_url=CRTSH_URL,
    ),
    Connector(
        connector_id="wayback",
        name="Internet Archive (Wayback CDX)",
        description="Distinct archived captures of a domain or URL with timestamps and status codes.",
        accepts=("domain", "url"),
        run=_wayback_connector,
        network=True,
        rate_per_minute=15,
        ttl_seconds=86400,
        source_url="https://web.archive.org/",
    ),
    Connector(
        connector_id="first-epss",
        name="FIRST EPSS",
        description="Exploit Prediction Scoring System probability and percentile for a CVE.",
        accepts=("cve",),
        run=_epss_connector,
        network=True,
        rate_per_minute=60,
        ttl_seconds=86400,
        source_url="https://www.first.org/epss/",
    ),
    Connector(
        connector_id="cisa-kev-local",
        name="CISA KEV (local snapshot)",
        description="Whether the CVE is in the locally cached CISA KEV catalogue. Refresh the catalogue on the CISA KEV page.",
        accepts=("cve",),
        run=_kev_connector,
    ),
)

for _connector in CONNECTORS:
    register_connector(_connector)
