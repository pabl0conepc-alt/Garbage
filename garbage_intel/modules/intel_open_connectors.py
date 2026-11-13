"""More public intelligence connectors (plan phase 7, no key required).

Shodan InternetDB, RIPEstat, PeeringDB, IPinfo, CIRCL hashlookup, urlscan.io
search, Cert Spotter, NVD and OSV. All are passive third-party lookups about
the artifact; none contacts the artifact's own servers. urlscan.io, NVD and
IPinfo accept an optional key that only raises their rate limits.
"""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import quote, urlencode, urlsplit

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError

FETCH: Callable[..., FetchResult] = net.fetch
RIPESTAT = "https://stat.ripe.net/data"
SOURCE_APP = "garbage-intel"


def request_json(
    url: str,
    *,
    hosts: tuple[str, ...],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    not_found: tuple[int, ...] = (404,),
    max_bytes: int = 4 * 1024 * 1024,
) -> tuple[Any, FetchResult]:
    """Fetch and decode JSON; ``None`` for the provider's "not found" codes."""
    result = FETCH(
        url,
        method=method,
        headers={"Accept": "application/json", **(headers or {})},
        body=body,
        allowed_hosts=hosts,
        max_bytes=max_bytes,
        timeout=20.0,
    )
    if result.status in not_found:
        return None, result
    if result.status in (401, 403):
        raise NetworkError(f"the source rejected the API key or requires one (HTTP {result.status})")
    if result.status == 429:
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        return json.loads(result.body.decode("utf-8")), result
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


def _list(value: Any, limit: int = 50) -> list[Any]:
    return [item for item in value if item not in (None, "")][:limit] if isinstance(value, list) else []


def _text(value: Any, limit: int = 300) -> str:
    return str(value)[:limit] if value not in (None, "") else ""


# ---------------------------------------------------------------------------
# Shodan InternetDB: open ports, hostnames, CPEs, tags and CVEs per IP


def _internetdb(context: ConnectorContext) -> list[Finding]:
    data, result = request_json(f"https://internetdb.shodan.io/{context.query_value}", hosts=("internetdb.shodan.io",))
    if not isinstance(data, dict):
        return []
    source = (result.final_url, result.sha256)
    findings = [Finding("open-port", str(port), {"source": "Shodan scan data"}, *source) for port in _list(data.get("ports"), 100)]
    findings += [Finding("hostname", _text(name, 253), {}, *source) for name in _list(data.get("hostnames"))]
    findings += [Finding("cpe", _text(cpe), {}, *source) for cpe in _list(data.get("cpes"))]
    findings += [Finding("tag", _text(tag, 60), {}, *source) for tag in _list(data.get("tags"))]
    findings += [Finding("cve", _text(cve, 30), {"meaning": "listed by Shodan from banner versions; not verified"}, *source) for cve in _list(data.get("vulns"), 100)]
    return findings


# ---------------------------------------------------------------------------
# RIPEstat: routing, holder and abuse contact for IPs, prefixes and ASNs


def _ripestat(context: ConnectorContext) -> list[Finding]:
    resource = context.query_value
    findings: list[Finding] = []

    def call(name: str) -> tuple[Any, FetchResult]:
        query = urlencode({"resource": resource, "sourceapp": SOURCE_APP})
        data, result = request_json(f"{RIPESTAT}/{name}/data.json?{query}", hosts=("stat.ripe.net",))
        return (data or {}).get("data") or {}, result

    if context.query_type == "asn":
        data, result = call("as-overview")
        if data.get("holder"):
            findings.append(
                Finding(
                    "as-holder",
                    _text(data["holder"]),
                    {"announced": bool(data.get("announced")), "registry_block": _text((data.get("block") or {}).get("desc"))},
                    result.final_url,
                    result.sha256,
                )
            )
        prefixes, result = call("announced-prefixes")
        for item in _list(prefixes.get("prefixes"), 100):
            if isinstance(item, dict) and item.get("prefix"):
                findings.append(Finding("announced-prefix", _text(item["prefix"], 50), {}, result.final_url, result.sha256))
    else:
        data, result = call("prefix-overview")
        for holder in _list(data.get("asns")):
            if isinstance(holder, dict) and holder.get("asn"):
                findings.append(
                    Finding(
                        "origin-asn",
                        f"AS{holder['asn']}",
                        {"holder": _text(holder.get("holder")), "prefix": _text(data.get("resource"), 50), "announced": bool(data.get("announced"))},
                        result.final_url,
                        result.sha256,
                    )
                )
        if data.get("resource") and not data.get("asns"):
            findings.append(Finding("routing", "not announced", {"prefix": _text(data.get("resource"), 50)}, result.final_url, result.sha256))
    abuse, result = call("abuse-contact-finder")
    for address in _list(abuse.get("abuse_contacts"), 10):
        findings.append(
            Finding("abuse-contact", _text(address, 254), {"registry": _text(abuse.get("authoritative_rir"), 20)}, result.final_url, result.sha256)
        )
    return findings


# ---------------------------------------------------------------------------
# PeeringDB: who operates an ASN and where it peers


def _peeringdb(context: ConnectorContext) -> list[Finding]:
    number = context.query_value[2:]
    data, result = request_json(f"https://www.peeringdb.com/api/net?asn={number}", hosts=("www.peeringdb.com",))
    findings = []
    for network in _list((data or {}).get("data"), 5):
        if not isinstance(network, dict):
            continue
        findings.append(
            Finding(
                "network-operator",
                _text(network.get("name")),
                {
                    "website": _text(network.get("website")),
                    "type": _text(network.get("info_type"), 60),
                    "scope": _text(network.get("info_scope"), 60),
                    "traffic_ratio": _text(network.get("info_ratio"), 60),
                    "ix_count": network.get("ix_count"),
                    "facility_count": network.get("fac_count"),
                    "irr_as_set": _text(network.get("irr_as_set"), 120),
                    "policy": _text(network.get("policy_general"), 60),
                },
                result.final_url,
                result.sha256,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# IPinfo: hostname, network owner and approximate location of an IP


def _ipinfo(context: ConnectorContext) -> list[Finding]:
    headers = {"Authorization": f"Bearer {context.api_key}"} if context.api_key else {}
    data, result = request_json(f"https://ipinfo.io/{context.query_value}/json", hosts=("ipinfo.io",), headers=headers)
    if not isinstance(data, dict) or data.get("bogon"):
        return []
    source = (result.final_url, result.sha256)
    findings = []
    if data.get("org"):
        findings.append(Finding("network-owner", _text(data["org"]), {"anycast": bool(data.get("anycast"))}, *source))
    if data.get("hostname"):
        findings.append(Finding("hostname", _text(data["hostname"], 253), {}, *source))
    if data.get("country"):
        place = ", ".join(part for part in (data.get("city"), data.get("region"), data.get("country")) if part)
        findings.append(
            Finding(
                "geolocation",
                _text(place, 200),
                {"coordinates": _text(data.get("loc"), 40), "timezone": _text(data.get("timezone"), 60), "meaning": "approximate location of the network, not of a person"},
                *source,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# CIRCL hashlookup: is this a known, distributed file (NSRL and others)?


def _hashlookup(context: ConnectorContext) -> list[Finding]:
    url = f"https://hashlookup.circl.lu/lookup/{context.query_type}/{context.query_value}"
    data, result = request_json(url, hosts=("hashlookup.circl.lu",))
    if not isinstance(data, dict):
        return [Finding("known-file", "not in hashlookup", {"meaning": "unknown to the known-software sets; says nothing about maliciousness"}, url)]
    product = data.get("ProductCode") if isinstance(data.get("ProductCode"), dict) else {}
    return [
        Finding(
            "known-file",
            _text(data.get("FileName") or "known file", 260),
            {
                "source_set": _text(data.get("source"), 60),
                "product": _text(product.get("ProductName"), 120),
                "product_version": _text(product.get("ProductVersion"), 60),
                "size_bytes": _text(data.get("FileSize"), 20),
                "trust": data.get("hashlookup:trust"),
                "known_malicious": _text(data.get("KnownMalicious"), 200),
                "sha256": _text(data.get("SHA-256"), 64).lower(),
                "sha1": _text(data.get("SHA-1"), 40).lower(),
                "md5": _text(data.get("MD5"), 32).lower(),
            },
            result.final_url,
            result.sha256,
        )
    ]


# ---------------------------------------------------------------------------
# urlscan.io: public scans that loaded this domain, IP, URL or file


def _urlscan_query(context: ConnectorContext) -> str:
    value = context.query_value
    if context.query_type == "domain":
        return f"page.domain:{value} OR domain:{value}"
    if context.query_type in ("ipv4", "ipv6"):
        return f'page.ip:"{value}" OR ip:"{value}"'
    if context.query_type == "url":
        return f'page.url:"{value}"'
    return f"hash:{value}"


def _urlscan(context: ConnectorContext) -> list[Finding]:
    query = urlencode({"q": _urlscan_query(context), "size": "50"})
    headers = {"API-Key": context.api_key} if context.api_key else {}
    data, result = request_json(f"https://urlscan.io/api/v1/search/?{query}", hosts=("urlscan.io",), headers=headers)
    findings = []
    for item in _list((data or {}).get("results"), 50):
        if not isinstance(item, dict):
            continue
        task = item.get("task") or {}
        page = item.get("page") or {}
        # A scan matches either because the page itself is on the artifact or
        # because the page loaded something from it (script, image, iframe).
        on_page = {
            "domain": page.get("domain") == context.query_value,
            "ipv4": page.get("ip") == context.query_value,
            "ipv6": page.get("ip") == context.query_value,
            "url": True,
        }.get(context.query_type, False)
        findings.append(
            Finding(
                "scan",
                _text(page.get("url") or task.get("url"), 500),
                {
                    "scanned_at": _text(task.get("time"), 40),
                    "relation": "page" if on_page else "loaded-resource",
                    "page_domain": _text(page.get("domain"), 253),
                    "page_ip": _text(page.get("ip"), 60),
                    "asn": _text(page.get("asn"), 20),
                    "asn_name": _text(page.get("asnname"), 120),
                    "country": _text(page.get("country"), 4),
                    "server": _text(page.get("server"), 120),
                    "title": _text(page.get("title"), 200),
                    "status": _text(page.get("status"), 6),
                    "tls_issuer": _text(page.get("tlsIssuer"), 120),
                    "domain_age_days": page.get("apexDomainAgeDays"),
                    "verdict_malicious": bool((item.get("verdicts") or {}).get("malicious")) if item.get("verdicts") else None,
                    "report": f"https://urlscan.io/result/{_text(task.get('uuid') or item.get('_id'), 40)}/",
                    "screenshot": _text(item.get("screenshot"), 200),
                },
                result.final_url,
                result.sha256,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Cert Spotter: certificate issuance from CT logs (complements crt.sh)


def _certspotter(context: ConnectorContext) -> list[Finding]:
    domain = context.query_value if context.query_type == "domain" else (urlsplit(context.query_value).hostname or "")
    if not domain:
        return []
    query = urlencode({"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
    data, result = request_json(f"https://api.certspotter.com/v1/issuances?{query}", hosts=("api.certspotter.com",))
    names: dict[str, dict[str, Any]] = {}
    certificates = []
    for item in _list(data, 200):
        if not isinstance(item, dict):
            continue
        certificates.append(item)
        for name in _list(item.get("dns_names"), 200):
            name = str(name).lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                seen = names.setdefault(name, {"certificates": 0, "first_seen": item.get("not_before", ""), "last_seen": item.get("not_after", "")})
                seen["certificates"] += 1
                seen["first_seen"] = min(seen["first_seen"], item.get("not_before", "") or seen["first_seen"])
                seen["last_seen"] = max(seen["last_seen"], item.get("not_after", ""))
    findings = [Finding("subdomain", name, info, result.final_url, result.sha256) for name, info in sorted(names.items())]
    findings += [
        Finding(
            "certificate",
            _text(item.get("cert_sha256"), 64),
            {
                "not_before": _text(item.get("not_before"), 30),
                "not_after": _text(item.get("not_after"), 30),
                "revoked": bool(item.get("revoked")),
                "spki_sha256": _text(item.get("pubkey_sha256"), 64),
                "names": _list(item.get("dns_names"), 20),
            },
            result.final_url,
            result.sha256,
        )
        for item in certificates[-40:]
    ]
    return findings


# ---------------------------------------------------------------------------
# NVD and OSV: vulnerability records


def _nvd(context: ConnectorContext) -> list[Finding]:
    headers = {"apiKey": context.api_key} if context.api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(context.query_value)}"
    data, result = request_json(url, hosts=("services.nvd.nist.gov",), headers=headers)
    findings = []
    for entry in _list((data or {}).get("vulnerabilities"), 1):
        cve = (entry or {}).get("cve") or {}
        description = next((item.get("value") for item in cve.get("descriptions") or [] if item.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        cvss: dict[str, Any] = {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                primary = next((item for item in metrics[key] if item.get("type") == "Primary"), metrics[key][0])
                data_block = primary.get("cvssData") or {}
                cvss = {
                    "version": _text(data_block.get("version"), 6),
                    "score": data_block.get("baseScore"),
                    "severity": _text(data_block.get("baseSeverity") or primary.get("baseSeverity"), 20),
                    "vector": _text(data_block.get("vectorString"), 200),
                }
                break
        weaknesses = sorted(
            {item.get("value") for weakness in cve.get("weaknesses") or [] for item in weakness.get("description") or [] if str(item.get("value", "")).startswith("CWE-")}
        )
        findings.append(
            Finding(
                "cve-record",
                _text(cve.get("id"), 30),
                {
                    "description": _text(description, 1500),
                    "status": _text(cve.get("vulnStatus"), 40),
                    "published": _text(cve.get("published"), 30),
                    "modified": _text(cve.get("lastModified"), 30),
                    "cvss": cvss,
                    "cwe": weaknesses[:10],
                    "kev_due_date": _text(cve.get("cisaActionDue"), 20),
                },
                result.final_url,
                result.sha256,
            )
        )
        for reference in _list(cve.get("references"), 40):
            if isinstance(reference, dict) and reference.get("url"):
                findings.append(
                    Finding("reference", _text(reference["url"], 500), {"tags": _list(reference.get("tags"), 8)}, result.final_url, result.sha256)
                )
    return findings


def _osv_record(identifier: str) -> tuple[Any, FetchResult]:
    return request_json(f"https://api.osv.dev/v1/vulns/{quote(identifier)}", hosts=("api.osv.dev",))


def _osv(context: ConnectorContext) -> list[Finding]:
    data, result = _osv_record(context.query_value)
    if not isinstance(data, dict):
        return []
    findings = []
    affected_list = [item for item in _list(data.get("affected"), 60) if ((item or {}).get("package") or {}).get("name")]
    if not affected_list:
        # CVE records imported from NVD often list no packages; the GitHub
        # advisory alias usually does.
        alias = next((item for item in _list(data.get("aliases"), 20) if str(item).startswith("GHSA-")), None)
        if alias:
            advisory, advisory_result = _osv_record(alias)
            if isinstance(advisory, dict):
                affected_list = _list(advisory.get("affected"), 60)
                result = advisory_result
    for affected in affected_list:
        package = (affected or {}).get("package") or {}
        if not package.get("name"):
            continue
        fixed = sorted(
            {
                event.get("fixed")
                for item in affected.get("ranges") or []
                for event in item.get("events") or []
                if event.get("fixed")
            }
        )
        findings.append(
            Finding(
                "affected-package",
                f"{package.get('ecosystem', '?')}:{_text(package.get('name'), 200)}",
                {"fixed_in": fixed[:10], "purl": _text(package.get("purl"), 200), "versions_listed": len(affected.get("versions") or [])},
                result.final_url,
                result.sha256,
            )
        )
    for alias in _list(data.get("aliases"), 20):
        findings.append(Finding("alias", _text(alias, 60), {}, result.final_url, result.sha256))
    return findings


for _connector in (
    Connector("shodan-internetdb", "Shodan InternetDB", "Open ports, hostnames, CPEs, tags and CVEs that Shodan's scans recorded for an IP.",
              ("ipv4", "ipv6"), _internetdb, network=True, rate_per_minute=60, ttl_seconds=12 * 3600, source_url="https://internetdb.shodan.io/"),
    Connector("ripestat", "RIPEstat", "Routing origin, AS holder, announced prefixes and abuse contact from RIPE NCC.",
              ("ipv4", "ipv6", "cidr", "asn"), _ripestat, network=True, rate_per_minute=30, ttl_seconds=6 * 3600, source_url="https://stat.ripe.net/"),
    Connector("peeringdb", "PeeringDB", "Operator, network type, traffic profile and peering footprint of an ASN.",
              ("asn",), _peeringdb, network=True, rate_per_minute=20, ttl_seconds=24 * 3600, source_url="https://www.peeringdb.com/"),
    Connector("ipinfo", "IPinfo", "Network owner, reverse hostname and approximate network location of an IP.",
              ("ipv4", "ipv6"), _ipinfo, network=True, key_id="ipinfo", rate_per_minute=30, ttl_seconds=24 * 3600, source_url="https://ipinfo.io/"),
    Connector("circl-hashlookup", "CIRCL hashlookup", "Whether a hash belongs to known, distributed software (NSRL and other sets).",
              ("md5", "sha1", "sha256"), _hashlookup, network=True, rate_per_minute=60, ttl_seconds=7 * 24 * 3600, source_url="https://hashlookup.circl.lu/"),
    Connector("urlscan", "urlscan.io", "Public urlscan.io scans of pages that loaded this domain, IP, URL or file.",
              ("domain", "ipv4", "ipv6", "url", "sha256"), _urlscan, network=True, key_id="urlscan", rate_per_minute=20, ttl_seconds=3600, source_url="https://urlscan.io/"),
    Connector("certspotter", "Cert Spotter", "Certificates issued for a domain and its subdomains, from Certificate Transparency.",
              ("domain", "url"), _certspotter, network=True, rate_per_minute=10, ttl_seconds=6 * 3600, source_url="https://sslmate.com/certspotter/"),
    Connector("nvd", "NVD", "NIST record of a CVE: description, CVSS, CWE and references.",
              ("cve",), _nvd, network=True, key_id="nvd", rate_per_minute=10, ttl_seconds=24 * 3600, source_url="https://nvd.nist.gov/"),
    Connector("osv", "OSV.dev", "Open-source packages and versions affected by a vulnerability, and their fixes.",
              ("cve",), _osv, network=True, rate_per_minute=60, ttl_seconds=24 * 3600, source_url="https://osv.dev/"),
):
    register_connector(_connector)
