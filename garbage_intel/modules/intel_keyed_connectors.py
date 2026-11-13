"""Reputation and threat connectors tied to a provider account (plan phase
7): VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, Shodan, URLhaus,
ThreatFox and MalwareBazaar.

VirusTotal, AbuseIPDB and the abuse.ch services run only when a key for their
provider is saved locally; otherwise the run reports ``key-missing`` without a
request. GreyNoise Community, OTX and Shodan host lookups answer without a key
(checked 2026-11-12) and use one when present. Keys travel in the header the
provider documents (Shodan only accepts a query parameter, so its stored
source URL is rebuilt without it). Reporter names and free-text comments from
community feeds are not stored.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

from ..intel import Connector, ConnectorContext, Finding, register_connector
from . import intel_open_connectors as shared

_text = shared._text
_list = shared._list


def _get(url: str, hosts: tuple[str, ...], headers: dict[str, str], not_found: tuple[int, ...] = (404,)) -> tuple[Any, Any]:
    return shared.request_json(url, hosts=hosts, headers=headers, not_found=not_found)


def _post_form(url: str, hosts: tuple[str, ...], headers: dict[str, str], fields: dict[str, str]) -> tuple[Any, Any]:
    return shared.request_json(
        url,
        hosts=hosts,
        method="POST",
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
        body=urlencode(fields).encode("ascii"),
    )


def _post_json(url: str, hosts: tuple[str, ...], headers: dict[str, str], payload: dict[str, Any]) -> tuple[Any, Any]:
    return shared.request_json(
        url,
        hosts=hosts,
        method="POST",
        headers={**headers, "Content-Type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
    )


def _stats(stats: Any) -> dict[str, int]:
    if not isinstance(stats, dict):
        return {}
    return {key: int(stats.get(key) or 0) for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")}


# ---------------------------------------------------------------------------
# VirusTotal


_VT_PATHS = {"ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains", "url": "urls", "md5": "files", "sha1": "files", "sha256": "files"}


def _virustotal(context: ConnectorContext) -> list[Finding]:
    identifier = context.query_value
    if context.query_type == "url":
        identifier = base64.urlsafe_b64encode(identifier.encode("utf-8")).decode("ascii").rstrip("=")
    url = f"https://www.virustotal.com/api/v3/{_VT_PATHS[context.query_type]}/{quote(identifier, safe='')}"
    data, result = _get(url, ("www.virustotal.com",), {"x-apikey": context.api_key})
    if not isinstance(data, dict):
        return [Finding("verdict", "not in VirusTotal", {"meaning": "never submitted or scanned; not a clean result"}, url)]
    attributes = (data.get("data") or {}).get("attributes") or {}
    gui_kind = {"files": "file", "urls": "url", "domains": "domain", "ip_addresses": "ip-address"}[_VT_PATHS[context.query_type]]
    source = (f"https://www.virustotal.com/gui/{gui_kind}/{identifier}", result.sha256)
    stats = _stats(attributes.get("last_analysis_stats"))
    engines = sum(stats.values())
    findings = [
        Finding(
            "verdict",
            f"{stats.get('malicious', 0)}/{engines} engines flag it",
            {
                **stats,
                "reputation": attributes.get("reputation"),
                "last_analysis": attributes.get("last_analysis_date"),
                "meaning": "engine detections are signals with false positives, not proof",
            },
            *source,
        )
    ]
    threat = attributes.get("popular_threat_classification") or {}
    if threat.get("suggested_threat_label"):
        findings.append(Finding("threat-label", _text(threat["suggested_threat_label"], 120), {"categories": [_text(item.get("value"), 60) for item in _list(threat.get("popular_threat_category"), 5)]}, *source))
    for tag in _list(attributes.get("tags"), 30):
        findings.append(Finding("tag", _text(tag, 80), {}, *source))
    categories = attributes.get("categories") if isinstance(attributes.get("categories"), dict) else {}
    for category in sorted(set(categories.values()))[:15]:
        findings.append(Finding("category", _text(category, 80), {}, *source))
    if context.query_type in ("md5", "sha1", "sha256"):
        findings.append(
            Finding(
                "file",
                _text(attributes.get("meaningful_name") or attributes.get("type_description") or "file", 260),
                {
                    "type": _text(attributes.get("type_description"), 80),
                    "size_bytes": attributes.get("size"),
                    "first_submission": attributes.get("first_submission_date"),
                    "names": _list(attributes.get("names"), 10),
                    "sha256": _text(attributes.get("sha256"), 64),
                    "ssdeep": _text(attributes.get("ssdeep"), 160),
                    "tlsh": _text(attributes.get("tlsh"), 80),
                },
                *source,
            )
        )
    if context.query_type in ("ipv4", "ipv6") and attributes.get("as_owner"):
        findings.append(Finding("network-owner", _text(attributes["as_owner"]), {"asn": attributes.get("asn"), "network": _text(attributes.get("network"), 50), "country": _text(attributes.get("country"), 4)}, *source))
    if context.query_type == "domain":
        for record in _list(attributes.get("last_dns_records"), 30):
            if isinstance(record, dict) and record.get("value"):
                findings.append(Finding("dns-record", _text(record["value"], 300), {"type": _text(record.get("type"), 10)}, *source))
    if context.query_type == "url" and attributes.get("last_final_url"):
        findings.append(Finding("final-url", _text(attributes["last_final_url"], 500), {"title": _text(attributes.get("title"), 200)}, *source))
    return findings


# ---------------------------------------------------------------------------
# AbuseIPDB


def _abuseipdb(context: ConnectorContext) -> list[Finding]:
    url = "https://api.abuseipdb.com/api/v2/check?" + urlencode({"ipAddress": context.query_value, "maxAgeInDays": "90"})
    data, result = _get(url, ("api.abuseipdb.com",), {"Key": context.api_key})
    record = (data or {}).get("data") or {}
    if not record:
        return []
    return [
        Finding(
            "abuse-score",
            f"{int(record.get('abuseConfidenceScore') or 0)}/100",
            {
                "reports_90d": record.get("totalReports"),
                "distinct_reporters": record.get("numDistinctUsers"),
                "last_reported": _text(record.get("lastReportedAt"), 40),
                "usage_type": _text(record.get("usageType"), 80),
                "isp": _text(record.get("isp")),
                "domain": _text(record.get("domain"), 253),
                "country": _text(record.get("countryCode"), 4),
                "tor_exit": bool(record.get("isTor")),
                "allow_listed": record.get("isWhitelisted"),
                "meaning": "community reports; shared or reassigned addresses inherit old reports",
            },
            f"https://www.abuseipdb.com/check/{context.query_value}",
            result.sha256,
        )
    ]


# ---------------------------------------------------------------------------
# GreyNoise Community


def _greynoise(context: ConnectorContext) -> list[Finding]:
    url = f"https://api.greynoise.io/v3/community/{context.query_value}"
    data, result = _get(url, ("api.greynoise.io",), {"key": context.api_key} if context.api_key else {})
    if not isinstance(data, dict) or not (data.get("noise") or data.get("riot")):
        return [Finding("internet-noise", "not observed", {"meaning": "not seen mass-scanning and not a known benign service"}, url)]
    return [
        Finding(
            "internet-noise",
            _text(data.get("classification") or ("benign service" if data.get("riot") else "scanner"), 40),
            {
                "scanning_internet": bool(data.get("noise")),
                "known_benign_service": bool(data.get("riot")),
                "name": _text(data.get("name"), 120),
                "last_seen": _text(data.get("last_seen"), 30),
            },
            _text(data.get("link"), 200) or url,
            result.sha256,
        )
    ]


# ---------------------------------------------------------------------------
# AlienVault OTX


_OTX_SECTIONS = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file", "cve": "cve"}


def _otx(context: ConnectorContext) -> list[Finding]:
    section = _OTX_SECTIONS[context.query_type]
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(context.query_value, safe='')}/general"
    headers = {"X-OTX-API-KEY": context.api_key} if context.api_key else {}
    data, result = _get(url, ("otx.alienvault.com",), headers, not_found=(404, 400))
    if not isinstance(data, dict):
        return []
    pulses = (data.get("pulse_info") or {}).get("pulses") or []
    browse = f"https://otx.alienvault.com/indicator/{section.lower()}/{quote(context.query_value, safe='')}"
    findings = [Finding("pulse-count", str((data.get("pulse_info") or {}).get("count", len(pulses))), {"meaning": "community threat reports that list this indicator"}, browse, result.sha256)]
    families: set[str] = set()
    techniques: set[str] = set()
    for pulse in pulses[:40]:
        if not isinstance(pulse, dict):
            continue
        families.update(_text(item.get("display_name"), 80) for item in _list(pulse.get("malware_families"), 10) if isinstance(item, dict))
        techniques.update(_text(item.get("id"), 20) for item in _list(pulse.get("attack_ids"), 20) if isinstance(item, dict))
        findings.append(
            Finding(
                "pulse",
                _text(pulse.get("name"), 200),
                {
                    "created": _text(pulse.get("created"), 30),
                    "modified": _text(pulse.get("modified"), 30),
                    "adversary": _text(pulse.get("adversary"), 120),
                    "tags": _list(pulse.get("tags"), 12),
                    "tlp": _text(pulse.get("TLP") or pulse.get("tlp"), 10),
                    "references": _list(pulse.get("references"), 5),
                    "link": f"https://otx.alienvault.com/pulse/{_text(pulse.get('id'), 40)}",
                },
                browse,
                result.sha256,
            )
        )
    findings += [Finding("malware-family", family, {}, browse, result.sha256) for family in sorted(families - {""})]
    findings += [Finding("attack-technique", technique, {}, browse, result.sha256) for technique in sorted(techniques - {""})]
    return findings


# ---------------------------------------------------------------------------
# Shodan host


def _shodan(context: ConnectorContext) -> list[Finding]:
    url = f"https://api.shodan.io/shodan/host/{context.query_value}"
    if context.api_key:
        url += "?" + urlencode({"key": context.api_key})
    data, result = _get(url, ("api.shodan.io",), {})
    public = f"https://www.shodan.io/host/{context.query_value}"
    if not isinstance(data, dict):
        return [Finding("host", "no Shodan record", {"meaning": "not indexed by Shodan's scans"}, public)]
    findings = [
        Finding(
            "host",
            _text(data.get("org") or data.get("isp") or context.query_value),
            {
                "isp": _text(data.get("isp")),
                "asn": _text(data.get("asn"), 20),
                "os": _text(data.get("os"), 80),
                "country": _text(data.get("country_code"), 4),
                "last_update": _text(data.get("last_update"), 30),
                "ports": _list(data.get("ports"), 100),
            },
            public,
            result.sha256,
        )
    ]
    findings += [Finding("hostname", _text(name, 253), {}, public, result.sha256) for name in _list(data.get("hostnames"))]
    findings += [Finding("tag", _text(tag, 60), {}, public, result.sha256) for tag in _list(data.get("tags"))]
    vulns = data.get("vulns")
    for cve in (list(vulns) if isinstance(vulns, (list, dict)) else [])[:100]:
        findings.append(Finding("cve", _text(cve, 30), {"meaning": "inferred by Shodan from banner versions; not verified"}, public, result.sha256))
    for banner in _list(data.get("data"), 60):
        if not isinstance(banner, dict):
            continue
        http = banner.get("http") or {}
        certificate = ((banner.get("ssl") or {}).get("cert") or {}).get("subject") or {}
        findings.append(
            Finding(
                "service",
                f"{banner.get('port')}/{_text(banner.get('transport') or 'tcp', 4)}",
                {
                    "product": _text(banner.get("product"), 120),
                    "version": _text(banner.get("version"), 60),
                    "module": _text((banner.get("_shodan") or {}).get("module"), 40),
                    "cpe": _list(banner.get("cpe23") or banner.get("cpe"), 5),
                    "http_title": _text(http.get("title"), 200),
                    "http_server": _text(http.get("server"), 120),
                    "tls_subject_cn": _text(certificate.get("CN"), 200),
                    "seen": _text(banner.get("timestamp"), 30),
                },
                public,
                result.sha256,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# abuse.ch: URLhaus, ThreatFox and MalwareBazaar (one Auth-Key)


def _urlhaus(context: ConnectorContext) -> list[Finding]:
    headers = {"Auth-Key": context.api_key}
    hosts = ("urlhaus-api.abuse.ch",)
    if context.query_type == "url":
        data, result = _post_form("https://urlhaus-api.abuse.ch/v1/url/", hosts, headers, {"url": context.query_value})
        entries = [data] if isinstance(data, dict) and data.get("query_status") == "ok" else []
    elif context.query_type in ("md5", "sha256"):
        field = "md5_hash" if context.query_type == "md5" else "sha256_hash"
        data, result = _post_form("https://urlhaus-api.abuse.ch/v1/payload/", hosts, headers, {field: context.query_value})
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            return []
        payload = Finding(
            "payload",
            _text(data.get("signature") or data.get("file_type") or "payload", 120),
            {"file_type": _text(data.get("file_type"), 40), "first_seen": _text(data.get("firstseen"), 30), "url_count": data.get("url_count")},
            f"https://urlhaus.abuse.ch/browse.php?search={context.query_value}",
            result.sha256,
        )
        entries = _list(data.get("urls"), 50)
        return [payload] + [
            Finding("malicious-url", _text(item.get("url"), 500), {"status": _text(item.get("url_status"), 20), "first_seen": _text(item.get("firstseen"), 30)}, _text(item.get("urlhaus_reference"), 200), result.sha256)
            for item in entries
            if isinstance(item, dict) and item.get("url")
        ]
    else:
        data, result = _post_form("https://urlhaus-api.abuse.ch/v1/host/", hosts, headers, {"host": context.query_value})
        entries = _list((data or {}).get("urls"), 100) if isinstance(data, dict) and data.get("query_status") == "ok" else []
    return [
        Finding(
            "malicious-url",
            _text(item.get("url"), 500),
            {
                "status": _text(item.get("url_status"), 20),
                "threat": _text(item.get("threat"), 60),
                "tags": _list(item.get("tags"), 10),
                "date_added": _text(item.get("date_added"), 30),
            },
            _text(item.get("urlhaus_reference"), 200) or "https://urlhaus.abuse.ch/",
            result.sha256,
        )
        for item in entries
        if isinstance(item, dict) and item.get("url")
    ]


def _threatfox(context: ConnectorContext) -> list[Finding]:
    headers = {"Auth-Key": context.api_key}
    if context.query_type in ("md5", "sha256"):
        payload = {"query": "search_hash", "hash": context.query_value}
    else:
        payload = {"query": "search_ioc", "search_term": context.query_value, "exact_match": True}
    data, result = _post_json("https://threatfox-api.abuse.ch/api/v1/", ("threatfox-api.abuse.ch",), headers, payload)
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return []
    return [
        Finding(
            "ioc",
            _text(item.get("ioc"), 500),
            {
                "threat_type": _text(item.get("threat_type_desc") or item.get("threat_type"), 120),
                "malware": _text(item.get("malware_printable"), 120),
                "aliases": _text(item.get("malware_alias"), 200),
                "confidence": item.get("confidence_level"),
                "first_seen": _text(item.get("first_seen"), 30),
                "last_seen": _text(item.get("last_seen"), 30),
                "tags": _list(item.get("tags"), 10),
                "reference": _text(item.get("reference"), 300),
            },
            f"https://threatfox.abuse.ch/ioc/{_text(item.get('id'), 20)}/",
            result.sha256,
        )
        for item in _list(data.get("data"), 100)
        if isinstance(item, dict)
    ]


def _malwarebazaar(context: ConnectorContext) -> list[Finding]:
    data, result = _post_form("https://mb-api.abuse.ch/api/v1/", ("mb-api.abuse.ch",), {"Auth-Key": context.api_key}, {"query": "get_info", "hash": context.query_value})
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return []
    findings = []
    for item in _list(data.get("data"), 5):
        if not isinstance(item, dict):
            continue
        link = f"https://bazaar.abuse.ch/sample/{_text(item.get('sha256_hash'), 64)}/"
        findings.append(
            Finding(
                "sample",
                _text(item.get("signature") or item.get("file_name") or "sample", 200),
                {
                    "file_name": _text(item.get("file_name"), 260),
                    "file_type": _text(item.get("file_type"), 40),
                    "mime": _text(item.get("file_type_mime"), 100),
                    "size_bytes": item.get("file_size"),
                    "first_seen": _text(item.get("first_seen"), 30),
                    "last_seen": _text(item.get("last_seen"), 30),
                    "delivery": _text(item.get("delivery_method"), 60),
                    "imphash": _text(item.get("imphash"), 32),
                    "tlsh": _text(item.get("tlsh"), 80),
                    "ssdeep": _text(item.get("ssdeep"), 160),
                    "sha256": _text(item.get("sha256_hash"), 64),
                },
                link,
                result.sha256,
            )
        )
        findings += [Finding("tag", _text(tag, 80), {}, link, result.sha256) for tag in _list(item.get("tags"), 20)]
    return findings


for _connector in (
    Connector("virustotal", "VirusTotal", "Engine detections, threat label, tags and context for IPs, domains, URLs and files.",
              ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"), _virustotal, network=True, requires_key=True, key_id="virustotal",
              rate_per_minute=4, ttl_seconds=6 * 3600, source_url="https://www.virustotal.com/"),
    Connector("abuseipdb", "AbuseIPDB", "Community abuse reports and confidence score for an IP over 90 days.",
              ("ipv4", "ipv6"), _abuseipdb, network=True, requires_key=True, key_id="abuseipdb", rate_per_minute=30, ttl_seconds=6 * 3600,
              source_url="https://www.abuseipdb.com/"),
    Connector("greynoise", "GreyNoise", "Whether an IP mass-scans the internet or is a known benign service.",
              ("ipv4",), _greynoise, network=True, key_id="greynoise", rate_per_minute=20, ttl_seconds=6 * 3600,
              source_url="https://viz.greynoise.io/"),
    Connector("otx", "AlienVault OTX", "Community threat reports (pulses), malware families and ATT&CK techniques for an indicator.",
              ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve"), _otx, network=True, key_id="otx",
              rate_per_minute=30, ttl_seconds=6 * 3600, source_url="https://otx.alienvault.com/"),
    Connector("shodan", "Shodan", "Services, banners, products, TLS names and inferred CVEs for an IP.",
              ("ipv4", "ipv6"), _shodan, network=True, key_id="shodan", rate_per_minute=30, ttl_seconds=12 * 3600,
              source_url="https://www.shodan.io/"),
    Connector("urlhaus", "URLhaus", "Malware distribution URLs for a URL, host or payload hash.",
              ("url", "domain", "ipv4", "md5", "sha256"), _urlhaus, network=True, requires_key=True, key_id="abusech", rate_per_minute=30,
              ttl_seconds=3600, source_url="https://urlhaus.abuse.ch/"),
    Connector("threatfox", "ThreatFox", "Indicators of compromise tied to malware families and botnet infrastructure.",
              ("ipv4", "domain", "url", "md5", "sha256"), _threatfox, network=True, requires_key=True, key_id="abusech", rate_per_minute=30,
              ttl_seconds=3600, source_url="https://threatfox.abuse.ch/"),
    Connector("malwarebazaar", "MalwareBazaar", "Malware sample record for a hash: family, type, delivery and similarity digests.",
              ("md5", "sha1", "sha256"), _malwarebazaar, network=True, requires_key=True, key_id="abusech", rate_per_minute=30,
              ttl_seconds=24 * 3600, source_url="https://bazaar.abuse.ch/"),
):
    register_connector(_connector)
