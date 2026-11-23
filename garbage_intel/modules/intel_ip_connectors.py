"""IP and network sources: co-hosted domains, passive DNS, public lists, DNSBLs.

* **HackerTarget reverse IP**: domains whose DNS points at the IP today.
* **Mnemonic passive DNS**: what an IP or domain resolved to over time,
  with first and last sighting.
* **Public IP lists**: Tor exit nodes, Feodo Tracker botnet C2 servers,
  Spamhaus DROP (hijacked networks) and the published ranges of AWS, Google
  Cloud, Cloudflare and Fastly. The lists are downloaded whole and matched
  here, so the IP itself is never sent anywhere.
* **DNS blocklists**: spam and abuse lists asked through the public
  DNS-over-HTTPS resolver.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError
from . import intel_connectors as ic

FETCH: Callable[..., FetchResult] = net.fetch
MAX_ITEMS = 500
LIST_TTL_SECONDS = 6 * 3600
DNSBLS = (
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.dronebl.org", "DroneBL"),
    ("psbl.surriel.com", "PSBL"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT nível 1"),
    ("all.s5h.net", "s5h"),
)


def _get(url: str, host: str, *, headers: dict[str, str] | None = None, max_bytes: int = 4 * 1024 * 1024) -> FetchResult:
    result = FETCH(url, headers={"Accept": "application/json, text/plain", **(headers or {})}, allowed_hosts=(host,), max_bytes=max_bytes, timeout=30.0)
    if result.status == 429:
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    return result


def _json(result: FetchResult) -> Any:
    try:
        return json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


# ---------------------------------------------------------------------------
# Co-hosted domains and passive DNS


def _reverse_ip(context: ConnectorContext) -> list[Finding]:
    result = _get(f"https://api.hackertarget.com/reverseiplookup/?q={quote(context.query_value)}", "api.hackertarget.com")
    text = result.body.decode("utf-8", "replace").strip()
    if "API count exceeded" in text:
        raise NetworkError("HackerTarget's free daily limit (50 queries) was reached")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    if text.lower().startswith(("error", "no dns a records")):
        return []
    names = sorted({line.strip().lower().rstrip(".") for line in text.splitlines() if "." in line and " " not in line.strip()})
    findings = [Finding("cohosted-domain", name, {}, result.final_url, result.sha256) for name in names[:MAX_ITEMS]]
    if len(names) > MAX_ITEMS:
        findings.append(Finding("notice", f"{len(names)} domínios no mesmo IP; guardados os {MAX_ITEMS} primeiros", {}))
    return findings


def _moment(milliseconds: Any) -> str:
    try:
        return datetime.fromtimestamp(int(milliseconds) / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return ""


def _passive_dns(context: ConnectorContext) -> list[Finding]:
    result = _get(f"https://api.mnemonic.no/pdns/v3/{quote(context.query_value)}?limit=500", "api.mnemonic.no")
    if result.status == 404:
        return []
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    data = _json(result)
    rows = data.get("data") if isinstance(data, dict) else None
    findings = []
    by_ip = context.query_type in ("ipv4", "ipv6")
    for row in (rows or [])[:MAX_ITEMS]:
        if not isinstance(row, dict):
            continue
        # For an IP the interesting side is the name; for a domain, the answer.
        value = str(row.get("query" if by_ip else "answer") or "").lower().rstrip(".")
        if not value:
            continue
        findings.append(
            Finding(
                "pdns-name" if by_ip else "pdns-answer",
                value[:300],
                {
                    "rrtype": str(row.get("rrtype") or "")[:10],
                    "first_seen": _moment(row.get("firstSeenTimestamp")),
                    "last_seen": _moment(row.get("lastSeenTimestamp")),
                    "times": row.get("times"),
                },
                result.final_url,
                result.sha256,
            )
        )
    if isinstance(data, dict) and (data.get("count") or 0) > len(findings):
        findings.append(Finding("notice", f"histórico com {data['count']} registros; guardados {len(findings)}", {}))
    return findings


# ---------------------------------------------------------------------------
# Public lists, downloaded whole and matched locally

_LISTS: dict[str, tuple[float, Any]] = {}
_LISTS_LOCK = threading.Lock()


def _cached(name: str, load: Callable[[], Any]) -> Any:
    with _LISTS_LOCK:
        entry = _LISTS.get(name)
        if entry and time.monotonic() - entry[0] < LIST_TTL_SECONDS:
            return entry[1]
    value = load()
    with _LISTS_LOCK:
        _LISTS[name] = (time.monotonic(), value)
    return value


def _tor_exits() -> set[str]:
    result = _get("https://check.torproject.org/torbulkexitlist", "check.torproject.org")
    return {line.strip() for line in result.body.decode("utf-8", "replace").splitlines() if line.strip() and not line.startswith("#")}


def _feodo() -> dict[str, dict[str, Any]]:
    data = _json(_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", "feodotracker.abuse.ch"))
    return {str(item.get("ip_address")): item for item in data if isinstance(item, dict)} if isinstance(data, list) else {}


def _networks(rows: list[tuple[str, dict[str, Any]]]) -> list[tuple[Any, dict[str, Any]]]:
    parsed = []
    for prefix, info in rows:
        try:
            parsed.append((ipaddress.ip_network(prefix, strict=False), info))
        except ValueError:
            continue
    return parsed


def _drop() -> list[tuple[Any, dict[str, Any]]]:
    result = _get("https://www.spamhaus.org/drop/drop_v4.json", "www.spamhaus.org")
    rows = []
    for line in result.body.decode("utf-8", "replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("cidr"):
            rows.append((str(item["cidr"]), {"sblid": str(item.get("sblid") or ""), "rir": str(item.get("rir") or "")}))
    return _networks(rows)


def _clouds() -> list[tuple[Any, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    aws = _json(_get("https://ip-ranges.amazonaws.com/ip-ranges.json", "ip-ranges.amazonaws.com", max_bytes=16 * 1024 * 1024))
    for item in aws.get("prefixes", []) + aws.get("ipv6_prefixes", []):
        prefix = item.get("ip_prefix") or item.get("ipv6_prefix")
        if prefix and item.get("service") != "AMAZON":
            rows.append((prefix, {"provider": "Amazon Web Services", "service": item.get("service", ""), "region": item.get("region", "")}))
    google = _json(_get("https://www.gstatic.com/ipranges/cloud.json", "www.gstatic.com"))
    for item in google.get("prefixes", []):
        prefix = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if prefix:
            rows.append((prefix, {"provider": "Google Cloud", "service": item.get("service", ""), "region": item.get("scope", "")}))
    for url, host in (("https://www.cloudflare.com/ips-v4", "www.cloudflare.com"), ("https://www.cloudflare.com/ips-v6", "www.cloudflare.com")):
        for line in _get(url, host).body.decode("utf-8", "replace").split():
            rows.append((line.strip(), {"provider": "Cloudflare", "service": "CDN e proxy", "region": ""}))
    fastly = _json(_get("https://api.fastly.com/public-ip-list", "api.fastly.com"))
    for prefix in fastly.get("addresses", []) + fastly.get("ipv6_addresses", []):
        rows.append((prefix, {"provider": "Fastly", "service": "CDN", "region": ""}))
    return _networks(rows)


def _match(networks: list[tuple[Any, dict[str, Any]]], address: Any) -> list[tuple[Any, dict[str, Any]]]:
    return [(network, info) for network, info in networks if network.version == address.version and address in network]


def _ip_lists(context: ConnectorContext) -> list[Finding]:
    address = ipaddress.ip_address(context.query_value)
    findings: list[Finding] = []
    failures: list[str] = []

    def attempt(name: str, check: Callable[[], None]) -> None:
        try:
            check()
        except (NetworkError, ValueError, KeyError, AttributeError, TypeError):
            failures.append(name)

    def tor() -> None:
        if str(address) in _cached("tor", _tor_exits):
            findings.append(Finding("tor-exit", "nó de saída da rede Tor", {"meaning": "Tráfego vindo deste IP pode ser de qualquer usuário do Tor."}))

    def feodo() -> None:
        item = _cached("feodo", _feodo).get(str(address))
        if item:
            findings.append(
                Finding(
                    "botnet-c2",
                    f"servidor de comando de botnet ({item.get('malware') or 'Feodo Tracker'})",
                    {"status": item.get("status"), "port": item.get("port"), "first_seen": str(item.get("first_seen") or "")[:10], "last_online": str(item.get("last_online") or "")[:10]},
                )
            )

    def drop() -> None:
        for network, info in _match(_cached("drop", _drop), address)[:1]:
            findings.append(Finding("drop-listed", f"rede {network} na Spamhaus DROP ({info['sblid']})", {**info, "meaning": "Rede sequestrada ou usada só por criminosos; a Spamhaus recomenda bloquear todo o tráfego."}))

    def cloud() -> None:
        matches = sorted(_match(_cached("clouds", _clouds), address), key=lambda item: -item[0].prefixlen)
        if matches:
            network, info = matches[0]
            findings.append(Finding("cloud-range", info["provider"], {**info, "prefix": str(network)}))

    for name, check in (("Tor", tor), ("Feodo Tracker", feodo), ("Spamhaus DROP", drop), ("faixas de nuvem", cloud)):
        attempt(name, check)
    findings.append(Finding("lists-checked", "listas públicas conferidas", {"failed": failures, "checked": ["Tor", "Feodo Tracker", "Spamhaus DROP", "AWS", "Google Cloud", "Cloudflare", "Fastly"]}))
    if len(failures) == 4:
        raise NetworkError("none of the public lists could be downloaded")
    return findings


# ---------------------------------------------------------------------------
# DNS blocklists


def _dnsbl(context: ConnectorContext) -> list[Finding]:
    address = ipaddress.ip_address(context.query_value)
    reversed_ip = ".".join(reversed(str(address).split(".")))

    def ask(zone: tuple[str, str]) -> tuple[str, str, list[str] | None]:
        try:
            answers, _ = ic.doh_query(f"{reversed_ip}.{zone[0]}", "A")
        except NetworkError:
            return zone[0], zone[1], None
        return zone[0], zone[1], answers

    with ThreadPoolExecutor(max_workers=len(DNSBLS)) as pool:
        replies = list(pool.map(ask, DNSBLS))
    findings = []
    clean, refused = [], []
    for zone, label, answers in replies:
        if answers is None:
            refused.append(label)
        elif any(answer.startswith("127.255.255.") for answer in answers):
            # Spamhaus refuses queries that come through public resolvers.
            refused.append(label)
        elif answers:
            findings.append(Finding("blocklist", label, {"zone": zone, "codes": answers[:5]}))
        else:
            clean.append(label)
    findings.append(Finding("blocklist-check", f"{len(findings)} de {len(DNSBLS)} listas", {"clean": clean, "unanswered": refused}))
    return findings


for _connector in (
    Connector("reverse-ip", "Domínios no mesmo IP (HackerTarget)", "Domains whose DNS points at the IP, from HackerTarget (50 free queries a day, shared with its host search).",
              ("ipv4",), _reverse_ip, network=True, rate_per_minute=10, ttl_seconds=24 * 3600, source_url="https://hackertarget.com/reverse-ip-lookup/"),
    Connector("mnemonic-pdns", "Histórico de DNS (Mnemonic)", "Passive DNS: what an IP or domain resolved to over time, with first and last sighting.",
              ("ipv4", "ipv6", "domain"), _passive_dns, network=True, rate_per_minute=10, ttl_seconds=12 * 3600, source_url="https://passivedns.mnemonic.no/"),
    Connector("ip-lists", "Listas públicas de IP", "Tor exit nodes, Feodo Tracker botnet C2s, Spamhaus DROP and AWS, Google Cloud, Cloudflare and Fastly ranges; the lists are downloaded and matched locally, so the IP is not sent.",
              ("ipv4", "ipv6"), _ip_lists, network=True, rate_per_minute=60, ttl_seconds=3 * 3600, source_url="https://feodotracker.abuse.ch/"),
    Connector("dnsbl", "Listas antispam (DNSBL)", "Whether the IP is on seven spam and abuse DNS blocklists, asked through the public DNS-over-HTTPS resolver.",
              ("ipv4",), _dnsbl, network=True, rate_per_minute=20, ttl_seconds=6 * 3600, source_url=ic.DOH_URL),
):
    register_connector(_connector)
