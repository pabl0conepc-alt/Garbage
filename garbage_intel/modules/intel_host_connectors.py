"""More passive sources for a domain's hosts (subdomain enumeration).

Each source answers with names it has already seen; none of them touches the
domain's servers:

* **HackerTarget** host search: names and the IP each one resolved to, from
  its DNS datasets (free tier: 50 queries a day).
* **AlienVault OTX** URL list: hosts and URLs the OTX community observed.
* **subdomain.center**: names gathered from public datasets.
* **Common names over DNS**: a short list of usual names (www, mail, vpn,
  api...) asked to the public DNS-over-HTTPS resolver, which only says
  whether they exist.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError
from . import intel_connectors as ic

FETCH: Callable[..., FetchResult] = net.fetch
MAX_HOSTS = 500
COMMON_NAMES = (
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx", "autodiscover", "vpn", "remote", "portal", "intranet",
    "extranet", "api", "app", "apps", "dev", "staging", "stage", "test", "homolog", "hml", "beta", "admin", "painel",
    "sso", "login", "auth", "id", "cdn", "static", "assets", "img", "files", "ftp", "git", "gitlab", "jira",
    "confluence", "wiki", "docs", "status", "blog", "shop", "loja", "m", "mobile", "ns1", "ns2", "owa", "crm", "erp",
)
DNS_WORKERS = 8


def _domain(context: ConnectorContext) -> str:
    if context.query_type == "domain":
        return context.query_value.lower().rstrip(".")
    return (urlsplit(context.query_value).hostname or "").lower().rstrip(".")


def _under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _fetch_text(url: str, host: str, headers: dict[str, str] | None = None) -> FetchResult:
    return FETCH(url, headers={"Accept": "application/json, text/plain", **(headers or {})}, allowed_hosts=(host,), max_bytes=4 * 1024 * 1024, timeout=25.0)


def _hackertarget(context: ConnectorContext) -> list[Finding]:
    domain = _domain(context)
    if not domain:
        return []
    result = _fetch_text(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", "api.hackertarget.com")
    text = result.body.decode("utf-8", "replace").strip()
    if result.status == 429 or "API count exceeded" in text:
        raise NetworkError("HackerTarget's free daily limit (50 queries) was reached")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    if text.lower().startswith(("error", "no records")):
        return []
    findings: dict[str, Finding] = {}
    for line in text.splitlines()[: MAX_HOSTS * 2]:
        name, _, address = line.strip().partition(",")
        name = name.lower().rstrip(".")
        if name and _under(name, domain) and name not in findings:
            findings[name] = Finding("subdomain", name, {"ip": address.strip()[:45]}, result.final_url, result.sha256)
    return list(findings.values())[:MAX_HOSTS]


def _otx_hosts(context: ConnectorContext) -> list[Finding]:
    domain = _domain(context)
    if not domain:
        return []
    headers = {"X-OTX-API-KEY": context.api_key} if context.api_key else {}
    result = _fetch_text(f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/url_list?limit=200&page=1", "otx.alienvault.com", headers)
    if result.status == 404:
        return []
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        data = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc
    hosts: dict[str, dict[str, Any]] = {}
    urls: list[Finding] = []
    for item in (data.get("url_list") or [])[:200] if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("hostname") or "").lower().rstrip(".")
        if not name or not _under(name, domain):
            continue
        seen = hosts.setdefault(name, {"ip": "", "last_seen": "", "urls": 0})
        seen["urls"] += 1
        seen["ip"] = seen["ip"] or str(((item.get("result") or {}).get("urlworker") or {}).get("ip") or "")[:45]
        seen["last_seen"] = max(seen["last_seen"], str(item.get("date") or "")[:19])
        if len(urls) < 40 and item.get("url"):
            urls.append(Finding("observed-url", str(item["url"])[:500], {"date": str(item.get("date") or "")[:19], "status": item.get("httpcode")}, result.final_url, result.sha256))
    findings = [Finding("subdomain", name, info, result.final_url, result.sha256) for name, info in sorted(hosts.items())]
    return findings + urls


def _subdomain_center(context: ConnectorContext) -> list[Finding]:
    domain = _domain(context)
    if not domain:
        return []
    result = _fetch_text(f"https://api.subdomain.center/?domain={quote(domain)}", "api.subdomain.center")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        data = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc
    if isinstance(data, dict) and data.get("error"):
        raise NetworkError(f"the source is busy: {str(data['error'])[:120]}")
    names = sorted({str(name).lower().rstrip(".") for name in data if isinstance(name, str)} if isinstance(data, list) else set())
    return [Finding("subdomain", name, {}, result.final_url, result.sha256) for name in names if _under(name, domain)][:MAX_HOSTS]


def _common_names(context: ConnectorContext) -> list[Finding]:
    domain = _domain(context)
    if not domain:
        return []

    def ask(label: str) -> Finding | None:
        name = f"{label}.{domain}"
        try:
            addresses, result = ic.doh_query(name, "A")
            if not addresses:
                addresses, result = ic.doh_query(name, "CNAME")
        except NetworkError:
            return None
        if not addresses:
            return None
        return Finding("subdomain", name, {"ip": addresses[0][:253], "how": "nome comum que existe no DNS"}, result.final_url, result.sha256)

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        found = list(pool.map(ask, COMMON_NAMES))
    return [item for item in found if item]


for _connector in (
    Connector("hackertarget-hosts", "HackerTarget", "Hosts under a domain and the IP each resolved to, from HackerTarget's DNS datasets (50 free queries a day).",
              ("domain",), _hackertarget, network=True, rate_per_minute=10, ttl_seconds=24 * 3600, source_url="https://hackertarget.com/find-dns-host-records/"),
    Connector("otx-hosts", "AlienVault OTX (hosts)", "Hosts and URLs under a domain that the OTX community observed.",
              ("domain", "url"), _otx_hosts, network=True, key_id="otx", rate_per_minute=20, ttl_seconds=12 * 3600, source_url="https://otx.alienvault.com/"),
    Connector("subdomain-center", "subdomain.center", "Subdomains gathered from public datasets.",
              ("domain",), _subdomain_center, network=True, rate_per_minute=10, ttl_seconds=24 * 3600, source_url="https://www.subdomain.center/"),
    Connector("dns-common-names", "Nomes comuns (DNS)", "Whether about fifty usual names (www, mail, vpn, api, dev...) exist under the domain, asked to the public DNS-over-HTTPS resolver.",
              ("domain",), _common_names, network=True, rate_per_minute=10, ttl_seconds=12 * 3600, source_url=ic.DOH_URL),
):
    register_connector(_connector)
