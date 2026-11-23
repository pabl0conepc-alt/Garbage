"""Public phishing lists, downloaded whole and matched on this machine.

OpenPhish (active phishing URLs), Phishing Army, the Block List Project's
phishing list and Phishing.Database (active domains). The queried domain or
URL is never sent: the lists are fetched as files, kept in memory for a few
hours and searched locally, including names listed under the queried domain.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit

from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import NetworkError, NetworkPolicyError
from . import intel_ip_connectors as lists

MAX_LIST_BYTES = 16 * 1024 * 1024
MAX_UNDER = 20
SOURCES = (
    # OpenPhish publishes its community feed on GitHub.
    ("openphish", "OpenPhish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "raw.githubusercontent.com", "urls"),
    ("phishing-army", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist_extended.txt", "phishing.army", "domains"),
    ("blocklist-project", "Block List Project", "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt", "blocklistproject.github.io", "domains"),
    ("phishing-database", "Phishing.Database", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", "raw.githubusercontent.com", "domains"),
)


def _loader(url: str, host: str, kind: str) -> Callable[[], tuple[set[str], set[str]]]:
    def load() -> tuple[set[str], set[str]]:
        result = lists._get(url, host, max_bytes=MAX_LIST_BYTES)
        if result.status >= 400:
            raise NetworkError(f"the list answered HTTP {result.status}")
        urls: set[str] = set()
        domains: set[str] = set()
        for line in result.body.decode("utf-8", "replace").splitlines():
            entry = line.strip()
            if not entry or entry.startswith(("#", "!")):
                continue
            if kind == "urls":
                urls.add(entry.rstrip("/").lower())
                host_name = (urlsplit(entry).hostname or "").lower()
                if host_name:
                    domains.add(host_name)
            else:
                domains.add(entry.split()[-1].lower().rstrip("."))
        return urls, domains

    return load


def _phishing_lists(context: ConnectorContext) -> list[Finding]:
    if context.query_type == "url":
        url = context.query_value.rstrip("/").lower()
        domain = (urlsplit(context.query_value).hostname or "").lower()
    else:
        url, domain = "", context.query_value.lower().rstrip(".")
    parents = {".".join(domain.split(".")[index:]) for index in range(len(domain.split(".")) - 1)} if domain else set()
    findings: list[Finding] = []
    checked: list[str] = []
    failed: list[str] = []
    for source_id, name, address, host, kind in SOURCES:
        try:
            urls, domains = lists._cached(f"phish:{source_id}", _loader(address, host, kind))
        except (NetworkError, NetworkPolicyError):
            failed.append(name)
            continue
        checked.append(name)
        if url and url in urls:
            findings.append(Finding("phishing-listed", name, {"match": "URL exata", "entry": url[:500]}))
            continue
        hit = next((parent for parent in sorted(parents, key=len, reverse=True) if parent in domains), "")
        if hit:
            findings.append(Finding("phishing-listed", name, {"match": "domínio" if hit == domain else f"domínio acima ({hit})", "entry": hit}))
        suffix = "." + domain
        under = sorted(entry for entry in domains if entry.endswith(suffix))[:MAX_UNDER] if domain else []
        if under:
            findings.append(Finding("phishing-under", name, {"names": under, "meaning": f"Nomes abaixo de {domain} nesta lista"}))
    if len(failed) == len(SOURCES):
        raise NetworkError("none of the phishing lists could be downloaded")
    findings.append(Finding("phishing-check", f"{len(checked)} lista(s) de phishing conferidas", {"checked": checked, "failed": failed}))
    return findings


register_connector(
    Connector(
        "phishing-lists",
        "Listas públicas de phishing",
        "OpenPhish, Phishing Army, Block List Project and Phishing.Database, downloaded whole and matched locally, so the domain or URL is not sent.",
        ("domain", "url"),
        _phishing_lists,
        network=True,
        rate_per_minute=60,
        ttl_seconds=3 * 3600,
        source_url="https://openphish.com/",
    )
)
