"""Organisations named as victims on ransomware leak sites (ransomware.live).

ransomware.live tracks the posts that ransomware groups publish about the
companies they claim to have hit. For a domain, or a CNPJ through the
company's names, the victims whose name or domain match are listed with the
group, the dates and the country. A post is the group's claim, not a
confirmed breach.

Matches are graded: the same domain is a confirmed match; the same name is a
probable one; a mention only inside another victim's description (a client
or partner) is listed apart, as context.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import quote

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError
from . import intel_br_connectors as br

FETCH: Callable[..., FetchResult] = net.fetch
API = "https://api.ransomware.live/v2/"
MAX_VICTIMS = 50
GENERIC_LABELS = frozenset({"www", "mail", "com", "net", "org", "gov", "app", "site", "online", "shop", "loja", "grupo", "group"})


def _search(term: str) -> tuple[list[dict[str, Any]], FetchResult]:
    result = FETCH(
        f"{API}searchvictims/{quote(term)}",
        headers={"Accept": "application/json", "User-Agent": br.USER_AGENT},
        allowed_hosts=("api.ransomware.live",),
        max_bytes=8 * 1024 * 1024,
        timeout=30.0,
    )
    if result.status == 404:
        return [], result
    if result.status == 429:
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        data = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else [], result


def _normal(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", br._slug(text))


def _terms(context: ConnectorContext) -> tuple[list[str], str, set[str]]:
    """(search terms, domain, normalised company names) for the query."""
    if context.query_type == "domain":
        domain = context.query_value.lower()
        label = next((part for part in domain.split(".") if part not in GENERIC_LABELS), domain.split(".")[0])
        return [label], domain, {_normal(label)}
    company, _ = br._get_json(f"{br.BRASILAPI}{context.query_value}", "brasilapi.com.br")
    names = [br._text((company or {}).get(field)) for field in ("nome_fantasia", "razao_social")]
    # An individual entrepreneur's company name is a person's name: not searched.
    names = [name for name in names if name and not br._NAME_CPF.search(name)]
    terms = []
    for name in names:
        words = [word for word in re.findall(r"[A-Za-zÀ-ÿ0-9]+", name) if br._slug(word) and br._slug(word) not in ("ltda", "sa", "me", "epp", "eireli")]
        if words:
            terms.append(" ".join(words[:2]))
    email = br._text((company or {}).get("email"), 200).lower()
    domain = email.rsplit("@", 1)[1] if "@" in email and email.rsplit("@", 1)[1] not in br.FREE_MAIL else ""
    return list(dict.fromkeys(terms))[:2], domain, {_normal(term) for term in terms}


def _ransomware(context: ConnectorContext) -> list[Finding]:
    terms, domain, names = _terms(context)
    if not terms:
        return []
    seen: dict[str, Finding] = {}
    last: FetchResult | None = None
    for term in terms:
        victims, last = _search(term)
        for victim in victims[:200]:
            victim_domain = str(victim.get("domain") or "").lower().strip()
            victim_name = str(victim.get("victim") or "")
            if domain and victim_domain and (victim_domain == domain or victim_domain.endswith("." + domain) or domain.endswith("." + victim_domain)):
                strength = "mesmo domínio"
            elif names and _normal(victim_name) and any(name and (name == _normal(victim_name) or name in _normal(victim_name)) for name in names):
                strength = "mesmo nome"
            else:
                strength = "citado na descrição de outra vítima"
            key = f"{victim_name}|{victim.get('group')}|{str(victim.get('attackdate'))[:10]}"
            if key in seen:
                continue
            seen[key] = Finding(
                "ransomware-victim" if strength != "citado na descrição de outra vítima" else "ransomware-mention",
                victim_name[:200] or victim_domain,
                {
                    "group": str(victim.get("group") or "")[:80],
                    "attack_date": str(victim.get("attackdate") or "")[:10],
                    "discovered": str(victim.get("discovered") or "")[:10],
                    "country": str(victim.get("country") or "")[:4],
                    "activity": str(victim.get("activity") or "")[:80],
                    "domain": victim_domain[:200],
                    "match": strength,
                    "summary": " ".join(str(victim.get("description") or "").split())[:300],
                    "link": str(victim.get("url") or "")[:300],
                },
                last.final_url,
                last.sha256,
            )
    # Direct matches first, newest attack first within each group.
    findings = sorted(seen.values(), key=lambda item: item.data["attack_date"], reverse=True)
    findings = sorted(findings, key=lambda item: item.result_type != "ransomware-victim")[:MAX_VICTIMS]
    findings.append(Finding("ransomware-check", f"procurado como: {', '.join(terms)}", {"terms": terms}))
    return findings


register_connector(
    Connector(
        "ransomware-live",
        "Vítimas de ransomware (ransomware.live)",
        "Whether the organisation behind a domain or CNPJ appears as a victim on ransomware leak sites tracked by ransomware.live; a post is the group's claim.",
        ("domain", "cnpj"),
        _ransomware,
        network=True,
        # The keyless API allows only a few searches a minute.
        rate_per_minute=4,
        ttl_seconds=6 * 3600,
        source_url="https://www.ransomware.live/",
    )
)
