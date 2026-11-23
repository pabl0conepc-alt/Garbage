"""Side-by-side comparison of two saved runs (catalogue block 9, items 36-37).

Typical use: two account lookups (user:alice vs user:alice_99, a Steam
profile vs a Roblox one) or two domains. The score adds up named signals,
each with its weight and the values that triggered it, so the analyst can
see exactly why two results look related. It is a lead for review, never an
identification: common names, shared hosting and popular avatars all produce
coincidences.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlsplit

from .errors import ValidationError
from .intel import get_run
from .modules.intel_account_connectors import normalise_username

NAME_TYPES = {"username", "persona-name", "telegram-name", "custom-url", "previous-username", "user-id"}
DISPLAY_KEYS = ("display_name", "global_name")
TEXT_TYPES = {"description", "headline", "seo-meta"}
IMAGE_TYPES = {"avatar", "skin", "banner"}
# Values every lookup of that kind shares; matching on them says nothing.
IGNORED_TYPES = {"site-unknown", "http-response", "missing-header", "security-header", "posture-check", "variation",
                 "username-analysis", "created-at", "member-count", "followers-count", "friends-count", "following-count"}
_WORD = re.compile(r"[a-z0-9à-ú]{3,}")


def _findings(run: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in run.get("results") or [] if item.get("status") == "ok" and item.get("result_type")]


def _names(items: list[dict[str, Any]], query: str) -> set[str]:
    names = {query.split(":", 1)[-1]}
    for item in items:
        if item["result_type"] in NAME_TYPES:
            names.add(str(item["value"]))
        for key in DISPLAY_KEYS:
            if (item.get("data") or {}).get(key):
                names.add(str(item["data"][key]))
    return {name.strip().lower() for name in names if name and len(name.strip()) >= 2}


def _sites(items: list[dict[str, Any]]) -> set[str]:
    return {str(item["value"]) for item in items if item["result_type"] == "account" and item["value"] not in ("none found", "not found")}


def _links(items: list[dict[str, Any]]) -> set[str]:
    hosts = set()
    for item in items:
        if item["result_type"] == "account":
            continue  # the site's own profile URL; already counted by same-sites
        data = item.get("data") or {}
        for value in (data.get("url"), data.get("profile_url"), item["value"] if str(item["value"]).startswith("http") else None):
            if value:
                hosts.add((urlsplit(str(value)).hostname or "").lower())
        for host in data.get("external_hosts") or []:
            hosts.add(str(host).lower())
    return {host for host in hosts if host}


def _words(items: list[dict[str, Any]]) -> set[str]:
    text = " ".join(str(item["value"]) for item in items if item["result_type"] in TEXT_TYPES).lower()
    return set(_WORD.findall(text))


def compare_runs(database: str, run_a: str, run_b: str) -> dict[str, Any]:
    if not run_a or not run_b or run_a == run_b:
        raise ValidationError("choose two different runs")
    a, b = get_run(database, run_a), get_run(database, run_b)
    items_a, items_b = _findings(a), _findings(b)
    signals: list[dict[str, Any]] = []

    def signal(name: str, weight: int, detail: str, evidence: list[str]) -> None:
        signals.append({"signal": name, "weight": weight, "detail": detail, "evidence": evidence[:10]})

    names_a, names_b = _names(items_a, a["query_value"]), _names(items_b, b["query_value"])
    exact = sorted(names_a & names_b)
    if exact:
        signal("same-name", 25, "The same name or handle appears in both.", exact)
    else:
        normal_a = {normalise_username(name): name for name in names_a}
        normal_b = {normalise_username(name): name for name in names_b}
        shared = sorted(set(normal_a) & set(normal_b) - {""})
        if shared:
            signal("normalised-name", 18, "Names match once separators, trailing digits and leetspeak are removed.",
                   [f"{normal_a[key]} ≈ {normal_b[key]}" for key in shared])
        else:
            best = max(((SequenceMatcher(None, x, y).ratio(), x, y) for x in names_a for y in names_b), default=(0, "", ""))
            if best[0] >= 0.8:
                signal("similar-name", 10, f"Names are {round(best[0] * 100)}% similar.", [f"{best[1]} ~ {best[2]}"])

    images = sorted({str(i["value"]) for i in items_a if i["result_type"] in IMAGE_TYPES} & {str(i["value"]) for i in items_b if i["result_type"] in IMAGE_TYPES})
    if images:
        signal("same-image", 25, "The same avatar, skin or banner URL is used by both.", images)

    sites = sorted(_sites(items_a) & _sites(items_b))
    if sites:
        weight = min(10, 2 * len(sites))
        signal("same-sites", weight, f"The name exists on {len(sites)} of the same sites (common names collide often).", sites)

    links = sorted(_links(items_a) & _links(items_b) - {"github.com", "www.google.com", "twitter.com", "x.com", "www.youtube.com", "youtube.com", "www.facebook.com"})
    if links:
        signal("shared-links", min(15, 5 * len(links)), "Both link to the same less-common hosts.", links)

    words_a, words_b = _words(items_a), _words(items_b)
    if words_a and words_b:
        jaccard = len(words_a & words_b) / len(words_a | words_b)
        if jaccard >= 0.3:
            signal("similar-text", round(15 * jaccard), f"Bios or descriptions share {round(jaccard * 100)}% of their words.", sorted(words_a & words_b))

    values_a = {(i["result_type"], str(i["value"])) for i in items_a if i["result_type"] not in IGNORED_TYPES | NAME_TYPES | IMAGE_TYPES | {"account"}}
    values_b = {(i["result_type"], str(i["value"])) for i in items_b if i["result_type"] not in IGNORED_TYPES | NAME_TYPES | IMAGE_TYPES | {"account"}}
    other = sorted(values_a & values_b)
    if other:
        signal("shared-values", min(20, 3 * len(other)), "Other identical findings (IPs, name servers, certificates, groups…).", [f"{kind}: {value}" for kind, value in other])

    score = min(100, sum(item["weight"] for item in signals))
    level = "strong" if score >= 60 else "moderate" if score >= 30 else "weak" if score else "none"
    return {
        "a": {"run_id": a["id"], "query_type": a["query_type"], "query_value": a["query_value"], "findings": len(items_a)},
        "b": {"run_id": b["id"], "query_type": b["query_type"], "query_value": b["query_value"], "findings": len(items_b)},
        "score": score,
        "level": level,
        "signals": sorted(signals, key=lambda item: -item["weight"]),
        "caution": "A lead for manual review, not an identification. Common names, shared hosting and default avatars produce coincidences.",
    }
