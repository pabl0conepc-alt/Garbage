"""Typosquatting candidates for a domain, and which of them resolve.

Label variants come from the Rust engine (``native/rust/src/typosquat.rs``)
when it is built, otherwise from the identical Python reference below; the
test suite checks both give the same set. Common TLD swaps are added here.

The ``typosquat`` connector asks a public DNS-over-HTTPS resolver whether
each candidate exists (NOERROR with any record vs NXDOMAIN). It never
contacts the candidate domains themselves. Existing is not malicious: many
variants are defensive registrations or unrelated sites.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import quote

from .. import native
from ..errors import ValidationError
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import NetworkError
from ..resolution import registrable_parts
from . import intel_connectors

KINDS = {
    1: "omission",
    2: "repetition",
    3: "transposition",
    4: "replacement",
    5: "insertion",
    6: "homoglyph",
    7: "hyphenation",
    8: "vowel-swap",
    9: "bitsquatting",
    10: "addition",
    11: "subdomain",
    12: "tld-swap",
}
TLD_SWAPS = (
    "com", "net", "org", "info", "biz", "co", "io", "xyz", "online", "site", "top", "shop", "app",
    "dev", "live", "store", "club", "me", "us", "cc", "com.br", "net.br", "br", "pt", "cn", "ru",
)
MAX_CHECKS = 160
# Kinds checked first when there are more candidates than checks.
PRIORITY = (12, 6, 1, 3, 4, 7, 9, 2, 8, 5, 10, 11)

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_VOWELS = "aeiou"
_KEYBOARD = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")
_GLYPHS = (
    ("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("i", "1"), ("i", "l"), ("l", "i"),
    ("m", "rn"), ("rn", "m"), ("w", "vv"), ("vv", "w"), ("d", "cl"), ("cl", "d"), ("e", "3"),
)


def _neighbours(key: str) -> list[str]:
    found: set[str] = set()
    for row_index, row in enumerate(_KEYBOARD):
        column = row.find(key)
        if column < 0:
            continue
        if column > 0:
            found.add(row[column - 1])
        if column + 1 < len(row):
            found.add(row[column + 1])
        for other in (row_index - 1, row_index + 1):
            if 0 <= other < len(_KEYBOARD):
                for offset in (column - 1, column, column + 1):
                    if 0 <= offset < len(_KEYBOARD[other]):
                        found.add(_KEYBOARD[other][offset])
    return sorted(found)


def _valid(label: str) -> bool:
    return (
        0 < len(label) <= 63
        and label[0] != "-"
        and label[-1] != "-"
        and all(char in _ALPHABET or char == "-" for char in label)
    )


def python_variants(label: str) -> list[tuple[int, str]]:
    """Reference implementation of the Rust generator (same output)."""
    label = label.lower()
    if not _valid(label):
        return []
    out: set[tuple[int, str]] = set()

    def add(kind: int, candidate: str) -> None:
        if candidate != label and (kind == 11 or _valid(candidate)):
            out.add((kind, candidate))

    length = len(label)
    for index, char in enumerate(label):
        add(1, label[:index] + label[index + 1:])
        add(2, label[:index] + char + label[index:])
        if index + 1 < length and label[index + 1] != char:
            add(3, label[:index] + label[index + 1] + char + label[index + 2:])
        for near in _neighbours(char):
            add(4, label[:index] + near + label[index + 1:])
            add(5, label[:index] + near + label[index:])
            add(5, label[:index + 1] + near + label[index + 1:])
        if index > 0 and char != "-" and label[index - 1] != "-":
            add(7, label[:index] + "-" + label[index:])
        if char in _VOWELS:
            for vowel in _VOWELS:
                if vowel != char:
                    add(8, label[:index] + vowel + label[index + 1:])
        for bit in range(8):
            flipped = chr(ord(char) ^ (1 << bit))
            if flipped in _ALPHABET or flipped == "-":
                add(9, label[:index] + flipped + label[index + 1:])
        if index > 0 and char != "-" and label[index - 1] != "-":
            add(11, label[:index] + "." + label[index:])
    for source, target in _GLYPHS:
        for start in range(length - len(source) + 1):
            if label[start:start + len(source)] == source:
                add(6, label[:start] + target + label[start + len(source):])
    for extra in _ALPHABET:
        add(10, label + extra)
    # Rust orders by (kind, bytes); for ASCII this is the same as Python's.
    return sorted(out)


def label_variants(label: str) -> tuple[list[tuple[int, str]], str]:
    native_result = native.typosquat_variants(label)
    if native_result is not None:
        return native_result, "rust"
    return python_variants(label), "python"


def generate(domain: str) -> dict[str, Any]:
    """Every candidate for ``domain`` with its kind; nothing is resolved."""
    domain = domain.strip().lower().rstrip(".")
    label, suffix = registrable_parts(domain)
    if not suffix or not _valid(label):
        raise ValidationError("give a registrable domain such as example.com")
    variants, engine = label_variants(label)
    rank = {kind: position for position, kind in enumerate(PRIORITY)}
    # One entry per spelling, under the most telling technique that makes it.
    best: dict[str, int] = {}
    for kind, candidate in variants:
        name = f"{candidate}.{suffix}"
        if name not in best or rank[kind] < rank[best[name]]:
            best[name] = kind
    for tld in TLD_SWAPS:
        if tld != suffix:
            best[f"{label}.{tld}"] = 12
    candidates = [{"domain": name, "kind": KINDS[kind]} for name, kind in sorted(best.items(), key=lambda item: (item[1], item[0]))]
    return {"domain": f"{label}.{suffix}", "label": label, "suffix": suffix, "engine": engine, "candidates": candidates, "total": len(candidates)}


def _prioritised(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    order = {KINDS[kind]: rank for rank, kind in enumerate(PRIORITY)}
    return sorted(candidates, key=lambda item: (order[item["kind"]], item["domain"]))


def _exists(name: str) -> tuple[bool, list[str]]:
    data, _result = intel_connectors._get_json(
        f"{intel_connectors.DOH_URL}?name={quote(name, safe='')}&type=NS",
        hosts=intel_connectors.DOH_HOSTS,
        headers={"Accept": "application/dns-json"},
    )
    if not isinstance(data, dict):
        return False, []
    # NXDOMAIN (3) means the name is not delegated; NOERROR (0) means it is,
    # even with no answer for this record type (the SOA is then in Authority).
    if data.get("Status") != 0:
        return False, []
    servers = [str(item.get("data", "")).rstrip(".") for item in data.get("Answer") or [] if isinstance(item, dict) and item.get("type") == 2]
    return True, servers


def _connector(context: ConnectorContext) -> list[Finding]:
    plan = generate(context.query_value)
    checks = _prioritised(plan["candidates"])[:MAX_CHECKS]
    names = [item["domain"] for item in checks]
    findings: list[Finding] = []
    failures = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {name: pool.submit(_exists, name) for name in names}
        for item in checks:
            try:
                exists, servers = futures[item["domain"]].result()
            except NetworkError:
                failures += 1
                continue
            if exists:
                findings.append(
                    Finding(
                        "typosquat",
                        item["domain"],
                        {"kind": item["kind"], "nameservers": servers[:4], "meaning": "registered or delegated; not necessarily malicious"},
                        intel_connectors.DOH_URL,
                    )
                )
    if failures == len(names) and names:
        raise NetworkError("the DNS resolver did not answer")
    findings.insert(
        0,
        Finding(
            "typosquat-summary",
            f"{len(findings)} of {len(names)} checked",
            {"generated": plan["total"], "checked": len(names), "existing": len(findings), "unanswered": failures, "engine": plan["engine"]},
            intel_connectors.DOH_URL,
        ),
    )
    return findings


register_connector(
    Connector(
        "typosquat",
        "Typosquatting",
        "Generates misspellings, look-alike characters, bit flips and TLD swaps of a domain and asks a DNS-over-HTTPS resolver which exist. Never contacts the candidates.",
        ("domain",),
        _connector,
        network=True,
        rate_per_minute=3,
        ttl_seconds=24 * 3600,
        source_url=intel_connectors.DOH_URL,
    )
)
