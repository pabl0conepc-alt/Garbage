"""Offline field tools for text triage and single-indicator inspection.

These helpers never resolve DNS, contact a reputation service or persist the
submitted text. They explain what a value is, not whether it is malicious.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .indicators import (
    FILE_SUFFIXES,
    canonical_indicator,
    extract_indicators,
    refang_text,
)

MAX_TRIAGE_CHARS = 20000
_ASN = re.compile(r"^AS(\d{1,10})$", re.IGNORECASE)
_FILENAME = re.compile(r"^[^/\s]{1,240}\.[A-Za-z0-9]{1,16}$")
_DOMAIN_ASCII = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def _fact(label: str, value: object) -> dict[str, str]:
    return {"label": label, "value": str(value)}


def _base_result(raw: str, clean: str) -> dict[str, Any]:
    return {
        "input": raw[:2000],
        "defanged": clean != raw,
        "facts": [],
        "warnings": [],
        "limitations": [
            "Structural inspection only; no DNS, WHOIS, reputation or attribution lookup.",
            "Canonical values are for comparison and may normalize presentation.",
        ],
    }


def _address_facts(value: str) -> dict[str, Any]:
    address = ipaddress.ip_address(value)
    scope = "global"
    if address.is_private:
        scope = "private"
    if address.is_loopback:
        scope = "loopback"
    if address.is_link_local:
        scope = "link-local"
    if address.is_multicast:
        scope = "multicast"
    if address.is_reserved:
        scope = "reserved"
    if address.is_unspecified:
        scope = "unspecified"
    facts = [
        _fact("Version", f"IPv{address.version}"),
        _fact("Scope", scope),
        _fact("Global", "yes" if address.is_global else "no"),
        _fact("Reverse pointer", address.reverse_pointer),
    ]
    if address.version == 6 and address.scope_id:
        facts.append(_fact("Zone", address.scope_id))
    warnings: list[str] = []
    if not address.is_global:
        warnings.append(
            "This address is not globally routable; it may be private, reserved, "
            "loopback or documentation space. Treat it as infrastructure context."
        )
    return {
        "kind": f"ipv{address.version}",
        "label": f"IPv{address.version} address",
        "canonical": str(address),
        "facts": facts,
        "warnings": warnings,
    }


def _network_facts(value: str) -> dict[str, Any]:
    network = ipaddress.ip_network(value, strict=False)
    facts = [
        _fact("Version", f"IPv{network.version}"),
        _fact("Network", str(network)),
        _fact("Prefix length", f"/{network.prefixlen}"),
        _fact("Address count", network.num_addresses),
        _fact("First address", network.network_address),
        _fact("Last address", network.broadcast_address),
        _fact("Private range", "yes" if network.is_private else "no"),
    ]
    warnings = []
    if network.is_private:
        warnings.append(
            "This range is private or reserved; it is not globally routable."
        )
    return {
        "kind": "cidr",
        "label": "CIDR network",
        "canonical": str(network),
        "facts": facts,
        "warnings": warnings,
    }


def _domain_facts(value: str) -> dict[str, Any]:
    ascii_name = value.rstrip(".").lower()
    try:
        ascii_name = ascii_name.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    labels = ascii_name.split(".") if ascii_name else []
    return {
        "kind": "domain",
        "label": "Domain name",
        "canonical": ascii_name,
        "facts": [
            _fact("ASCII form", ascii_name or "—"),
            _fact("Unicode form", value.rstrip(".")),
            _fact("Labels", len(labels) if ascii_name else 0),
            _fact("Top-level label", labels[-1] if labels else "—"),
            _fact("Length", len(ascii_name)),
            _fact("Internationalized", "yes" if value != ascii_name else "no"),
        ],
        "warnings": [
            "No DNS resolution or registration lookup was performed. "
            "A syntactically valid domain is not evidence of ownership or intent."
        ],
    }


def _url_facts(value: str) -> dict[str, Any]:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = 443 if parsed.scheme == "https" else 80
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    host_version: str | None = None
    try:
        host_version = f"IPv{ipaddress.ip_address(host).version}"
    except ValueError:
        pass
    facts = [
        _fact("Scheme", parsed.scheme.lower()),
        _fact("Host", host or "—"),
        _fact("Host kind", host_version or "domain"),
        _fact("Port", port if port is not None else default_port),
        _fact("Default port", "yes" if port in {None, default_port} else "no"),
        _fact("Path", parsed.path or "/"),
        _fact("Query parameters", len(query_items)),
        _fact("Fragment", "yes" if parsed.fragment else "no"),
        _fact("Embedded credentials", "yes" if parsed.username or parsed.password else "no"),
    ]
    if query_items:
        facts.append(
            _fact(
                "Parameter names",
                ", ".join(sorted({name for name, _ in query_items})[:12]),
            )
        )
    warnings: list[str] = []
    if parsed.scheme.lower() == "http":
        warnings.append("The URL uses unencrypted HTTP.")
    if parsed.username or parsed.password:
        warnings.append(
            "The URL embeds credentials; do not paste it into external services."
        )
    if host_version:
        warnings.append(
            "The host is an IP literal, so there is no registrable domain layer."
        )
    if port is not None and port != default_port:
        warnings.append("The URL uses a non-default port.")
    return {
        "kind": "url",
        "label": "URL",
        "canonical": canonical_indicator("url", value),
        "facts": facts,
        "warnings": warnings,
    }


def _email_facts(value: str) -> dict[str, Any]:
    local, _, domain = value.lower().partition("@")
    return {
        "kind": "email",
        "label": "Email address",
        "canonical": value.lower(),
        "facts": [
            _fact("Local part", local),
            _fact("Domain", domain),
            _fact("Length", len(value)),
        ],
        "warnings": [
            "No mailbox, MX or reputation lookup was performed."
        ],
    }


def _hash_facts(kind: str, value: str) -> dict[str, Any]:
    labels = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
    return {
        "kind": kind,
        "label": f"{labels[kind]} digest",
        "canonical": value.lower(),
        "facts": [
            _fact("Algorithm", labels[kind]),
            _fact("Hex length", len(value)),
            _fact("Normalized", value.lower()),
        ],
        "warnings": [
            "A digest identifies exact bytes; it is not a reputation verdict. "
            "Compare it with evidence or file-analysis records stored here."
        ],
    }


def inspect_value(raw: object) -> dict[str, Any]:
    """Describe one value without contacting any external service."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("value must be a non-empty string")
    original = raw.strip()[:2000]
    clean = refang_text(original).strip()
    result = _base_result(original, clean)

    asn = _ASN.fullmatch(clean)
    if asn:
        result.update(
            {
                "kind": "asn",
                "label": "Autonomous system number",
                "canonical": f"AS{asn.group(1)}",
                "facts": [_fact("ASN", f"AS{asn.group(1)}")],
                "warnings": [
                    "No routing or registry lookup was performed; this is syntax only."
                ],
            }
        )
        return result

    # Unicode domains are valid but the extractor intentionally matches ASCII.
    # Classify them before extraction so an ASCII suffix is not split from the
    # internationalized label.
    if "." in clean and not re.search(r"\s", clean) and any(
        ord(character) > 127 for character in clean
    ):
        try:
            ascii_name = clean.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_name = ""
        if ascii_name and _DOMAIN_ASCII.fullmatch(ascii_name):
            result.update(_domain_facts(clean))
            return result

    findings = extract_indicators(
        [{"id": "inspect", "content": clean}], deduplicate=False
    )
    if len(findings) > 1:
        result.update(
            {
                "kind": "multiple",
                "label": "Multiple indicators",
                "canonical": "",
                "facts": [
                    _fact("Candidates", len(findings)),
                    _fact(
                        "Types",
                        ", ".join(sorted({finding["type"] for finding in findings})),
                    ),
                ],
                "warnings": [
                    "The input contains more than one indicator. Inspect one value "
                    "at a time for exact structural facts."
                ],
            }
        )
        result["candidates"] = [
            {"type": finding["type"], "value": finding["value"]}
            for finding in findings[:20]
        ]
        return result

    if len(findings) == 1:
        finding = findings[0]
        kind = finding["type"]
        value = finding["value"]
        try:
            if kind in {"ipv4", "ipv6"}:
                result.update(_address_facts(value))
            elif kind == "cidr":
                result.update(_network_facts(value))
            elif kind == "domain":
                result.update(_domain_facts(value))
            elif kind == "url":
                result.update(_url_facts(value))
            elif kind == "email":
                result.update(_email_facts(value))
            elif kind in {"md5", "sha1", "sha256"}:
                result.update(_hash_facts(kind, value))
            else:
                raise ValueError("unsupported indicator kind")
        except ValueError as error:
            result.update(
                {
                    "kind": "unknown",
                    "label": "Unrecognized value",
                    "canonical": clean,
                    "warnings": [f"The value could not be parsed: {error}."],
                }
            )
        return result

    suffix = clean.rsplit(".", 1)[-1].lower() if "." in clean else ""
    if _FILENAME.fullmatch(clean) and suffix in FILE_SUFFIXES:
        result.update(
            {
                "kind": "filename",
                "label": "Filename",
                "canonical": clean,
                "facts": [
                    _fact("Filename", clean),
                    _fact("Suffix", f".{suffix}"),
                ],
                "warnings": [
                    "This looks like a filename, not a domain. Use File intelligence "
                    "to inspect the bytes read-only."
                ],
            }
        )
        return result

    result.update(
        {
            "kind": "unknown",
            "label": "Unrecognized value",
            "canonical": clean,
            "facts": [
                _fact("Characters", len(clean)),
                _fact("Contains whitespace", "yes" if re.search(r"\s", clean) else "no"),
            ],
            "warnings": [
                "The value is not a recognized IPv4, IPv6, CIDR, domain, URL, "
                "email, hash or ASN form."
            ],
        }
    )
    return result


def triage_text(text: object) -> dict[str, Any]:
    """Extract and summarize indicators from pasted text without storing it."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    original = text.strip()
    truncated = len(original) > MAX_TRIAGE_CHARS
    sample = original[:MAX_TRIAGE_CHARS]
    findings = extract_indicators(
        [{"id": "triage", "content": sample}], deduplicate=False
    )
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["type"], finding["value"])
        item = grouped.setdefault(
            key,
            {
                "type": finding["type"],
                "value": finding["value"],
                "count": 0,
                "defanged": bool(finding.get("defanged")),
                "contexts": [],
            },
        )
        item["count"] += 1
        item["defanged"] = item["defanged"] or bool(finding.get("defanged"))
        context = finding.get("context", "")
        if context and context not in item["contexts"] and len(item["contexts"]) < 3:
            item["contexts"].append(context)

    items = sorted(grouped.values(), key=lambda item: (item["type"], item["value"]))
    counts = Counter(item["type"] for item in items)
    warnings: list[str] = []
    if not items:
        warnings.append(
            "No recognized indicator was found. Check the text or inspect the "
            "value directly."
        )
    if truncated:
        warnings.append(
            f"Only the first {MAX_TRIAGE_CHARS:,} characters were analyzed."
        )
    return {
        "sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "characters": len(original),
        "lines": original.count("\n") + 1,
        "truncated": truncated,
        "limit": MAX_TRIAGE_CHARS,
        "defanged": refang_text(original) != original,
        "indicator_count": len(findings),
        "unique_count": len(items),
        "counts": dict(counts),
        "items": items,
        "warnings": warnings,
        "limitations": [
            "Syntactic extraction only; matches are not reputation or attribution.",
            "Text is analyzed in memory and is not written to the database.",
        ],
    }
