"""Pattern-based indicator extraction from analyst-recorded text.

Extraction is deliberately syntactic. Values are refanged before matching so
common analyst notation (``hxxp``, ``[.]``, ``[:]``) does not hide an indicator.
Hosts embedded in a URL or email are not emitted as separate indicators: the
URL/email is the observed value, and duplicating its host inflates every count.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_IPV4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
)
# Candidate scan only. ipaddress performs the real validation below, which
# rejects clock times, MAC addresses and malformed compressed forms. The tail
# accepts an embedded dotted quad so IPv4-mapped addresses stay one value.
_IPV4_TAIL = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:" + _IPV4_TAIL + r"|[0-9A-Fa-f]{0,4})"
    r"(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Fa-f:])"
)
_CIDR4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}/"
    r"(?:3[0-2]|[12]?\d)(?!\d)"
)
_CIDR6 = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){1,7}"
    r"(?:" + _IPV4_TAIL + r"|[0-9A-Fa-f]{0,4})/"
    r"(?:12[0-8]|1[01]\d|[1-9]?\d)(?![0-9A-Fa-f:])"
)
_DOMAIN = re.compile(
    r"(?<![A-Z0-9._-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}\.?(?![A-Z0-9_-])",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"']{3,2000}", re.IGNORECASE)
_EMAIL = re.compile(
    r"(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}",
    re.IGNORECASE,
)
_HASHES = (
    ("sha256", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")),
    ("sha1", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")),
    ("md5", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")),
)

# A final label in this set is a filename, not a delegated TLD. The list is
# intentionally limited to suffixes that are not real TLDs (so ``.zip``,
# ``.py``, ``.sh`` and ``.md`` are still candidates and remain extractable).
_FILE_SUFFIXES = frozenset(
    {
        "7z", "avi", "bak", "bat", "bin", "bmp", "cfg", "csv", "dll", "doc",
        "docx", "eml", "exe", "gif", "gz", "html", "htm", "ini", "iso", "jar",
        "jpeg", "jpg", "js", "json", "log", "mkv", "mov", "mp3", "mp4", "msg",
        "msi", "odt", "pdf", "png", "ppt", "pptx", "rar", "sqlite", "svg",
        "tar", "tgz", "tmp", "toml", "txt", "wav", "webp", "xls", "xlsx",
        "xml", "yaml", "yml",
    }
)
FILE_SUFFIXES = _FILE_SUFFIXES
_DEFANG_RULES = (
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)", re.IGNORECASE), ":"),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[\s*/\s*\]|\(\s*/\s*\)", re.IGNORECASE), "/"),
)
_TRAILING = ".,;:!?'\""
_CLOSERS = {"]": "[", ")": "(", "}": "{"}


def refang_text(text: str) -> str:
    """Return text with common defanged indicator notation restored."""
    value = str(text)
    for pattern, replacement in _DEFANG_RULES:
        value = pattern.sub(replacement, value)
    value = re.sub(r"\bhxxps(?=\s*://)", "https", value, flags=re.IGNORECASE)
    value = re.sub(r"\bhxxp(?=\s*://)", "http", value, flags=re.IGNORECASE)
    return value


def _canonical_domain(value: str) -> str:
    return value.rstrip(".").lower()


def canonical_indicator(kind: str, value: str) -> str:
    """Return a stable comparison form without changing display semantics."""
    raw = str(value).strip()
    if kind == "domain":
        return _canonical_domain(raw)
    if kind == "email":
        return raw.lower()
    if kind in {"md5", "sha1", "sha256"}:
        return raw.lower()
    if kind in {"ipv4", "ipv6"}:
        candidate = raw.strip("[]")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return candidate
    if kind == "cidr":
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return raw
    if kind == "url":
        try:
            parsed = urlsplit(raw)
        except ValueError:
            return raw
        host = (parsed.hostname or "").lower()
        if not host:
            return raw
        try:
            port = parsed.port
        except ValueError:
            port = None
        if (parsed.scheme == "http" and port == 80) or (
            parsed.scheme == "https" and port == 443
        ):
            port = None
        # urlsplit removes the brackets from an IPv6 hostname. Put them back
        # or the canonical URL becomes ambiguous and invalid.
        netloc_host = f"[{host}]" if ":" in host else host
        netloc = netloc_host if port is None else f"{netloc_host}:{port}"
        if parsed.username or parsed.password:
            credentials = parsed.username or ""
            if parsed.password:
                credentials += f":{parsed.password}"
            netloc = f"{credentials}@{netloc}"
        return urlunsplit(
            (
                parsed.scheme.lower(),
                netloc,
                parsed.path or "/",
                parsed.query,
                parsed.fragment,
            )
        )
    return raw


def _url_value(raw: str) -> str | None:
    value = raw.rstrip(_TRAILING)
    # Keep a closing bracket that belongs to the URL's IPv6 host, while still
    # removing prose parentheses around the URL.
    while value and value[-1] in _CLOSERS:
        closer = value[-1]
        opener = _CLOSERS[closer]
        if value.count(closer) <= value.count(opener):
            break
        value = value[:-1]
    if len(value) <= 3:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
    except ValueError:
        return None
    return value


def _ipv6_value(raw: str) -> str | None:
    candidate = raw.strip("[]")
    try:
        return str(ipaddress.IPv6Address(candidate))
    except ipaddress.AddressValueError:
        return None


def _cidr_value(raw: str) -> str | None:
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return None


def _domain_value(raw: str) -> str | None:
    value = raw.rstrip(".")
    suffix = value.rsplit(".", 1)[-1].lower()
    if suffix in _FILE_SUFFIXES:
        return None
    if len(value) > 253:
        return None
    return value.lower()


def _context(text: str, start: int, end: int, width: int = 56) -> str:
    snippet = text[max(0, start - width) : min(len(text), end + width)]
    return re.sub(r"\s+", " ", snippet).strip()


def extract_indicators(
    observations: Iterable[Mapping[str, Any]],
    *,
    deduplicate: bool = True,
) -> list[dict[str, Any]]:
    """Extract syntactic indicators, carrying their source and access provenance.

    ``deduplicate`` keeps one record per exact value within an observation. Set
    it to false for triage counts; callers that persist findings should keep the
    default so one observation cannot inflate the index.
    """
    findings: list[dict[str, Any]] = []
    for observation in observations:
        original = str(observation.get("content", ""))
        content = refang_text(original)
        matches: list[tuple[int, int, str, str]] = []

        url_ranges: list[tuple[int, int]] = []
        for match in _URL.finditer(content):
            value = _url_value(match.group())
            if value is None:
                continue
            url_ranges.append((match.start(), match.end()))
            matches.append(
                (match.start(), match.end(), "url", canonical_indicator("url", value))
            )

        email_ranges: list[tuple[int, int]] = []
        for match in _EMAIL.finditer(content):
            if any(start <= match.start() < end for start, end in url_ranges):
                continue
            value = match.group().lower()
            email_ranges.append((match.start(), match.end()))
            matches.append((match.start(), match.end(), "email", value))

        cidr_ranges: list[tuple[int, int]] = []
        for pattern in (_CIDR4, _CIDR6):
            for match in pattern.finditer(content):
                if any(start <= match.start() < end for start, end in url_ranges):
                    continue
                value = _cidr_value(match.group())
                if value is None:
                    continue
                cidr_ranges.append((match.start(), match.end()))
                matches.append((match.start(), match.end(), "cidr", value))

        ipv6_ranges: list[tuple[int, int]] = []
        for match in _IPV6.finditer(content):
            if any(
                start <= match.start() < end
                for start, end in (*url_ranges, *cidr_ranges)
            ):
                continue
            value = _ipv6_value(match.group())
            if value is None:
                continue
            ipv6_ranges.append((match.start(), match.end()))
            matches.append((match.start(), match.end(), "ipv6", value))

        for match in _IPV4.finditer(content):
            if any(
                start <= match.start() < end
                for start, end in (*url_ranges, *cidr_ranges, *ipv6_ranges)
            ):
                continue
            try:
                value = str(ipaddress.IPv4Address(match.group()))
            except ipaddress.AddressValueError:
                continue
            matches.append((match.start(), match.end(), "ipv4", value))

        for match in _DOMAIN.finditer(content):
            if any(
                start <= match.start() < end
                for start, end in (*url_ranges, *email_ranges)
            ):
                continue
            value = _domain_value(match.group())
            if value is None:
                continue
            matches.append((match.start(), match.end(), "domain", value))

        for kind, pattern in _HASHES:
            for match in pattern.finditer(content):
                matches.append(
                    (match.start(), match.end(), kind, match.group().lower())
                )

        seen: set[tuple[str, str]] = set()
        for start, end, kind, value in sorted(matches):
            key = (kind, value)
            if deduplicate and key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": kind,
                    "value": value,
                    "source_observation_id": str(observation.get("id", "")),
                    "source_reference": str(observation.get("source_reference", "")),
                    "collection_basis": str(observation.get("collection_basis", "")),
                    "observed_at": str(observation.get("observed_at", "")),
                    "recorded_at": str(observation.get("recorded_at", "")),
                    "verification_status": "not-verified",
                    "context": _context(content, start, end),
                }
            )
    return findings
