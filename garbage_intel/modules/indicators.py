"""Pattern-based indicator extraction from analyst-recorded observations."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any


_IPV4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
)
_DOMAIN = re.compile(
    r"(?<![A-Z0-9._-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}\.?(?![A-Z0-9_-])",
    re.IGNORECASE,
)
_HASHES = (
    ("sha256", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")),
    ("sha1", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")),
    ("md5", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")),
)


def extract_indicators(
    observations: Iterable[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Extract syntactic indicators, carrying their source and access provenance."""
    findings: list[dict[str, str]] = []
    for observation in observations:
        content = str(observation.get("content", ""))
        matches: list[tuple[int, str, str]] = []

        for match in _IPV4.finditer(content):
            value = match.group()
            try:
                address = ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                continue
            matches.append((match.start(), "ipv4", str(address)))

        for match in _DOMAIN.finditer(content):
            matches.append((match.start(), "domain", match.group().rstrip(".").lower()))

        for kind, pattern in _HASHES:
            for match in pattern.finditer(content):
                matches.append((match.start(), kind, match.group().lower()))

        seen: set[tuple[str, str]] = set()
        for _, kind, value in sorted(matches):
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
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
                }
            )
    return findings
