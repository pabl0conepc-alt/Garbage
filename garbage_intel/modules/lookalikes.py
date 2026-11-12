"""Structural domain lookalikes, not registrations or reputation claims.

Candidates come only from the local workspace and are compared with a bounded
edit distance. The Rust helper accelerates the distance when built; the Python
reference implementation is always available.
"""

from __future__ import annotations

import re
from typing import Any

from .. import native

_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_MAX_CANDIDATES = 600


def _reason(target: str, candidate: str, distance: int) -> str:
    target_plain = target.replace("-", "")
    candidate_plain = candidate.replace("-", "")
    target_skeleton = native.domain_skeleton(target)
    candidate_skeleton = native.domain_skeleton(candidate)
    if target_skeleton is None or candidate_skeleton is None:
        target_skeleton = native.python_domain_skeleton(target)
        candidate_skeleton = native.python_domain_skeleton(candidate)
    if target_skeleton == candidate_skeleton and target != candidate:
        if target_plain == candidate_plain:
            return "hyphen variation"
        return "digit or hyphen skeleton match"
    if distance == 1:
        return "one insertion, deletion, substitution or transposition"
    if distance == 2:
        return "two edits"
    return "near spelling"


def find_domain_lookalikes(
    value: str, candidates: list[str], *, limit: int = 8
) -> dict[str, Any]:
    """Return bounded local lookalikes for one domain."""
    target = value.strip().rstrip(".").lower()
    if not _DOMAIN.fullmatch(target):
        return {"engine": "none", "items": [], "scanned": 0}

    unique: dict[str, None] = {}
    for candidate in candidates:
        item = candidate.strip().rstrip(".").lower()
        if item and item != target and item not in unique and _DOMAIN.fullmatch(item):
            unique[item] = None
    ordered = sorted(
        unique,
        key=lambda item: (abs(len(item) - len(target)), item),
    )[:_MAX_CANDIDATES]

    rust_available = bool(native.native_status()["engines"]["rust_similarity"])
    native_used = rust_available
    items: list[dict[str, Any]] = []
    for candidate in ordered:
        if abs(len(candidate) - len(target)) > 2:
            continue
        distance = (
            native.domain_distance(target, candidate, 2) if rust_available else None
        )
        if distance is None:
            native_used = False
            distance = native.python_domain_distance(target, candidate, 2)
        if distance > 2:
            continue
        items.append(
            {
                "value": candidate,
                "distance": distance,
                "reason": _reason(target, candidate, distance),
            }
        )

    items.sort(key=lambda item: (item["distance"], item["value"]))
    return {
        "engine": "rust-native" if native_used else "python-fallback",
        "items": items[: max(0, int(limit))],
        "scanned": len(ordered),
    }
