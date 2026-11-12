"""Exact-value correlation for indicators extracted from multiple observations."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


_SOURCE_FIELDS = (
    "source_observation_id",
    "source_reference",
    "collection_basis",
    "observed_at",
    "recorded_at",
    "verification_status",
)


def correlate_indicators(
    indicators: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    for indicator in indicators:
        kind = str(indicator.get("type", ""))
        value = str(indicator.get("value", ""))
        observation_id = str(indicator.get("source_observation_id", ""))
        if not kind or not value or not observation_id:
            continue
        source = {
            field: str(indicator.get(field, ""))
            for field in _SOURCE_FIELDS
        }
        groups[(kind, value)].setdefault(observation_id, source)

    correlations = []
    for (kind, value), sources in sorted(groups.items()):
        if len(sources) < 2:
            continue
        references = {
            source["source_reference"]
            for source in sources.values()
            if source["source_reference"]
        }
        independent = len(references)
        if independent >= 3:
            strength = "high"
        elif independent == 2:
            strength = "medium"
        elif independent == 1:
            strength = "low"
        else:
            strength = "unattributed"
        correlations.append(
            {
                "type": kind,
                "value": value,
                "match_method": "exact-normalized-value",
                "observation_count": len(sources),
                "independent_source_count": independent,
                "strength": strength,
                "note": (
                    "Multiple observations are not independent unless their source "
                    "references differ."
                ),
                "sources": [sources[key] for key in sorted(sources)],
            }
        )
    return correlations
