"""Interchange renderers for investigation reports."""

from __future__ import annotations

import csv
import html
import json
from collections import defaultdict
from io import StringIO
from typing import Any


CSV_FIELDS = (
    "investigation_id",
    "investigation_name",
    "investigation_status",
    "record_type",
    "observation_id",
    "title",
    "content",
    "source_reference",
    "collection_basis",
    "observed_at",
    "recorded_at",
    "indicators",
    "correlations",
    "limitations",
)


def _spreadsheet_safe(value: object) -> str:
    text = str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def render_csv_report(report: dict[str, Any]) -> str:
    investigation = report.get("investigation")
    observations = report.get("observations")
    indicators = report.get("indicators")
    correlations = report.get("correlations")
    limitations = report.get("limitations")
    if (
        not isinstance(investigation, dict)
        or not isinstance(observations, list)
        or not isinstance(indicators, list)
        or not isinstance(correlations, list)
        or not isinstance(limitations, list)
    ):
        raise ValueError("invalid report data")

    indicators_by_observation: dict[str, list[dict[str, str]]] = defaultdict(list)
    for indicator in indicators:
        if not isinstance(indicator, dict):
            raise ValueError("invalid indicator data")
        observation_id = str(indicator.get("source_observation_id", ""))
        indicators_by_observation[observation_id].append(
            {
                "type": str(indicator.get("type", "")),
                "value": str(indicator.get("value", "")),
                "verification_status": str(
                    indicator.get("verification_status", "")
                ),
            }
        )

    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for observation in observations or [None]:
        has_observation = observation is not None
        if has_observation and not isinstance(observation, dict):
            raise ValueError("invalid observation data")
        if observation is None:
            observation = {}
        row = {
            "investigation_id": investigation.get("id", ""),
            "investigation_name": investigation.get("name", ""),
            "investigation_status": investigation.get("status", ""),
            "record_type": "observation" if has_observation else "investigation",
            "observation_id": observation.get("id", ""),
            "title": observation.get("title", ""),
            "content": observation.get("content", ""),
            "source_reference": observation.get("source_reference", ""),
            "collection_basis": observation.get("collection_basis", ""),
            "observed_at": observation.get("observed_at", ""),
            "recorded_at": observation.get("recorded_at", ""),
            "indicators": json.dumps(
                indicators_by_observation.get(str(observation.get("id", "")), []),
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "correlations": json.dumps(
                correlations, ensure_ascii=False, separators=(",", ":")
            ),
            "limitations": json.dumps(
                limitations, ensure_ascii=False, separators=(",", ":")
            ),
        }
        writer.writerow(
            {field: _spreadsheet_safe(value) for field, value in row.items()}
        )
    return output.getvalue()


def render_html_report(report: dict[str, Any]) -> str:
    investigation = report["investigation"]
    observations = report["observations"]
    indicators = report["indicators"]
    correlations = report["correlations"]
    limitations = report["limitations"]
    if (
        not isinstance(investigation, dict)
        or not isinstance(observations, list)
        or not isinstance(indicators, list)
        or not isinstance(correlations, list)
        or not isinstance(limitations, list)
    ):
        raise ValueError("invalid report data")

    observation_sections = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("invalid observation data")
        observation_sections.append(
            "<article><h2>{}</h2><p>{}</p><dl>"
            "<dt>Source reference</dt><dd><code>{}</code></dd>"
            "<dt>Collection basis</dt><dd>{}</dd>"
            "<dt>Observed at</dt><dd><time>{}</time></dd>"
            "<dt>Recorded at</dt><dd><time>{}</time></dd>"
            "</dl></article>".format(
                html.escape(str(observation.get("title", ""))),
                html.escape(str(observation.get("content", ""))),
                html.escape(str(observation.get("source_reference", ""))),
                html.escape(str(observation.get("collection_basis", ""))),
                html.escape(str(observation.get("observed_at", ""))),
                html.escape(str(observation.get("recorded_at", ""))),
            )
        )

    limitation_items = "".join(
        f"<li>{html.escape(str(limitation))}</li>"
        for limitation in limitations
    )
    indicator_sections = [
        "<li><strong>{}</strong>: <code>{}</code>"
        " <span>from {} | {} | {} | observed {} | {}</span></li>".format(
            html.escape(str(indicator.get("type", ""))),
            html.escape(str(indicator.get("value", ""))),
            html.escape(str(indicator.get("source_observation_id", ""))),
            html.escape(str(indicator.get("source_reference", ""))),
            html.escape(str(indicator.get("collection_basis", ""))),
            html.escape(str(indicator.get("observed_at", ""))),
            html.escape(str(indicator.get("verification_status", ""))),
        )
        for indicator in indicators
        if isinstance(indicator, dict)
    ]
    correlation_items = "".join(
        "<li><strong>{}</strong>: <code>{}</code> "
        "matched across {} observations</li>".format(
            html.escape(str(correlation.get("type", ""))),
            html.escape(str(correlation.get("value", ""))),
            html.escape(str(correlation.get("observation_count", ""))),
        )
        for correlation in correlations
        if isinstance(correlation, dict)
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>{} | GARBAGE report</title><link rel=\"stylesheet\" href=\"/style.css\">"
        "<script src=\"/report.js\" defer></script>"
        "</head><body><main><header><h1>{}</h1><p>{}</p>"
        "<p>Status: {}</p><p>Created: <time>{}</time></p>"
        "<button id=\"print-button\" type=\"button\">Print report</button>"
        "</header><section><h2>Observations ({})</h2>{}</section>"
        "<section><h2>Extracted indicators ({})</h2><ul>{}</ul></section>"
        "<section><h2>Exact-value correlations ({})</h2><ul>{}</ul></section>"
        "<section><h2>Limitations</h2><ul>{}</ul></section>"
        "<p><a href=\"/\">Return to the local ledger</a></p>"
        "</main></body></html>"
    ).format(
        html.escape(str(investigation.get("name", "Investigation"))),
        html.escape(str(investigation.get("name", "Investigation"))),
        html.escape(str(investigation.get("description", ""))),
        html.escape(str(investigation.get("status", "open"))),
        html.escape(str(investigation.get("created_at", ""))),
        len(observation_sections),
        "".join(observation_sections) or "<p>No observations recorded.</p>",
        len(indicator_sections),
        "".join(indicator_sections) or "<li>No indicators detected.</li>",
        len(correlations),
        correlation_items or "<li>No repeated indicators detected.</li>",
        limitation_items,
    )
