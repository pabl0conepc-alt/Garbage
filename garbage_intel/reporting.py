"""Interchange renderers for integrated investigation reports."""

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
    "record_id",
    "record_class",
)


def _spreadsheet_safe(value: object) -> str:
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _json_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


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
            "record_id": "",
            "record_class": "Observation (analyst-recorded, not independently verified)"
            if has_observation
            else "Investigation record",
        }
        writer.writerow(
            {field: _spreadsheet_safe(value) for field, value in row.items()}
        )

    def base_row(record_type: str, record_class: str) -> dict[str, Any]:
        return {
            "investigation_id": investigation.get("id", ""),
            "investigation_name": investigation.get("name", ""),
            "investigation_status": investigation.get("status", ""),
            "record_type": record_type,
            "observation_id": "",
            "title": "",
            "content": "",
            "source_reference": "",
            "collection_basis": "",
            "observed_at": "",
            "recorded_at": "",
            "indicators": "[]",
            "correlations": "[]",
            "limitations": "[]",
            "record_id": "",
            "record_class": record_class,
        }

    for entity in _json_list(report.get("entities")):
        row = base_row("entity", "Entity registry record")
        row.update(
            record_id=entity.get("id", ""),
            title=entity.get("name", ""),
            content=entity.get("description", ""),
            source_reference=entity.get("source_reference", ""),
            collection_basis=entity.get("collection_basis", ""),
            recorded_at=entity.get("created_at", ""),
        )
        writer.writerow({field: _spreadsheet_safe(value) for field, value in row.items()})
    for relationship in _json_list(report.get("relationships")):
        row = base_row("relationship", "Analyst-entered relationship")
        row.update(
            record_id=relationship.get("id", ""),
            title=relationship.get("relationship_type", ""),
            content=relationship.get("description", ""),
            source_reference=relationship.get("source_reference", ""),
            recorded_at=relationship.get("created_at", ""),
        )
        writer.writerow({field: _spreadsheet_safe(value) for field, value in row.items()})
    for record in _json_list(report.get("evidence")):
        row = base_row("evidence", "Hashed evidence record")
        row.update(
            record_id=record.get("id", ""),
            title=record.get("title", ""),
            content=record.get("description", ""),
            source_reference=record.get("source_reference", ""),
            recorded_at=record.get("recorded_at", ""),
        )
        writer.writerow({field: _spreadsheet_safe(value) for field, value in row.items()})
    for source in _json_list(report.get("sources")):
        row = base_row("source", "Consulted source record")
        row.update(
            record_id=source.get("id", ""),
            title=source.get("title", ""),
            content=source.get("description", ""),
            source_reference=source.get("reference", ""),
            recorded_at=source.get("accessed_at", ""),
        )
        writer.writerow({field: _spreadsheet_safe(value) for field, value in row.items()})
    return output.getvalue()


def _html_observation_sections(observations: list[dict[str, Any]]) -> str:
    sections = []
    for observation in observations:
        sections.append(
            "<article class=\"report-record\"><h2>{}</h2><p>{}</p><dl>"
            "<dt>Source reference</dt><dd><code>{}</code></dd>"
            "<dt>Collection basis</dt><dd>{}</dd>"
            "<dt>Observed at</dt><dd><time>{}</time></dd>"
            "<dt>Recorded at</dt><dd><time>{}</time></dd>"
            "</dl></article>".format(
                _esc(observation.get("title", "")),
                _esc(observation.get("content", "")),
                _esc(observation.get("source_reference", "")),
                _esc(observation.get("collection_basis", "")),
                _esc(observation.get("observed_at", "")),
                _esc(observation.get("recorded_at", "")),
            )
        )
    return "".join(sections)


def render_html_report(report: dict[str, Any]) -> str:
    investigation = report["investigation"]
    observations = report["observations"]
    indicators = report["indicators"]
    correlations = report["correlations"]
    limitations = report["limitations"]
    options = report.get("options")
    metadata = report.get("metadata")
    entities = _json_list(report.get("entities"))
    relationships = _json_list(report.get("relationships"))
    evidence = _json_list(report.get("evidence"))
    sources = _json_list(report.get("sources"))
    if (
        not isinstance(investigation, dict)
        or not isinstance(observations, list)
        or not isinstance(indicators, list)
        or not isinstance(correlations, list)
        or not isinstance(limitations, list)
    ):
        raise ValueError("invalid report data")
    if not isinstance(options, dict):
        options = {}
    if not isinstance(metadata, dict):
        metadata = {}

    include_raw = options.get("include_raw_observations", True) is not False
    observation_sections = (
        _html_observation_sections(observations)
        if include_raw
        else (
            f"<p class=\"report-note\">{len(observations)} observation(s) are "
            "retained in the investigation but raw text is excluded by the "
            "current report setting.</p>"
        )
    )
    limitation_items = "".join(
        f"<li>{_esc(limitation)}</li>" for limitation in limitations
    )
    indicator_sections = [
        "<li><strong>{}</strong>: <code>{}</code>"
        " <span>from {} | {} | {} | observed {} | {}</span></li>".format(
            _esc(indicator.get("type", "")),
            _esc(indicator.get("value", "")),
            _esc(indicator.get("source_observation_id", "")),
            _esc(indicator.get("source_reference", "")),
            _esc(indicator.get("collection_basis", "")),
            _esc(indicator.get("observed_at", "")),
            _esc(indicator.get("verification_status", "")),
        )
        for indicator in indicators
        if isinstance(indicator, dict)
    ]
    correlation_items = "".join(
        "<li><strong>{}</strong>: <code>{}</code> "
        "matched across {} observations</li>".format(
            _esc(correlation.get("type", "")),
            _esc(correlation.get("value", "")),
            _esc(correlation.get("observation_count", "")),
        )
        for correlation in correlations
        if isinstance(correlation, dict)
    )
    entity_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td>"
        "<td>{}</td><td>{}</td></tr>".format(
            _esc(entity.get("entity_type", "")),
            _esc(entity.get("name", "")),
            _esc(entity.get("identifier", "")),
            _esc(entity.get("verification_status", "")),
            _esc(entity.get("source_reference", "")),
        )
        for entity in entities
    )
    relationship_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(relationship.get("source_name", relationship.get("source_entity_id", ""))),
            _esc(relationship.get("relationship_type", "")),
            _esc(relationship.get("target_name", relationship.get("target_entity_id", ""))),
            _esc(relationship.get("verification_status", "")),
            _esc(relationship.get("source_reference", "")),
        )
        for relationship in relationships
    )
    evidence_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td>"
        "<td>{}</td><td>{}</td></tr>".format(
            _esc(record.get("title", "")),
            _esc(record.get("evidence_type", "")),
            _esc(record.get("sha256", "")),
            _esc(record.get("size_bytes", "")),
            _esc(record.get("integrity_status", "")),
            _esc(
                f"{record.get('image_format')} {record.get('image_width')}×"
                f"{record.get('image_height')}"
                if record.get("image_format")
                else ""
            ),
        )
        for record in evidence
    )
    source_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td>"
        "<td>{}</td></tr>".format(
            _esc(source.get("title", "")),
            _esc(source.get("category", "")),
            _esc(source.get("reference", "")),
            _esc(source.get("accessed_at", "")),
            _esc(source.get("verification_status", "")),
        )
        for source in sources
    )
    record_classes = metadata.get("record_classes")
    record_class_items = ""
    if isinstance(record_classes, dict):
        record_class_items = "".join(
            f"<li><strong>{_esc(key)}</strong>: {_esc(value)}</li>"
            for key, value in record_classes.items()
        )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>{} | GARBAGE report</title><link rel=\"stylesheet\" href=\"/style.css\">"
        "<script src=\"/report.js\" defer></script>"
        "</head><body class=\"report-page\"><main class=\"report-main\"><header>"
        "<p class=\"eyebrow\">GARBAGE INVESTIGATION REPORT</p>"
        "<h1>{}</h1><p>{}</p>"
        "<p>Status: {}</p><p>Created: <time>{}</time></p>"
        "<p>Generated: <time>{}</time></p>"
        "<button id=\"print-button\" type=\"button\">Print report</button>"
        "</header>"
        "<section><h2>Entities ({})</h2>"
        "<table><thead><tr><th>Type</th><th>Name</th><th>Identifier</th>"
        "<th>Verification</th><th>Source</th></tr></thead><tbody>{}</tbody></table>"
        "<p class=\"report-note\">{}</p></section>"
        "<section><h2>Relationships ({})</h2>"
        "<table><thead><tr><th>Source</th><th>Type</th><th>Target</th>"
        "<th>Verification</th><th>Source reference</th></tr></thead><tbody>{}</tbody></table>"
        "<p class=\"report-note\">{}</p></section>"
        "<section><h2>Evidence ({})</h2>"
        "<table><thead><tr><th>Title</th><th>Type</th><th>SHA-256</th>"
        "<th>Size (bytes)</th><th>Integrity</th><th>Image</th></tr></thead>"
        "<tbody>{}</tbody></table><p class=\"report-note\">{}</p></section>"
        "<section><h2>Sources ({})</h2>"
        "<table><thead><tr><th>Title</th><th>Category</th><th>Reference</th>"
        "<th>Accessed</th><th>Verification</th></tr></thead><tbody>{}</tbody></table>"
        "<p class=\"report-note\">{}</p></section>"
        "<section><h2>Observations ({})</h2>{}</section>"
        "<section><h2>Extracted indicators ({})</h2><ul>{}</ul></section>"
        "<section><h2>Exact-value correlations ({})</h2><ul>{}</ul></section>"
        "<section><h2>Record classes</h2><ul>{}</ul></section>"
        "<section><h2>Limitations</h2><ul>{}</ul></section>"
        "<p><a href=\"/\">Return to the GARBAGE workspace</a></p>"
        "</main></body></html>"
    ).format(
        _esc(investigation.get("name", "Investigation")),
        _esc(investigation.get("name", "Investigation")),
        _esc(investigation.get("description", "")),
        _esc(investigation.get("status", "open")),
        _esc(investigation.get("created_at", "")),
        _esc(metadata.get("generated_at", "")),
        len(entities),
        entity_rows or "<tr><td colspan=\"5\">No entities linked.</td></tr>",
        "Entities are analyst-entered records and are not independently verified.",
        len(relationships),
        relationship_rows
        or "<tr><td colspan=\"5\">No relationships recorded.</td></tr>",
        "Relationships are analyst-entered links; the verification status is "
        "recorded per link.",
        len(evidence),
        evidence_rows or "<tr><td colspan=\"6\">No evidence recorded.</td></tr>",
        "Digests confirm file identity only; they do not establish authenticity.",
        len(sources),
        source_rows or "<tr><td colspan=\"5\">No sources linked.</td></tr>",
        "Sources record where information was consulted and when.",
        len(observations),
        observation_sections or "<p>No observations recorded.</p>",
        len(indicator_sections),
        "".join(indicator_sections) or "<li>No indicators detected.</li>",
        len(correlations),
        correlation_items or "<li>No repeated indicators detected.</li>",
        record_class_items or "<li>No record classes reported.</li>",
        limitation_items or "<li>No limitations recorded.</li>",
    )


def render_markdown_report(report: dict[str, Any]) -> str:
    investigation = report["investigation"]
    options = report.get("options") if isinstance(report.get("options"), dict) else {}
    include_raw = options.get("include_raw_observations", True) is not False
    lines = [
        f"# {investigation.get('name', 'Investigation')}",
        "",
        "GARBAGE investigation report",
        "",
        f"- Status: {investigation.get('status', 'open')}",
        f"- Created: {investigation.get('created_at', '')}",
        f"- Investigation ID: `{investigation.get('id', '')}`",
        "",
        str(investigation.get("description", "")) or "_No description recorded._",
        "",
        "## Entities",
        "",
    ]
    entities = _json_list(report.get("entities"))
    if entities:
        lines.extend(
            [
                "| Type | Name | Identifier | Verification |",
                "| --- | --- | --- | --- |",
            ]
        )
        for entity in entities:
            lines.append(
                "| {} | {} | `{}` | {} |".format(
                    str(entity.get("entity_type", "")).replace("|", "\\|"),
                    str(entity.get("name", "")).replace("|", "\\|"),
                    str(entity.get("identifier", "")).replace("|", "\\|"),
                    str(entity.get("verification_status", "")).replace("|", "\\|"),
                )
            )
    else:
        lines.append("_No entities linked._")
    lines.extend(["", "## Relationships", ""])
    relationships = _json_list(report.get("relationships"))
    if relationships:
        for relationship in relationships:
            lines.append(
                "- {} --**{}**--> {} ({})".format(
                    relationship.get("source_name", relationship.get("source_entity_id", "")),
                    relationship.get("relationship_type", ""),
                    relationship.get("target_name", relationship.get("target_entity_id", "")),
                    relationship.get("verification_status", ""),
                )
            )
    else:
        lines.append("_No relationships recorded._")
    lines.extend(["", "## Evidence", ""])
    evidence = _json_list(report.get("evidence"))
    if evidence:
        for record in evidence:
            image = (
                f" · {record.get('image_format')} {record.get('image_width')}×"
                f"{record.get('image_height')}"
                if record.get("image_format")
                else ""
            )
            lines.append(
                "- **{}** · {} · `{}` · {} bytes · integrity {}{}".format(
                    record.get("title", ""),
                    record.get("evidence_type", ""),
                    record.get("sha256", ""),
                    record.get("size_bytes", ""),
                    record.get("integrity_status", ""),
                    image,
                )
            )
    else:
        lines.append("_No evidence recorded._")
    lines.extend(["", "## Sources", ""])
    sources = _json_list(report.get("sources"))
    if sources:
        lines.extend(
            f"- **{source.get('title', '')}** · {source.get('category', '')} · "
            f"`{source.get('reference', '')}` · accessed "
            f"{source.get('accessed_at', '')}"
            for source in sources
        )
    else:
        lines.append("_No sources linked._")
    lines.extend(["", "## Observations", ""])
    observations = report["observations"]
    if not include_raw:
        lines.append(
            f"_{len(observations)} observation(s) retained; raw text excluded by "
            "the current report setting._"
        )
    elif observations:
        for observation in observations:
            lines.extend(
                [
                    f"### {observation.get('title', '')}",
                    "",
                    str(observation.get("content", "")),
                    "",
                    f"- Source: `{observation.get('source_reference', '')}`",
                    f"- Collection basis: {observation.get('collection_basis', '')}",
                    f"- Observed at: {observation.get('observed_at', '')}",
                    "",
                ]
            )
    else:
        lines.append("_No observations recorded._")
    lines.extend(["", "## Extracted indicators", ""])
    indicators = [item for item in report["indicators"] if isinstance(item, dict)]
    if indicators:
        for indicator in indicators:
            lines.append(
                f"- **{indicator.get('type', '')}** `{indicator.get('value', '')}` "
                f"· source observation {indicator.get('source_observation_id', '')} "
                f"· {indicator.get('verification_status', '')}"
            )
    else:
        lines.append("_No indicators detected._")
    lines.extend(["", "## Exact-value correlations", ""])
    correlations = [item for item in report["correlations"] if isinstance(item, dict)]
    if correlations:
        for correlation in correlations:
            lines.append(
                f"- **{correlation.get('type', '')}** "
                f"`{correlation.get('value', '')}` · matched across "
                f"{correlation.get('observation_count', '')} observations"
            )
    else:
        lines.append("_No repeated indicators detected._")
    lines.extend(["", "## Limitations", ""])
    limitations = report["limitations"]
    if limitations:
        lines.extend(f"- {limitation}" for limitation in limitations)
    else:
        lines.append("_No limitations recorded._")
    lines.append("")
    return "\n".join(lines)
