"""Report sections computed from the case's own records: methodology,
ATT&CK techniques, evidence custody and a static graph picture.

The methodology describes what was actually done in this workspace (which
sources were queried and with what outcome, which transforms ran, what was
analysed, imported and verified), so a reader can judge the findings. It is
generated, never written by hand, and claims nothing beyond the records.
"""

from __future__ import annotations

import math
import random
from html import escape
from typing import Any

from .db import _connection

SECTIONS = (
    "summary", "methodology", "entities", "relationships", "graph", "evidence", "custody",
    "sources", "observations", "indicators", "correlations", "techniques", "limitations",
)
MAX_GRAPH_NODES = 150
SHADES = {
    "domain": "#B4BAC0", "url": "#A5ACB3", "ipv4": "#969DA4", "ipv6": "#969DA4", "email": "#D2D6DA",
    "organization": "#C3C8CD", "hash": "#6C737A", "file": "#7A8188", "image": "#7A8188",
    "person": "#F0F1F2", "username": "#E1E4E7", "profile": "#E1E4E7", "ioc": "#D2D6DA", "other": "#5F666D",
}


def parse_sections(raw: object) -> tuple[str, ...]:
    if raw in (None, "", "all"):
        return SECTIONS
    names = [part.strip() for part in str(raw).split(",") if part.strip()]
    unknown = [name for name in names if name not in SECTIONS]
    if unknown:
        from .errors import ValidationError

        raise ValidationError(f"unknown report sections: {', '.join(unknown)}")
    return tuple(name for name in SECTIONS if name in names)


def methodology(database: str, investigation_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        def all_rows(sql: str, *args: Any) -> list[dict[str, Any]]:
            return [dict(row) for row in connection.execute(sql, args)]

        runs = all_rows(
            """SELECT r.connector_id, COUNT(DISTINCT r.run_id) AS runs,
                      SUM(CASE WHEN r.status IN ('ok', 'empty') THEN 1 ELSE 0 END) AS answered_rows,
                      SUM(CASE WHEN r.status = 'error' THEN 1 ELSE 0 END) AS error_rows,
                      SUM(CASE WHEN r.value <> '' THEN 1 ELSE 0 END) AS findings,
                      MIN(r.fetched_at) AS first_at, MAX(r.fetched_at) AS last_at
               FROM intel_results r JOIN intel_runs u ON u.id = r.run_id
               WHERE u.investigation_id = ? AND r.status NOT IN ('unsupported', 'pending')
               GROUP BY r.connector_id ORDER BY runs DESC, r.connector_id""",
            investigation_id,
        )
        transforms = all_rows(
            """SELECT transform_id, COUNT(*) AS runs, SUM(created_count) AS created, SUM(relationship_count) AS relationships
               FROM transform_runs WHERE investigation_id = ? GROUP BY transform_id ORDER BY runs DESC""",
            investigation_id,
        )
        analyses = all_rows(
            "SELECT format, COUNT(*) AS count FROM file_analyses WHERE investigation_id = ? GROUP BY format ORDER BY count DESC",
            investigation_id,
        )
        bases = all_rows(
            "SELECT collection_basis, COUNT(*) AS count FROM observations WHERE investigation_id = ? GROUP BY collection_basis",
            investigation_id,
        )
        entity_status = all_rows(
            """SELECT e.verification_status AS status, COUNT(*) AS count FROM entities e
               JOIN investigation_entities ie ON ie.entity_id = e.id WHERE ie.investigation_id = ? GROUP BY e.verification_status""",
            investigation_id,
        )
        relationship_status = all_rows(
            "SELECT verification_status AS status, COUNT(*) AS count FROM relationships WHERE investigation_id = ? GROUP BY verification_status",
            investigation_id,
        )
        imports = all_rows(
            """SELECT summary, created_at FROM activities
               WHERE investigation_id = ? AND action = 'import' ORDER BY created_at""",
            investigation_id,
        )
        period = connection.execute(
            """SELECT MIN(at) AS first_at, MAX(at) AS last_at FROM (
                   SELECT observed_at AS at FROM observations WHERE investigation_id = ?
                   UNION ALL SELECT recorded_at FROM evidence WHERE investigation_id = ?
                   UNION ALL SELECT created_at FROM activities WHERE investigation_id = ?)""",
            (investigation_id, investigation_id, investigation_id),
        ).fetchone()
    return {
        "period": {"first": period["first_at"] or "", "last": period["last_at"] or ""},
        "sources_queried": runs,
        "transforms": transforms,
        "file_analyses": analyses,
        "collection_bases": {row["collection_basis"]: row["count"] for row in bases},
        "entity_verification": {row["status"]: row["count"] for row in entity_status},
        "relationship_verification": {row["status"]: row["count"] for row in relationship_status},
        "imports": imports,
        "statement": (
            "Generated from the workspace records of this case. Third-party findings were copied as the sources "
            "published them; only items marked verified were checked by the analyst."
        ),
    }


def techniques(database: str, investigation_id: str) -> list[dict[str, Any]]:
    with _connection(database) as connection:
        return [dict(row) for row in connection.execute(
            """SELECT c.technique_id, COALESCE(t.name, '') AS name, COALESCE(t.tactics, '') AS tactics, c.note, c.source, c.created_at
               FROM case_techniques c LEFT JOIN attack_techniques t ON t.id = c.technique_id
               WHERE c.investigation_id = ? ORDER BY c.technique_id""",
            (investigation_id,),
        )]


def custody_summary(database: str, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from .custody import chain

    summary = []
    for record in evidence:
        log = chain(database, record["id"])
        summary.append(
            {
                "evidence_id": record["id"],
                "title": record.get("title", ""),
                "events": len(log["events"]),
                "intact": log["intact"],
                "head": log["head"],
                "actions": [event["action"] for event in log["events"]],
                "last_at": log["events"][-1]["occurred_at"] if log["events"] else "",
            }
        )
    return summary


def graph_svg(entities: list[dict[str, Any]], relationships: list[dict[str, Any]]) -> str:
    """A static, deterministic picture of the case graph (spring layout)."""
    nodes = sorted(entities, key=lambda item: item["id"])[:MAX_GRAPH_NODES]
    index = {item["id"]: position for position, item in enumerate(nodes)}
    edges = [
        (index[item["source_entity_id"]], index[item["target_entity_id"]])
        for item in relationships
        if item.get("source_entity_id") in index and item.get("target_entity_id") in index
    ]
    if not nodes:
        return ""
    positions, width, height = _layout(len(nodes), edges)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {int(width)} {int(height)}" role="img" aria-label="Case graph">',
        f'<rect width="{int(width)}" height="{int(height)}" fill="#101214"/>',
    ]
    for a, b in edges:
        parts.append(
            f'<line x1="{positions[a][0]:.1f}" y1="{positions[a][1]:.1f}" x2="{positions[b][0]:.1f}" y2="{positions[b][1]:.1f}" stroke="#4a5157" stroke-width="1.2"/>'
        )
    for item, (x, y) in zip(nodes, positions):
        label = item.get("name") or item.get("identifier") or ""
        label = label if len(label) <= 28 else label[:26] + "…"
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{SHADES.get(item.get("entity_type"), "#5F666D")}" stroke="#101214" stroke-width="1.5"/>')
        parts.append(
            f'<text x="{x:.1f}" y="{y + 19:.1f}" fill="#c9ced3" font-family="sans-serif" font-size="10" text-anchor="middle">{escape(label)}</text>'
        )
    if len(entities) > MAX_GRAPH_NODES:
        parts.append(f'<text x="12" y="{int(height) - 12}" fill="#8a939b" font-family="sans-serif" font-size="11">Showing {MAX_GRAPH_NODES} of {len(entities)} entities.</text>')
    parts.append("</svg>")
    return "".join(parts)

def _spring(size: int, edges: list[tuple[int, int]], seed: int) -> list[list[float]]:
    """Fruchterman-Reingold for one connected component, unit edge length 70."""
    if size == 1:
        return [[0.0, 0.0]]
    generator = random.Random(seed)
    radius = 35.0 * math.sqrt(size)
    positions = [[radius * math.cos(2 * math.pi * k / size) + generator.uniform(-5, 5),
                  radius * math.sin(2 * math.pi * k / size) + generator.uniform(-5, 5)] for k in range(size)]
    ideal, temperature = 70.0, radius / 2
    for _ in range(200):
        moves = [[0.0, 0.0] for _ in range(size)]
        for a in range(size):
            for b in range(a + 1, size):
                dx, dy = positions[a][0] - positions[b][0], positions[a][1] - positions[b][1]
                distance = max(0.01, math.hypot(dx, dy))
                force = ideal * ideal / distance
                moves[a][0] += dx / distance * force
                moves[a][1] += dy / distance * force
                moves[b][0] -= dx / distance * force
                moves[b][1] -= dy / distance * force
        for a, b in edges:
            dx, dy = positions[a][0] - positions[b][0], positions[a][1] - positions[b][1]
            distance = max(0.01, math.hypot(dx, dy))
            force = distance * distance / ideal
            moves[a][0] -= dx / distance * force
            moves[a][1] -= dy / distance * force
            moves[b][0] += dx / distance * force
            moves[b][1] += dy / distance * force
        for position, move in zip(positions, moves):
            length = max(0.01, math.hypot(*move))
            position[0] += move[0] / length * min(length, temperature)
            position[1] += move[1] / length * min(length, temperature)
        temperature = max(1.0, temperature * 0.96)
    return positions


def _layout(count: int, edges: list[tuple[int, int]]) -> tuple[list[list[float]], float, float]:
    """Lay out each connected component on its own and pack them in rows,
    largest first, so isolated entities do not squash the main cluster."""
    neighbours: dict[int, set[int]] = {index: set() for index in range(count)}
    for a, b in edges:
        neighbours[a].add(b)
        neighbours[b].add(a)
    seen: set[int] = set()
    groups: list[list[int]] = []
    for start in range(count):
        if start in seen:
            continue
        group, queue = [], [start]
        seen.add(start)
        while queue:
            current = queue.pop()
            group.append(current)
            for following in sorted(neighbours[current] - seen):
                seen.add(following)
                queue.append(following)
        groups.append(sorted(group))
    groups.sort(key=len, reverse=True)
    positions = [[0.0, 0.0] for _ in range(count)]
    row_width, cursor_x, cursor_y, row_height = 1100.0, 0.0, 0.0, 0.0
    for number, group in enumerate(groups):
        local = {node: position for position, node in enumerate(group)}
        placed = _spring(len(group), [(local[a], local[b]) for a, b in edges if a in local and b in local], 31 * number + len(group))
        min_x = min(point[0] for point in placed)
        min_y = min(point[1] for point in placed)
        box_w = max(point[0] for point in placed) - min_x + 140
        box_h = max(point[1] for point in placed) - min_y + 70
        if cursor_x and cursor_x + box_w > row_width:
            cursor_x, cursor_y, row_height = 0.0, cursor_y + row_height, 0.0
        for node, point in zip(group, placed):
            positions[node] = [cursor_x + point[0] - min_x + 70, cursor_y + point[1] - min_y + 35]
        cursor_x += box_w
        row_height = max(row_height, box_h)
    width = max(point[0] for point in positions) + 70
    height = cursor_y + row_height
    return positions, max(width, 300.0), max(height, 120.0)
