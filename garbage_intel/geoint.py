"""GEOINT points from records already in the workspace.

Two kinds, never mixed up:

* ``photo``: GPS coordinates in the EXIF of an image the analyst analysed.
  Device-written, possibly stale or edited.
* ``network``: approximate location of an IP's network block from a
  multi-source query (IPinfo). City or region of the network, not of a
  person or a device.

Nothing is geocoded, reverse-geocoded or fetched here; the map's base layer
is a local file.
"""

from __future__ import annotations

import json
from typing import Any

from .db import _connection, require_module

IMAGE_FORMATS = ("png", "jpeg", "gif", "webp", "bmp")
MAX_POINTS = 2000


def _coordinates(text: str) -> tuple[float, float] | None:
    try:
        latitude, longitude = (float(part) for part in str(text).split(","))
    except ValueError:
        return None
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180) or (latitude == 0 and longitude == 0):
        return None
    return round(latitude, 6), round(longitude, 6)


def geo_points(database: str, *, investigation_id: str | None = None) -> dict[str, Any]:
    with _connection(database) as connection:
        require_module(connection, "geoint")
        scope = "AND a.investigation_id = ?" if investigation_id else ""
        params: list[Any] = list(IMAGE_FORMATS) + ([investigation_id] if investigation_id else [])
        photos = connection.execute(
            f"""SELECT a.id, a.investigation_id, a.file_name, a.sha256, a.analysis_json, a.created_at,
                       i.name AS investigation_name
                FROM file_analyses a LEFT JOIN investigations i ON i.id = a.investigation_id
                WHERE a.format IN ({",".join("?" * len(IMAGE_FORMATS))}) {scope}
                  AND a.analysis_json LIKE '%"gps"%'
                ORDER BY a.created_at DESC LIMIT ?""",
            (*params, MAX_POINTS),
        ).fetchall()
        run_scope = "AND u.investigation_id = ?" if investigation_id else ""
        networks = connection.execute(
            f"""SELECT r.run_id, r.connector_id, r.value, r.data_json, r.source_url, r.fetched_at,
                       u.query_type, u.query_value, u.investigation_id
                FROM intel_results r JOIN intel_runs u ON u.id = r.run_id
                WHERE r.result_type = 'geolocation' {run_scope}
                ORDER BY r.fetched_at DESC LIMIT ?""",
            ([investigation_id] if investigation_id else []) + [MAX_POINTS * 4],
        ).fetchall()

    points: list[dict[str, Any]] = []
    for row in photos:
        try:
            analysis = json.loads(row["analysis_json"])
        except ValueError:
            continue
        exif = (analysis.get("metadata") or {}).get("exif") or {}
        gps = exif.get("gps") or {}
        if not gps.get("valid"):
            continue
        points.append(
            {
                "id": f"photo:{row['id']}",
                "kind": "photo",
                "latitude": gps["latitude"],
                "longitude": gps["longitude"],
                "label": row["file_name"],
                "precision": "device",
                "horizontal_error_m": gps.get("horizontal_error_m"),
                "observed_at": gps.get("gps_time_utc") or exif.get("captured_at") or "",
                "recorded_at": row["created_at"],
                "source": "exif",
                "analysis_id": row["id"],
                "sha256": row["sha256"],
                "camera": " ".join(part for part in (exif.get("make"), exif.get("model")) if part),
                "investigation_id": row["investigation_id"],
                "investigation_name": row["investigation_name"],
            }
        )
    seen: set[str] = set()
    for row in networks:
        if row["query_value"] in seen:
            continue  # newest observation per artifact
        try:
            data = json.loads(row["data_json"] or "{}")
        except ValueError:
            continue
        coordinates = _coordinates(data.get("coordinates", ""))
        if coordinates is None:
            continue
        seen.add(row["query_value"])
        points.append(
            {
                "id": f"network:{row['query_value']}",
                "kind": "network",
                "latitude": coordinates[0],
                "longitude": coordinates[1],
                "label": row["query_value"],
                "place": row["value"],
                "precision": "network-approximate",
                "observed_at": row["fetched_at"],
                "recorded_at": row["fetched_at"],
                "source": row["connector_id"],
                "source_url": row["source_url"],
                "run_id": row["run_id"],
                "timezone": data.get("timezone", ""),
                "investigation_id": row["investigation_id"],
            }
        )
        if len(points) >= MAX_POINTS:
            break
    counts = {"photo": sum(1 for item in points if item["kind"] == "photo"), "network": sum(1 for item in points if item["kind"] == "network")}
    return {"points": points, "counts": counts, "total": len(points)}
