"""GEOINT points from records already in the workspace.

Two kinds, never mixed up:

* ``photo``: GPS coordinates in the EXIF of an image the analyst analysed.
  Device-written, possibly stale or edited.
* ``network``: approximate location of an IP's network block from a
  multi-source query (IPinfo). City or region of the network, not of a
  person or a device.
* ``manual``: a point the analyst added to a case, with a note and source.

Photos come from analysed images and from JPEG evidence. Points export as
GeoJSON or KML for desktop GIS tools.

Nothing is geocoded, reverse-geocoded or fetched here; the map's base layer
is a local file.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape

from .db import _connection, new_id, record_activity, require_module, utc_now
from .errors import NotFoundError, ValidationError
from .evidence import _read_stored_file
from .modules.exif import parse_exif
from .validation import clean_text

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

        evidence_scope = "AND e.investigation_id = ?" if investigation_id else ""
        evidence = connection.execute(
            f"""SELECT e.id, e.investigation_id, e.title, e.stored_name, e.sha256, e.recorded_at, i.name AS investigation_name
                FROM evidence e LEFT JOIN investigations i ON i.id = e.investigation_id
                WHERE e.stored_name <> '' AND (e.media_type = 'image/jpeg' OR lower(e.original_name) LIKE '%.jp%g')
                {evidence_scope} ORDER BY e.recorded_at DESC LIMIT ?""",
            ([investigation_id] if investigation_id else []) + [MAX_POINTS],
        ).fetchall()
        manual_scope = "WHERE g.investigation_id = ?" if investigation_id else ""
        manual = connection.execute(
            f"""SELECT g.*, i.name AS investigation_name FROM geo_points g
                LEFT JOIN investigations i ON i.id = g.investigation_id {manual_scope}
                ORDER BY g.created_at DESC LIMIT ?""",
            ([investigation_id] if investigation_id else []) + [MAX_POINTS],
        ).fetchall()

    points: list[dict[str, Any]] = []
    for row in evidence:
        try:
            exif = parse_exif(_read_stored_file(database, row["stored_name"])) or {}
        except (NotFoundError, OSError, ValidationError):
            continue
        gps = exif.get("gps") or {}
        if not gps.get("valid"):
            continue
        points.append(
            {
                "id": f"evidence:{row['id']}",
                "kind": "photo",
                "latitude": gps["latitude"],
                "longitude": gps["longitude"],
                "label": row["title"],
                "precision": "device",
                "horizontal_error_m": gps.get("horizontal_error_m"),
                "observed_at": gps.get("gps_time_utc") or exif.get("captured_at") or "",
                "recorded_at": row["recorded_at"],
                "source": "evidence",
                "evidence_id": row["id"],
                "sha256": row["sha256"],
                "camera": " ".join(part for part in (exif.get("make"), exif.get("model")) if part),
                "investigation_id": row["investigation_id"],
                "investigation_name": row["investigation_name"],
            }
        )
    for row in manual:
        points.append(
            {
                "id": f"manual:{row['id']}",
                "kind": "manual",
                "point_id": row["id"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "label": row["label"],
                "note": row["note"],
                "precision": "analyst",
                "observed_at": row["observed_at"] or row["created_at"],
                "recorded_at": row["created_at"],
                "source": row["source_reference"] or "analyst",
                "investigation_id": row["investigation_id"],
                "investigation_name": row["investigation_name"],
            }
        )
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
        try:
            data = json.loads(row["data_json"] or "{}")
        except ValueError:
            continue
        coordinates = _coordinates(data.get("coordinates", ""))
        if coordinates is None:
            continue
        # Geocoded places (Nominatim) carry their own kind; IP locations do not.
        kind = "place" if data.get("kind") == "place" else "network"
        key = f"{kind}:{row['query_value']}" if kind == "network" else f"place:{data.get('coordinates', '')}"
        if key in seen:
            continue
        seen.add(key)
        points.append(
            {
                "id": key,
                "kind": kind,
                "latitude": coordinates[0],
                "longitude": coordinates[1],
                "label": row["query_value"] if kind == "network" else row["value"],
                "place": row["value"],
                "precision": data.get("precision") or "network-approximate",
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
    counts = {kind: sum(1 for item in points if item["kind"] == kind) for kind in ("photo", "network", "place", "manual")}
    return {"points": points, "counts": counts, "total": len(points)}


def _number(value: Any, low: float, high: float, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be a number") from exc
    if not low <= number <= high:
        raise ValidationError(f"{name} must be between {low} and {high}")
    return round(number, 7)


def add_point(database: str, investigation_id: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) - {"label", "latitude", "longitude", "note", "source_reference", "observed_at"}:
        raise ValidationError("send {label, latitude, longitude, note?, source_reference?, observed_at?}")
    point = {
        "id": new_id(),
        "investigation_id": investigation_id,
        "label": clean_text(payload.get("label"), "label", max_length=200, required=True),
        "latitude": _number(payload.get("latitude"), -90, 90, "latitude"),
        "longitude": _number(payload.get("longitude"), -180, 180, "longitude"),
        "note": clean_text(payload.get("note", ""), "note", max_length=2000),
        "source_reference": clean_text(payload.get("source_reference", ""), "source reference", max_length=1000),
        "observed_at": clean_text(payload.get("observed_at", ""), "observed at", max_length=40),
        "created_at": utc_now(),
    }
    with _connection(database) as connection:
        require_module(connection, "geoint")
        if connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            raise NotFoundError("investigation not found")
        connection.execute(
            """INSERT INTO geo_points (id, investigation_id, label, latitude, longitude, note, source_reference, observed_at, created_at)
               VALUES (:id, :investigation_id, :label, :latitude, :longitude, :note, :source_reference, :observed_at, :created_at)""",
            point,
        )
        record_activity(connection, action="geo-point", target_type="investigation", target_id=investigation_id,
                        investigation_id=investigation_id, summary=f"Map point added: {point['label'][:100]}")
    return point


def delete_point(database: str, point_id: str) -> None:
    with _connection(database) as connection:
        if connection.execute("DELETE FROM geo_points WHERE id = ?", (point_id,)).rowcount == 0:
            raise NotFoundError("map point not found")


def to_geojson(points: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ("label", "kind", "observed_at", "source", "note", "place", "investigation_id")
    return {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [point["longitude"], point["latitude"]]},
                "properties": {key: point[key] for key in keys if point.get(key) not in (None, "")},
            }
            for point in points
        ],
    }


def to_kml(points: list[dict[str, Any]], name: str) -> str:
    def describe(point: dict[str, Any]) -> str:
        parts = [point["kind"], str(point.get("observed_at") or ""), str(point.get("note") or point.get("place") or ""), str(point.get("source") or "")]
        return " · ".join(part for part in parts if part)

    placemarks = "".join(
        f"<Placemark><name>{escape(str(point['label']))}</name><description>{escape(describe(point))}</description>"
        f"<Point><coordinates>{point['longitude']},{point['latitude']},0</coordinates></Point></Placemark>"
        for point in points
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        f"<name>{escape(name)}</name>{placemarks}</Document></kml>\n"
    )
