"""Geospatial view of a case (catalogue block 6).

Points come from what the case already holds, each with its origin:
- GPS positions in the EXIF of JPEG evidence and analysed photos;
- approximate network locations returned for IPs by intelligence runs saved
  to the case (where a network is registered, not where a person is);
- points the analyst adds by hand, with a note and a source.
Points export as GeoJSON or KML for desktop GIS tools. Nothing is geocoded
and no map tiles are fetched by the server.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape

from .db import _connection, new_id, record_activity, require_module, utc_now
from .errors import NotFoundError, ValidationError
from .evidence import _read_stored_file
from .modules.exif import read_exif
from .validation import clean_text

MAX_POINTS = 5000
ORIGIN_LABELS = {"photo": "Foto (EXIF)", "network": "Rede de IP (aproximada)", "manual": "Adicionado pelo analista"}


def _coordinate(value: Any, low: float, high: float, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be a number") from exc
    if not low <= number <= high:
        raise ValidationError(f"{name} must be between {low} and {high}")
    return round(number, 7)


def _case_filter(investigation_id: str | None, column: str) -> tuple[str, tuple[Any, ...]]:
    return (f" AND {column} = ?", (investigation_id,)) if investigation_id else ("", ())


def collect_points(database: str, investigation_id: str | None = None) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    with _connection(database) as connection:
        require_module(connection, "investigations")
        if investigation_id and connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            raise NotFoundError("investigation not found")
        where, args = _case_filter(investigation_id, "investigation_id")
        evidence = connection.execute(
            f"""SELECT id, investigation_id, title, stored_name, acquired_at FROM evidence
                WHERE stored_name <> '' AND (media_type = 'image/jpeg' OR lower(original_name) LIKE '%.jp%g'){where}""",
            args,
        ).fetchall()
        analyses = connection.execute(
            f"SELECT id, investigation_id, file_name, analysis_json, created_at FROM file_analyses WHERE analysis_json LIKE '%\"gps\"%'{where}",
            args,
        ).fetchall()
        where_run, run_args = _case_filter(investigation_id, "r.investigation_id")
        network = connection.execute(
            f"""SELECT res.id, r.investigation_id, r.query_value, res.value, res.data_json, res.fetched_at, res.source_url
                FROM intel_results res JOIN intel_runs r ON r.id = res.run_id
                WHERE res.result_type = 'geolocation' AND r.investigation_id IS NOT NULL{where_run}""",
            run_args,
        ).fetchall()
        manual = connection.execute(f"SELECT * FROM geo_points WHERE 1 = 1{where}", args).fetchall()

    for row in evidence:
        try:
            gps = (read_exif(_read_stored_file(database, row["stored_name"])) or {}).get("gps")
        except (NotFoundError, OSError):
            gps = None
        if gps:
            points.append({"id": row["id"], "origin": "photo", "investigation_id": row["investigation_id"], "label": row["title"],
                           "latitude": gps["latitude"], "longitude": gps["longitude"], "time": gps.get("utc") or row["acquired_at"],
                           "source": f"evidence:{row['id']}", "note": ""})
    for row in analyses:
        try:
            gps = json.loads(row["analysis_json"]).get("metadata", {}).get("exif", {}).get("gps")
        except (ValueError, AttributeError):
            gps = None
        if gps:
            points.append({"id": row["id"], "origin": "photo", "investigation_id": row["investigation_id"], "label": row["file_name"],
                           "latitude": gps["latitude"], "longitude": gps["longitude"], "time": gps.get("utc") or row["created_at"],
                           "source": f"file-analysis:{row['id']}", "note": ""})
    seen_network = set()
    for row in network:
        try:
            coordinates = json.loads(row["data_json"] or "{}").get("coordinates", "")
            latitude, longitude = (float(part) for part in str(coordinates).split(","))
        except ValueError:
            continue
        key = (row["query_value"], latitude, longitude)
        if key in seen_network:
            continue
        seen_network.add(key)
        points.append({"id": row["id"], "origin": "network", "investigation_id": row["investigation_id"], "label": row["query_value"],
                       "latitude": latitude, "longitude": longitude, "time": row["fetched_at"], "source": row["source_url"],
                       "note": f"{row['value']} (approximate network location, not a person)"})
    for row in manual:
        points.append({"id": row["id"], "origin": "manual", "investigation_id": row["investigation_id"], "label": row["label"],
                       "latitude": row["latitude"], "longitude": row["longitude"], "time": row["observed_at"] or row["created_at"],
                       "source": row["source_reference"], "note": row["note"]})
    points = points[:MAX_POINTS]
    for point in points:
        point["origin_label"] = ORIGIN_LABELS[point["origin"]]
        point["map_url"] = f"https://www.openstreetmap.org/?mlat={point['latitude']}&mlon={point['longitude']}#map=15/{point['latitude']}/{point['longitude']}"
    return {"items": points, "total": len(points)}


def add_point(database: str, investigation_id: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) - {"label", "latitude", "longitude", "note", "source_reference", "observed_at"}:
        raise ValidationError("send {label, latitude, longitude, note?, source_reference?, observed_at?}")
    point = {
        "id": new_id(),
        "investigation_id": investigation_id,
        "label": clean_text(payload.get("label"), "label", max_length=200, required=True),
        "latitude": _coordinate(payload.get("latitude"), -90, 90, "latitude"),
        "longitude": _coordinate(payload.get("longitude"), -180, 180, "longitude"),
        "note": clean_text(payload.get("note", ""), "note", max_length=2000),
        "source_reference": clean_text(payload.get("source_reference", ""), "source reference", max_length=1000),
        "observed_at": clean_text(payload.get("observed_at", ""), "observed at", max_length=40),
        "created_at": utc_now(),
    }
    with _connection(database) as connection:
        require_module(connection, "investigations")
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
    return {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [point["longitude"], point["latitude"]]},
                "properties": {key: point[key] for key in ("label", "origin", "time", "source", "note", "investigation_id")},
            }
            for point in points
        ],
    }


def to_kml(points: list[dict[str, Any]], name: str) -> str:
    placemarks = "".join(
        f"<Placemark><name>{escape(str(point['label']))}</name>"
        f"<description>{escape(point['origin_label'] + ' · ' + str(point['time']) + (' · ' + point['note'] if point['note'] else '') + (' · ' + point['source'] if point['source'] else ''))}</description>"
        f"<Point><coordinates>{point['longitude']},{point['latitude']},0</coordinates></Point></Placemark>"
        for point in points
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        f"<name>{escape(name)}</name>{placemarks}</Document></kml>\n"
    )
