"""Catalogue block 6: map points, origins and GeoJSON/KML export."""

import json
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from garbage_intel import geo
from garbage_intel.db import _connection, new_id, utc_now
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.evidence import add_evidence
from garbage_intel.modules.file_intel import analyze_file
from garbage_intel.store import create_investigation, initialize
from tests.test_intel_accounts import jpeg_with_gps


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.tmp.name) / "g.db")
        initialize(self.database)
        self.case = create_investigation(self.database, name="Map case")["id"]
        self.other = create_investigation(self.database, name="Other")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def add_network_result(self, case, coordinates="-23.5,-46.6"):
        run_id = new_id()
        with _connection(self.database) as connection:
            connection.execute(
                "INSERT INTO intel_runs (id, investigation_id, query_type, query_value, status, started_at) VALUES (?, ?, 'ipv4', '203.0.113.5', 'completed', ?)",
                (run_id, case, utc_now()),
            )
            connection.execute(
                """INSERT INTO intel_results (id, run_id, connector_id, status, result_type, value, data_json, source_url, fetched_at)
                   VALUES (?, ?, 'ipinfo', 'ok', 'geolocation', 'São Paulo, BR', ?, 'https://ipinfo.io/203.0.113.5', ?)""",
                (new_id(), run_id, json.dumps({"coordinates": coordinates}), utc_now()),
            )

    def test_all_origins_and_case_filter(self):
        add_evidence(self.database, self.case, title="Photo evidence", original_name="p.jpg", data=jpeg_with_gps())
        analyze_file(self.database, data=jpeg_with_gps(latitude=(10, 0, 0), lat_ref=b"N"), filename="a.jpg", investigation_id=self.case)
        self.add_network_result(self.case)
        self.add_network_result(self.case)  # same IP and place: listed once
        geo.add_point(self.database, self.case, {"label": "Meeting place", "latitude": "48.8584", "longitude": 2.2945, "note": "from witness"})
        geo.add_point(self.database, self.other, {"label": "Elsewhere", "latitude": 0, "longitude": 0})

        points = geo.collect_points(self.database, self.case)["items"]
        origins = sorted(point["origin"] for point in points)
        self.assertEqual(origins, ["manual", "network", "photo", "photo"])
        network = [point for point in points if point["origin"] == "network"][0]
        self.assertEqual((network["latitude"], network["longitude"]), (-23.5, -46.6))
        self.assertIn("not a person", network["note"])
        photo_labels = {point["label"] for point in points if point["origin"] == "photo"}
        self.assertEqual(photo_labels, {"Photo evidence", "a.jpg"})
        self.assertEqual(geo.collect_points(self.database)["total"], 5)

    def test_validation(self):
        with self.assertRaises(ValidationError):
            geo.add_point(self.database, self.case, {"label": "x", "latitude": 91, "longitude": 0})
        with self.assertRaises(ValidationError):
            geo.add_point(self.database, self.case, {"label": "x", "latitude": "abc", "longitude": 0})
        with self.assertRaises(ValidationError):
            geo.add_point(self.database, self.case, {"latitude": 1, "longitude": 1})
        with self.assertRaises(NotFoundError):
            geo.add_point(self.database, new_id(), {"label": "x", "latitude": 1, "longitude": 1})
        point = geo.add_point(self.database, self.case, {"label": "x", "latitude": 1, "longitude": 1})
        geo.delete_point(self.database, point["id"])
        with self.assertRaises(NotFoundError):
            geo.delete_point(self.database, point["id"])

    def test_exports(self):
        geo.add_point(self.database, self.case, {"label": "A & B <x>", "latitude": 1.5, "longitude": -2.25, "note": "n"})
        points = geo.collect_points(self.database, self.case)["items"]
        feature = geo.to_geojson(points)["features"][0]
        self.assertEqual(feature["geometry"]["coordinates"], [-2.25, 1.5])
        self.assertEqual(feature["properties"]["label"], "A & B <x>")
        kml = ElementTree.fromstring(geo.to_kml(points, "Case"))
        ns = {"k": "http://www.opengis.net/kml/2.2"}
        self.assertEqual(kml.find(".//k:Placemark/k:name", ns).text, "A & B <x>")
        self.assertEqual(kml.find(".//k:coordinates", ns).text, "-2.25,1.5,0")


if __name__ == "__main__":
    unittest.main()
