"""Map points merged into GEOINT: JPEG evidence, analyst points, GeoJSON/KML."""

import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from garbage_intel import geoint
from garbage_intel.db import new_id
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.evidence import add_evidence
from garbage_intel.store import create_investigation, initialize
from tests.test_intel_accounts import jpeg_with_gps


class GeointPointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.tmp.name) / "g.db")
        initialize(self.database)
        self.case = create_investigation(self.database, name="Map case")["id"]
        self.other = create_investigation(self.database, name="Other")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_evidence_photos_and_manual_points(self):
        add_evidence(self.database, self.case, title="Photo evidence", original_name="p.jpg", data=jpeg_with_gps())
        geoint.add_point(self.database, self.case, {"label": "Meeting place", "latitude": "48.8584", "longitude": 2.2945, "note": "witness"})
        geoint.add_point(self.database, self.other, {"label": "Elsewhere", "latitude": 1, "longitude": 1})
        result = geoint.geo_points(self.database, investigation_id=self.case)
        self.assertEqual(result["counts"]["photo"], 1)
        self.assertEqual(result["counts"]["manual"], 1)
        photo = [item for item in result["points"] if item["kind"] == "photo"][0]
        self.assertEqual((photo["label"], photo["source"]), ("Photo evidence", "evidence"))
        manual = [item for item in result["points"] if item["kind"] == "manual"][0]
        self.assertEqual((manual["label"], manual["note"]), ("Meeting place", "witness"))
        self.assertEqual(geoint.geo_points(self.database)["counts"]["manual"], 2)

    def test_validation_and_delete(self):
        for bad in ({"label": "x", "latitude": 91, "longitude": 0}, {"label": "x", "latitude": "a", "longitude": 0}, {"latitude": 1, "longitude": 1}):
            with self.assertRaises(ValidationError):
                geoint.add_point(self.database, self.case, bad)
        with self.assertRaises(NotFoundError):
            geoint.add_point(self.database, new_id(), {"label": "x", "latitude": 1, "longitude": 1})
        point = geoint.add_point(self.database, self.case, {"label": "x", "latitude": 1, "longitude": 1})
        geoint.delete_point(self.database, point["id"])
        with self.assertRaises(NotFoundError):
            geoint.delete_point(self.database, point["id"])

    def test_exports(self):
        geoint.add_point(self.database, self.case, {"label": "A & B <x>", "latitude": 1.5, "longitude": -2.25, "note": "n"})
        points = geoint.geo_points(self.database, investigation_id=self.case)["points"]
        feature = geoint.to_geojson(points)["features"][0]
        self.assertEqual(feature["geometry"]["coordinates"], [-2.25, 1.5])
        self.assertEqual(feature["properties"]["label"], "A & B <x>")
        kml = ElementTree.fromstring(geoint.to_kml(points, "Case"))
        ns = {"k": "http://www.opengis.net/kml/2.2"}
        self.assertEqual(kml.find(".//k:Placemark/k:name", ns).text, "A & B <x>")
        self.assertEqual(kml.find(".//k:coordinates", ns).text, "-2.25,1.5,0")


if __name__ == "__main__":
    unittest.main()
