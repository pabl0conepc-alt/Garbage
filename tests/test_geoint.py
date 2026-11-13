"""Step 4a: EXIF, perceptual hashes and GEOINT points.

The EXIF fixtures were written with Pillow 13.0 (GPS IFD in JPEG APP1, PNG
eXIf and WebP EXIF); the expected values are what Pillow reads back.
"""

import json
import random
import tempfile
import unittest
import uuid
from pathlib import Path

from garbage_intel.db import _connection, initialize
from garbage_intel.errors import ValidationError
from garbage_intel.geoint import geo_points
from garbage_intel.modules.exif import parse_exif
from garbage_intel.modules.file_intel import analyze_file, hamming64, similar_file_analyses
from garbage_intel.store import create_investigation

FIXTURES = Path(__file__).parent / "fixtures" / "exif"
GPS = {"valid": True, "latitude": -23.5613, "longitude": -46.6565, "altitude_m": 760.5, "gps_time_utc": "2025-04-03T13:20:30Z", "datum": "WGS-84"}


class ExifTests(unittest.TestCase):
    def test_containers(self):
        for name in ("gps.jpg", "gps.png", "gps.webp"):
            exif = parse_exif((FIXTURES / name).read_bytes())
            self.assertEqual(exif["make"], "TestCam", name)
            self.assertEqual(exif["model"], "Model X")
            self.assertEqual(exif["orientation"], 6)
            self.assertEqual(exif["captured_at"], "2025:04:03 10:20:30")
            self.assertEqual(exif["gps"], GPS, name)
            # The author's name is never copied, only that the field is set.
            self.assertTrue(exif["artist_present"])
            self.assertNotIn("Someone Private", json.dumps(exif))
        self.assertEqual(parse_exif((FIXTURES / "nogps.jpg").read_bytes()), {"make": "NoGPS"})
        self.assertIsNone(parse_exif((FIXTURES / "bare.jpg").read_bytes()))
        self.assertIsNone(parse_exif(b"not an image"))

    def test_mutated_input_never_raises(self):
        source = bytearray((FIXTURES / "gps.jpg").read_bytes())
        generator = random.Random(4)
        for _ in range(400):
            data = bytearray(source)
            for _ in range(generator.randint(1, 12)):
                data[generator.randrange(len(data))] = generator.randrange(256)
            result = parse_exif(bytes(data[: generator.randint(20, len(data))]))
            self.assertTrue(result is None or isinstance(result, dict))


class PerceptualAndMapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "geo.sqlite3")
        initialize(self.database)
        self.case = create_investigation(self.database, "Fotos")["id"]

    def tearDown(self):
        self.directory.cleanup()

    def test_hamming(self):
        self.assertEqual(hamming64("ffffffffffffffff", "fffffffffffffffe"), 1)
        self.assertEqual(hamming64("0000000000000000", "ffffffffffffffff"), 64)

    def test_perceptual_hashes_drive_visual_similarity(self):
        photo = analyze_file(self.database, data=(FIXTURES / "gps.jpg").read_bytes(), filename="a.jpg", investigation_id=self.case,
                             perceptual={"phash": "c3d1a4b2e0f01234", "dhash": "0f0f0f0f0f0f0f0f"})
        self.assertEqual(photo["perceptual"]["computed_by"], "browser")
        self.assertIn("exif-gps", [item["code"] for item in photo["findings"]])
        near = analyze_file(self.database, data=(FIXTURES / "nogps.jpg").read_bytes(), filename="b.jpg",
                            perceptual={"phash": "c3d1a4b2e0f01237", "dhash": "0f0f0f0f0f0f0f0e"})
        analyze_file(self.database, data=(FIXTURES / "bare.jpg").read_bytes(), filename="c.jpg",
                     perceptual={"phash": "3c2e5b4d1f0fedcb", "dhash": "f0f0f0f0f0f0f0f0"})
        similar = similar_file_analyses(self.database, photo["analysis_id"])
        visual = {item["id"]: item["phash_distance"] for item in similar["items"]}
        self.assertEqual(visual.get(near["analysis_id"]), 2)
        self.assertEqual(similar["thresholds"]["phash_max_distance"], 10)
        for bad in ({"phash": "xyz", "dhash": "0" * 16}, {"phash": "0" * 16}, "c3d1"):
            with self.assertRaises(ValidationError):
                analyze_file(self.database, data=(FIXTURES / "bare.jpg").read_bytes(), filename="d.jpg", perceptual=bad)
        # Hashes sent for a non-image are dropped, not an error.
        text = analyze_file(self.database, data=b"hello world\n", filename="e.txt", perceptual={"phash": "0" * 16, "dhash": "0" * 16})
        self.assertNotIn("perceptual", text)

    def test_points(self):
        analyze_file(self.database, data=(FIXTURES / "gps.png").read_bytes(), filename="praça.png", investigation_id=self.case)
        analyze_file(self.database, data=(FIXTURES / "nogps.jpg").read_bytes(), filename="sem.jpg", investigation_id=self.case)
        with _connection(self.database) as connection:
            for value, coordinates, when in (("192.0.2.1", "37.7749,-122.4194", "2026-01-02T00:00:00Z"), ("192.0.2.1", "1,1", "2026-01-01T00:00:00Z"), ("198.51.100.1", "0,0", "2026-01-01T00:00:00Z")):
                run = str(uuid.uuid4())
                connection.execute("INSERT INTO intel_runs (id, investigation_id, query_type, query_value, status, connector_count, started_at) VALUES (?, ?, 'ipv4', ?, 'completed', 1, ?)", (run, self.case, value, when))
                connection.execute(
                    """INSERT INTO intel_results (id, run_id, connector_id, status, cached, result_type, value, data_json, source_url, response_sha256, error, elapsed_ms, fetched_at)
                       VALUES (?, ?, 'ipinfo', 'ok', 0, 'geolocation', 'San Francisco, California, US', ?, 'https://ipinfo.io/', '', '', 0, ?)""",
                    (str(uuid.uuid4()), run, json.dumps({"coordinates": coordinates}), when),
                )
        result = geo_points(self.database, investigation_id=self.case)
        self.assertEqual(result["counts"], {"photo": 1, "network": 1})
        photo = next(item for item in result["points"] if item["kind"] == "photo")
        self.assertEqual((photo["latitude"], photo["longitude"], photo["camera"]), (-23.5613, -46.6565, "TestCam Model X"))
        network = next(item for item in result["points"] if item["kind"] == "network")
        self.assertEqual((network["latitude"], network["precision"]), (37.7749, "network-approximate"))  # newest only; 0,0 dropped
        other = create_investigation(self.database, "Outro")["id"]
        self.assertEqual(geo_points(self.database, investigation_id=other)["total"], 0)


if __name__ == "__main__":
    unittest.main()
