"""Catalogue block 5: page capture, verifiable package export, integrity checks."""

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, preservation
from garbage_intel.errors import ValidationError
from garbage_intel.db import _connection
from garbage_intel.evidence import _stored_path, add_evidence
from garbage_intel.net import FetchResult
from garbage_intel.store import create_investigation, initialize
from garbage_intel.workspace import update_settings
from tests.test_intel_sources import reply

PAGE = b"<html><head><title>T</title><script>x()</script></head><body><h1>Statement</h1><p>We will  ship.</p></body></html>"


def page_fetch(url, **options):
    return FetchResult(url, "https://news.example/final", 200,
                       {"content-type": "text/html; charset=utf-8", "server": "nginx"},
                       PAGE, hashlib.sha256(PAGE).hexdigest(), "192.0.2.10", 1, ["https://news.example/old"])


def stored_file(database, evidence_id):
    with _connection(database) as connection:
        name = connection.execute("SELECT stored_name FROM evidence WHERE id = ?", (evidence_id,)).fetchone()[0]
    return _stored_path(database, name)


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.tmp.name) / "p.db")
        initialize(self.database)
        self.case = create_investigation(self.database, name="Case A")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def allow(self):
        update_settings(self.database, {"intel.allow_network": "true", "intel.allow_target_contact": "true"})

    def test_capture_requires_permissions_and_https(self):
        with self.assertRaises(ValidationError):
            preservation.capture_url(self.database, self.case, {"url": "https://news.example/"})
        self.allow()
        with self.assertRaises(ValidationError):
            preservation.capture_url(self.database, self.case, {"url": "http://news.example/"})

    def test_capture_keeps_original_and_working_copy(self):
        self.allow()
        with patch.object(preservation, "FETCH", page_fetch):
            result = preservation.capture_url(self.database, self.case, {"url": "https://news.example/old", "note": "press release"})
        original = result["original"]
        self.assertEqual(original["sha256"], hashlib.sha256(PAGE).hexdigest())
        self.assertEqual(original["source_reference"], "https://news.example/final")
        self.assertIn("Server address: 192.0.2.10", original["description"])
        self.assertIn("server: nginx", original["description"])
        self.assertIn("Redirects: https://news.example/old", original["description"])
        working = result["working_copy"]
        self.assertIn(original["id"], working["description"])
        stored = stored_file(self.database, working["id"]).read_bytes()
        self.assertEqual(stored, b"T Statement We will ship.")

    def test_package_verifies_independently_and_detects_tampering(self):
        add_evidence(self.database, self.case, title="Photo", original_name="a.jpg", data=b"\xff\xd8 image bytes")
        add_evidence(self.database, self.case, title="Note only", evidence_type="note", source_reference="https://example.org/ref")
        data, name = preservation.export_package(self.database, self.case)
        self.assertTrue(name.startswith("evidencias_Case_A_") and name.endswith(".zip"))
        archive = zipfile.ZipFile(io.BytesIO(data))
        self.assertTrue({"manifest.json", "SHA256SUMS", "verify.py"} <= set(archive.namelist()))
        manifest = json.loads(archive.read("manifest.json"))
        self.assertEqual(len(manifest["items"]), 2)
        photo = [item for item in manifest["items"] if item["title"] == "Photo"][0]
        self.assertEqual(photo["sha256"], photo["sha256_at_export"])
        self.assertTrue(photo["custody"])
        folder = Path(self.tmp.name) / "pkg"
        archive.extractall(folder)
        ok = subprocess.run([sys.executable, "-I", "verify.py"], cwd=folder, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn("All files match.", ok.stdout)
        (folder / photo["file"]).write_bytes(b"tampered")
        bad = subprocess.run([sys.executable, "-I", "verify.py"], cwd=folder, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("MISMATCH", bad.stdout)

    def test_verify_all_reports_and_notifies(self):
        record = add_evidence(self.database, self.case, title="Doc", original_name="d.txt", data=b"original")
        self.assertEqual(preservation.verify_all(self.database)["counts"]["verified"], 1)
        stored_file(self.database, record["id"]).write_bytes(b"changed")
        update_settings(self.database, {"intel.allow_network": "true", "intel.webhook_url": "https://example.net/h"})
        sent = []
        with patch.object(intel, "WEBHOOK_FETCH", lambda url, **o: sent.append(o) or reply(url, {})):
            result = preservation.verify_all(self.database)
        self.assertEqual(result["problems"][0]["status"], "mismatch")
        self.assertIn("Doc: mismatch", json.loads(sent[0]["body"])["content"])

    def test_daily_runs_once_per_day(self):
        preservation._LAST_DAILY["at"] = 0.0
        self.assertTrue(preservation.run_daily_verification(self.database, now=1000.0))
        self.assertFalse(preservation.run_daily_verification(self.database, now=1000.0 + 3600))
        self.assertTrue(preservation.run_daily_verification(self.database, now=1000.0 + 86401))


if __name__ == "__main__":
    unittest.main()
