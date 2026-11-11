import http.client
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from garbage_intel.api import _read_web_asset, create_server
from garbage_intel.store import initialize


class LocalApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "intel.sqlite3"
        initialize(self.database)
        self.server = create_server(self.database, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        body = json.dumps(payload).encode() if payload is not None else None
        request_headers = {"Origin": f"http://127.0.0.1:{self.port}"}
        request_headers.update(headers or {})
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_api_round_trip_preserves_provenance(self):
        status, investigation = self.request(
            "POST",
            "/api/investigations",
            {"name": "API check", "description": "local test"},
        )
        self.assertEqual(status, 201)
        status, observation = self.request(
            "POST",
            f"/api/investigations/{investigation['id']}/observations",
            {
                "title": "Notice",
                "content": "Recorded evidence at 203.0.113.8",
                "source_reference": "https://example.test/notice",
                "collection_basis": "public",
                "observed_at": "2025-01-02T03:04:05+02:00",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(observation["collection_basis"], "public")
        status, report = self.request(
            "GET", f"/api/investigations/{investigation['id']}/report"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            report["observations"][0]["observed_at"], "2025-01-02T01:04:05Z"
        )
        self.assertEqual(report["indicators"][0]["value"], "203.0.113.8")
        self.assertEqual(
            report["indicators"][0]["source_observation_id"], observation["id"]
        )
        self.request(
            "POST",
            f"/api/investigations/{investigation['id']}/observations",
            {
                "title": "Second source",
                "content": "Same indicator: 203.0.113.8",
                "source_reference": "https://second.example/report",
                "collection_basis": "authorized",
            },
        )
        _, report = self.request(
            "GET", f"/api/investigations/{investigation['id']}/report"
        )
        self.assertEqual(report["correlations"][0]["observation_count"], 2)
        status, timeline = self.request(
            "GET", f"/api/investigations/{investigation['id']}/timeline"
        )
        self.assertEqual(status, 200)
        self.assertEqual(timeline["events"][0]["type"], "observation")
        self.assertEqual(
            timeline["events"][0]["source_reference"],
            "https://example.test/notice",
        )
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        connection.request("GET", f"/reports/{investigation['id']}")
        html_response = connection.getresponse()
        html_report = html_response.read().decode()
        self.assertEqual(html_response.status, 200)
        self.assertIn("Extracted indicators (2)", html_report)
        self.assertIn("Exact-value correlations (1)", html_report)
        connection.close()

    def test_serves_web_assets_with_security_headers(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn("GARBAGE", page)
        self.assertIn('src="/app.js"', page)
        self.assertIn("default-src 'self'", response.getheader("Content-Security-Policy"))
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        connection.close()

    def test_reads_web_assets_from_zipapp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "garbage.pyz"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("web/index.html", b"<html>bundled</html>")

            with patch("garbage_intel.api.sys.argv", [str(archive_path)]):
                self.assertEqual(
                    _read_web_asset("index.html"), b"<html>bundled</html>"
                )

    def test_rejects_non_local_origin(self):
        status, result = self.request(
            "GET",
            "/api/investigations",
            headers={"Origin": f"http://attacker.example:{self.port}"},
        )
        self.assertEqual(status, 403)
        self.assertIn("loopback", result["error"])

    def test_api_status_closes_and_reopens_investigations(self):
        _, investigation = self.request(
            "POST", "/api/investigations", {"name": "Lifecycle"}
        )
        status, closed = self.request(
            "PATCH",
            f"/api/investigations/{investigation['id']}",
            {"status": "closed"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(closed["status"], "closed")

        status, error = self.request(
            "POST",
            f"/api/investigations/{investigation['id']}/observations",
            {
                "title": "Blocked",
                "content": "Closed investigations are read-only.",
                "source_reference": "note://analyst",
                "collection_basis": "user-provided",
            },
        )
        self.assertEqual(status, 409)
        self.assertIn("investigation is closed", error["error"])

        status, opened = self.request(
            "PATCH",
            f"/api/investigations/{investigation['id']}",
            {"status": "open"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(opened["status"], "open")

        _, cancelled = self.request(
            "PATCH",
            f"/api/investigations/{investigation['id']}",
            {"status": "cancelled"},
        )
        self.assertEqual(cancelled["status"], "cancelled")
        status, error = self.request(
            "POST",
            f"/api/investigations/{investigation['id']}/observations",
            {
                "title": "Blocked after cancellation",
                "content": "Reopen before adding",
                "source_reference": "note://analyst",
                "collection_basis": "user-provided",
            },
        )
        self.assertEqual(status, 409)
        self.assertIn("investigation is cancelled", error["error"])

    def test_cisa_kev_api_requires_manual_refresh(self):
        status, error = self.request("GET", "/api/intel/cisa-kev")
        self.assertEqual(status, 404)
        self.assertIn("explicit refresh", error["error"])

        with patch(
            "garbage_intel.api.refresh_cisa_kev",
            return_value={
                "source_url": "https://www.cisa.gov/feed.json",
                "refresh_status": "updated",
                "count": 1,
                "items": [],
            },
        ) as refresh:
            status, result = self.request(
                "POST", "/api/intel/cisa-kev/refresh", {}
            )
        self.assertEqual(status, 200)
        self.assertEqual(result["refresh_status"], "updated")
        refresh.assert_called_once_with(self.database, force=False)

        status, error = self.request(
            "POST", "/api/intel/cisa-kev/refresh", {"force": "true"}
        )
        self.assertEqual(status, 400)
        self.assertIn("force must be a boolean", error["error"])

    def test_rejects_wrong_host(self):
        status, result = self.request(
            "GET",
            "/api/health",
            headers={"Host": f"attacker.example:{self.port}"},
        )
        self.assertEqual(status, 403)
        self.assertIn("loopback", result["error"])

    def test_html_report_escapes_untrusted_observation_content(self):
        _, investigation = self.request(
            "POST", "/api/investigations", {"name": "HTML report"}
        )
        self.request(
            "POST",
            f"/api/investigations/{investigation['id']}/observations",
            {
                "title": "Untrusted title",
                "content": "<script>alert(1)</script>",
                "source_reference": "javascript:alert(1)",
                "collection_basis": "user-provided",
            },
        )
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        connection.request("GET", f"/reports/{investigation['id']}")
        response = connection.getresponse()
        body = response.read().decode()
        self.assertEqual(response.status, 200)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("javascript:alert(1)", body)
        self.assertEqual(
            response.getheader("X-Content-Type-Options"), "nosniff"
        )
        connection.close()


if __name__ == "__main__":
    unittest.main()
