import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
import urllib.error
import urllib.request

from garbage_intel.modules.cisa_kev import (
    MAX_FEED_BYTES,
    FEED_URL,
    CisaKevError,
    _CisaRedirectHandler,
    list_cached,
    parse_feed,
    refresh_cisa_kev,
)


NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def feed_document():
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.10",
        "dateReleased": "2026-11-10T10:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-12345",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Example vulnerability",
                "dateAdded": "2026-11-10",
                "shortDescription": "A concise public catalog description.",
                "requiredAction": "Apply the vendor's security update.",
                "dueDate": "2026-11-24",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "Ignored external references are not imported.",
            }
        ],
    }


class FakeResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self.closed = False

    def getcode(self):
        return self.status

    def read(self, limit):
        return self.body[:limit]

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class CisaKevConnectorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "intel.sqlite3"

    def tearDown(self):
        self.temp_dir.cleanup()

    def response_for_feed(self, headers=None):
        raw = json.dumps(feed_document()).encode("utf-8")
        return FakeResponse(
            200,
            raw,
            {"Content-Length": str(len(raw)), **(headers or {})},
        )

    def test_explicit_refresh_fetches_validated_metadata_and_caches_provenance(self):
        opener = FakeOpener(
            self.response_for_feed(
                {"ETag": '"catalog-1"', "Last-Modified": "Tue, 10 Nov 2026 10:00:00 GMT"}
            )
        )
        result = refresh_cisa_kev(
            self.database, opener=opener, now=NOW
        )
        self.assertEqual(result["refresh_status"], "updated")
        self.assertEqual(result["source_url"].split(":")[0], "https")
        self.assertEqual(result["catalog_version"], "2026.11.10")
        self.assertEqual(result["source_updated_at"], "2026-11-10T10:00:00Z")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["cve_id"], "CVE-2026-12345")
        self.assertNotIn("notes", result["items"][0])
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, result["source_url"])
        self.assertEqual(timeout, 10)
        self.assertEqual(request.get_header("User-agent"), "GARBAGE local defensive metadata connector")
        self.assertTrue(opener.response.closed)

        cached = list_cached(self.database, search="example product")
        self.assertEqual(cached["matched"], 1)
        self.assertEqual(cached["sha256"], result["sha256"])
        self.assertEqual(cached["items"][0]["required_action"], "Apply the vendor's security update.")

    def test_recent_refresh_uses_cache_without_network(self):
        first_opener = FakeOpener(self.response_for_feed())
        refresh_cisa_kev(self.database, opener=first_opener, now=NOW)

        class NoNetwork:
            def open(self, request, timeout):
                raise AssertionError("fresh cache should suppress network access")

        result = refresh_cisa_kev(
            self.database,
            opener=NoNetwork(),
            now=NOW + timedelta(minutes=5),
        )
        self.assertEqual(result["refresh_status"], "cache_fresh")
        self.assertEqual(len(first_opener.requests), 1)

    def test_stale_refresh_uses_conditional_request_and_accepts_not_modified(self):
        initial = FakeOpener(self.response_for_feed({"ETag": '"catalog-1"'}))
        refresh_cisa_kev(self.database, opener=initial, now=NOW)

        not_modified = FakeResponse(304, headers={"ETag": '"catalog-1"'})
        conditional = FakeOpener(not_modified)
        result = refresh_cisa_kev(
            self.database,
            opener=conditional,
            now=NOW + timedelta(minutes=16),
        )
        request, _ = conditional.requests[0]
        self.assertEqual(request.get_header("If-none-match"), '"catalog-1"')
        self.assertEqual(result["refresh_status"], "not_modified")
        self.assertEqual(result["fetched_at"], "2026-11-10T12:16:00Z")
        self.assertTrue(not_modified.closed)

    def test_invalid_schema_and_oversized_response_are_rejected(self):
        invalid = feed_document()
        invalid["count"] = 2
        with self.assertRaisesRegex(CisaKevError, "count does not match"):
            parse_feed(json.dumps(invalid).encode("utf-8"), fetched_at=NOW)

        response = FakeResponse(
            200,
            b"",
            {"Content-Length": str(MAX_FEED_BYTES + 1)},
        )
        with self.assertRaisesRegex(CisaKevError, "10 MiB limit"):
            refresh_cisa_kev(
                self.database, opener=FakeOpener(response), now=NOW
            )
        self.assertTrue(response.closed)

    def test_rate_limit_is_reported_without_retry(self):
        response = FakeResponse(
            429,
            headers={"Retry-After": "120"},
        )
        opener = FakeOpener(response)
        with self.assertRaisesRegex(CisaKevError, "Retry-After: 120"):
            refresh_cisa_kev(self.database, opener=opener, now=NOW)
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(response.closed)

    def test_redirect_handler_refuses_non_cisa_or_non_https_destinations(self):
        handler = _CisaRedirectHandler()
        request = urllib.request.Request(FEED_URL)
        with self.assertRaisesRegex(urllib.error.HTTPError, "Refused redirect") as caught:
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://127.0.0.1/private",
            )
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
