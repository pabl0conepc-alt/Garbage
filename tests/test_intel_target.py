"""Phase 4: certificate parsing, web fingerprinting and the target-contact gate.

Certificate fixtures are public leaf certificates captured on 2026-11-12;
expected values were cross-checked with ``openssl x509``.
"""

import base64
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel
from garbage_intel.intel import ConnectorContext, run_query
from garbage_intel.modules import intel_target_connectors as itc
from garbage_intel.modules.web_fingerprint import (
    analyse_cookies,
    analyse_headers,
    detect_technologies,
    favicon_hash,
    murmur3_32,
    page_metadata,
)
from garbage_intel.modules.x509 import CertificateError, hostname_matches, parse_certificate
from garbage_intel.net import FetchResult, TlsPeer
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)


def fixture(name):
    return (FIXTURES / name).read_bytes()


class CertificateParserTests(unittest.TestCase):
    def test_public_ec_certificate(self):
        cert = parse_certificate(fixture("cert-github.com.der"), now=NOW)
        self.assertEqual(cert["subject"], "CN=github.com")
        self.assertEqual(cert["issuer_cn"], "Sectigo Public Server Authentication CA DV E36")
        self.assertEqual(cert["issuer_org"], "Sectigo Limited")
        self.assertEqual(cert["not_before"], "2026-10-30T00:00:00Z")
        self.assertEqual(cert["not_after"], "2027-01-27T23:59:59Z")
        self.assertEqual(cert["serial"].upper(), "3E1D6026B4B0AEA279DCA2EFBBCED82B")
        self.assertEqual(
            cert["sha256"],
            "7dc4d85cf1e310971225bc9a9257679043a243d70a3cc2a91cc5d389892c2776",
        )
        self.assertEqual(cert["spki_sha256"], "8gWWkWa8AfAz0khtRYRodss7ieQPpu8Sd7DppK94eVo=")
        self.assertEqual(cert["san"]["dns"], ["github.com", "www.github.com"])
        self.assertEqual(cert["public_key"], {"algorithm": "EC", "bits": 256, "curve": "P-256"})
        self.assertEqual(cert["signature_algorithm"], "ecdsa-with-SHA256")
        self.assertFalse(cert["self_issued"])
        self.assertFalse(cert["expired"])
        self.assertTrue(cert["sct_embedded"])
        self.assertIn("serverAuth", cert["extended_key_usage"])
        self.assertTrue(cert["ocsp"] or cert["ca_issuers"])
        self.assertEqual(cert["days_remaining"], 76)

    def test_self_signed_rsa_certificate(self):
        cert = parse_certificate(fixture("cert-self-signed.badssl.com.der"), now=NOW)
        self.assertTrue(cert["self_issued"])
        self.assertEqual(cert["public_key"]["algorithm"], "RSA")
        self.assertEqual(cert["public_key"]["bits"], 2048)
        self.assertEqual(cert["spki_sha256"], "9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=")
        self.assertEqual(cert["san"]["dns"], ["*.badssl.com", "badssl.com"])
        later = parse_certificate(fixture("cert-self-signed.badssl.com.der"), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(later["expired"])

    def test_rejects_garbage_and_truncation(self):
        for value in (b"", b"\x30\x82\xff\xff", b"not a certificate", fixture("cert-github.com.der")[:300]):
            with self.assertRaises(CertificateError):
                parse_certificate(value)
        with self.assertRaises(CertificateError):
            parse_certificate(b"\x30" * (70 * 1024))

    def test_hostname_matching(self):
        self.assertTrue(hostname_matches("www.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("a.b.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("example.com", ["*.example.com"]))
        self.assertTrue(hostname_matches("Example.COM.", ["example.com"]))


class FingerprintTests(unittest.TestCase):
    def test_murmur3_reference_vectors(self):
        self.assertEqual(murmur3_32(b""), 0)
        self.assertEqual(murmur3_32(b"", 1), 0x514E28B7)
        self.assertEqual(murmur3_32(b"hello"), 613153351)
        self.assertEqual(murmur3_32(b"foo"), -156908512)
        self.assertEqual(murmur3_32(b"The quick brown fox jumps over the lazy dog"), 776992547)
        self.assertEqual(favicon_hash(b"\x00" * 10), murmur3_32(base64.encodebytes(b"\x00" * 10)))

    def test_headers_cookies_and_metadata(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "server": "nginx/1.25.3",
            "x-powered-by": "PHP/8.2.1",
            "set-cookie": "PHPSESSID=abc; path=/; HttpOnly\nprefs=1; Secure; SameSite=Lax",
        }
        analysis = analyse_headers(headers)
        self.assertIn("HSTS", analysis["present"])
        self.assertIn("CSP", analysis["missing"])
        self.assertEqual(analysis["hsts_max_age"], 31536000)
        self.assertTrue(analysis["hsts_subdomains"])
        self.assertEqual(analysis["disclosure"]["server"], "nginx/1.25.3")
        cookies = analyse_cookies(headers["set-cookie"])
        self.assertEqual(cookies[0], {"name": "PHPSESSID", "secure": False, "httponly": True, "samesite": ""})
        self.assertEqual(cookies[1]["samesite"], "Lax")
        body = (
            b"<html><head><title> Shop &amp; Co </title>"
            b'<meta name="generator" content="WordPress 6.4.2">'
            b'<link rel="shortcut icon" href="/static/fav.ico">'
            b'<script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script></head></html>'
        )
        meta = page_metadata(body)
        self.assertEqual(meta["title"], "Shop & Co")
        self.assertEqual(meta["meta"]["generator"], "WordPress 6.4.2")
        self.assertEqual(meta["favicon_href"], "/static/fav.ico")
        found = {item["name"]: item for item in detect_technologies(headers, body)}
        self.assertEqual(found["nginx"]["version"], "1.25.3")
        self.assertEqual(found["PHP"]["version"], "8.2.1")
        self.assertIn("WordPress", found)
        self.assertEqual(found["jQuery"]["version"], "3.7.1")
        self.assertNotIn("Drupal", found)


def page(url, body=b"", status=200, headers=None, redirects=None):
    return FetchResult(
        url=url,
        final_url=url,
        status=status,
        headers=headers or {},
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        address="93.184.216.34",
        elapsed_ms=1,
        redirects=redirects or [],
    )


class TargetConnectorTests(unittest.TestCase):
    def test_certificate_connector(self):
        peer = TlsPeer("github.com", "4.228.31.150", fixture("cert-github.com.der"), True, "", "TLSv1.3", "TLS_AES_128_GCM_SHA256", 5)
        with patch.object(itc, "TLS_PEER", lambda host: peer):
            findings = itc._certificate_connector(ConnectorContext("", "url", "https://github.com/x", None))
        by_type = {}
        for item in findings:
            by_type.setdefault(item.result_type, []).append(item)
        self.assertEqual(by_type["tls-trust"][0].value, "trusted")
        self.assertTrue(by_type["tls-trust"][0].data["hostname_match"])
        self.assertEqual([item.value for item in by_type["cert-san"]], ["github.com", "www.github.com"])
        self.assertTrue(all(item.source_url == "tls://github.com:443" for item in findings))

    def test_web_connector_fetches_page_and_same_host_favicon_only(self):
        calls = []

        def fake_fetch(url, **options):
            calls.append((url, options))
            if url.endswith("/fav.ico"):
                return page(url, b"\x00\x01icon")
            return page(
                url,
                b'<title>Example</title><link rel="icon" href="/fav.ico">',
                headers={"content-type": "text/html", "server": "nginx", "set-cookie": "s=1; Secure"},
            )

        with patch.object(itc, "FETCH", fake_fetch):
            findings = itc._web_connector(ConnectorContext("", "url", "http://example.com/path#frag", None))
        self.assertEqual(calls[0][0], "https://example.com/path")
        self.assertTrue(calls[0][1]["keep_all_headers"])
        self.assertEqual(calls[1][0], "https://example.com/fav.ico")
        types = {item.result_type for item in findings}
        self.assertTrue({"http-response", "page-title", "missing-header", "cookie", "technology", "favicon"} <= types)
        favicon = next(item for item in findings if item.result_type == "favicon")
        self.assertEqual(favicon.value, str(favicon_hash(b"\x00\x01icon")))

    def test_cross_host_favicon_is_not_fetched(self):
        calls = []

        def fake_fetch(url, **options):
            calls.append(url)
            return page(url, b'<link rel="icon" href="https://cdn.other.example/i.ico">', headers={"content-type": "text/html"})

        with patch.object(itc, "FETCH", fake_fetch):
            itc._web_connector(ConnectorContext("", "domain", "example.com", None))
        self.assertEqual(calls, ["https://example.com/"])

    def test_gate_requires_both_switches(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "intel.sqlite3")
            initialize(database)
            intel.RATE_LIMITER.reset()
            touched = []
            with patch.object(itc, "FETCH", lambda url, **options: touched.append(url) or page(url)), \
                 patch.object(itc, "TLS_PEER", lambda host: touched.append(host)):
                ids = ["tls-certificate", "web-fingerprint"]
                run = run_query(database, value="example.com", connector_ids=ids)
                self.assertEqual({item["status"] for item in run["sources"]}, {"network-disabled"})
                update_settings(database, {"intel.allow_network": "true"})
                run = run_query(database, value="example.com", connector_ids=ids)
                self.assertEqual({item["status"] for item in run["sources"]}, {"target-contact-disabled"})
                self.assertEqual(touched, [])
                update_settings(database, {"intel.allow_target_contact": "true"})
                run_query(database, value="example.com", connector_ids=["web-fingerprint"])
                self.assertEqual(touched[0], "https://example.com/")


if __name__ == "__main__":
    unittest.main()
