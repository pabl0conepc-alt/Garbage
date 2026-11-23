"""Catalogue block 4: passive website surface."""

import hashlib
import json
import unittest
from unittest.mock import patch

from garbage_intel.intel import ConnectorContext, _run_one, connectors
from garbage_intel.modules import intel_target_connectors as target
from garbage_intel.modules.intel_web_surface import analyse_csp, visible_text_hash
from garbage_intel.net import FetchResult

BY_ID = {connector.connector_id: connector for connector in connectors()}

HOME = b"""<html><head><title>Shop</title>
<meta name="description" content="Best shop">
<meta property="og:title" content="Shop &amp; Co">
<link rel="canonical" href="/">
<link rel="alternate" hreflang="pt-br" href="https://shop.example/pt/">
<link rel="manifest" href="/site.webmanifest">
<script>var hidden = "not text";</script>
</head><body><h1>Welcome</h1><a href="/about">About</a><a href="https://cdn.other.example/x">x</a>
<a href="mailto:a@b.example">mail</a><img src="http://insecure.example/i.png"></body></html>"""

ROBOTS = b"""User-agent: *
Disallow: /admin/
Disallow: /cart  # shopping cart
Sitemap: https://shop.example/sm.xml
"""
SITEMAP = b"""<urlset><url><loc>https://shop.example/products/1</loc></url>
<url><loc>https://shop.example/staging/preview</loc></url><url><loc>https://shop.example/blog/a</loc></url></urlset>"""


def site(routes):
    calls = []

    def fetch(url, **options):
        calls.append(url)
        status, body, headers = routes.get(url, (404, b"", {}))
        return FetchResult(url, url, status, headers, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])

    return fetch, calls


def by_type(findings):
    result = {}
    for item in findings:
        result.setdefault(item.result_type, []).append(item)
    return result


class WebSurfaceTests(unittest.TestCase):
    def test_contacts_target_only(self):
        connector = BY_ID["web-surface"]
        self.assertTrue(connector.network and connector.contacts_target)

    def test_full_surface(self):
        routes = {
            "https://shop.example/": (200, HOME, {"content-type": "text/html", "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}),
            "https://shop.example/robots.txt": (200, ROBOTS, {"content-type": "text/plain"}),
            "https://shop.example/sm.xml": (200, SITEMAP, {"content-type": "application/xml"}),
            "https://shop.example/site.webmanifest": (200, json.dumps({"name": "Shop App", "display": "standalone"}).encode(), {}),
        }
        fetch, calls = site(routes)
        with patch.object(target, "FETCH", fetch):
            status, findings, error, _ = _run_one(BY_ID["web-surface"], ConnectorContext("", "domain", "shop.example", None))
        self.assertEqual(status, "ok", error)
        found = by_type(findings)
        self.assertEqual(found["canonical"][0].value, "https://shop.example/")
        self.assertTrue(found["canonical"][0].data["same_url"])
        self.assertEqual(found["social-meta"][0].value, "Shop & Co")
        self.assertEqual(found["hreflang"][0].value, "pt-br")
        self.assertIn("og:image", found["seo-missing"][0].value)
        self.assertEqual(found["page-links"][0].data["external_hosts"], ["cdn.other.example"])
        self.assertEqual(found["mixed-content"][0].value, "1 http:// references")
        self.assertIn("script-src allows 'unsafe-inline'", found["csp"][0].data["issues"])
        self.assertEqual({item.value for item in found["robots-disallow"]}, {"/admin/", "/cart"})
        self.assertTrue([item for item in found["robots-disallow"] if item.value == "/admin/"][0].data["notable"])
        self.assertEqual(found["sitemap"][0].data["sections"], ["/blog", "/products", "/staging"])
        self.assertEqual([item.value for item in found["sitemap-notable"]], ["/staging/preview"])
        self.assertEqual(found["web-manifest"][0].value, "Shop App")
        self.assertEqual(len(found["page-text-hash"][0].value), 64)
        # Only the page, robots, the declared sitemap and the linked manifest: no guessing.
        self.assertEqual(sorted(calls), sorted(routes))

    def test_missing_files(self):
        fetch, calls = site({"https://bare.example/": (200, b"<html><body>hi</body></html>", {"content-type": "text/html"})})
        with patch.object(target, "FETCH", fetch):
            _, findings, _, _ = _run_one(BY_ID["web-surface"], ConnectorContext("", "domain", "bare.example", None))
        found = by_type(findings)
        self.assertEqual(found["robots-txt"][0].value, "not published")
        self.assertEqual(found["sitemap"][0].value, "not found")
        self.assertEqual(found["csp"][0].value, "absent")
        self.assertIn("https://bare.example/sitemap.xml", calls)


class HelperTests(unittest.TestCase):
    def test_csp(self):
        self.assertEqual(analyse_csp("default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'"), [])
        issues = analyse_csp("img-src *")
        self.assertIn("no script-src or default-src: scripts are not restricted", issues)
        self.assertEqual(analyse_csp("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"), [])

    def test_text_hash_ignores_markup_and_scripts(self):
        one, words = visible_text_hash(b"<p>Hello   <b>world</b></p><script>x=1</script>")
        two, _ = visible_text_hash(b"<div>Hello world</div><script>x=2</script>")
        self.assertEqual(one, two)
        self.assertEqual(words, 2)
        self.assertNotEqual(one, visible_text_hash(b"<p>Hello there</p>")[0])


if __name__ == "__main__":
    unittest.main()
