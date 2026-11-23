"""Catalogue block 8: topic queries, news, research and feeds."""

import hashlib
import unittest
from unittest.mock import patch

from garbage_intel.errors import ValidationError
from garbage_intel.intel import ConnectorContext, _run_one, connectors, detect_artifact
from garbage_intel.modules import intel_open_connectors as shared
from garbage_intel.modules.intel_research_connectors import parse_feed
from garbage_intel.net import FetchResult
from tests.test_intel_sources import Router

BY_ID = {connector.connector_id: connector for connector in connectors()}


def run(connector_id, value, routes, kind="topic", api_key=""):
    router = Router(routes)
    with patch.object(shared, "FETCH", router):
        status, findings, error, _ = _run_one(BY_ID[connector_id], ConnectorContext("", kind, value, None, api_key))
    return status, findings, error, router.calls


class TopicTests(unittest.TestCase):
    def test_detection(self):
        self.assertEqual(detect_artifact("topic:  ransomware   hospital "), {"type": "topic", "value": "ransomware hospital", "label": "Topic"})
        self.assertEqual(detect_artifact("news: Lula")["type"], "topic")
        with self.assertRaises(ValidationError):
            detect_artifact("ransomware hospital")

    def test_gdelt(self):
        routes = {"api.gdeltproject.org": {"articles": [{"title": "Hospital hit &amp; down", "url": "https://n.example/a", "domain": "n.example", "seendate": "20261120T101500Z", "language": "Portuguese", "sourcecountry": "Brazil"}]}}
        status, findings, _, calls = run("gdelt-news", "ransomware hospital", routes)
        self.assertEqual(findings[0].value, "Hospital hit & down")
        self.assertEqual(findings[0].data["country"], "Brazil")
        self.assertIn("query=ransomware+hospital", calls[0][0])
        status, _, error, _ = run("gdelt-news", "x", {"api.gdeltproject.org": (429, {})})
        self.assertEqual(status, "error")
        self.assertIn("one request every 5 seconds", error)

    def test_hackernews_and_wikipedia(self):
        _, findings, _, _ = run("hackernews", "rust", {"hn.algolia.com": {"hits": [{"title": "Rust 2.0", "url": "https://r.example", "objectID": "42", "points": 900, "num_comments": 300}]}})
        self.assertEqual(findings[0].data["thread"], "https://news.ycombinator.com/item?id=42")
        routes = {
            "pt.wikipedia.org": {"query": {"search": [{"title": "Ransomware", "snippet": "<span>sequestro</span> de dados"}]}},
            "en.wikipedia.org": {"query": {"search": [{"title": "WannaCry ransomware attack", "snippet": "x"}]}},
            "wikidata.org": {"search": [{"id": "Q926331", "label": "ransomware", "description": "malware"}]},
        }
        _, findings, _, _ = run("wikipedia", "ransomware", routes)
        values = {item.result_type: [] for item in findings}
        for item in findings:
            values[item.result_type].append(item)
        self.assertEqual(values["encyclopedia-article"][0].data["snippet"], "sequestro de dados")
        self.assertEqual(values["encyclopedia-article"][1].data["url"], "https://en.wikipedia.org/wiki/WannaCry_ransomware_attack")
        self.assertEqual(values["wikidata-entity"][0].value, "ransomware (Q926331)")

    def test_crossref_and_openalex(self):
        crossref = {"message": {"items": [{"DOI": "10.1/x", "title": ["Paper A"], "author": [{"given": "Ana", "family": "Silva"}], "issued": {"date-parts": [[2024, 5]]}, "container-title": ["J. Sec"], "type": "journal-article"}]}}
        _, findings, _, _ = run("crossref", "x", {"api.crossref.org": crossref})
        self.assertEqual((findings[0].value, findings[0].data["year"], findings[0].data["authors"]), ("Paper A", 2024, "Ana Silva"))
        openalex = {"results": [{"id": "https://openalex.org/W1", "display_name": "Paper B", "publication_year": 2023, "cited_by_count": 7, "authorships": [{"author": {"display_name": "B. Lee"}}], "primary_location": {"source": {"display_name": "Venue"}}}]}
        _, findings, _, calls = run("openalex", "x", {"api.openalex.org": openalex}, api_key="oa-key-1234")
        self.assertEqual((findings[0].value, findings[0].data["cited_by"], findings[0].data["venue"]), ("Paper B", 7, "Venue"))
        self.assertIn("api_key=oa-key-1234", calls[0][0])
        self.assertNotIn("oa-key-1234", findings[0].source_url)


RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Advisories</title>
<item><title>Patch now</title><link>https://a.example/1</link><pubDate>Mon, 23 Nov 2026 10:00:00 GMT</pubDate><description>&lt;p&gt;Critical&lt;/p&gt;</description></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Blog</title>
<entry><title>Post</title><link rel="self" href="https://b.example/self"/><link rel="alternate" href="https://b.example/p"/><updated>2026-11-20T00:00:00Z</updated><summary>Hi</summary></entry></feed>"""


class FeedTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_feed(RSS), ("Advisories", [{"title": "Patch now", "url": "https://a.example/1", "date": "Mon, 23 Nov 2026 10:00:00 GMT", "summary": "<p>Critical</p>"}]))
        title, items = parse_feed(ATOM)
        self.assertEqual((title, items[0]["url"]), ("Blog", "https://b.example/p"))
        for bad in (b"<html></html>", b"not xml", b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss/>'):
            with self.assertRaises(ValueError):
                parse_feed(bad)

    def test_connector_needs_target_contact_and_ignores_html(self):
        self.assertTrue(BY_ID["rss-feed"].contacts_target)

        def fetch(body, ctype):
            return lambda url, **o: FetchResult(url, url, 200, {"content-type": ctype}, body, hashlib.sha256(body).hexdigest(), "", 1, [])

        with patch.object(shared, "FETCH", fetch(RSS, "application/rss+xml")):
            status, findings, _, _ = _run_one(BY_ID["rss-feed"], ConnectorContext("", "url", "https://a.example/feed", None))
        self.assertEqual([item.result_type for item in findings], ["feed", "feed-item"])
        self.assertEqual(findings[1].data["summary"], "Critical")
        with patch.object(shared, "FETCH", fetch(b"<html><body>page</body></html>", "text/html")):
            status, findings, _, _ = _run_one(BY_ID["rss-feed"], ConnectorContext("", "url", "https://a.example/", None))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
