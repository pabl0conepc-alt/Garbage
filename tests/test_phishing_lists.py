"""Public phishing lists, downloaded whole and matched locally."""

import unittest
from unittest.mock import patch

from garbage_intel.dossier import build
from garbage_intel.intel import ConnectorContext
from garbage_intel.modules import intel_ip_connectors as ips
from garbage_intel.modules import intel_list_connectors as phishing

from tests.test_intel_connectors import FakeWeb, result

LISTS = [
    (lambda url: "openphish" in url, result("u", b"http://login.evil.example/verify\nhttps://other.example.net/\n")),
    (lambda url: "phishing.army" in url, result("u", b"# comment\nbad.example.org\n")),
    (lambda url: "blocklistproject" in url, result("u", b"a.shared.example\nb.shared.example\n")),
    (lambda url: "Phishing.Database" in url, result("u", b"", status=503)),
]


def context(kind, value):
    return ConnectorContext("", kind, value, None)


class PhishingListTests(unittest.TestCase):
    def setUp(self):
        ips._LISTS.clear()
        self.addCleanup(ips._LISTS.clear)

    def run_lists(self, kind, value):
        web = FakeWeb(LISTS)
        with patch.object(ips, "FETCH", web):
            found = phishing._phishing_lists(context(kind, value))
        return found, web

    def test_url_domain_parent_and_names_under(self):
        found, web = self.run_lists("url", "http://login.evil.example/verify/")
        self.assertEqual([(item.value, item.data.get("match")) for item in found if item.result_type == "phishing-listed"], [("OpenPhish", "URL exata")])
        self.assertFalse(any("login.evil.example" in url for url in web.urls))
        check = next(item for item in found if item.result_type == "phishing-check")
        self.assertEqual(check.data["failed"], ["Phishing.Database"])
        parent, _ = self.run_lists("domain", "x.bad.example.org")
        self.assertEqual(parent[0].data["match"], "domínio acima (bad.example.org)")
        under, again = self.run_lists("domain", "shared.example")
        self.assertEqual(under[0].data["names"], ["a.shared.example", "b.shared.example"])
        self.assertEqual(again.urls, [u for u in again.urls if "Phishing.Database" in u])  # only the failed list is retried

    def test_dossier_flags_listed_values(self):
        found, _ = self.run_lists("url", "http://login.evil.example/verify")
        results = [{"connector_id": "phishing-lists", "result_type": item.result_type, "value": item.value, "data": item.data, "status": "ok"} for item in found]
        dossier = build({"query_type": "url", "query_value": "http://login.evil.example/verify", "sources": [], "results": results})
        self.assertIn("lista pública de phishing", dossier["flags"][0]["text"])
        self.assertEqual(next(section for section in dossier["sections"] if section["id"] == "phishing")["rows"][0]["value"], "OpenPhish (URL exata)")


if __name__ == "__main__":
    unittest.main()
