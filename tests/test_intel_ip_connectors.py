"""IP and network sources: reverse IP, passive DNS, public lists and DNSBLs."""

import json
import unittest
from unittest.mock import patch

from garbage_intel.dossier import build
from garbage_intel.intel import ConnectorContext
from garbage_intel.modules import intel_connectors as ic
from garbage_intel.modules import intel_ip_connectors as ips

from tests.test_intel_connectors import FakeWeb, doh_route, result


def context(value, kind="ipv4"):
    return ConnectorContext("", kind, value, None)


AWS = {"prefixes": [{"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "S3"},
                    {"ip_prefix": "3.0.0.0/8", "region": "GLOBAL", "service": "AMAZON"}], "ipv6_prefixes": []}
GOOGLE = {"prefixes": [{"ipv4Prefix": "34.35.0.0/16", "service": "Google Cloud", "scope": "africa-south1"}]}
LISTS = [
    (lambda url: "torbulkexitlist" in url, result("u", b"198.51.100.7\n")),
    (lambda url: "feodotracker" in url, [{"ip_address": "203.0.113.66", "malware": "Emotet", "status": "online", "port": 443, "first_seen": "2026-01-02 10:00:00"}]),
    (lambda url: "drop_v4" in url, result("u", b'{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}\n{"type":"metadata"}\n')),
    (lambda url: "amazonaws" in url, AWS),
    (lambda url: "gstatic" in url, GOOGLE),
    (lambda url: "ips-v4" in url, result("u", b"104.16.0.0/13\n")),
    (lambda url: "ips-v6" in url, result("u", b"2606:4700::/32\n")),
    (lambda url: "fastly" in url, {"addresses": ["151.101.0.0/16"], "ipv6_addresses": []}),
]


class IpSourceTests(unittest.TestCase):
    def setUp(self):
        ips._LISTS.clear()
        self.addCleanup(ips._LISTS.clear)

    def lists(self, value):
        web = FakeWeb(LISTS)
        with patch.object(ips, "FETCH", web):
            found = ips._ip_lists(context(value))
        return {item.result_type: item for item in found}, web

    def test_public_lists_are_matched_locally(self):
        found, web = self.lists("3.5.141.9")
        self.assertEqual((found["cloud-range"].value, found["cloud-range"].data["service"], found["cloud-range"].data["prefix"]), ("Amazon Web Services", "S3", "3.5.140.0/22"))
        self.assertFalse(any("3.5.141.9" in url for url in web.urls))
        self.assertIn("Emotet", self.lists("203.0.113.66")[0]["botnet-c2"].value)
        self.assertIn("SBL1", self.lists("192.0.2.10")[0]["drop-listed"].value)
        self.assertIn("tor-exit", self.lists("198.51.100.7")[0])
        self.assertEqual(self.lists("2606:4700::1")[0]["cloud-range"].value, "Cloudflare")
        # Downloaded once, then served from memory.
        _, again = self.lists("8.8.8.8")
        self.assertEqual(again.urls, [])

    def test_dnsbl_listed_clean_and_refused(self):
        routes = [doh_route("2.0.0.127.bl.spamcop.net", "A", ["127.0.0.2"]), doh_route("2.0.0.127.zen.spamhaus.org", "A", ["127.255.255.254"])]
        with patch.object(ic, "FETCH", FakeWeb(routes)):
            found = ips._dnsbl(context("127.0.0.2"))
        listed = [item.value for item in found if item.result_type == "blocklist"]
        check = next(item for item in found if item.result_type == "blocklist-check")
        self.assertEqual(listed, ["SpamCop"])
        self.assertEqual(check.data["unanswered"], ["Spamhaus ZEN"])
        self.assertEqual(len(check.data["clean"]), 5)

    def test_reverse_ip_and_passive_dns(self):
        with patch.object(ips, "FETCH", FakeWeb([(lambda url: True, result("u", b"a.example.org\nb.example.net\n"))])):
            self.assertEqual([item.value for item in ips._reverse_ip(context("192.0.2.1"))], ["a.example.org", "b.example.net"])
        pdns = {"count": 1, "data": [{"query": "a.example.org", "answer": "192.0.2.1", "rrtype": "a", "firstSeenTimestamp": 1586260939975, "lastSeenTimestamp": 1794738872474}]}
        with patch.object(ips, "FETCH", FakeWeb([(lambda url: True, pdns)])):
            by_ip = ips._passive_dns(context("192.0.2.1"))
            by_domain = ips._passive_dns(context("a.example.org", "domain"))
        self.assertEqual((by_ip[0].result_type, by_ip[0].value, by_ip[0].data["first_seen"]), ("pdns-name", "a.example.org", "2020-04-07"))
        self.assertEqual((by_domain[0].result_type, by_domain[0].value), ("pdns-answer", "192.0.2.1"))

    def test_ip_dossier_flags_and_sections(self):
        def item(connector, kind, value, **data):
            return {"connector_id": connector, "result_type": kind, "value": value, "data": data, "status": "ok"}

        dossier = build({"query_type": "ipv4", "query_value": "203.0.113.66", "sources": [], "results": [
            item("ip-lists", "botnet-c2", "servidor de comando de botnet (Emotet)", status="online"),
            item("ip-lists", "cloud-range", "Amazon Web Services", service="EC2", region="sa-east-1", prefix="203.0.113.0/24"),
            item("ip-lists", "lists-checked", "listas públicas conferidas"),
            item("dnsbl", "blocklist", "SpamCop"),
            item("dnsbl", "blocklist-check", "1 de 7 listas", clean=["PSBL"], unanswered=["Spamhaus ZEN"]),
            item("reverse-ip", "cohosted-domain", "a.example.org"),
            item("mnemonic-pdns", "pdns-name", "old.example.org", first_seen="2020-01-01", last_seen="2021-01-01"),
        ]})
        texts = " ".join(flag["text"] for flag in dossier["flags"])
        self.assertIn("Emotet", texts)
        self.assertIn("SpamCop", texts)
        sections = {section["id"]: section for section in dossier["sections"]}
        network = {row["label"]: row["value"] for row in sections["network"]["rows"]}
        self.assertEqual(network["Nuvem ou CDN"], "Amazon Web Services · EC2 · sa-east-1")
        reputation = {row["label"]: row["value"] for row in sections["reputation"]["rows"]}
        self.assertEqual((reputation["Spamhaus DROP"], reputation["Listas antispam"]), ("não listado", "SpamCop"))
        self.assertEqual(sections["pdns"]["list"]["items"][0]["meta"], "01/01/2020 → 01/01/2021")
        self.assertEqual(sections["cohosted"]["list"]["items"][0]["value"], "a.example.org")
        json.dumps(dossier)


if __name__ == "__main__":
    unittest.main()
