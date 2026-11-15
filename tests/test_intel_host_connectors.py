"""Passive host sources for a domain: HackerTarget, OTX, subdomain.center, common names."""

import json
import unittest
from unittest.mock import patch

from garbage_intel.dossier import build
from garbage_intel.intel import ConnectorContext
from garbage_intel.modules import intel_connectors as ic
from garbage_intel.modules import intel_host_connectors as hosts
from garbage_intel.net import NetworkError

from tests.test_intel_connectors import FakeWeb, doh_route, result


def context(value="example.org", kind="domain", key=""):
    return ConnectorContext("", kind, value, None, api_key=key)


class HostSourceTests(unittest.TestCase):
    def test_hackertarget_names_with_ips_and_its_daily_limit(self):
        text = b"example.org,192.0.2.1\nwww.example.org,192.0.2.2\nevil.other.org,192.0.2.3\nwww.example.org,192.0.2.9\n"
        with patch.object(hosts, "FETCH", FakeWeb([(lambda url: "hostsearch" in url, result("u", text))])):
            found = hosts._hackertarget(context())
        self.assertEqual([(item.value, item.data["ip"]) for item in found], [("example.org", "192.0.2.1"), ("www.example.org", "192.0.2.2")])
        with patch.object(hosts, "FETCH", FakeWeb([(lambda url: True, result("u", b"API count exceeded - Increase Quota with Membership"))])):
            with self.assertRaises(NetworkError):
                hosts._hackertarget(context())

    def test_otx_hosts_and_urls_stay_under_the_domain(self):
        payload = {"url_list": [
            {"url": "https://app.example.org/login", "hostname": "app.example.org", "date": "2026-11-01T10:00:00", "httpcode": 200,
             "result": {"urlworker": {"ip": "192.0.2.5"}}},
            {"url": "https://example.net/", "hostname": "example.net"},
        ]}
        web = FakeWeb([(lambda url: "url_list" in url, payload)])
        with patch.object(hosts, "FETCH", web):
            found = hosts._otx_hosts(context(key="k" * 64))
        self.assertEqual([(item.result_type, item.value) for item in found], [("subdomain", "app.example.org"), ("observed-url", "https://app.example.org/login")])
        self.assertEqual(found[0].data["ip"], "192.0.2.5")
        self.assertEqual(web.calls[0]["headers"]["X-OTX-API-KEY"], "k" * 64)

    def test_subdomain_center_list_and_busy_answer(self):
        with patch.object(hosts, "FETCH", FakeWeb([(lambda url: True, ["a.example.org", "B.example.org", "x.other.org"])])):
            self.assertEqual([item.value for item in hosts._subdomain_center(context())], ["a.example.org", "b.example.org"])
        with patch.object(hosts, "FETCH", FakeWeb([(lambda url: True, {"error": "server busy"})])):
            with self.assertRaises(NetworkError):
                hosts._subdomain_center(context())

    def test_common_names_only_report_names_that_exist(self):
        web = FakeWeb([doh_route("www.example.org", "A", ["192.0.2.10"]), doh_route("mail.example.org", "CNAME", ["mx.provider.net."])])
        with patch.object(ic, "FETCH", web):
            found = hosts._common_names(context())
        self.assertEqual(sorted((item.value, item.data["ip"]) for item in found), [("mail.example.org", "mx.provider.net."), ("www.example.org", "192.0.2.10")])

    def test_dossier_shows_the_ip_each_source_saw(self):
        dossier = build({"query_type": "domain", "query_value": "example.org", "sources": [], "results": [
            {"connector_id": "hackertarget-hosts", "result_type": "subdomain", "value": "www.example.org", "data": {"ip": "192.0.2.2"}, "status": "ok"},
            {"connector_id": "otx-hosts", "result_type": "observed-url", "value": "https://www.example.org/a", "data": {"date": "2026-11-01T10:00:00"}, "status": "ok"},
        ]})
        sections = {section["id"]: section for section in dossier["sections"]}
        self.assertEqual(sections["subdomains"]["list"]["items"][0]["meta"], "192.0.2.2 · HackerTarget")
        self.assertEqual(sections["urls"]["list"]["items"][0], {"value": "https://www.example.org/a", "meta": "01/11/2026"})
        json.dumps(dossier)


if __name__ == "__main__":
    unittest.main()
