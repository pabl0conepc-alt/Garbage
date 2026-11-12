"""Offline tests for the public connectors, using response shapes recorded
from the live services on 2026-11-12."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from garbage_intel import intel
from garbage_intel.intel import ConnectorContext, run_query
from garbage_intel.modules import intel_connectors as ic
from garbage_intel.net import FetchResult
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings


def result(url, payload, status=200):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return FetchResult(
        url=url,
        final_url=url,
        status=status,
        headers={},
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        address="93.184.216.34",
        elapsed_ms=1,
    )


def doh(name, record_type, answers):
    return {
        "Status": 0,
        "Question": [{"name": name, "type": ic.DNS_TYPES[record_type]}],
        "Answer": [
            {"name": name, "type": ic.DNS_TYPES[record_type], "TTL": 300, "data": data}
            for data in answers
        ],
    }


class FakeWeb:
    """Routes requests to canned responses and records every URL."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []
        self.calls = []

    def __call__(self, url, **options):
        self.urls.append(url)
        self.calls.append(options)
        for matcher, response in self.routes:
            if matcher(url):
                return result(url, response) if not isinstance(response, FetchResult) else response
        return result(url, {"Status": 3}, status=200)


def doh_route(name, record_type, answers):
    def match(url):
        query = parse_qs(urlsplit(url).query)
        return (
            url.startswith(ic.DOH_URL)
            and query.get("name") == [name]
            and query.get("type") == [record_type]
        )

    return match, doh(name, record_type, answers)


def context(kind, value, database=""):
    return ConnectorContext(database, kind, value, None)


class DnsTests(unittest.TestCase):
    def test_records_spf_dmarc_and_null_mx(self):
        web = FakeWeb(
            [
                doh_route("example.com", "A", ["104.20.23.154"]),
                doh_route("example.com", "MX", ["0 ."]),
                doh_route("example.com", "NS", ["elliott.ns.cloudflare.com."]),
                doh_route("example.com", "TXT", ['"v=spf1 -all"', '"site-verification=x"']),
                doh_route("_dmarc.example.com", "TXT", ['"v=DMARC1;p=reject"']),
            ]
        )
        with patch.object(ic, "FETCH", web):
            findings = ic._dns_connector(context("domain", "example.com"))
        values = {(item.result_type, item.value): item for item in findings}
        self.assertIn(("dns-a", "104.20.23.154"), values)
        self.assertTrue(values[("dns-mx", "0 .")].data["null_mx"])
        self.assertIn(("dns-ns", "elliott.ns.cloudflare.com"), values)
        self.assertEqual(values[("dns-txt", "v=spf1 -all")].data["policy"], "spf")
        self.assertIn(("dns-dmarc", "v=DMARC1;p=reject"), values)
        self.assertTrue(all(len(item.response_sha256) == 64 for item in findings))
        self.assertTrue(all(call["allowed_hosts"] == ic.DOH_HOSTS for call in web.calls))

    def test_email_queries_only_mail_exchangers_of_its_domain(self):
        web = FakeWeb([doh_route("mail.example", "MX", ["10 mx.mail.example."])])
        with patch.object(ic, "FETCH", web):
            findings = ic._dns_connector(context("email", "a@mail.example"))
        self.assertEqual([(item.result_type, item.value) for item in findings], [("dns-mx", "10 mx.mail.example")])
        self.assertEqual(len(web.urls), 1)

    def test_ip_url_has_no_host_to_resolve(self):
        with patch.object(ic, "FETCH", FakeWeb([])) as web:
            self.assertEqual(ic._dns_connector(context("url", "https://8.8.8.8/x")), [])
        self.assertEqual(web.urls, [])


class CymruTests(unittest.TestCase):
    def test_ipv4_and_as_name(self):
        web = FakeWeb(
            [
                doh_route("8.8.8.8.origin.asn.cymru.com", "TXT", ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"']),
                doh_route("AS15169.asn.cymru.com", "TXT", ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"']),
            ]
        )
        with patch.object(ic, "FETCH", web):
            findings = ic._cymru_connector(context("ipv4", "8.8.8.8"))
        self.assertEqual(findings[0].value, "AS15169")
        self.assertEqual(findings[0].data["prefix"], "8.8.8.0/24")
        self.assertEqual(findings[1].value, "GOOGLE - Google LLC, US")

    def test_ipv6_uses_nibble_format(self):
        name = ic._cymru_origin_name("2606:4700:4700::1111")
        self.assertTrue(name.endswith(".origin6.asn.cymru.com"))
        self.assertTrue(name.startswith("1.1.1.1.0.0.0.0"))


class RdapTests(unittest.TestCase):
    DOMAIN = {
        "objectClassName": "domain",
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "EXAMPLE.COM",
        "status": ["client delete prohibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrar Inc"]]],
                "entities": [
                    {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@registrar.example"]]]}
                ],
            },
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Jane Private Person"], ["email", {}, "text", "jane@example.com"]]]},
            {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Tech Person"]]]},
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-11-12T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET."}],
        "secureDNS": {"delegationSigned": True},
    }
    NETWORK = {
        "objectClassName": "ip network",
        "handle": "NET-8-8-8-0-2",
        "name": "GOGL",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "type": "DIRECT ALLOCATION",
        "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
        "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]},
        ],
    }

    def run_rdap(self, kind, value, payload):
        web = FakeWeb([(lambda url: url.startswith(ic.RDAP_BOOTSTRAP), payload)])
        with patch.object(ic, "FETCH", web):
            findings = ic._rdap_connector(context(kind, value))
        return findings, web

    def test_domain_keeps_organisation_roles_and_drops_people(self):
        findings, web = self.run_rdap("domain", "example.com", self.DOMAIN)
        self.assertEqual(web.urls, ["https://rdap.org/domain/example.com"])
        values = {(item.result_type, item.value) for item in findings}
        self.assertIn(("organization", "Registrar Inc"), values)
        self.assertIn(("abuse-contact", "abuse@registrar.example"), values)
        self.assertIn(("nameserver", "ns1.example.net"), values)
        self.assertIn(("dnssec", "signed"), values)
        flat = json.dumps([item.__dict__ for item in findings])
        self.assertNotIn("Jane", flat)
        self.assertNotIn("jane@example.com", flat)
        self.assertNotIn("Tech Person", flat)
        self.assertNotIn("last update of RDAP database", flat)

    def test_network_keeps_holder_and_deduplicates(self):
        findings, _ = self.run_rdap("ipv4", "8.8.8.8", self.NETWORK)
        organisations = [item.value for item in findings if item.result_type == "organization"]
        self.assertEqual(organisations.count("Abuse"), 1)
        self.assertIn("Google LLC", organisations)
        self.assertIn(("cidr", "8.8.8.0/24"), {(item.result_type, item.value) for item in findings})

    def test_paths_keep_ipv6_colons_and_cidr_slash(self):
        self.assertEqual(ic._rdap_path(context("ipv6", "2606:4700::1")), "/ip/2606:4700::1")
        self.assertEqual(ic._rdap_path(context("cidr", "8.8.8.0/24")), "/ip/8.8.8.0/24")
        self.assertEqual(ic._rdap_path(context("asn", "AS15169")), "/autnum/15169")

    def test_not_found_and_errors(self):
        findings, _ = self.run_rdap("domain", "missing.example", None)
        web = FakeWeb([(lambda url: True, result("x", {}, status=404))])
        with patch.object(ic, "FETCH", web):
            self.assertEqual(ic._rdap_connector(context("domain", "missing.example")), [])
        web = FakeWeb([(lambda url: True, result("x", {}, status=429))])
        with patch.object(ic, "FETCH", web), self.assertRaises(ic.NetworkError):
            ic._rdap_connector(context("domain", "busy.example"))
        web = FakeWeb([(lambda url: True, result("x", b"<html>not json"))])
        with patch.object(ic, "FETCH", web), self.assertRaises(ic.NetworkError):
            ic._rdap_connector(context("domain", "broken.example"))


class CrtShTests(unittest.TestCase):
    def test_names_are_scoped_aggregated_and_issuers_counted(self):
        rows = [
            {"issuer_name": "CN=CA One", "name_value": "*.example.com\nexample.com", "not_before": "2026-09-26T22:49:11"},
            {"issuer_name": "CN=CA One", "name_value": "www.example.com", "not_before": "2025-01-01T00:00:00"},
            {"issuer_name": "CN=CA Two", "name_value": "www.example.com\nevil-example.com", "not_before": "2026-01-01T00:00:00"},
        ]
        web = FakeWeb([(lambda url: url.startswith(ic.CRTSH_URL), rows)])
        with patch.object(ic, "FETCH", web):
            findings = ic._crtsh_connector(context("domain", "example.com"))
        names = {item.value: item.data for item in findings if item.result_type == "ct-name"}
        self.assertEqual(set(names), {"*.example.com", "example.com", "www.example.com"})
        self.assertEqual(names["www.example.com"]["certificates"], 2)
        self.assertEqual(names["www.example.com"]["first_seen"], "2025-01-01T00:00:00")
        self.assertEqual(names["www.example.com"]["last_seen"], "2026-01-01T00:00:00")
        self.assertTrue(names["*.example.com"]["wildcard"])
        issuers = {item.value: item.data["certificates"] for item in findings if item.result_type == "ct-issuer"}
        self.assertEqual(issuers, {"CN=CA One": 2, "CN=CA Two": 1})
        self.assertIn("q=%25.example.com", web.urls[0])
        self.assertIn("exclude=expired", web.urls[0])


class WaybackTests(unittest.TestCase):
    def test_summary_and_capture_links(self):
        payload = [
            ["timestamp", "original", "statuscode", "mimetype", "digest"],
            ["20020120142510", "http://example.com:80/", "200", "text/html", "A"],
            ["20160822144917", "http://example.com/", "200", "text/html", "B"],
        ]
        web = FakeWeb([(lambda url: url.startswith(ic.WAYBACK_CDX), payload)])
        with patch.object(ic, "FETCH", web):
            findings = ic._wayback_connector(context("domain", "example.com"))
        self.assertEqual(findings[0].value, "2 distinct captures")
        self.assertEqual(findings[0].data["first"], "20020120142510")
        self.assertEqual(findings[-1].value, "https://web.archive.org/web/20160822144917/http://example.com/")
        with patch.object(ic, "FETCH", FakeWeb([(lambda url: True, [])])):
            self.assertEqual(ic._wayback_connector(context("domain", "new.example")), [])


class CveConnectorTests(unittest.TestCase):
    def test_epss_parses_matching_row(self):
        payload = {"status": "OK", "version": "1.0", "data": [{"cve": "CVE-2024-3094", "epss": "0.909000000", "percentile": "0.998100000", "date": "2026-11-12"}]}
        with patch.object(ic, "FETCH", FakeWeb([(lambda url: url.startswith(ic.EPSS_URL), payload)])):
            findings = ic._epss_connector(context("cve", "CVE-2024-3094"))
        self.assertEqual(findings[0].value, "0.9090")
        self.assertEqual(findings[0].data["percentile"], 0.9981)

    def test_kev_without_cache_is_a_notice_not_a_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "intel.sqlite3")
            initialize(database)
            findings = ic._kev_connector(context("cve", "CVE-2024-3094", database))
        self.assertEqual(findings[0].result_type, "notice")


class RegistrationTests(unittest.TestCase):
    def test_public_connectors_are_registered_as_network_connectors(self):
        registered = {item.connector_id: item for item in intel.connectors()}
        for connector_id in ("dns-doh", "cymru-asn", "rdap", "crtsh", "wayback", "first-epss"):
            self.assertTrue(registered[connector_id].network, connector_id)
            self.assertFalse(registered[connector_id].requires_key, connector_id)
            self.assertGreater(registered[connector_id].ttl_seconds, 0, connector_id)
        self.assertFalse(registered["cisa-kev-local"].network)

    def test_network_connectors_never_fetch_while_network_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "intel.sqlite3")
            initialize(database)
            intel.RATE_LIMITER.reset()
            web = FakeWeb([])
            with patch.object(ic, "FETCH", web):
                run = run_query(database, value="example.com")
                statuses = {item["connector_id"]: item["status"] for item in run["sources"]}
                self.assertEqual(web.urls, [])
                self.assertEqual(statuses["rdap"], "network-disabled")
                update_settings(database, {"intel.allow_network": "true"})
                run = run_query(database, value="example.com", connector_ids=["rdap"])
                self.assertEqual(web.urls, ["https://rdap.org/domain/example.com"])


if __name__ == "__main__":
    unittest.main()
