"""Phase 7: more sources and the local API key manager.

Responses under ``fixtures/sources`` were recorded from the live services on
2026-11-12 and trimmed. VirusTotal, AbuseIPDB and abuse.ch replies are built
from each provider's documented format, since recording them needs a key.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from garbage_intel import intel, intel_keys
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.intel import ConnectorContext, _run_one, connectors, list_connectors, run_query
from garbage_intel.modules import intel_open_connectors as shared
from garbage_intel.net import FetchResult
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings

FIXTURES = Path(__file__).parent / "fixtures" / "sources"
BY_ID = {connector.connector_id: connector for connector in connectors()}


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def reply(url, payload, status=200):
    body = json.dumps(payload).encode() if payload is not None else b"{}"
    return FetchResult(url, url, status, {}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])


class Router:
    """Answer requests from a table of (substring -> payload | (status, payload))."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, **options):
        self.calls.append((url, options))
        for needle, payload in self.routes.items():
            if needle in url:
                status, body = payload if isinstance(payload, tuple) else (200, payload)
                return reply(url, body, status)
        return reply(url, {"detail": "not found"}, 404)


def run(connector_id, kind, value, routes, api_key=""):
    router = Router(routes)
    with patch.object(shared, "FETCH", router):
        status, findings, error, _ = _run_one(BY_ID[connector_id], ConnectorContext("", kind, value, None, api_key))
    return status, findings, error, router.calls


def types(findings):
    counts = {}
    for item in findings:
        counts[item.result_type] = counts.get(item.result_type, 0) + 1
    return counts


class OpenSourceTests(unittest.TestCase):
    def test_shodan_internetdb(self):
        status, findings, _, calls = run("shodan-internetdb", "ipv4", "1.1.1.1", {"internetdb.shodan.io/1.1.1.1": fixture("internetdb-1.1.1.1")})
        self.assertEqual(status, "ok")
        self.assertIn("443", [item.value for item in findings if item.result_type == "open-port"])
        self.assertIn("one.one.one.one", [item.value for item in findings if item.result_type == "hostname"])
        self.assertEqual(calls[0][1]["allowed_hosts"], ("internetdb.shodan.io",))

    def test_ripestat_ip_and_asn(self):
        routes = {
            "prefix-overview": fixture("ripestat-prefix-1.1.1.1"),
            "abuse-contact-finder": fixture("ripestat-abuse-1.1.1.1"),
            "as-overview": fixture("ripestat-as-AS13335"),
            "announced-prefixes": fixture("ripestat-prefixes-AS13335"),
        }
        status, findings, _, calls = run("ripestat", "ipv4", "1.1.1.1", routes)
        origin = next(item for item in findings if item.result_type == "origin-asn")
        self.assertEqual((origin.value, origin.data["prefix"]), ("AS13335", "1.1.1.0/24"))
        self.assertEqual([item.value for item in findings if item.result_type == "abuse-contact"], ["helpdesk@apnic.net"])
        self.assertEqual(parse_qs(urlsplit(calls[0][0]).query)["sourceapp"], ["garbage-intel"])
        _, findings, _, _ = run("ripestat", "asn", "AS13335", routes)
        self.assertEqual(types(findings), {"as-holder": 1, "announced-prefix": 3, "abuse-contact": 1})

    def test_peeringdb_ipinfo_hashlookup(self):
        _, findings, _, calls = run("peeringdb", "asn", "AS13335", {"peeringdb.com/api/net?asn=13335": fixture("peeringdb-13335")})
        self.assertEqual(findings[0].value, "Cloudflare")
        self.assertGreater(findings[0].data["ix_count"], 100)
        _, findings, _, calls = run("ipinfo", "ipv4", "8.8.8.8", {"ipinfo.io/8.8.8.8": fixture("ipinfo-8.8.8.8")})
        self.assertEqual(types(findings), {"network-owner": 1, "hostname": 1, "geolocation": 1})
        self.assertNotIn("Authorization", calls[0][1]["headers"])
        _, _, _, calls = run("ipinfo", "ipv4", "8.8.8.8", {"ipinfo.io/8.8.8.8": fixture("ipinfo-8.8.8.8")}, api_key="abcdef0123456789")
        self.assertEqual(calls[0][1]["headers"]["Authorization"], "Bearer abcdef0123456789")
        _, findings, _, _ = run("circl-hashlookup", "sha1", "fffffdac1b1b4c513896c805c2c698d9688be69f", {"lookup/sha1/": fixture("hashlookup-sha1")})
        self.assertEqual((findings[0].value, findings[0].data["source_set"]), (".rela.dyn", "NSRL"))
        _, findings, _, _ = run("circl-hashlookup", "md5", "0" * 32, {})
        self.assertEqual(findings[0].value, "not in hashlookup")

    def test_urlscan_marks_page_or_resource(self):
        _, findings, _, calls = run("urlscan", "domain", "baliprema.com", {"urlscan.io/api/v1/search": fixture("urlscan-example.com")})
        self.assertEqual([item.data["relation"] for item in findings], ["page", "loaded-resource", "loaded-resource", "loaded-resource"])
        self.assertIn("page.domain:baliprema.com", parse_qs(urlsplit(calls[0][0]).query)["q"][0])
        self.assertTrue(findings[0].data["report"].startswith("https://urlscan.io/result/"))

    def test_certspotter_subdomains(self):
        _, findings, _, _ = run("certspotter", "domain", "example.com", {"api.certspotter.com": fixture("certspotter-example.com")})
        names = [item.value for item in findings if item.result_type == "subdomain"]
        self.assertIn("www.example.com", names)
        self.assertNotIn("example.org", names)
        self.assertEqual(types(findings)["certificate"], 4)

    def test_nvd_and_osv_alias_follow(self):
        _, findings, _, _ = run("nvd", "cve", "CVE-2021-44228", {"services.nvd.nist.gov": fixture("nvd-CVE-2021-44228")})
        record = findings[0]
        self.assertEqual(record.result_type, "cve-record")
        self.assertEqual(record.data["cvss"]["score"], 10.0)
        self.assertIn("CWE-502", record.data["cwe"])
        self.assertEqual(types(findings)["reference"], 3)
        routes = {"vulns/CVE-2021-44228": fixture("osv-CVE-2021-44228"), "vulns/GHSA-jfh8-c2jp-5v3q": fixture("osv-GHSA-jfh8-c2jp-5v3q")}
        _, findings, _, calls = run("osv", "cve", "CVE-2021-44228", routes)
        self.assertEqual(len(calls), 2)
        package = next(item for item in findings if item.result_type == "affected-package")
        self.assertTrue(package.value.startswith("Maven:"))
        self.assertTrue(package.data["fixed_in"])


class KeyedSourceTests(unittest.TestCase):
    def test_keyless_capable_providers(self):
        _, findings, _, calls = run("greynoise", "ipv4", "71.6.135.131", {"community/71.6.135.131": fixture("greynoise-71.6.135.131")})
        self.assertEqual((findings[0].value, findings[0].data["name"]), ("benign", "Shodan.io"))
        self.assertEqual(calls[0][1]["headers"].get("key"), None)
        _, findings, _, _ = run("greynoise", "ipv4", "8.8.8.8", {"community/8.8.8.8": (404, {"noise": False, "riot": False})})
        self.assertEqual(findings[0].value, "not observed")
        _, findings, _, calls = run("shodan", "ipv4", "1.1.1.1", {"shodan/host/1.1.1.1": fixture("shodan-1.1.1.1")})
        self.assertEqual(types(findings)["service"], 3)
        self.assertNotIn("key=", calls[0][0])
        self.assertTrue(all(item.source_url == "https://www.shodan.io/host/1.1.1.1" for item in findings))
        _, findings, _, _ = run("otx", "cve", "CVE-2021-44228", {"indicators/cve/CVE-2021-44228/general": fixture("otx-CVE-2021-44228")})
        self.assertEqual(types(findings)["pulse"], 3)
        self.assertIn("attack-technique", types(findings))

    def test_virustotal_file_and_url(self):
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 52, "suspicious": 0, "undetected": 14, "harmless": 0, "timeout": 0},
                    "popular_threat_classification": {"suggested_threat_label": "trojan.emotet/heodo", "popular_threat_category": [{"value": "trojan", "count": 30}]},
                    "type_description": "Win32 DLL",
                    "meaningful_name": "invoice.dll",
                    "size": 4096,
                    "names": ["invoice.dll"],
                    "tags": ["peexe", "dll"],
                    "sha256": "a" * 64,
                }
            }
        }
        status, findings, _, calls = run("virustotal", "sha256", "a" * 64, {"api/v3/files/": payload}, api_key="k" * 64)
        self.assertEqual(status, "ok")
        self.assertEqual(findings[0].value, "52/66 engines flag it")
        self.assertEqual(calls[0][1]["headers"]["x-apikey"], "k" * 64)
        self.assertEqual(next(item for item in findings if item.result_type == "threat-label").value, "trojan.emotet/heodo")
        _, _, _, calls = run("virustotal", "url", "https://example.com/", {"api/v3/urls/": {"data": {"attributes": {}}}}, api_key="k" * 64)
        self.assertTrue(calls[0][0].endswith("/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8"))
        _, findings, _, _ = run("virustotal", "domain", "never-seen.example", {}, api_key="k" * 64)
        self.assertEqual(findings[0].value, "not in VirusTotal")

    def test_abuse_sources(self):
        abuse = {"data": {"abuseConfidenceScore": 87, "totalReports": 312, "numDistinctUsers": 40, "isTor": False, "usageType": "Data Center/Web Hosting/Transit", "countryCode": "NL"}}
        _, findings, _, calls = run("abuseipdb", "ipv4", "192.0.2.10", {"api.abuseipdb.com": abuse}, api_key="b" * 80)
        self.assertEqual(findings[0].value, "87/100")
        self.assertEqual(calls[0][1]["headers"]["Key"], "b" * 80)
        host = {"query_status": "ok", "urls": [{"url": "http://192.0.2.10/bins/x.sh", "url_status": "online", "threat": "malware_download", "tags": ["mirai"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}]}
        _, findings, _, calls = run("urlhaus", "ipv4", "192.0.2.10", {"urlhaus-api.abuse.ch/v1/host/": host}, api_key="c" * 48)
        self.assertEqual((findings[0].value, findings[0].data["tags"]), ("http://192.0.2.10/bins/x.sh", ["mirai"]))
        self.assertEqual(calls[0][1]["method"], "POST")
        self.assertEqual(calls[0][1]["body"], b"host=192.0.2.10")
        fox = {"query_status": "ok", "data": [{"id": "9", "ioc": "192.0.2.10:443", "threat_type_desc": "Botnet C&C", "malware_printable": "Cobalt Strike", "confidence_level": 100}]}
        _, findings, _, calls = run("threatfox", "ipv4", "192.0.2.10", {"threatfox-api.abuse.ch": fox}, api_key="c" * 48)
        self.assertEqual(findings[0].data["malware"], "Cobalt Strike")
        self.assertEqual(json.loads(calls[0][1]["body"])["query"], "search_ioc")
        bazaar = {"query_status": "ok", "data": [{"sha256_hash": "d" * 64, "signature": "AgentTesla", "file_type": "exe", "tags": ["AgentTesla", "exe"], "reporter": "someone"}]}
        _, findings, _, _ = run("malwarebazaar", "sha256", "d" * 64, {"mb-api.abuse.ch": bazaar}, api_key="c" * 48)
        self.assertEqual(findings[0].value, "AgentTesla")
        self.assertNotIn("reporter", json.dumps([item.data for item in findings]))

    def test_rejected_key_is_reported_and_scrubbed(self):
        secret = "s3cr3t-key-value-123"

        def leaky(url, **options):
            raise intel.NetworkError(f"connection failed for {url}")

        with patch.object(shared, "FETCH", leaky):
            _, _, error, _ = _run_one(BY_ID["shodan"], ConnectorContext("", "ipv4", "1.1.1.1", None, secret))
        self.assertNotIn(secret, error)
        self.assertIn("***", error)
        status, _, error, _ = run("virustotal", "ipv4", "1.1.1.1", {"virustotal.com": (401, {})}, api_key="k" * 64)
        self.assertEqual(status, "error")
        self.assertIn("rejected the API key", error)


class KeyManagerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "keys.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        self.directory.cleanup()

    def test_keys_are_never_listed(self):
        saved = intel_keys.set_key(self.database, "virustotal", "  " + "f" * 60 + "abcd  ")
        self.assertEqual(saved["hint"], "…abcd")
        listing = json.dumps(intel_keys.list_keys(self.database))
        self.assertNotIn("f" * 60, listing)
        self.assertTrue(next(item for item in intel_keys.list_keys(self.database)["items"] if item["provider_id"] == "virustotal")["configured"])
        with self.assertRaises(ValidationError):
            intel_keys.set_key(self.database, "virustotal", "has spaces inside")
        with self.assertRaises(NotFoundError):
            intel_keys.set_key(self.database, "nope", "abcdefgh1234")
        self.assertTrue(intel_keys.delete_key(self.database, "virustotal")["deleted"])
        self.assertEqual(intel_keys.get_secret(self.database, "virustotal"), "")

    def test_runs_skip_keyed_sources_without_a_key(self):
        update_settings(self.database, {"intel.allow_network": "true"})
        listed = {item["connector_id"]: item for item in list_connectors(self.database)["items"]}
        self.assertEqual(listed["virustotal"]["availability"], "key-missing")
        self.assertEqual(listed["shodan"]["availability"], "ready")
        router = Router({"api/v3/ip_addresses/": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}})
        with patch.object(shared, "FETCH", router):
            first = run_query(self.database, value="198.51.100.7", connector_ids=["virustotal"])
            self.assertEqual(first["sources"][0]["status"], "key-missing")
            self.assertEqual(router.calls, [])
            intel_keys.set_key(self.database, "virustotal", "e" * 64)
            second = run_query(self.database, value="198.51.100.7", connector_ids=["virustotal"], use_cache=False)
        self.assertEqual(second["sources"][0]["status"], "ok")
        self.assertEqual(router.calls[0][1]["headers"]["x-apikey"], "e" * 64)
        self.assertNotIn("e" * 64, json.dumps(second))


if __name__ == "__main__":
    unittest.main()
