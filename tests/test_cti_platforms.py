"""Sending cases to MISP and OpenCTI, and looking values up in them."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import cti_platforms, net
from garbage_intel.db import initialize
from garbage_intel.dossier import build
from garbage_intel.entities import create_entity, link_entity_to_investigation
from garbage_intel.errors import ValidationError
from garbage_intel.intel import ConnectorContext
from garbage_intel.net import NetworkError, NetworkPolicyError
from garbage_intel.store import create_investigation

from tests.test_intel_connectors import result

MISP_KEY = "A" * 40
OPENCTI_KEY = "1b2c3d4e-0000-4000-8000-000000000000"


class Recorder:
    """Answers each request from a list of (matcher, status, payload)."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, url, **options):
        body = json.loads(options["body"]) if options.get("body") else None
        self.calls.append({**options, "url": url, "body": body})
        for matcher, status, payload in self.answers:
            if matcher(url, body):
                return result(url, payload, status=status)
        return result(url, {}, status=404)


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "cti.sqlite3")
        initialize(self.database)
        self.case = create_investigation(self.database, "Phishing banco", objective="Mapear a infraestrutura")
        for kind, value in (("domain", "bb-login.example"), ("ipv4", "203.0.113.7"), ("hash", "d41d8cd98f00b204e9800998ecf8427e")):
            entity = create_entity(self.database, entity_type=kind, name=value, identifier=value)
            link_entity_to_investigation(self.database, self.case["id"], entity["id"])

    def configure(self):
        cti_platforms.configure(self.database, "misp", url="https://misp.example.org", key=MISP_KEY)
        cti_platforms.configure(self.database, "opencti", url="http://10.0.0.5:8080", private=True, key=OPENCTI_KEY)

    def test_configuration_rules_and_no_key_back(self):
        with self.assertRaises(ValidationError):
            cti_platforms.configure(self.database, "misp", url="http://misp.example.org", key=MISP_KEY)
        with self.assertRaises(ValidationError):
            cti_platforms.configure(self.database, "misp", url="https://10.0.0.5", key=MISP_KEY)
        with self.assertRaises(ValidationError):
            cti_platforms.configure(self.database, "misp", url="http://169.254.169.254", private=True, key=MISP_KEY)
        self.configure()
        status = cti_platforms.status(self.database)["items"]
        self.assertTrue(status["misp"]["configured"] and status["opencti"]["private"])
        self.assertNotIn(MISP_KEY, json.dumps(status))
        self.assertNotIn(OPENCTI_KEY, json.dumps(status))

    def test_private_addresses_need_an_allowlist(self):
        with self.assertRaises(NetworkPolicyError):
            net.validate_url("http://10.0.0.5:8080/", allow_private=True, allow_http=True)
        self.assertEqual(net.validate_url("http://10.0.0.5:8080/x", allowed_hosts=["10.0.0.5"], allow_http=True, allow_private=True)[2], 8080)
        with self.assertRaises(NetworkPolicyError):
            net.validate_url("http://10.0.0.5/", allowed_hosts=["10.0.0.5"], allow_http=True)

    def test_send_to_misp_creates_then_updates(self):
        self.configure()
        web = Recorder([
            (lambda url, body: url.endswith("/events/add"), 201, {"Event": {"id": "42"}}),
        ])
        with patch.object(cti_platforms, "FETCH", web):
            sent = cti_platforms.push_case(self.database, "misp", self.case["id"])
        self.assertEqual((sent["remote_id"], sent["objects"]), ("42", 3))
        self.assertEqual(sent["link"], "https://misp.example.org/events/view/42")
        self.assertEqual(web.calls[0]["headers"]["Authorization"], MISP_KEY)
        self.assertEqual({item["type"] for item in web.calls[0]["body"]["Event"]["Attribute"]}, {"domain", "ip-dst", "md5"})
        again = Recorder([
            (lambda url, body: url.endswith("/events/add"), 403, {"message": "Event already exists"}),
            (lambda url, body: "/events/edit/" in url, 200, {"Event": {"id": "42"}}),
        ])
        with patch.object(cti_platforms, "FETCH", again):
            cti_platforms.push_case(self.database, "misp", self.case["id"])
        self.assertIn("/events/edit/", again.calls[1]["url"])
        self.assertEqual(cti_platforms.pushes(self.database, self.case["id"])["items"][0]["remote_id"], "42")

    def test_send_to_opencti_observables_then_one_report(self):
        self.configure()
        web = Recorder([
            (lambda url, body: "stixCyberObservableAdd" in body["query"], 200, {"data": {"stixCyberObservableAdd": {"id": "obs"}}}),
            (lambda url, body: "reportAdd" in body["query"], 200, {"data": {"reportAdd": {"id": "rep-1"}}}),
        ])
        with patch.object(cti_platforms, "FETCH", web):
            sent = cti_platforms.push_case(self.database, "opencti", self.case["id"])
        added = [call["body"]["variables"] for call in web.calls if "stixCyberObservableAdd" in call["body"]["query"]]
        self.assertEqual(sorted(item["type"] for item in added), ["Domain-Name", "IPv4-Addr", "StixFile"])
        hashed = next(item for item in added if item["type"] == "StixFile")
        self.assertEqual(hashed["StixFile"]["hashes"][0]["algorithm"], "MD5")
        report = web.calls[-1]["body"]["variables"]["input"]
        self.assertEqual((report["name"], report["objects"]), ("Phishing banco", ["obs", "obs", "obs"]))
        self.assertTrue(report["stix_id"].startswith("report--"))
        self.assertEqual(web.calls[0]["headers"]["Authorization"], f"Bearer {OPENCTI_KEY}")
        self.assertTrue(web.calls[0]["allow_private"])
        self.assertEqual(sent["link"], "http://10.0.0.5:8080/dashboard/analyses/reports/rep-1")

    def test_lookups_and_dossier(self):
        self.configure()
        misp = Recorder([(lambda url, body: "restSearch" in url, 200, {"response": {"Attribute": [
            {"event_id": "7", "type": "domain", "to_ids": True, "Event": {"id": "7", "info": "Campanha X", "date": "2026-10-01", "Tag": [{"name": "tlp:amber"}]}},
        ]}})])
        with patch.object(cti_platforms, "FETCH", misp):
            events = cti_platforms._misp_lookup(ConnectorContext(self.database, "domain", "bb-login.example", None))
        self.assertEqual((events[0].value, events[0].data["tags"]), ("Campanha X", ["tlp:amber"]))
        opencti = Recorder([(lambda url, body: True, 200, {"data": {"stixCyberObservables": {"edges": [{"node": {
            "id": "o1", "entity_type": "Domain-Name", "observable_value": "bb-login.example", "x_opencti_score": 80,
            "objectLabel": [{"value": "phishing"}], "indicators": {"edges": []},
            "reports": {"edges": [{"node": {"id": "r1", "name": "Relatório Y", "published": "2026-10-02T00:00:00Z"}}]},
        }}]}}})])
        with patch.object(cti_platforms, "FETCH", opencti):
            found = cti_platforms._opencti_lookup(ConnectorContext(self.database, "domain", "bb-login.example", None))
        self.assertEqual([item.result_type for item in found], ["opencti-observable", "opencti-report"])
        dossier = build({"query_type": "domain", "query_value": "bb-login.example", "sources": [], "results": [
            {"connector_id": "misp", "result_type": "misp-event", "value": "Campanha X", "data": events[0].data, "status": "ok"},
            *({"connector_id": "opencti", "result_type": item.result_type, "value": item.value, "data": item.data, "status": "ok"} for item in found),
        ]})
        self.assertEqual(dossier["sections"][0]["id"], "own-intel")
        self.assertIn("1 evento(s) do seu MISP", dossier["flags"][0]["text"])

    def test_refused_key_message_has_no_key(self):
        self.configure()
        with patch.object(cti_platforms, "FETCH", Recorder([(lambda url, body: True, 401, {"message": "Authentication failed"})])):
            with self.assertRaises(NetworkError) as raised:
                cti_platforms.check(self.database, "misp")
        self.assertIn("refused the API key", str(raised.exception))
        self.assertNotIn(MISP_KEY, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
