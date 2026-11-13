"""Step 4b: TAXII 2.1 client and Sigma rules.

``mitre-attack-taxii.json`` holds responses recorded from MITRE's public
TAXII 2.1 server (attack-taxii.mitre.org) on 2026-11-13, trimmed: discovery,
the default root's collections and two pages of the ICS collection. The
Sigma reader was checked against PyYAML on all 1377 rules of SigmaHQ release
r2026-07-01 (14803 fields, one difference in an unused nested block); the
rules below are written for these tests.
"""

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from garbage_intel.db import initialize
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.modules import sigma, taxii
from garbage_intel.net import FetchResult, NetworkError
from garbage_intel.store import create_investigation

RECORDED = json.loads((Path(__file__).parent / "fixtures" / "taxii" / "mitre-attack-taxii.json").read_text())
DISCOVERY = "https://attack-taxii.mitre.org/taxii2/"
ROOT = "https://attack-taxii.mitre.org/api/v21/"
ICS = "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09"


def reply(url, payload, status=200, redirects=None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return FetchResult(url, url, status, {"content-type": "application/taxii+json;version=2.1"}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, redirects or [])


def mitre(url, **options):
    assert options["allowed_hosts"] == ("attack-taxii.mitre.org",), options["allowed_hosts"]
    assert options["headers"]["Accept"] == taxii.ACCEPT
    parts = urlsplit(url)
    if url == DISCOVERY:
        return reply(url, RECORDED["discovery"])
    if url == ROOT + "collections/":
        return reply(url, RECORDED["collections"])
    if parts.path == f"/api/v21/collections/{ICS}/objects/":
        query = parse_qs(parts.query)
        return reply(url, RECORDED["page2"] if query.get("next") == ["1"] else RECORDED["page1"])
    return reply(url, {}, 404)


class TaxiiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "feeds.sqlite3")
        initialize(self.database)
        self.server = taxii.add_server(self.database, name="MITRE ATT&CK", discovery_url=DISCOVERY)

    def tearDown(self):
        self.directory.cleanup()

    def test_server_validation(self):
        for bad in ("http://insecure.example/taxii2/", "ftp://x/", ""):
            with self.assertRaises(ValidationError):
                taxii.add_server(self.database, name="x", discovery_url=bad)
        with self.assertRaises(ValidationError):
            taxii.add_server(self.database, name="x", discovery_url="https://feed.example/taxii2/", username="only-user")
        secured = taxii.add_server(self.database, name="Privado", discovery_url="https://feed.example/taxii2/", username="u", password="segredo")
        self.assertTrue(secured["has_credentials"])
        self.assertNotIn("segredo", json.dumps(taxii.list_servers(self.database)))

    def test_discovery_collections_and_paged_pull(self):
        with patch.object(taxii, "FETCH", mitre):
            discovery = taxii.discover(self.database, self.server["id"])
            self.assertEqual(discovery["default"], ROOT)
            self.assertEqual(discovery["api_roots"][0], ROOT)
            listing = taxii.collections(self.database, self.server["id"], ROOT)
            self.assertEqual([item["title"] for item in listing["items"]], ["ICS ATT&CK", "Enterprise ATT&CK"])
            with self.assertRaises(ValidationError):
                taxii.collections(self.database, self.server["id"], "https://elsewhere.example/api/")
            pulled = taxii.pull(self.database, self.server["id"], api_root=ROOT, collection_id=ICS, object_types=["attack-pattern"], max_objects=3)
        self.assertEqual(pulled["object_count"], 3)  # stops at the cap mid-page
        self.assertEqual(pulled["page_count"], 2)
        self.assertEqual(pulled["by_type"], {"attack-pattern": 3})
        stored = taxii.list_objects(self.database, server_id=self.server["id"], collection_id=ICS)
        self.assertEqual(stored["total"], 3)
        first = RECORDED["page1"]["objects"][0]
        self.assertEqual(taxii.get_object(self.database, self.server["id"], ICS, first["id"])["name"], first["name"])
        with self.assertRaises(ValidationError):
            taxii.pull(self.database, self.server["id"], api_root=ROOT, collection_id="../x", max_objects=10)

    def test_transient_gateway_errors_are_retried(self):
        answers = iter([502, 503, 200])
        with patch.object(taxii, "SLEEP", lambda seconds: None), patch.object(
            taxii, "FETCH", lambda url, **options: reply(url, RECORDED["discovery"], next(answers))
        ):
            self.assertEqual(taxii.discover(self.database, self.server["id"])["default"], ROOT)

    def test_refused_credentials(self):
        with patch.object(taxii, "FETCH", lambda url, **options: reply(url, {}, 401)):
            with self.assertRaises(NetworkError):
                taxii.discover(self.database, self.server["id"])

    def test_pattern_values_and_case_observation(self):
        self.assertEqual(
            taxii.pattern_values("[domain-name:value = 'bad.example'] OR [ipv4-addr:value = '192.0.2.5'] AND [file:hashes.'SHA-256' = '" + "a" * 64 + "']"),
            [("domain-name:value", "bad.example"), ("ipv4-addr:value", "192.0.2.5"), ("file:hashes.'SHA-256'", "a" * 64)],
        )
        self.assertEqual(taxii.pattern_values("[process:name = 'x.exe']"), [])
        envelope = {"objects": [
            {"type": "indicator", "id": "indicator--1", "name": "C2 domain", "pattern": "[domain-name:value = 'c2.example']", "pattern_type": "stix", "modified": "2026-01-01T00:00:00Z"},
            {"type": "indicator", "id": "indicator--2", "name": "Sigma-like", "pattern": "title: x", "pattern_type": "sigma"},
            {"type": "malware", "id": "malware--1", "name": "Family"},
        ], "more": False}
        with patch.object(taxii, "FETCH", lambda url, **options: reply(url, envelope)):
            taxii.pull(self.database, self.server["id"], api_root=ROOT, collection_id="feed-1", max_objects=100)
        case = create_investigation(self.database, "Campanha")["id"]
        result = taxii.indicators_to_case(self.database, investigation_id=case, server_id=self.server["id"], collection_id="feed-1", object_ids=["indicator--1", "indicator--2", "malware--1"])
        self.assertEqual((result["indicator_count"], result["observable_count"]), (2, 1))
        observation = result["observation"]
        self.assertIn("domain-name:value = c2.example", observation["content"])
        self.assertNotIn("attack-taxii.mitre.org", observation["content"])
        with self.assertRaises(ValidationError):
            taxii.indicators_to_case(self.database, investigation_id=case, server_id=self.server["id"], collection_id="feed-1", object_ids=["malware--1"])

    def test_delete(self):
        taxii.delete_server(self.database, self.server["id"])
        with self.assertRaises(NotFoundError):
            taxii.discover(self.database, self.server["id"])


RULE_A = """title: Encoded PowerShell Command Line
id: 11111111-2222-4333-8444-555555555555
status: test
description: |
    Detects a PowerShell process started with an encoded command.
    Written for the GARBAGE tests.
references:
    - https://example.org/encoded-commands
author: GARBAGE tests
date: 2026-01-02
modified: 2026-02-03
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' -enc '
    condition: selection
falsepositives:
    - 'Administrative scripts'
level: high
"""
RULE_B = """title: "Suspicious DNS Query: Long Label"
id: 66666666-7777-4888-9999-000000000000
status: experimental
description: Long DNS labels can carry tunnelled data.
tags:
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|re: '[a-z0-9]{60,}'
    condition: selection
level: medium
"""


def package(*rules):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index, text in enumerate(rules):
            archive.writestr(f"rules/test/rule_{index}.yml", text)
        archive.writestr("README.md", "not a rule")
    return buffer.getvalue()


class SigmaTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "sigma.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def test_parse_rule(self):
        fields = sigma.parse_rule(RULE_A)
        self.assertEqual(fields["title"], "Encoded PowerShell Command Line")
        self.assertEqual(fields["description"], "Detects a PowerShell process started with an encoded command.\nWritten for the GARBAGE tests.")
        self.assertEqual(fields["tags"][1], "attack.t1059.001")
        self.assertEqual(fields["logsource"], {"category": "process_creation", "product": "windows"})
        self.assertEqual(fields["falsepositives"], ["Administrative scripts"])
        self.assertEqual(sigma.parse_rule(RULE_B)["title"], "Suspicious DNS Query: Long Label")
        self.assertEqual(sigma.techniques(fields["tags"]), ["T1027", "T1059.001"])

    def test_refresh_search_and_detail(self):
        data = package(RULE_A, RULE_B, "title: no id\n")
        redirects = ["https://github.com/SigmaHQ/sigma/releases/download/r2026-07-01/sigma_core.zip"]

        def fake(url, **options):
            self.assertEqual(options["allowed_hosts"], sigma.HOSTS)
            return FetchResult(url, "https://release-assets.githubusercontent.com/x", 200, {}, data, "", "192.0.2.1", 1, redirects)

        with patch.object(sigma, "FETCH", fake):
            status = sigma.refresh(self.database)
        self.assertEqual((status["version"], status["rule_count"], status["with_techniques"]), ("r2026-07-01", 2, 2))
        self.assertEqual([item["id"] for item in sigma.search(self.database, technique="T1059")["items"]], ["11111111-2222-4333-8444-555555555555"])
        self.assertEqual(sigma.search(self.database, technique="T1071.004")["total"], 1)
        self.assertEqual(sigma.search(self.database, level="medium")["items"][0]["product"], "")
        self.assertEqual(sigma.search(self.database, query="tunnelled")["total"], 1)
        rule = sigma.get_rule(self.database, "11111111-2222-4333-8444-555555555555")
        self.assertIn("CommandLine|contains", rule["raw"])
        self.assertIn("Detection Rule License", rule["license"])
        self.assertEqual(sigma.counts_for(self.database, ["T1027", "T1059.001", "T1003"]), {"T1027": 1, "T1059.001": 1})
        with self.assertRaises(sigma.SigmaError):
            sigma.load_package(self.database, b"not a zip", version="x", source_url="x")
        with self.assertRaises(sigma.SigmaError):
            sigma.load_package(self.database, package("nothing: here\n"), version="x", source_url="x")


if __name__ == "__main__":
    unittest.main()
