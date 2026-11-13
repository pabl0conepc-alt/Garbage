"""Phase 8: STIX 2.1, MISP and CSV exports.

Deterministic SCO identifiers were checked against the OASIS stix2 library
(3.0.1); a full export of a sample case passed stix2-validator and loaded in
PyMISP when this was written.
"""

import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.cti_export import _sco_id, build_ioc_csv, build_misp, build_stix
from garbage_intel.entities import create_entity, create_relationship, link_entity_to_investigation
from garbage_intel.errors import ValidationError
from garbage_intel.modules import attack
from garbage_intel.modules.file_intel import analyze_file
from garbage_intel.store import add_observation, create_investigation, initialize

from tests.test_attack import BUNDLE, reply


class CtiExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "cti.sqlite3")
        initialize(self.database)
        self.case = create_investigation(self.database, "Campanha de phishing")["id"]
        ids = {}
        for kind, identifier, status in (
            ("domain", "Login-Secure.example", "verified"),
            ("ipv4", "192.0.2.10", "not-verified"),
            ("hash", "a" * 64, "not-verified"),
            ("organization", "Hosting Alpha", "not-verified"),
            ("person", "Fulano de Tal", "not-verified"),
        ):
            entity = create_entity(self.database, entity_type=kind, identifier=identifier, name=identifier, verification_status=status)
            link_entity_to_investigation(self.database, self.case, entity["id"])
            ids[kind] = entity["id"]
        create_relationship(self.database, source_entity_id=ids["domain"], target_entity_id=ids["ipv4"], relationship_type="hosted-on", investigation_id=self.case)
        create_relationship(self.database, source_entity_id=ids["ipv4"], target_entity_id=ids["organization"], relationship_type="belongs-to", investigation_id=self.case)
        create_relationship(self.database, source_entity_id=ids["person"], target_entity_id=ids["domain"], relationship_type="associated-with", investigation_id=self.case)
        add_observation(self.database, self.case, title="Página falsa", content="=cmd|' /C calc'!A0 apontou para login-secure.example", source_reference="note://test", collection_basis="user-provided")
        analyze_file(self.database, data=b"MZ" + bytes(2000) + b"https://login-secure.example/x", filename="dropper.bin", investigation_id=self.case)
        index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/x.json"}]}]}
        with patch.object(attack, "FETCH", lambda url, **options: reply(url, index if url.endswith("index.json") else BUNDLE)):
            attack.refresh(self.database)
        attack.link(self.database, self.case, "T1566.001")

    def tearDown(self):
        self.directory.cleanup()

    def test_sco_ids_follow_the_specification(self):
        self.assertEqual(_sco_id("domain-name", {"value": "example.org"}), "domain-name--3500c14b-9bde-5393-b4e5-b260aea7e058")
        self.assertEqual(_sco_id("ipv4-addr", {"value": "192.0.2.10"}), "ipv4-addr--a2fbe2c6-009e-52e0-b452-90b71e3109c2")

    def test_stix_bundle(self):
        result = build_stix(self.database, self.case, tlp="green")
        objects = result["bundle"]["objects"]
        by_type = {}
        for item in objects:
            by_type.setdefault(item["type"], []).append(item)
        self.assertEqual(result["skipped"], ["person"])
        self.assertEqual(by_type["domain-name"][0]["value"], "login-secure.example")
        self.assertEqual({item["indicator_types"][0] for item in by_type["indicator"]}, {"unknown"})
        self.assertIn("[ipv4-addr:value = '192.0.2.10']", {item["pattern"] for item in by_type["indicator"]})
        self.assertEqual(by_type["identity"][1]["identity_class"], "organization")
        types = {item["relationship_type"] for item in by_type["relationship"]}
        self.assertTrue({"based-on", "hosted-on", "belongs-to"} <= types)
        self.assertNotIn("associated-with", types)  # the person is not exported
        self.assertEqual(by_type["attack-pattern"][0]["external_references"][0]["external_id"], "T1566.001")
        file_object = next(item for item in by_type["file"] if item.get("name") == "dropper.bin")
        self.assertEqual(len(file_object["hashes"]["SHA-256"]), 64)
        report = by_type["report"][0]
        self.assertEqual(report["name"], "Campanha de phishing")
        self.assertIn(by_type["note"][0]["id"], report["object_refs"])
        self.assertTrue(all(item.get("object_marking_refs") == ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"] for item in objects if item["type"] not in ("marking-definition", "identity") or item.get("identity_class") == "organization"))
        again = build_stix(self.database, self.case, tlp="green")["bundle"]["objects"]
        self.assertEqual([item["id"] for item in again], [item["id"] for item in objects])
        with self.assertRaises(ValidationError):
            build_stix(self.database, self.case, tlp="purple")

    def test_misp_event(self):
        event = build_misp(self.database, self.case)["Event"]
        attributes = {(item["type"], item["value"]): item for item in event["Attribute"]}
        self.assertTrue(attributes[("domain", "login-secure.example")]["to_ids"])
        self.assertFalse(attributes[("ip-dst", "192.0.2.10")]["to_ids"])
        self.assertIn(("sha256", "a" * 64), attributes)
        self.assertTrue(any(kind == "filename|sha256" and value.startswith("dropper.bin|") for kind, value in attributes))
        self.assertNotIn("Fulano de Tal", str(event))
        self.assertEqual(event["Tag"][0], {"name": "tlp:amber"})
        self.assertIn('misp-galaxy:mitre-attack-pattern="Spearphishing Attachment - T1566.001"', [tag["name"] for tag in event["Tag"]])

    def test_ioc_csv_escapes_formulas(self):
        rows = list(csv.reader(io.StringIO(build_ioc_csv(self.database, self.case))))
        self.assertEqual(rows[0][:3], ["type", "value", "origin"])
        values = {row[1] for row in rows[1:]}
        self.assertIn("login-secure.example", values)
        self.assertNotIn("Fulano de Tal", values)
        self.assertTrue(all(not cell.startswith("=") for row in rows for cell in row))


if __name__ == "__main__":
    unittest.main()
