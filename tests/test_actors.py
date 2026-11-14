"""Threat-actor profiles and case overlap, on the recorded ATT&CK subset.

The subset has APT28 (G0007: T1059.001, T1204.002, T1221, T1566.001) and
APT29 (G0016: T1059.001, T1204.002, T1566.001). It carries no group-to-software
relationship, so one is added here (APT29 uses TrickBot) to cover the parser.
"""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.modules import actors, attack
from garbage_intel.store import create_investigation, initialize

from tests.test_attack import BUNDLE, reply


def bundle_with_software():
    bundle = copy.deepcopy(BUNDLE)
    stix = {}
    for item in bundle["objects"]:
        for reference in item.get("external_references") or []:
            if reference.get("source_name") == "mitre-attack":
                stix[reference.get("external_id")] = item["id"]
    bundle["objects"].append(
        {
            "type": "relationship",
            "id": "relationship--00000000-0000-4000-8000-00000000a29b",
            "relationship_type": "uses",
            "source_ref": stix["G0016"],
            "target_ref": stix["S0266"],
        }
    )
    return bundle


class ActorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "actors.sqlite3")
        initialize(self.database)
        index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"version": "20.1", "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json"}]}]}
        bundle = bundle_with_software()
        with patch.object(attack, "FETCH", lambda url, **options: reply(url, index if url.endswith("index.json") else bundle)):
            attack.refresh(self.database)

    def case(self, *techniques):
        case = create_investigation(self.database, "Caso ATT&CK")
        for technique in techniques:
            attack.link(self.database, case["id"], technique)
        return case["id"]

    def test_group_list_and_search(self):
        listing = actors.groups(self.database)
        self.assertEqual(listing["total"], 2)
        self.assertEqual([(item["id"], item["technique_count"]) for item in listing["items"]], [("G0007", 4), ("G0016", 3)])
        self.assertEqual(listing["items"][1]["software_count"], 1)
        alias = next(item for item in actors.groups(self.database)["items"] if item["id"] == "G0016")["aliases"][0]
        self.assertEqual([item["id"] for item in actors.groups(self.database, query=alias)["items"]], ["G0016"])
        self.assertEqual(actors.groups(self.database, query="nothing-like-this")["items"], [])

    def test_profile(self):
        case_id = self.case("T1566.001")
        profile = actors.group(self.database, "G0016")
        self.assertEqual((profile["name"], profile["technique_count"]), ("APT29", 3))
        tactics = [item["shortname"] for item in profile["tactics"]]
        self.assertEqual(tactics, sorted(tactics, key=["initial-access", "execution"].index))
        self.assertEqual([item["id"] for item in profile["software"]], ["S0266"])
        self.assertTrue(profile["software_known"])
        # M1021 maps to T1566.001 and to the parents T1059 and T1204.
        restrict = next(item for item in profile["mitigations"] if item["id"] == "M1021")
        self.assertEqual(restrict["techniques"], ["T1059.001", "T1204.002", "T1566.001"])
        self.assertEqual(profile["mitigations"][0]["id"], "M1021")
        self.assertEqual(profile["detection"], {"techniques_with_rules": 0, "techniques": 3})
        self.assertEqual([(item["investigation_id"], item["shared"]) for item in profile["cases"]], [(case_id, 1)])
        with self.assertRaises(ValidationError):
            actors.group(self.database, "APT29")
        with self.assertRaises(NotFoundError):
            actors.group(self.database, "G9999")

    def test_case_overlap_ranks_by_rare_shared_techniques(self):
        # T1221 is used only by APT28, so APT28 leads; both share PowerShell.
        overlap = actors.case_overlap(self.database, self.case("T1221", "T1059.001"))
        self.assertEqual([item["id"] for item in overlap["items"]], ["G0007", "G0016"])
        self.assertEqual(overlap["items"][0]["score"], 1.0)
        self.assertLess(overlap["items"][1]["score"], 0.5)
        self.assertTrue(overlap["weak"])
        self.assertIn("not attribution", overlap["caveat"])
        # A parent technique in the case is covered by a group's sub-technique.
        parent = actors.case_overlap(self.database, self.case("T1566"))
        self.assertEqual({item["id"] for item in parent["items"]}, {"G0007", "G0016"})
        self.assertEqual(parent["items"][0]["shared"], [{"id": "T1566", "name": "Phishing", "exact": False}])
        # Equal coverage: the group with the smaller repertoire comes first.
        self.assertEqual(parent["items"][0]["id"], "G0016")
        empty = actors.case_overlap(self.database, self.case())
        self.assertEqual((empty["items"], empty["weak"]), ([], True))
        with self.assertRaises(NotFoundError):
            actors.case_overlap(self.database, "00000000-0000-4000-8000-000000000000")


if __name__ == "__main__":
    unittest.main()
