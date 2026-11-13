"""Phase 8: offline MITRE ATT&CK.

``attack-enterprise-20.1-subset.json.gz`` is a trimmed copy of the official
Enterprise ATT&CK 20.1 bundle (mitre-attack/attack-stix-data), recorded on
2026-11-13: the matrix, all tactics, ten techniques, one revoked technique,
two groups, two software entries, two mitigations and their relationships.
"""

import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.errors import ConflictError, NotFoundError, ValidationError
from garbage_intel.modules import attack
from garbage_intel.modules.file_intel import analyze_file
from garbage_intel.net import FetchResult
from garbage_intel.store import create_investigation, initialize

from tests.test_legacy_formats import word_document

BUNDLE = json.loads(gzip.decompress((Path(__file__).parent / "fixtures" / "attack-enterprise-20.1-subset.json.gz").read_bytes()))


def reply(url, payload):
    body = json.dumps(payload).encode()
    return FetchResult(url, url, 200, {}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])


class AttackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "attack.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def load(self):
        index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"version": "20.1", "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json"}]}]}

        def fake(url, **options):
            self.assertEqual(options["allowed_hosts"], attack.HOSTS)
            return reply(url, index if url.endswith("index.json") else BUNDLE)

        with patch.object(attack, "FETCH", fake):
            return attack.refresh(self.database)

    def test_parse_and_store(self):
        status = self.load()
        self.assertEqual(status["version"], "20.1")
        self.assertEqual(status["counts"]["tactics"], 15)
        self.assertEqual(status["counts"]["techniques"] + status["counts"]["subtechniques"], 10)
        matrix = attack.matrix(self.database)
        self.assertEqual([column["name"] for column in matrix["tactics"]][:4], ["Reconnaissance", "Resource Development", "Initial Access", "Execution"])
        execution = next(column for column in matrix["tactics"] if column["shortname"] == "execution")
        interpreter = next(cell for cell in execution["techniques"] if cell["id"] == "T1059")
        self.assertEqual([sub["id"] for sub in interpreter["subtechniques"]], ["T1059.001", "T1059.005"])
        detail = attack.technique(self.database, "T1059.001")
        self.assertEqual(detail["name"], "PowerShell")
        self.assertIn("execution", detail["tactics"])
        self.assertTrue(detail["groups"] or detail["software"])
        self.assertTrue(attack.search(self.database, "spearphishing")["items"])

    def test_rejects_foreign_bundle_location(self):
        index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"url": "https://raw.githubusercontent.com/someone/else/x.json"}]}]}
        with patch.object(attack, "FETCH", lambda url, **options: reply(url, index)):
            with self.assertRaises(attack.AttackError):
                attack.refresh(self.database)
        with self.assertRaises(attack.AttackError):
            attack.parse_bundle({"type": "bundle", "objects": []})

    def test_links_and_suggestions(self):
        case = create_investigation(self.database, "Campanha")
        with self.assertRaises(NotFoundError):
            attack.link(self.database, case["id"], "T1059")
        self.load()
        attack.link(self.database, case["id"], "T1566.001", note="anexo de phishing")
        with self.assertRaises(ConflictError):
            attack.link(self.database, case["id"], "T1566.001")
        with self.assertRaises(ValidationError):
            attack.link(self.database, case["id"], "1566")
        self.assertEqual([item["id"] for item in attack.case_techniques(self.database, case["id"])["items"]], ["T1566.001"])
        analyze_file(self.database, data=word_document(), filename="relatorio.doc", investigation_id=case["id"])
        suggested = {item["id"]: item for item in attack.suggestions(self.database, case["id"])["items"]}
        self.assertIn("T1059.005", suggested)
        self.assertIn("T1204.002", suggested)
        self.assertIn("T1059.001", suggested)
        self.assertTrue(all(item["reasons"] and item["origins"] == ["file-analysis"] for item in suggested.values()))
        matrix = attack.matrix(self.database, investigation_id=case["id"])
        self.assertEqual(matrix["linked_count"], 1)
        attack.unlink(self.database, case["id"], "T1566.001")
        self.assertEqual(attack.case_techniques(self.database, case["id"])["items"], [])


if __name__ == "__main__":
    unittest.main()
