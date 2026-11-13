"""Phase 11: workspace analytics aggregates."""

import tempfile
import unittest
from pathlib import Path

from garbage_intel.analytics import workspace_analytics
from garbage_intel.entities import create_entity, create_relationship, graph_payload, link_entity_to_investigation
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.modules.file_intel import analyze_file
from garbage_intel.store import create_investigation, initialize


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "analytics.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def test_counts_and_scoping(self):
        case = create_investigation(self.database, "Caso A")
        other = create_investigation(self.database, "Caso B")
        domain = create_entity(self.database, entity_type="domain", identifier="example.org")
        address = create_entity(self.database, entity_type="ipv4", identifier="192.0.2.10")
        loose = create_entity(self.database, entity_type="domain", identifier="example.net")
        link_entity_to_investigation(self.database, case["id"], domain["id"])
        link_entity_to_investigation(self.database, case["id"], address["id"])
        create_relationship(self.database, source_entity_id=domain["id"], target_entity_id=address["id"], relationship_type="hosted-on", investigation_id=case["id"])
        create_relationship(self.database, source_entity_id=loose["id"], target_entity_id=address["id"], relationship_type="hosted-on", investigation_id=other["id"], verification_status="verified")
        analyze_file(self.database, data=b"{\\rtf1{\\object{\\*\\objclass Equation.3}}}", filename="a.doc", investigation_id=case["id"])

        everything = workspace_analytics(self.database, days=7)
        self.assertEqual(everything["totals"]["entities"], 3)
        self.assertEqual(everything["totals"]["relationships"], 2)
        self.assertEqual({row["key"]: row["count"] for row in everything["relationship_verification"]}, {"not-verified": 1, "verified": 1})
        self.assertEqual(len(everything["activity"]["days"]), 7)
        create_count = next(item for item in everything["activity"]["series"] if item["key"] == "create")
        self.assertGreaterEqual(create_count["values"][-1], 3)
        self.assertEqual({row["key"] for row in everything["finding_codes"]}, {"rtf-objects", "rtf-equation-editor", "extension-mismatch"})
        self.assertEqual({row["key"]: row["count"] for row in everything["finding_levels"]}, {"note": 1, "warning": 2})

        scoped = workspace_analytics(self.database, investigation_id=case["id"], days=30)
        self.assertEqual(scoped["totals"]["entities"], 2)
        self.assertEqual(scoped["totals"]["relationships"], 1)
        self.assertEqual(scoped["totals"]["file_analyses"], 1)
        self.assertEqual(workspace_analytics(self.database, investigation_id=other["id"], days=30)["totals"]["file_analyses"], 0)

    def test_validation_and_graph_timestamps(self):
        with self.assertRaises(ValidationError):
            workspace_analytics(self.database, days=12)
        with self.assertRaises(NotFoundError):
            workspace_analytics(self.database, investigation_id="00000000-0000-0000-0000-000000000000")
        first = create_entity(self.database, entity_type="domain", identifier="example.org")
        second = create_entity(self.database, entity_type="domain", identifier="example.com")
        create_relationship(self.database, source_entity_id=first["id"], target_entity_id=second["id"], relationship_type="related-to")
        graph = graph_payload(self.database)
        self.assertTrue(all(node["created_at"] for node in graph["nodes"]))
        self.assertTrue(graph["edges"][0]["created_at"])


if __name__ == "__main__":
    unittest.main()
