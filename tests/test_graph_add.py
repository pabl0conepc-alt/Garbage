"""The search screen's "+" button puts results on the graph."""

import tempfile
import unittest
from pathlib import Path

from garbage_intel import intel
from garbage_intel.db import initialize
from garbage_intel.entities import graph_payload, list_entities
from garbage_intel.errors import ValidationError
from garbage_intel.graph_add import add_to_graph
from garbage_intel.intel import Connector, Finding, register_connector, run_query, unregister_connector
from garbage_intel.store import create_investigation
from garbage_intel.workspace import update_settings


class GraphAddTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "graph.sqlite3")
        initialize(self.database)
        update_settings(self.database, {"intel.allow_network": False})
        intel.RATE_LIMITER.reset()
        register_connector(Connector("test-subs", "Subs", "test", ("domain",), lambda context: [Finding("subdomain", "mail.example.org")]))
        self.addCleanup(unregister_connector, "test-subs")
        self.case = create_investigation(self.database, "Caso")
        self.run = run_query(self.database, value="example.org", investigation_id=self.case["id"], wait=True)

    def test_root_and_typed_item_are_linked_once(self):
        added = add_to_graph(self.database, run_id=self.run["id"], item={"value": "mail.example.org", "pivot_value": "mail.example.org", "section": "Subdomínios", "sources": ["crt.sh"]})
        self.assertEqual(added["entity"]["entity_type"], "domain")
        self.assertEqual(added["investigation_id"], self.case["id"])
        again = add_to_graph(self.database, run_id=self.run["id"], item={"value": "mail.example.org", "section": "Subdomínios"})
        self.assertEqual(again["entity_id"], added["entity_id"])
        self.assertFalse(again["created"])
        graph = graph_payload(self.database, investigation_id=self.case["id"])
        self.assertEqual(sorted(node["name"] for node in graph["nodes"]), ["example.org", "mail.example.org"])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["description"], "Subdomínios")

    def test_plain_facts_become_other_entities_with_their_details(self):
        added = add_to_graph(self.database, run_id=self.run["id"], item={"label": "Criado em", "value": "01/12/2025", "hint": "há 11 meses", "sources": ["RDAP"], "section": "Registro"})
        entity = added["entity"]
        self.assertEqual((entity["entity_type"], entity["name"]), ("other", "01/12/2025"))
        self.assertTrue(entity["description"].startswith("Criado em\nhá 11 meses\nFontes: RDAP"))
        self.assertEqual(list_entities(self.database)["total"], 2)

    def test_root_only_and_validation(self):
        root = add_to_graph(self.database, run_id=self.run["id"])
        self.assertEqual(root["entity_id"], root["root_id"])
        with self.assertRaises(ValidationError):
            add_to_graph(self.database, run_id=self.run["id"], item={"value": ""})
        with self.assertRaises(ValidationError):
            add_to_graph(self.database, run_id="")


if __name__ == "__main__":
    unittest.main()
