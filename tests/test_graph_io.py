"""Graph import: GraphML and JSON, preview first, commit on request."""

import json
import tempfile
import unittest
from pathlib import Path

from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, get_entity, graph_payload, list_relationships
from garbage_intel.errors import ValidationError
from garbage_intel.graph_io import entity_type_for, import_graph, parse_graphml, relationship_type_for
from garbage_intel.store import create_investigation

GRAPHML = """<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="d0" for="node" attr.name="label" attr.type="string"/>
  <key id="d1" for="node" attr.name="type" attr.type="string"/>
  <key id="d2" for="edge" attr.name="label" attr.type="string"/>
  <graph id="G" edgedefault="directed">
    <node id="n0"><data key="d0">Login-Secure.example</data><data key="d1">maltego.Domain</data></node>
    <node id="n1"><data key="d0">192.0.2.10</data><data key="d1">maltego.IPv4Address</data></node>
    <node id="n2"><data key="d0">Hosting Alpha</data><data key="d1">maltego.Company</data></node>
    <node id="n3"><data key="d0">not a domain!</data><data key="d1">domain</data></node>
    <node id="n4"><data key="d0">198.51.100.4</data></node>
    <edge source="n0" target="n1"><data key="d2">resolves to</data></edge>
    <edge source="n1" target="n2"><data key="d2">belongs-to</data></edge>
    <edge source="n0" target="n3"/>
    <edge source="n0" target="n1"><data key="d2">resolves to</data></edge>
    <edge source="n4" target="n4"/>
  </graph>
</graphml>"""


class GraphImportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "import.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def test_type_mapping(self):
        self.assertEqual(entity_type_for("maltego.IPv4Address", "192.0.2.1"), "ipv4")
        self.assertEqual(entity_type_for("IP", "2001:db8::1"), "ipv6")
        self.assertEqual(entity_type_for("maltego.DNSName", "a.example"), "domain")
        self.assertEqual(entity_type_for("", "https://a.example/x"), "url")
        self.assertEqual(entity_type_for("", "Something"), "other")
        self.assertEqual(entity_type_for("Organization", "x"), "organization")
        self.assertEqual(relationship_type_for("Resolves To"), "hosted-on")
        self.assertEqual(relationship_type_for("owns"), "owns")
        self.assertEqual(relationship_type_for("weird link"), "related-to")

    def test_graphml_preview_then_commit(self):
        case = create_investigation(self.database, "Importado")["id"]
        existing = create_entity(self.database, entity_type="ipv4", identifier="192.0.2.10", name="192.0.2.10")
        preview = import_graph(self.database, content=GRAPHML, file_format="graphml", file_name="maltego.graphml", investigation_id=case)
        self.assertFalse(preview["committed"])
        self.assertEqual(
            preview["counts"],
            {"new_entities": 3, "existing_entities": 1, "invalid_nodes": 1, "new_relationships": 2, "existing_relationships": 0, "skipped_edges": 3},
        )
        self.assertEqual(preview["new_by_type"], {"domain": 1, "organization": 1, "ipv4": 1})
        self.assertEqual(graph_payload(self.database)["nodes"].__len__(), 1)  # nothing written

        result = import_graph(self.database, content=GRAPHML, file_format="graphml", file_name="maltego.graphml", investigation_id=case, commit=True)
        self.assertTrue(result["committed"])
        graph = graph_payload(self.database, investigation_id=case)
        names = sorted(node["name"] for node in graph["nodes"])
        self.assertEqual(names, ["192.0.2.10", "198.51.100.4", "Hosting Alpha", "Login-Secure.example"])
        relationships = list_relationships(self.database)["items"] if isinstance(list_relationships(self.database), dict) else list_relationships(self.database)
        kinds = sorted(item["relationship_type"] for item in relationships)
        self.assertEqual(kinds, ["belongs-to", "hosted-on"])
        hosted = next(item for item in relationships if item["relationship_type"] == "hosted-on")
        self.assertEqual(hosted["target_entity_id"], existing["id"])
        self.assertTrue(hosted["description"].startswith("Imported relationship: resolves to."))
        self.assertEqual(hosted["verification_status"], "not-verified")
        self.assertTrue(hosted["source_reference"].startswith("note://garbage/graph-import/"))
        domain = next(node for node in graph["nodes"] if node["entity_type"] == "domain")
        self.assertEqual(get_entity(self.database, domain["id"])["identifier"], "login-secure.example")

        again = import_graph(self.database, content=GRAPHML, file_format="graphml", investigation_id=case)
        self.assertEqual(again["counts"]["new_entities"], 0)
        self.assertEqual(again["counts"]["existing_relationships"], 2)

    def test_json_formats(self):
        cytoscape = {"elements": {"nodes": [{"data": {"id": "a", "label": "a.example"}}, {"data": {"id": "b", "label": "203.0.113.5"}}],
                                  "edges": [{"data": {"source": "a", "target": "b", "label": "hosted-on"}}]}}
        result = import_graph(self.database, content=json.dumps(cytoscape), file_format="json")
        self.assertEqual(result["new_by_type"], {"domain": 1, "ipv4": 1})
        self.assertEqual(result["counts"]["new_relationships"], 1)
        d3 = {"nodes": [{"id": 1, "name": "x.example"}, {"id": 2, "name": "y.example"}], "links": [{"source": {"id": 1}, "target": 2}]}
        self.assertEqual(import_graph(self.database, content=json.dumps(d3), file_format="json")["counts"]["new_relationships"], 1)
        own = {"format": "garbage-graph", "nodes": [{"id": "p", "entity_type": "organization", "name": "Org"}, {"id": "q", "entity_type": "email", "name": "abuse@q.example", "identifier": "abuse@q.example"}],
               "edges": [{"source": "q", "target": "p", "relationship_type": "belongs-to"}]}
        committed = import_graph(self.database, content=json.dumps(own), file_format="json", commit=True)
        self.assertEqual(committed["counts"]["new_entities"], 2)
        # A name-only entity is reused on the next import instead of duplicated.
        self.assertEqual(import_graph(self.database, content=json.dumps(own), file_format="json")["counts"]["existing_entities"], 2)

    def test_rejections(self):
        with self.assertRaises(ValidationError):
            parse_graphml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph/></graphml>')
        with self.assertRaises(ValidationError):
            import_graph(self.database, content="<graphml", file_format="graphml")
        with self.assertRaises(ValidationError):
            import_graph(self.database, content='{"nodes": []}', file_format="json")
        with self.assertRaises(ValidationError):
            import_graph(self.database, content="{}", file_format="csv")
        big = {"nodes": [{"id": str(index), "name": f"n{index}"} for index in range(2001)], "edges": []}
        with self.assertRaises(ValidationError):
            import_graph(self.database, content=json.dumps(big), file_format="json")


if __name__ == "__main__":
    unittest.main()
