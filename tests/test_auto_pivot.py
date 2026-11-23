"""Automatic infrastructure pivot from a graph node."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import auto_pivot
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, graph_payload
from garbage_intel.errors import ValidationError
from garbage_intel.store import create_investigation


def result(kind, value, **data):
    return {"result_type": kind, "value": value, "data": data, "status": "ok"}


ANSWERS = {
    "example.org": [result("dns-a", "192.0.2.10"), result("dns-mx", "10 mail.example.org."), result("dns-ns", "ns1.provider.net."), result("dns-txt", "v=spf1 -all")],
    "192.0.2.10": [result("asn", "AS64500", prefix="192.0.2.0/24"), result("hostname", "web1.example.org"),
                   result("pdns-name", "old.example.org", last_seen="2019-01-01"), result("pdns-name", "shop.example.org", last_seen="2099-01-01")],
}


def fake_run(database, *, value, connector_ids, investigation_id, wait):
    return {"results": ANSWERS.get(value, [])}


class AutoPivotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "pivot.sqlite3")
        initialize(self.database)
        self.case = create_investigation(self.database, "Caso")
        self.domain = create_entity(self.database, entity_type="domain", name="example.org", identifier="example.org")

    def test_one_level_links_dns_answers(self):
        with patch.object(auto_pivot, "run_query", fake_run):
            outcome = auto_pivot.expand(self.database, entity_id=self.domain["id"], investigation_id=self.case["id"])
        self.assertEqual((outcome["created"], outcome["relationships"]), (3, 3))
        graph = graph_payload(self.database, investigation_id=self.case["id"])
        names = {node["name"]: node["entity_type"] for node in graph["nodes"]}
        self.assertEqual(names, {"example.org": "domain", "192.0.2.10": "ipv4", "mail.example.org": "domain", "ns1.provider.net": "domain"})
        kinds = sorted(edge["relationship_type"] for edge in graph["edges"])
        self.assertEqual(kinds, ["hosted-on", "uses", "uses"])

    def test_two_levels_reach_the_as_and_only_recent_passive_dns(self):
        with patch.object(auto_pivot, "run_query", fake_run):
            auto_pivot.expand(self.database, entity_id=self.domain["id"], depth=2)
            again = auto_pivot.expand(self.database, entity_id=self.domain["id"], depth=2)
        names = {node["name"] for node in graph_payload(self.database)["nodes"]}
        self.assertTrue({"AS64500", "web1.example.org", "shop.example.org"} <= names)
        self.assertNotIn("old.example.org", names)
        self.assertEqual((again["created"], again["relationships"]), (0, 0))

    def test_limits_and_inputs(self):
        many = {"example.org": [result("dns-a", f"198.51.100.{index}") for index in range(1, 30)]}
        with patch.object(auto_pivot, "run_query", lambda database, value, **options: {"results": many.get(value, [])}):
            outcome = auto_pivot.expand(self.database, entity_id=self.domain["id"])
        self.assertEqual(outcome["created"], auto_pivot.MAX_FANOUT)
        person = create_entity(self.database, entity_type="organization", name="ACME")
        with self.assertRaises(ValidationError):
            auto_pivot.expand(self.database, entity_id=person["id"])
        with self.assertRaises(ValidationError):
            auto_pivot.expand(self.database, entity_id=self.domain["id"], depth=3)


if __name__ == "__main__":
    unittest.main()
