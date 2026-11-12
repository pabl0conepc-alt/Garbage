import tempfile
import unittest
from pathlib import Path

from garbage_intel.db import initialize
from garbage_intel.entities import (
    create_entity,
    create_relationship,
    delete_entity,
    get_entity,
    graph_payload,
    link_entity_to_investigation,
    list_entities,
    list_relationships,
    unlink_entity_from_investigation,
    update_entity,
)
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.sources import (
    create_source,
    get_source,
    link_source_to_entity,
    link_source_to_investigation,
    unlink_source_from_entity,
)
from garbage_intel.store import create_investigation


class EntityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normalizes_and_deduplicates_identifiers(self):
        entity = create_entity(
            self.database,
            entity_type="domain",
            name="Threat infrastructure",
            identifier="Threat.Example.",
            source_reference="https://example.test/report",
            collection_basis="public",
            confidence="probable",
        )
        self.assertEqual(entity["identifier"], "threat.example")
        self.assertEqual(entity["verification_status"], "not-verified")
        self.assertEqual(entity["collection_basis"], "public")

        with self.assertRaisesRegex(ConflictError, "already exists"):
            create_entity(
                self.database,
                entity_type="domain",
                identifier="threat.example",
            )

    def test_rejects_invalid_identifiers_per_category(self):
        cases = [
            ("ipv4", "999.1.1.1"),
            ("ipv6", "not-an-ip"),
            ("email", "not-an-email"),
            ("url", "javascript:alert(1)"),
            ("hash", "abc123"),
            ("domain", "not a domain"),
            ("username", "bad username"),
        ]
        for entity_type, identifier in cases:
            with self.subTest(entity_type=entity_type):
                with self.assertRaises(ValidationError):
                    create_entity(
                        self.database,
                        entity_type=entity_type,
                        identifier=identifier,
                    )

    def test_requires_a_name_or_identifier(self):
        with self.assertRaisesRegex(ValidationError, "name or an identifier"):
            create_entity(self.database, entity_type="person")

    def test_updates_entity_and_preserves_display_fields(self):
        entity = create_entity(
            self.database, entity_type="domain", identifier="old.example"
        )
        self.assertEqual(entity["name"], "old.example")
        updated = update_entity(
            self.database,
            entity["id"],
            {"name": "Renamed", "confidence": "confirmed", "identifier": "new.example"},
        )
        self.assertEqual(updated["name"], "Renamed")
        self.assertEqual(updated["identifier"], "new.example")
        self.assertEqual(updated["confidence"], "confirmed")

        with self.assertRaisesRegex(ValidationError, "unsupported entity fields"):
            update_entity(self.database, entity["id"], {"unknown": "field"})

    def test_investigation_linking_and_search_filters(self):
        investigation = create_investigation(self.database, "Case")
        domain = create_entity(
            self.database, entity_type="domain", identifier="one.example"
        )
        create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.10"
        )
        linked = link_entity_to_investigation(
            self.database, investigation["id"], domain["id"]
        )
        self.assertTrue(linked["linked"])
        self.assertFalse(linked["already_linked"])
        again = link_entity_to_investigation(
            self.database, investigation["id"], domain["id"]
        )
        self.assertTrue(again["already_linked"])

        listed = list_entities(
            self.database, investigation_id=investigation["id"]
        )
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["investigation_count"], 1)
        filtered = list_entities(self.database, entity_type="ipv4")
        self.assertEqual(filtered["total"], 1)
        searched = list_entities(self.database, search="one.example")
        self.assertEqual(searched["total"], 1)

        unlink_entity_from_investigation(
            self.database, investigation["id"], domain["id"]
        )
        self.assertEqual(
            list_entities(self.database, investigation_id=investigation["id"])["total"],
            0,
        )

    def test_relationship_engine_and_graph_projection(self):
        investigation = create_investigation(self.database, "Graph case")
        domain = create_entity(
            self.database, entity_type="domain", identifier="graph.example"
        )
        address = create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.11"
        )
        link_entity_to_investigation(self.database, investigation["id"], domain["id"])
        link_entity_to_investigation(self.database, investigation["id"], address["id"])
        relationship = create_relationship(
            self.database,
            source_entity_id=domain["id"],
            target_entity_id=address["id"],
            relationship_type="hosted-on",
            source_reference="https://example.test/dns",
            confidence="probable",
            investigation_id=investigation["id"],
        )
        self.assertEqual(relationship["source_name"], "graph.example")
        self.assertEqual(relationship["target_name"], "203.0.113.11")
        relationships = list_relationships(
            self.database, investigation_id=investigation["id"]
        )
        self.assertEqual(len(relationships), 1)

        with self.assertRaisesRegex(ConflictError, "identical relationship"):
            create_relationship(
                self.database,
                source_entity_id=domain["id"],
                target_entity_id=address["id"],
                relationship_type="hosted-on",
                investigation_id=investigation["id"],
            )
        with self.assertRaisesRegex(ValidationError, "two different entities"):
            create_relationship(
                self.database,
                source_entity_id=domain["id"],
                target_entity_id=domain["id"],
                relationship_type="related-to",
            )

        graph = graph_payload(self.database, investigation_id=investigation["id"])
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["relationship_type"], "hosted-on")

        detail = get_entity(self.database, domain["id"])
        self.assertEqual(len(detail["relationships"]), 1)
        self.assertEqual(detail["relationships"][0]["direction"], "outgoing")
        self.assertEqual(detail["investigations"][0]["id"], investigation["id"])

    def test_delete_requires_force_when_relationships_exist(self):
        domain = create_entity(
            self.database, entity_type="domain", identifier="delete.example"
        )
        address = create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.12"
        )
        create_relationship(
            self.database,
            source_entity_id=domain["id"],
            target_entity_id=address["id"],
            relationship_type="associated-with",
        )
        with self.assertRaisesRegex(ConflictError, "pass force=true"):
            delete_entity(self.database, domain["id"])
        result = delete_entity(self.database, domain["id"], force=True)
        self.assertTrue(result["deleted"])
        self.assertEqual(result["removed_relationships"], 1)
        self.assertEqual(list_relationships(self.database), [])


class SourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_source_links_to_investigation_and_entity(self):
        investigation = create_investigation(self.database, "Sourced case")
        entity = create_entity(
            self.database, entity_type="domain", identifier="sourced.example"
        )
        source = create_source(
            self.database,
            title="Public registry record",
            reference="https://example.test/registry",
            category="public-database",
            verification_status="verified",
        )
        self.assertEqual(source["category"], "public-database")
        link_source_to_investigation(
            self.database, investigation["id"], source["id"]
        )
        link_source_to_entity(self.database, entity["id"], source["id"])
        detail = get_source(self.database, source["id"])
        self.assertEqual(detail["investigations"][0]["id"], investigation["id"])
        self.assertEqual(detail["entities"][0]["id"], entity["id"])

        unlink_source_from_entity(self.database, entity["id"], source["id"])
        self.assertEqual(get_source(self.database, source["id"])["entities"], [])

    def test_rejects_unsafe_source_references(self):
        with self.assertRaisesRegex(ValidationError, "http, https, file or note"):
            create_source(
                self.database, title="Unsafe", reference="javascript:alert(1)"
            )
        with self.assertRaisesRegex(ValidationError, "title must not be empty"):
            create_source(self.database, title="   ", reference="note://analyst")


if __name__ == "__main__":
    unittest.main()
