import tempfile
import unittest
from pathlib import Path

from garbage_intel.boards import get_board, save_board
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, create_relationship
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.store import create_investigation


class InvestigationBoardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")
        initialize(self.database)
        self.investigation = create_investigation(self.database, "Board case")
        self.domain = create_entity(
            self.database, entity_type="domain", identifier="board.example"
        )
        self.address = create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.13"
        )
        self.relationship = create_relationship(
            self.database,
            source_entity_id=self.domain["id"],
            target_entity_id=self.address["id"],
            relationship_type="hosted-on",
            investigation_id=self.investigation["id"],
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def payload(self, revision=0, layers=None):
        return {
            "revision": revision,
            "name": "Board case analysis",
            "viewport": {"x": -120, "y": 40, "zoom": 1.4},
            "layers": layers or {"notes": True, "people": False},
            "elements": [
                {
                    "id": "el-domain",
                    "element_kind": "entity",
                    "entity_id": self.domain["id"],
                    "x": 120,
                    "y": 80,
                    "z_index": 1,
                },
                {
                    "id": "el-address",
                    "element_kind": "entity",
                    "entity_id": self.address["id"],
                    "x": 460,
                    "y": 240,
                    "width": 240,
                    "height": 140,
                },
                {
                    "id": "el-note",
                    "element_kind": "note",
                    "label": "Analyst note",
                    "content": "Observed hosting relation.",
                    "x": 200,
                    "y": 320,
                },
            ],
            "connections": [
                {
                    "id": "cn-hosting",
                    "source_element_id": "el-domain",
                    "target_element_id": "el-address",
                    "relationship_id": self.relationship["id"],
                    "connection_type": "hosted-on",
                    "label": "resolves to",
                }
            ],
        }

    def test_board_auto_creates_and_persists_state(self):
        initial = get_board(self.database, self.investigation["id"])
        self.assertEqual(initial["board"]["revision"], 0)
        self.assertEqual(initial["elements"], [])
        self.assertTrue(initial["board"]["layers"]["people"])

        saved = save_board(
            self.database, self.investigation["id"], self.payload()
        )
        self.assertEqual(saved["board"]["revision"], 1)
        self.assertEqual(len(saved["elements"]), 3)
        self.assertEqual(saved["connections"][0]["relationship_id"], self.relationship["id"])
        by_id = {element["id"]: element for element in saved["elements"]}
        self.assertEqual(by_id["el-domain"]["entity_name"], "board.example")
        self.assertEqual(by_id["el-domain"]["layer"], "domains")
        self.assertEqual(by_id["el-note"]["layer"], "notes")
        self.assertEqual(saved["board"]["viewport"]["zoom"], 1.4)
        self.assertFalse(saved["board"]["layers"]["people"])

        reloaded = get_board(self.database, self.investigation["id"])
        self.assertEqual(reloaded["board"]["revision"], 1)
        self.assertEqual(
            next(
                element
                for element in reloaded["elements"]
                if element["id"] == "el-address"
            )["x"],
            460,
        )

    def test_stale_revision_is_rejected(self):
        save_board(self.database, self.investigation["id"], self.payload())
        with self.assertRaisesRegex(ConflictError, "revision conflict"):
            save_board(self.database, self.investigation["id"], self.payload())

    def test_connection_must_match_the_referenced_relationship(self):
        other_a = create_entity(
            self.database, entity_type="domain", identifier="other.example"
        )
        other_b = create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.99"
        )
        other_relationship = create_relationship(
            self.database,
            source_entity_id=other_a["id"],
            target_entity_id=other_b["id"],
            relationship_type="related-to",
        )
        payload = self.payload()
        payload["connections"][0]["relationship_id"] = other_relationship["id"]
        with self.assertRaisesRegex(ValidationError, "must join the entities"):
            save_board(self.database, self.investigation["id"], payload)

    def test_rejects_invalid_layers_and_duplicate_connections(self):
        payload = self.payload()
        payload["layers"] = {"unknown": True}
        with self.assertRaisesRegex(ValidationError, "unknown board layers"):
            save_board(self.database, self.investigation["id"], payload)

        payload = self.payload()
        payload["connections"].append(dict(payload["connections"][0]))
        payload["connections"][1]["id"] = "cn-duplicate"
        with self.assertRaisesRegex(ValidationError, "only be represented once"):
            save_board(self.database, self.investigation["id"], payload)

    def test_element_ids_can_be_omitted_and_are_generated(self):
        payload = self.payload()
        for element in payload["elements"]:
            element.pop("id")
        payload["connections"] = []
        saved = save_board(self.database, self.investigation["id"], payload)
        identifiers = [element["id"] for element in saved["elements"]]
        self.assertEqual(len(set(identifiers)), 3)
        self.assertTrue(all(len(identifier) <= 64 for identifier in identifiers))


if __name__ == "__main__":
    unittest.main()
