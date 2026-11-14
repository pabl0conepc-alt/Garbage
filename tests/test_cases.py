"""Step 6: case objective, archive, duplicate, package export/import, custody."""

import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path

from garbage_intel import cases, custody
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, create_relationship, link_entity_to_investigation
from garbage_intel.errors import ValidationError
from garbage_intel.evidence import add_evidence, delete_evidence, read_evidence_file, verify_evidence
from garbage_intel.store import add_observation, create_investigation, get_investigation, list_investigations, update_investigation


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "cases.sqlite3")
        initialize(self.database)
        self.case = create_investigation(self.database, "Operação Vidro", "Phishing bancário", objective="Mapear a infraestrutura do kit")["id"]
        self.domain = create_entity(self.database, entity_type="domain", identifier="kit.example", name="kit.example")
        self.ip = create_entity(self.database, entity_type="ipv4", identifier="192.0.2.80", name="192.0.2.80")
        for entity in (self.domain, self.ip):
            link_entity_to_investigation(self.database, self.case, entity["id"])
        create_relationship(self.database, source_entity_id=self.domain["id"], target_entity_id=self.ip["id"], relationship_type="hosted-on", investigation_id=self.case)
        add_observation(self.database, self.case, title="Nota", content="kit.example resolve para 192.0.2.80", source_reference="note://t", collection_basis="user-provided")
        self.evidence = add_evidence(self.database, investigation_id=self.case, title="Captura", evidence_type="file", data=b"pagina falsa\n", original_name="captura.html")

    def tearDown(self):
        self.directory.cleanup()


class LifecycleTests(Base):
    def test_objective_and_archive(self):
        self.assertEqual(get_investigation(self.database, self.case)["objective"], "Mapear a infraestrutura do kit")
        update_investigation(self.database, self.case, objective="Novo objetivo")
        self.assertEqual(get_investigation(self.database, self.case)["objective"], "Novo objetivo")
        archived = cases.set_archived(self.database, self.case, True)
        self.assertTrue(archived["archived_at"])
        self.assertTrue(next(item for item in list_investigations(self.database) if item["id"] == self.case)["archived_at"])
        self.assertEqual(cases.set_archived(self.database, self.case, False)["archived_at"], "")

    def test_duplicate(self):
        copy_case = cases.duplicate(self.database, self.case)
        self.assertEqual(copy_case["name"], "Cópia de Operação Vidro")
        self.assertEqual(copy_case["copied"], {"entities": 2, "relationships": 1, "sources": 0, "techniques": 0})
        detail = get_investigation(self.database, copy_case["id"])
        self.assertEqual((detail["status"], detail["objective"]), ("open", "Mapear a infraestrutura do kit"))
        listed = next(item for item in list_investigations(self.database) if item["id"] == copy_case["id"])
        self.assertEqual((listed["observation_count"], listed["evidence_count"], listed["entity_count"]), (0, 0, 2))


class CustodyTests(Base):
    def test_events_follow_the_evidence_lifecycle(self):
        verify_evidence(self.database, self.evidence["id"])
        read_evidence_file(self.database, self.evidence["id"], purpose="downloaded")
        custody.add_note(self.database, self.evidence["id"], "Coletada do link do e-mail")
        log = custody.chain(self.database, self.evidence["id"])
        self.assertTrue(log["intact"])
        self.assertEqual([event["action"] for event in log["events"]], ["recorded", "verified", "accessed", "annotated"])
        self.assertTrue(all(event["sha256"] == self.evidence["sha256"] for event in log["events"]))
        self.assertEqual(custody.list_notes(self.database, self.evidence["id"])["items"][0]["body"], "Coletada do link do e-mail")
        delete_evidence(self.database, self.evidence["id"])
        after = custody.chain(self.database, self.evidence["id"])
        self.assertFalse(after["exists"])
        self.assertEqual(after["events"][-1]["action"], "deleted")
        self.assertTrue(after["intact"])

    def test_tampering_breaks_the_chain(self):
        verify_evidence(self.database, self.evidence["id"])
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE evidence_events SET detail = 'edited' WHERE evidence_id = ? AND sequence = 1", (self.evidence["id"],))
        log = custody.chain(self.database, self.evidence["id"])
        self.assertFalse(log["intact"])
        self.assertEqual(log["broken_at"], 1)

    def test_backfill_for_older_evidence(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("DELETE FROM evidence_events")
            connection.execute("DELETE FROM schema_migrations WHERE version = 12")
        initialize(self.database)
        log = custody.chain(self.database, self.evidence["id"])
        self.assertEqual((log["events"][0]["action"], log["events"][0]["actor"]), ("recorded", "system"))


class PackageTests(Base):
    def test_round_trip(self):
        package = cases.export_package(self.database, self.case)
        self.assertEqual(package["format"], "garbage-case")
        self.assertIsNotNone(package["content"]["evidence"][0]["content_base64"])
        self.assertEqual(custody.chain(self.database, self.evidence["id"])["events"][-1]["action"], "exported")

        preview = cases.import_package(self.database, copy.deepcopy(package))
        self.assertFalse(preview["committed"])
        self.assertEqual(preview["plan"]["entities_reused"], 2)
        self.assertEqual(preview["plan"]["evidence_files"], 1)

        other = str(Path(self.directory.name) / "other.sqlite3")
        initialize(other)
        imported = cases.import_package(other, copy.deepcopy(package), commit=True)
        self.assertTrue(imported["committed"])
        listed = next(item for item in list_investigations(other) if item["id"] == imported["id"])
        self.assertEqual((listed["entity_count"], listed["observation_count"], listed["evidence_count"]), (2, 1, 1))
        self.assertEqual(get_investigation(other, imported["id"])["objective"], "Mapear a infraestrutura do kit")
        with sqlite3.connect(other) as connection:
            evidence_id = connection.execute("SELECT id FROM evidence").fetchone()[0]
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0], 1)
        data, *_ = read_evidence_file(other, evidence_id)
        self.assertEqual(data, b"pagina falsa\n")
        log = custody.chain(other, evidence_id)
        self.assertEqual([event["action"] for event in log["events"]], ["imported", "imported-history"])
        self.assertIn(package["sha256"][:16], log["events"][0]["detail"])

    def test_tampered_packages_are_refused(self):
        package = cases.export_package(self.database, self.case)
        edited = copy.deepcopy(package)
        edited["content"]["observations"][0]["content"] = "outra coisa"
        with self.assertRaises(ValidationError):
            cases.import_package(self.database, edited)
        with self.assertRaises(ValidationError):
            cases.import_package(self.database, {"format": "other"})
        # A file whose bytes do not match the recorded digest is rejected even
        # when the package digest was recomputed.
        forged = copy.deepcopy(package)
        forged["content"]["evidence"][0]["content_base64"] = "b3V0cm8K"
        forged["sha256"] = cases._digest(forged["content"])
        preview = cases.import_package(self.database, forged)
        self.assertEqual(preview["plan"]["evidence_rejected"], 1)
        self.assertIn("does not match", preview["problems"][0]["reason"])

    def test_metadata_only_export(self):
        package = cases.export_package(self.database, self.case, include_files=False)
        self.assertIsNone(package["content"]["evidence"][0]["content_base64"])


if __name__ == "__main__":
    unittest.main()


class ReportSectionTests(Base):
    def test_selected_sections(self):
        from garbage_intel.report_sections import parse_sections
        from garbage_intel.reporting import render_html_report, render_markdown_report
        from garbage_intel.store import build_report

        chosen = parse_sections("summary,methodology,graph,custody,techniques")
        report = build_report(self.database, self.case, chosen)
        self.assertEqual(report["sections"], ["summary", "methodology", "graph", "custody", "techniques"])
        self.assertEqual(report["methodology"]["collection_bases"], {"user-provided": 1})
        self.assertEqual(report["custody"][0]["actions"], ["recorded"])
        self.assertTrue(report["graph_svg"].startswith("<svg"))
        html = render_html_report(report)
        self.assertIn("<h2>Methodology</h2>", html)
        self.assertIn("Chain of custody", html)
        self.assertIn("Objective:", html)
        self.assertIn("<svg", html)
        self.assertNotIn("<h2>Observations", html)
        self.assertIn("## Chain of custody", render_markdown_report(report))
        legacy = render_html_report(build_report(self.database, self.case))
        self.assertIn("<h2>Observations (1)</h2>", legacy)
        self.assertNotIn("Methodology", legacy)
        with self.assertRaises(ValidationError):
            parse_sections("summary,secrets")
