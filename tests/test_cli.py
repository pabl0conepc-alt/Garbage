import csv
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.cli import main
from garbage_intel.store import build_report


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, *args):
        status, stdout, stderr = self.capture_cli(*args)
        self.assertEqual(status, 0, stderr)
        return json.loads(stdout)

    def capture_cli(self, *args):
        return self.capture_cli_with_database(self.database, *args)

    def capture_cli_with_database(self, database, *args):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = main(["--database", str(database), *args])
        return status, output.getvalue(), errors.getvalue()

    def test_investigation_observation_report_flow(self):
        self.run_cli("init")
        investigation = self.run_cli(
            "investigation", "create", "--name", "CLI check"
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Notice",
            "--content",
            "Recorded from a public source.",
            "--source-reference",
            "https://example.test/notice",
            "--collection-basis",
            "public",
        )
        report = self.run_cli(
            "report", "--investigation-id", investigation["id"]
        )
        self.assertEqual(report["investigation"]["name"], "CLI check")
        self.assertEqual(len(report["observations"]), 1)
        self.assertEqual(report["observations"][0]["collection_basis"], "public")

    def test_forensics_hash_is_recorded_as_user_provided_evidence(self):
        self.run_cli("init")
        investigation = self.run_cli(
            "investigation", "create", "--name", "Forensic test"
        )
        evidence = Path(self.temp_dir.name) / "evidence.bin"
        evidence.write_bytes(b"sample evidence")

        result = self.run_cli(
            "forensics",
            "hash-file",
            "--investigation-id",
            investigation["id"],
            "--path",
            str(evidence),
        )
        self.assertEqual(result["observation"]["collection_basis"], "user-provided")
        self.assertIn(result["file_analysis"]["sha256"], result["observation"]["content"])

    def test_document_metadata_command_does_not_initialize_database(self):
        document = Path(self.temp_dir.name) / "notes.txt"
        document.write_text("Analyst supplied notes")

        result = self.run_cli(
            "forensics", "document-metadata", "--path", str(document)
        )
        self.assertEqual(result["file_name"], "notes.txt")
        self.assertEqual(result["suffix"], ".txt")
        self.assertEqual(result["media_type"], "text/plain")
        self.assertEqual(result["size_bytes"], document.stat().st_size)
        self.assertFalse(Path(self.database).exists())

    def test_sqlite_backup_copies_database_and_never_overwrites(self):
        investigation = self.run_cli(
            "investigation", "create", "--name", "Backup test"
        )
        destination = Path(self.temp_dir.name) / "backup.sqlite3"

        result = self.run_cli(
            "backup", "--format", "sqlite", "--output", str(destination)
        )
        self.assertTrue(result["created"])
        self.assertEqual(result["source_database"], str(Path(self.database).resolve()))
        self.assertTrue(destination.is_file())

        backup_report = build_report(destination, investigation["id"])
        self.assertEqual(backup_report["investigation"]["name"], "Backup test")

        original_backup = destination.read_bytes()
        status, _, error = self.capture_cli(
            "backup",
            "--format",
            "sqlite",
            "--output",
            str(destination),
        )
        self.assertEqual(status, 2)
        self.assertIn("backup destination already exists", error)
        self.assertEqual(destination.read_bytes(), original_backup)

    def test_backup_requires_existing_source_and_does_not_initialize_it(self):
        destination = Path(self.temp_dir.name) / "missing-source-backup.json"
        status, _, error = self.capture_cli_with_database(
            self.database, "backup", "--output", str(destination)
        )
        self.assertEqual(status, 2)
        self.assertIn("existing regular file", error)
        self.assertFalse(Path(self.database).exists())
        self.assertFalse(destination.exists())

    def test_cisa_kev_cli_refresh_is_an_explicit_action(self):
        response = {
            "source_url": "https://www.cisa.gov/feed.json",
            "refresh_status": "updated",
            "count": 0,
            "items": [],
        }
        with patch("garbage_intel.cli.refresh_cisa_kev", return_value=response) as refresh:
            result = self.run_cli("intel", "kev", "refresh")
        self.assertEqual(result["refresh_status"], "updated")
        refresh.assert_called_once_with(self.database, force=False)

    def test_json_backup_import_preserves_provenance(self):
        investigation = self.run_cli(
            "investigation", "create", "--name", "Archive round-trip"
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Public evidence",
            "--content",
            "Observed indicator 203.0.113.8",
            "--source-reference",
            "https://example.test/evidence",
            "--collection-basis",
            "public",
            "--observed-at",
            "2025-03-01T10:00:00+02:00",
        )
        self.run_cli(
            "investigation",
            "set-status",
            "--investigation-id",
            investigation["id"],
            "--status",
            "closed",
        )
        archive_path = Path(self.temp_dir.name) / "archive.json"
        result = self.run_cli("backup", "--output", str(archive_path))
        self.assertEqual(result["format"], "garbage-evidence-archive")
        self.assertEqual(result["observations"], 1)
        self.assertEqual(result["status_events"], 1)
        original_backup = archive_path.read_bytes()
        status, _, error = self.capture_cli("backup", "--output", str(archive_path))
        self.assertEqual(status, 2)
        self.assertIn("backup destination already exists", error)
        self.assertEqual(archive_path.read_bytes(), original_backup)

        restored_database = Path(self.temp_dir.name) / "restored.sqlite3"
        status, stdout, stderr = self.capture_cli_with_database(
            restored_database, "import", "--input", str(archive_path)
        )
        self.assertEqual(status, 0, stderr)
        self.assertEqual(json.loads(stdout)["investigations"], 1)
        self.assertEqual(json.loads(stdout)["status_events"], 1)
        restored_report = build_report(restored_database, investigation["id"])
        self.assertEqual(restored_report["investigation"]["status"], "closed")
        restored_observation = restored_report["observations"][0]
        self.assertEqual(restored_observation["collection_basis"], "public")
        self.assertEqual(
            restored_observation["source_reference"],
            "https://example.test/evidence",
        )
        self.assertEqual(restored_observation["observed_at"], "2025-03-01T08:00:00Z")
        self.assertEqual(restored_report["indicators"][0]["value"], "203.0.113.8")
        timeline_status, timeline_output, timeline_error = self.capture_cli_with_database(
            restored_database,
            "investigation",
            "timeline",
            "--investigation-id",
            investigation["id"],
        )
        self.assertEqual(timeline_status, 0, timeline_error)
        self.assertEqual(
            json.loads(timeline_output)["events"][-1]["status"], "closed"
        )

    def test_invalid_archive_is_rejected_before_database_changes(self):
        investigation = self.run_cli(
            "investigation", "create", "--name", "Invalid archive source"
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Evidence",
            "--content",
            "Sample",
            "--source-reference",
            "note://analyst",
            "--collection-basis",
            "user-provided",
        )
        valid_archive_path = Path(self.temp_dir.name) / "valid.json"
        self.run_cli("backup", "--output", str(valid_archive_path))
        archive = json.loads(valid_archive_path.read_text())
        archive_path = Path(self.temp_dir.name) / "invalid.json"
        archive["observations"][0]["investigation_id"] = "missing-investigation"
        archive_path.write_text(json.dumps(archive))

        destination = Path(self.temp_dir.name) / "not-imported.sqlite3"
        status, _, error = self.capture_cli_with_database(
            destination, "import", "--input", str(archive_path)
        )
        self.assertEqual(status, 2)
        self.assertIn("references a missing investigation", error)
        self.assertFalse(destination.exists())

    def test_conflicting_archive_rolls_back_all_inserted_records(self):
        first = self.run_cli(
            "investigation", "create", "--name", "New before conflict"
        )
        second = self.run_cli(
            "investigation", "create", "--name", "Existing conflict"
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            first["id"],
            "--title",
            "Evidence",
            "--content",
            "Archive transaction",
            "--source-reference",
            "note://analyst",
            "--collection-basis",
            "user-provided",
        )
        full_archive_path = Path(self.temp_dir.name) / "full.json"
        self.run_cli("backup", "--output", str(full_archive_path))
        full_archive = json.loads(full_archive_path.read_text())
        first_record = next(
            item
            for item in full_archive["investigations"]
            if item["id"] == first["id"]
        )
        second_record = next(
            item
            for item in full_archive["investigations"]
            if item["id"] == second["id"]
        )
        full_archive["investigations"] = [first_record, second_record]

        seed_archive = dict(full_archive)
        seed_archive["investigations"] = [second_record]
        seed_archive["observations"] = []
        seed_archive["status_events"] = []
        seed_path = Path(self.temp_dir.name) / "seed.json"
        seed_path.write_text(json.dumps(seed_archive))
        target_database = Path(self.temp_dir.name) / "target.sqlite3"
        status, _, error = self.capture_cli_with_database(
            target_database, "import", "--input", str(seed_path)
        )
        self.assertEqual(status, 0, error)

        status, _, error = self.capture_cli_with_database(
            target_database, "import", "--input", str(full_archive_path)
        )
        self.assertEqual(status, 2)
        self.assertIn("archive conflicts with existing records", error)
        status, stdout, error = self.capture_cli_with_database(
            target_database, "investigation", "list"
        )
        self.assertEqual(status, 0, error)
        imported = json.loads(stdout)
        self.assertEqual([item["id"] for item in imported], [second["id"]])

    def test_investigation_lifecycle_and_csv_html_exports(self):
        investigation = self.run_cli(
            "investigation", "create", "--name", "Export test"
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Quoted evidence",
            "--content",
            'A comma, a quote " and 203.0.113.8',
            "--source-reference",
            "https://example.test/source",
            "--collection-basis",
            "public",
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Corroborating evidence",
            "--content",
            "203.0.113.8 appears again",
            "--source-reference",
            "https://second.example/report",
            "--collection-basis",
            "authorized",
        )
        self.run_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Formula-like content",
            "--content",
            '=HYPERLINK("https://example.test","open")',
            "--source-reference",
            "note://analyst",
            "--collection-basis",
            "user-provided",
        )

        listed = self.run_cli("investigation", "list")
        self.assertEqual(listed[0]["status"], "open")
        shown = self.run_cli(
            "investigation", "show", "--investigation-id", investigation["id"]
        )
        self.assertEqual(shown["observations"][0]["title"], "Quoted evidence")

        csv_status, csv_output, csv_error = self.capture_cli(
            "report",
            "--investigation-id",
            investigation["id"],
            "--format",
            "csv",
        )
        self.assertEqual(csv_status, 0, csv_error)
        csv_rows = list(csv.DictReader(io.StringIO(csv_output)))
        self.assertEqual(len(csv_rows), 3)
        self.assertEqual(csv_rows[0]["content"], 'A comma, a quote " and 203.0.113.8')
        self.assertEqual(csv_rows[0]["collection_basis"], "public")
        self.assertIn("203.0.113.8", csv_rows[0]["indicators"])
        self.assertIn("exact-normalized-value", csv_rows[0]["correlations"])
        self.assertTrue(csv_rows[2]["content"].startswith("'="))

        html_status, html_output, html_error = self.capture_cli(
            "report",
            "--investigation-id",
            investigation["id"],
            "--format",
            "html",
        )
        self.assertEqual(html_status, 0, html_error)
        self.assertIn("<title>Export test | GARBAGE report</title>", html_output)

        closed = self.run_cli(
            "investigation",
            "set-status",
            "--investigation-id",
            investigation["id"],
            "--status",
            "closed",
        )
        self.assertEqual(closed["status"], "closed")
        report = self.run_cli(
            "investigation", "show", "--investigation-id", investigation["id"]
        )
        self.assertEqual(report["investigation"]["status"], "closed")
        status, _, error = self.capture_cli(
            "observation",
            "add",
            "--investigation-id",
            investigation["id"],
            "--title",
            "Blocked",
            "--content",
            "Closed case",
            "--source-reference",
            "note://analyst",
            "--collection-basis",
            "user-provided",
        )
        self.assertEqual(status, 2)
        self.assertIn("investigation is closed", error)

        export_path = Path(self.temp_dir.name) / "report.csv"
        status, _, error = self.capture_cli(
            "report",
            "--investigation-id",
            investigation["id"],
            "--format",
            "csv",
            "--output",
            str(export_path),
        )
        self.assertEqual(status, 0, error)
        original_export = export_path.read_bytes()
        status, _, error = self.capture_cli(
            "report",
            "--investigation-id",
            investigation["id"],
            "--format",
            "csv",
            "--output",
            str(export_path),
        )
        self.assertEqual(status, 2)
        self.assertIn("output already exists", error)
        self.assertEqual(export_path.read_bytes(), original_export)


if __name__ == "__main__":
    unittest.main()
