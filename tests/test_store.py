from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.store import (
    INVESTIGATION_STATUSES,
    add_observation,
    build_report,
    build_timeline,
    create_investigation,
    initialize,
    list_investigations,
    set_investigation_status,
)


class EvidenceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "nested" / "intel.sqlite3"
        initialize(self.database)
        self.investigation = create_investigation(
            self.database, "Example", "A test investigation"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_report_preserves_source_and_collection_basis(self):
        add_observation(
            self.database,
            self.investigation["id"],
            "Public notice",
            "A user-recorded public notice.",
            "https://example.test/notice",
            "public",
            "2025-01-02T03:04:05+02:00",
        )

        report = build_report(self.database, self.investigation["id"])
        observation = report["observations"][0]
        self.assertEqual(observation["source_reference"], "https://example.test/notice")
        self.assertEqual(observation["collection_basis"], "public")
        self.assertEqual(observation["observed_at"], "2025-01-02T01:04:05Z")
        self.assertTrue(report["limitations"])

    def test_timeline_orders_events_and_retains_observation_provenance(self):
        observation = add_observation(
            self.database,
            self.investigation["id"],
            "Public notice",
            "A public observation.",
            "https://example.test/notice",
            "public",
            "2025-01-02T03:04:05Z",
        )

        timeline = build_timeline(self.database, self.investigation["id"])
        self.assertEqual(timeline["events"][0]["type"], "observation")
        self.assertEqual(timeline["events"][0]["observation_id"], observation["id"])
        self.assertEqual(
            timeline["events"][0]["source_reference"],
            "https://example.test/notice",
        )
        self.assertEqual(timeline["events"][0]["collection_basis"], "public")
        self.assertEqual(timeline["events"][-1]["type"], "investigation_created")
        set_investigation_status(
            self.database, self.investigation["id"], "closed"
        )
        timeline = build_timeline(self.database, self.investigation["id"])
        self.assertEqual(timeline["events"][-1]["type"], "status_changed")
        self.assertEqual(timeline["events"][-1]["status"], "closed")

    def test_timeline_skips_indicator_analysis(self):
        add_observation(
            self.database,
            self.investigation["id"],
            "Indicator-rich note",
            f"203.0.113.8 threat.example {'a' * 64}",
            "https://example.test/notice",
            "public",
        )

        with patch(
            "garbage_intel.store.extract_indicators",
            side_effect=AssertionError("timeline should not extract indicators"),
        ), patch(
            "garbage_intel.store.correlate_indicators",
            side_effect=AssertionError("timeline should not correlate indicators"),
        ):
            timeline = build_timeline(self.database, self.investigation["id"])

        self.assertEqual(
            [event["type"] for event in timeline["events"]],
            ["investigation_created", "observation"],
        )

    def test_observation_requires_an_existing_investigation(self):
        with self.assertRaisesRegex(ValueError, "investigation not found"):
            add_observation(
                self.database,
                "missing",
                "Title",
                "Content",
                "source",
                "user-provided",
            )

    def test_timestamp_must_include_a_timezone(self):
        with self.assertRaisesRegex(ValueError, "include a timezone"):
            add_observation(
                self.database,
                self.investigation["id"],
                "Title",
                "Content",
                "source",
                "authorized",
                "2025-01-02T03:04:05",
            )

    def test_closed_investigations_reject_new_observations_until_reopened(self):
        closed = set_investigation_status(
            self.database, self.investigation["id"], "closed"
        )
        self.assertEqual(closed["status"], "closed")
        with self.assertRaisesRegex(ValueError, "investigation is closed"):
            add_observation(
                self.database,
                self.investigation["id"],
                "Late evidence",
                "Needs reopening first",
                "note://analyst",
                "user-provided",
            )

        reopened = set_investigation_status(
            self.database, self.investigation["id"], "open"
        )
        self.assertEqual(reopened["status"], "open")
        self.assertEqual(list_investigations(self.database)[0]["status"], "open")
        cancelled = set_investigation_status(
            self.database, self.investigation["id"], "cancelled"
        )
        self.assertEqual(cancelled["status"], "cancelled")
        with self.assertRaisesRegex(ValueError, "investigation is cancelled"):
            add_observation(
                self.database,
                self.investigation["id"],
                "Cancelled evidence",
                "Reopen before adding",
                "note://analyst",
                "user-provided",
            )

    def test_initialize_migrates_existing_database_to_open_status(self):
        legacy_database = Path(self.temp_dir.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_database)) as connection:
            with connection:
                connection.execute(
                    """CREATE TABLE investigations (
                           id TEXT PRIMARY KEY,
                           name TEXT NOT NULL,
                           description TEXT NOT NULL DEFAULT '',
                           created_at TEXT NOT NULL
                       )"""
                )
                connection.execute(
                    "INSERT INTO investigations VALUES ('old-id', 'Legacy', '', '2025-01-01T00:00:00Z')"
                )

        initialize(legacy_database)
        legacy = list_investigations(legacy_database)[0]
        self.assertEqual(legacy["status"], "open")
        self.assertEqual(INVESTIGATION_STATUSES, ("open", "closed", "cancelled"))


if __name__ == "__main__":
    unittest.main()
