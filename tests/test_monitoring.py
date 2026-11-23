"""Step 7: monitors, differences between runs, notifications, scheduler."""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from garbage_intel import intel, monitoring
from garbage_intel.db import initialize
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.intel import Connector, Finding, register_connector, unregister_connector
from garbage_intel.store import create_investigation


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "monitor.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()
        self.answers = [["a.example", "b.example"]]

        def fake(context):
            current = self.answers[0]
            if current is None:
                raise ValueError("source down")
            return [Finding("subdomain", name) for name in current]

        register_connector(Connector("test-subs", "Subs", "test", ("domain",), fake))
        self.addCleanup(unregister_connector, "test-subs")

    def tearDown(self):
        self.directory.cleanup()

    def monitor(self, **extra):
        return monitoring.create_monitor(self.database, name="Subdomínios", value="Example.com", connector_ids=["test-subs"], interval_minutes=60, **extra)

    def test_validation(self):
        for kwargs in ({"connector_ids": []}, {"connector_ids": ["nope"]}, {"connector_ids": ["nvd"]}, {"interval_minutes": 5}):
            arguments = {"name": "x", "value": "example.com", "connector_ids": ["test-subs"], "interval_minutes": 60, **kwargs}
            with self.assertRaises(ValidationError):
                monitoring.create_monitor(self.database, **arguments)
        created = self.monitor(investigation_id=create_investigation(self.database, "Caso")["id"])
        self.assertEqual((created["query_type"], created["query_value"], created["enabled"]), ("domain", "example.com", True))

    def test_differences_and_notifications(self):
        monitor = self.monitor()
        first = monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual(first["status"], "baseline")
        self.assertEqual(monitoring.notifications(self.database)["unread"], 0)
        same = monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual(same["status"], "unchanged")
        self.answers[0] = ["b.example", "c.example"]
        changed = monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual(changed["status"], "changed")
        self.assertEqual([item["value"] for item in changed["added"]], ["c.example"])
        self.assertEqual([item["value"] for item in changed["removed"]], ["a.example"])
        inbox = monitoring.notifications(self.database)
        self.assertEqual(inbox["unread"], 1)
        self.assertIn("1 new, 1 gone", inbox["items"][0]["title"])
        # A failing source does not report everything as gone.
        self.answers[0] = None
        failed = monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual((failed["status"], failed["removed_count"]), ("unchanged", 0))
        history = monitoring.monitor_runs(self.database, monitor["id"])
        self.assertEqual([item["status"] for item in history["items"]], ["unchanged", "changed", "unchanged", "baseline"])
        self.assertEqual(monitoring.mark_read(self.database, "all")["unread"], 0)

    def test_scheduler_runs_only_due_monitors(self):
        due = self.monitor()
        later = self.monitor()
        paused = self.monitor()
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE monitors SET next_run_at = ? WHERE id = ?", (future, later["id"]))
        monitoring.update_monitor(self.database, paused["id"], {"enabled": False})
        scheduler = monitoring.Scheduler()
        scheduler._database = self.database
        self.assertEqual(scheduler.tick(), 1)
        self.assertEqual(monitoring.monitor_runs(self.database, due["id"])["items"][0]["trigger"], "schedule")
        self.assertEqual(scheduler.tick(), 0)  # next slot is an hour away
        listing = {item["id"]: item for item in monitoring.list_monitors(self.database)["items"]}
        self.assertGreater(listing[due["id"]]["next_run_at"], listing[due["id"]]["last_run_at"])
        self.assertEqual(listing[paused["id"]]["last_run_at"], "")

    def test_overlapping_runs_are_refused(self):
        monitor = self.monitor()
        monitoring._RUNNING.add(monitor["id"])
        self.addCleanup(monitoring._RUNNING.discard, monitor["id"])
        with self.assertRaises(ConflictError):
            monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual(monitoring.monitor_runs(self.database, monitor["id"])["items"], [])


if __name__ == "__main__":
    unittest.main()
