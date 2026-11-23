"""Catalogue block 3: watchlists, change detection, expiry warnings, scheduler."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, watchlist
from garbage_intel.errors import NotFoundError, ValidationError
from garbage_intel.intel import Connector, Finding, register_connector, unregister_connector
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings
from tests.test_intel_sources import reply

STATE = {"findings": []}


def _fake(context):
    return list(STATE["findings"])


class WatchlistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.tmp.name) / "w.db")
        initialize(self.database)
        update_settings(self.database, {"intel.allow_network": "true"})
        # Only the fake connector answers, so checks are deterministic and offline.
        self.saved = intel.connectors()
        for connector in self.saved:
            unregister_connector(connector.connector_id)
        register_connector(Connector("fake-source", "Fake", "test", ("domain", "username"), _fake, network=True))
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        unregister_connector("fake-source")
        for connector in self.saved:
            register_connector(connector)
        self.tmp.cleanup()

    def test_crud_and_validation(self):
        watch = watchlist.create_watch(self.database, {"value": "Example.COM", "label": "Main site", "interval_minutes": 60})
        self.assertEqual((watch["value"], watch["query_type"], watch["baseline"]), ("example.com", "domain", False))
        with self.assertRaises(ValidationError):
            watchlist.create_watch(self.database, {"value": "example.com"})
        with self.assertRaises(ValidationError):
            watchlist.create_watch(self.database, {"value": "other.com", "interval_minutes": 5})
        updated = watchlist.update_watch(self.database, watch["id"], {"enabled": False, "label": "Paused"})
        self.assertEqual((updated["enabled"], updated["label"]), (False, "Paused"))
        self.assertEqual(watchlist.list_watches(self.database)["total"], 1)
        watchlist.delete_watch(self.database, watch["id"])
        with self.assertRaises(NotFoundError):
            watchlist.get_watch(self.database, watch["id"])

    def test_baseline_then_change_alert_and_webhook(self):
        watch = watchlist.create_watch(self.database, {"value": "example.com"})
        STATE["findings"] = [Finding("dns-a", "192.0.2.1"), Finding("member-count", "10")]
        first = watchlist.check_watch(self.database, watch["id"])
        self.assertTrue(first["baseline"])
        self.assertEqual(first["alerts"], [])

        STATE["findings"] = [Finding("dns-a", "192.0.2.1"), Finding("member-count", "11")]
        self.assertEqual(watchlist.check_watch(self.database, watch["id"])["alerts"], [])  # volatile only

        sent = []
        update_settings(self.database, {"intel.webhook_url": "https://example.net/hook"})
        STATE["findings"] = [Finding("dns-a", "198.51.100.7")]
        with patch.object(intel, "WEBHOOK_FETCH", lambda url, **o: sent.append(o) or reply(url, {})):
            result = watchlist.check_watch(self.database, watch["id"])
        self.assertEqual(len(result["alerts"]), 1)
        alert = watchlist.list_alerts(self.database)["items"][0]
        self.assertEqual(alert["kind"], "change")
        self.assertEqual([item["value"] for item in alert["details"]["added"]], ["198.51.100.7"])
        self.assertEqual([item["value"] for item in alert["details"]["removed"]], ["192.0.2.1"])
        self.assertFalse(alert["read"])
        self.assertEqual(len(sent), 1)  # one watch alert, no per-run webhook
        self.assertIn("1 new, 1 gone", json.loads(sent[0]["body"])["content"])
        self.assertEqual(watchlist.mark_alerts_read(self.database), 1)
        self.assertEqual(watchlist.list_alerts(self.database, unread_only=True)["total"], 0)

    def test_expiry_warning_once(self):
        watch = watchlist.create_watch(self.database, {"value": "example.com"})
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        STATE["findings"] = [
            Finding("cert-validity", "x", {"days_remaining": 12}),
            Finding("rdap-event", soon, {"action": "expiration"}),
        ]
        first = watchlist.check_watch(self.database, watch["id"])
        self.assertEqual(len(first["alerts"]), 1)
        details = watchlist.list_alerts(self.database)["items"][0]["details"]["warnings"]
        self.assertTrue(any("certificate expires in 12 days" in text for text in details))
        self.assertTrue(any("Domain registration expires" in text for text in details))
        self.assertEqual(watchlist.check_watch(self.database, watch["id"])["alerts"], [])  # not repeated

    def test_network_required_and_due_selection(self):
        watch = watchlist.create_watch(self.database, {"value": "user:alice", "interval_minutes": 60})
        self.assertEqual(watch["query_type"], "username")
        self.assertEqual(watchlist.due_watches(self.database), [watch["id"]])
        STATE["findings"] = [Finding("account", "GitHub")]
        self.assertEqual(watchlist.run_due(self.database), 1)
        self.assertEqual(watchlist.due_watches(self.database), [])
        later = datetime.now(timezone.utc) + timedelta(minutes=61)
        self.assertEqual(watchlist.due_watches(self.database, later), [watch["id"]])
        update_settings(self.database, {"intel.allow_network": "false"})
        self.assertEqual(watchlist.run_due(self.database), 0)
        with self.assertRaises(ValidationError):
            watchlist.check_watch(self.database, watch["id"])

    def test_paused_watch_is_not_due(self):
        watch = watchlist.create_watch(self.database, {"value": "example.org"})
        watchlist.update_watch(self.database, watch["id"], {"enabled": False})
        self.assertEqual(watchlist.due_watches(self.database), [])


if __name__ == "__main__":
    unittest.main()
