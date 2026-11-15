"""Monitor changes delivered to a webhook (Discord, Slack or JSON)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, monitoring
from garbage_intel.db import initialize
from garbage_intel.errors import ValidationError
from garbage_intel.intel import Connector, Finding, register_connector, unregister_connector
from garbage_intel.net import NetworkError

from tests.test_intel_connectors import result

HOOK = "https://discord.com/api/webhooks/123/SECRETTOKENabcd"


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "hooks.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()
        self.answers = [["a.example"]]
        register_connector(Connector("test-subs", "Subs", "test", ("domain",), lambda context: [Finding("subdomain", name) for name in self.answers[0]]))
        self.addCleanup(unregister_connector, "test-subs")
        self.sent = []
        monitoring.WEBHOOK_SEND = lambda work: work()
        self.addCleanup(setattr, monitoring, "WEBHOOK_SEND", None)

    def fetch(self, url, **options):
        self.sent.append({"url": url, "body": json.loads(options["body"]), "hosts": options["allowed_hosts"]})
        return result(url, {}, status=204)

    def test_settings_hide_the_url_and_validate(self):
        with self.assertRaises(ValidationError):
            monitoring.set_webhook(self.database, url="http://hooks.example/x", kind="json")
        with self.assertRaises(ValidationError):
            monitoring.set_webhook(self.database, url=HOOK, kind="telegram")
        shown = monitoring.set_webhook(self.database, url=HOOK, kind="discord")
        self.assertEqual((shown["host"], shown["format"]), ("discord.com", "discord"))
        self.assertNotIn("SECRETTOKEN", json.dumps(shown))

    def test_a_change_is_sent_once_in_the_chosen_format(self):
        monitoring.set_webhook(self.database, url=HOOK, kind="discord")
        monitor = monitoring.create_monitor(self.database, name="Subs", value="example.com", connector_ids=["test-subs"], interval_minutes=60)
        with patch.object(monitoring.net, "fetch", self.fetch):
            monitoring.run_monitor(self.database, monitor["id"])  # baseline: nothing sent
            self.answers[0] = ["a.example", "b.example"]
            monitoring.run_monitor(self.database, monitor["id"])
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["hosts"], ("discord.com",))
        self.assertIn("Novos: b.example", self.sent[0]["body"]["content"])
        self.assertEqual(self.sent[0]["body"]["allowed_mentions"], {"parse": []})
        self.assertTrue(monitoring.webhook(self.database)["last"]["ok"])

    def test_json_format_and_failures_are_recorded_without_the_url(self):
        monitoring.set_webhook(self.database, url="https://hooks.example.net/garbage/SECRET", kind="json")
        with patch.object(monitoring.net, "fetch", self.fetch):
            outcome = monitoring.test_webhook(self.database)
        self.assertEqual((outcome["ok"], self.sent[0]["body"]["event"]), (True, "test"))

        def down(url, **options):
            raise NetworkError(f"connection to {url} failed")

        with patch.object(monitoring.net, "fetch", down):
            failed = monitoring.test_webhook(self.database)
        self.assertFalse(failed["ok"])
        self.assertNotIn("SECRET", json.dumps(monitoring.webhook(self.database)))


if __name__ == "__main__":
    unittest.main()
