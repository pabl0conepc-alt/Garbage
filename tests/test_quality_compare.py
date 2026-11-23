"""Catalogue block 9: run comparison, transient retries and usage counts."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import compare, intel
from garbage_intel.errors import ValidationError
from garbage_intel.intel import Connector, ConnectorContext, Finding, _run_one, register_connector, unregister_connector
from garbage_intel.net import NetworkError
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings

PROFILES = {
    "alice": [
        Finding("account", "GitHub", {"profile_url": "https://github.com/alice"}),
        Finding("account", "Keybase", {"profile_url": "https://keybase.io/alice"}),
        Finding("account", "Lichess", {}),
        Finding("username", "Alice", {"display_name": "Alice Doe"}),
        Finding("avatar", "https://cdn.example/a.png"),
        Finding("description", "Security researcher from Recife who loves chess and rust"),
        Finding("group", "Rustaceans BR"),
    ],
    "alice_99": [
        Finding("account", "GitHub", {"profile_url": "https://github.com/alice_99"}),
        Finding("account", "Keybase", {}),
        Finding("username", "alice_99", {"display_name": "Alice Doe"}),
        Finding("avatar", "https://cdn.example/a.png"),
        Finding("description", "Security researcher in Recife, chess and rust fan"),
        Finding("group", "Rustaceans BR"),
    ],
    "bob": [Finding("account", "Codeberg"), Finding("username", "bob")],
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.tmp.name) / "q.db")
        initialize(self.database)
        update_settings(self.database, {"intel.allow_network": "true"})
        self.saved = intel.connectors()
        for connector in self.saved:
            unregister_connector(connector.connector_id)
        register_connector(Connector("fake-profiles", "Fake", "test", ("username",), lambda ctx: list(PROFILES[ctx.query_value]), network=True))
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        unregister_connector("fake-profiles")
        for connector in self.saved:
            register_connector(connector)
        self.tmp.cleanup()

    def run_for(self, name):
        return intel.run_query(self.database, value=f"user:{name}", wait=True)["id"]


class CompareTests(Base):
    def test_strong_match_explains_each_signal(self):
        result = compare.compare_runs(self.database, self.run_for("alice"), self.run_for("alice_99"))
        signals = {item["signal"]: item for item in result["signals"]}
        self.assertIn("same-name", signals)  # display name "Alice Doe" on both
        self.assertEqual(signals["same-image"]["evidence"], ["https://cdn.example/a.png"])
        self.assertEqual(signals["same-sites"]["evidence"], ["GitHub", "Keybase"])
        self.assertIn("group: Rustaceans BR", signals["shared-values"]["evidence"])
        self.assertIn("similar-text", signals)
        self.assertEqual(result["level"], "strong")
        self.assertLessEqual(result["score"], 100)
        self.assertIn("not an identification", result["caution"])

    def test_unrelated_and_validation(self):
        result = compare.compare_runs(self.database, self.run_for("alice"), self.run_for("bob"))
        self.assertEqual((result["score"], result["level"], result["signals"]), (0, "none", []))
        run = self.run_for("bob")
        with self.assertRaises(ValidationError):
            compare.compare_runs(self.database, run, run)


class RetryAndUsageTests(Base):
    def test_transient_errors_retry_once(self):
        calls = []

        def flaky(context):
            calls.append(1)
            if len(calls) == 1:
                raise NetworkError("the source answered HTTP 503")
            return [Finding("x", "ok")]

        with patch.object(intel, "RETRY_DELAY_SECONDS", 0):
            status, findings, _, _ = _run_one(Connector("flaky", "F", "t", ("domain",), flaky), ConnectorContext("", "domain", "a.example", None))
        self.assertEqual((status, len(calls)), ("ok", 2))

        for message in ("the source rate-limited this request (HTTP 429)", "the source answered HTTP 404"):
            calls.clear()

            def failing(context, message=message):
                calls.append(1)
                raise NetworkError(message)

            with patch.object(intel, "RETRY_DELAY_SECONDS", 0):
                status, _, error, _ = _run_one(Connector("f2", "F", "t", ("domain",), failing), ConnectorContext("", "domain", "a.example", None))
            self.assertEqual((status, len(calls)), ("error", 1), message)

    def test_usage_today(self):
        register_connector(Connector("cached-profiles", "Cached", "test", ("username",), lambda ctx: [Finding("x", "1")], network=True, ttl_seconds=3600))
        try:
            self.run_for("alice")
            self.run_for("alice")  # the second run is answered from cache by cached-profiles
            rows = {item["connector_id"]: item["today"] for item in intel.list_connectors(self.database)["items"]}
        finally:
            unregister_connector("cached-profiles")
        self.assertEqual(rows["fake-profiles"], {"connector_id": "fake-profiles", "requests": 2, "errors": 0, "cached": 0})
        self.assertEqual((rows["cached-profiles"]["requests"], rows["cached-profiles"]["cached"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
