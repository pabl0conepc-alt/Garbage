"""Typosquatting candidates: Rust/Python parity, kinds and the DoH check."""

import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, native
from garbage_intel.db import initialize
from garbage_intel.errors import ValidationError
from garbage_intel.intel import run_query
from garbage_intel.modules import typosquat
from garbage_intel.workspace import update_settings


class GeneratorTests(unittest.TestCase):
    def test_kinds(self):
        variants = dict((candidate, kind) for kind, candidate in typosquat.python_variants("google"))
        self.assertEqual(variants["gogle"], 1)
        self.assertEqual(variants["g0ogle"], 6)
        self.assertEqual(variants["goo-gle"], 7)
        self.assertEqual(variants["coogle"], 9)
        self.assertEqual(variants["goo.gle"], 11)
        self.assertNotIn("google", variants)
        self.assertIn((6, "rnodern"), typosquat.python_variants("modern"))
        self.assertEqual(typosquat.python_variants("-bad"), [])

    def test_generate(self):
        plan = typosquat.generate("Login-Secure.com.br")
        self.assertEqual((plan["label"], plan["suffix"]), ("login-secure", "com.br"))
        domains = {item["domain"]: item["kind"] for item in plan["candidates"]}
        self.assertEqual(domains["login-secure.com"], "tld-swap")
        self.assertNotIn("login-secure.com.br", domains)
        self.assertEqual(domains["logim-secure.com.br"], "replacement")
        self.assertEqual(len(domains), len(plan["candidates"]))  # one entry per spelling
        self.assertEqual({item["domain"]: item["kind"] for item in typosquat.generate("paypal.com")["candidates"]}["0aypal.com"], "replacement")
        with self.assertRaises(ValidationError):
            typosquat.generate("localhost")

    @unittest.skipIf(native.typosquat_variants("a") is None, "Rust engine not built")
    def test_rust_matches_python(self):
        generator = random.Random(11)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
        labels = ["google", "microsoft", "banco-do-brasil", "a", "rnw", "vvclm"]
        for _ in range(400):
            size = generator.randint(1, 20)
            labels.append("".join(generator.choice(alphabet) for _ in range(size)))
        for label in labels:
            self.assertEqual(native.typosquat_variants(label), typosquat.python_variants(label), label)


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "typo.sqlite3")
        initialize(self.database)
        update_settings(self.database, {"intel.allow_network": "true"})
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        self.directory.cleanup()

    def test_existing_candidates_are_reported(self):
        registered = {"example.net": ["a.iana-servers.net"], "examp1e.com": []}
        asked = []

        def fake(url, **options):
            name = url.split("name=")[1].split("&")[0]
            asked.append(name)
            if name in registered:
                answer = [{"type": 2, "data": server + "."} for server in registered[name]]
                return {"Status": 0, "Answer": answer}, None
            return {"Status": 3}, None

        with patch.object(typosquat.intel_connectors, "_get_json", fake):
            run = run_query(self.database, value="example.com", connector_ids=["typosquat"])
        self.assertEqual(len(asked), typosquat.MAX_CHECKS)
        self.assertEqual(asked[0].rsplit(".", 1)[0], "example")  # TLD swaps first
        results = {item["value"]: item for item in run["results"]}
        self.assertEqual(results["example.net"]["data"]["kind"], "tld-swap")
        self.assertEqual(results["example.net"]["data"]["nameservers"], ["a.iana-servers.net"])
        self.assertEqual(results["examp1e.com"]["data"]["kind"], "homoglyph")
        summary = next(item for item in run["results"] if item["result_type"] == "typosquat-summary")
        self.assertEqual(summary["data"]["existing"], 2)


if __name__ == "__main__":
    unittest.main()
