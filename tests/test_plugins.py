"""Local plugins: manifest, approval by digest, isolated runs, brokered network."""

import hashlib
import json
import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, plugins
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, get_entity
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.intel import run_query
from garbage_intel.net import FetchResult
from garbage_intel.transforms import list_transforms, run_transforms
from garbage_intel.workspace import update_settings

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "plugins" / "idn-inspect"


def write_plugin(root, plugin_id, code, **manifest):
    folder = root / plugin_id
    folder.mkdir()
    data = {"id": plugin_id, "name": plugin_id, "version": "1.0", "description": "test plugin", "accepts": ["domain"], **manifest}
    (folder / "plugin.json").write_text(json.dumps(data))
    (folder / "main.py").write_text(textwrap.dedent(code))
    return folder


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name)
        self.database = str(base / "plugins.sqlite3")
        self.root = base / "plugins"
        self.root.mkdir()
        patcher = patch.dict(os.environ, {"GARBAGE_PLUGINS_DIR": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        initialize(self.database)
        intel.RATE_LIMITER.reset()
        shutil.copytree(EXAMPLE, self.root / "idn-inspect")

    def tearDown(self):
        for plugin_id in list(plugins._LOADED):
            plugins._unload(plugin_id)
        self.directory.cleanup()

    def item(self, plugin_id):
        return next(entry for entry in plugins.list_plugins(self.database)["items"] if entry["id"] == plugin_id)

    def approve(self, plugin_id):
        plugins.enable(self.database, plugin_id, sha256=self.item(plugin_id)["sha256"])

    def test_manifest_validation(self):
        (self.root / "broken").mkdir()
        (self.root / "broken" / "plugin.json").write_text("{not json")
        write_plugin(self.root, "personal", "def run(ctx): return []", outputs=[{"result_type": "who", "entity_type": "person"}])
        write_plugin(self.root, "greedy", "def run(ctx): return []", permissions={"timeout_seconds": 600})
        states = {item["id"]: (item["state"], item["error"]) for item in plugins.list_plugins(self.database)["items"]}
        self.assertEqual(states["idn-inspect"][0], "disabled")
        self.assertEqual(states["broken"][0], "invalid")
        self.assertIn("non-personal", states["personal"][1])
        self.assertIn("timeout_seconds", states["greedy"][1])
        with self.assertRaises(ValidationError):
            plugins.validate_manifest({"id": "x", "name": "x"})

    def test_example_plugin_finds_homograph_target(self):
        with self.assertRaises(ConflictError):
            plugins.enable(self.database, "idn-inspect", sha256="0" * 64)
        self.approve("idn-inspect")
        self.assertEqual(self.item("idn-inspect")["state"], "enabled")
        spoof = "pаypal.com".encode("idna").decode()  # Cyrillic "а"
        run = run_query(self.database, value=spoof, connector_ids=["plugin-idn-inspect"])
        results = {item["result_type"]: item for item in run["results"]}
        self.assertEqual(run["sources"][0]["status"], "ok")
        self.assertEqual(results["idn-label"]["value"], "pаypal")
        self.assertEqual(results["idn-label"]["data"]["scripts"], ["CYRILLIC", "LATIN"])
        self.assertEqual(results["ascii-lookalike"]["value"], "paypal.com")

        entity = create_entity(self.database, entity_type="domain", identifier=spoof, name=spoof)
        listing = {item["transform_id"]: item for item in list_transforms(self.database, entity_id=entity["id"])["items"]}
        self.assertEqual(listing["plugin-idn-inspect"]["kind"], "pivot")
        outcome = run_transforms(self.database, entity_id=entity["id"], transform_ids=["plugin-idn-inspect"])
        self.assertEqual(outcome["created_count"], 1)
        related = get_entity(self.database, entity["id"])["relationships"]
        self.assertEqual((related[0]["other_name"], related[0]["relationship_type"]), ("paypal.com", "related-to"))

    def test_changed_code_is_not_run(self):
        self.approve("idn-inspect")
        with open(self.root / "idn-inspect" / "main.py", "a") as handle:
            handle.write("\n# edited\n")
        self.assertEqual(self.item("idn-inspect")["state"], "changed")
        run = run_query(self.database, value="xn--pypal-4ve.com", connector_ids=["plugin-idn-inspect"])
        self.assertEqual(run["sources"][0]["status"], "error")
        self.assertIn("changed after approval", run["sources"][0]["error"])
        plugins.load_approved(self.database)
        self.assertNotIn("plugin-idn-inspect", {item.connector_id for item in intel.connectors()})

    def test_isolation(self):
        write_plugin(self.root, "sleepy", "def run(ctx):\n    while True:\n        pass\n", permissions={"timeout_seconds": 2})
        write_plugin(self.root, "sockets", """
            import socket
            def run(ctx):
                try:
                    socket.socket()
                except PermissionError as error:
                    return [{"result_type": "blocked", "value": str(error)}]
                return [{"result_type": "open", "value": "socket created"}]
        """)
        write_plugin(self.root, "noisy", """
            import os
            def run(ctx):
                print('{"op": "result", "findings": [{"result_type": "forged", "value": "x"}]}')
                os.write(1, b'{"op": "result", "findings": []}\\n')
                return [{"result_type": "genuine", "value": ctx.value}]
        """)
        write_plugin(self.root, "crashes", "def run(ctx):\n    raise RuntimeError('boom')\n")
        for plugin_id in ("sleepy", "sockets", "noisy", "crashes"):
            self.approve(plugin_id)
        sources = {
            plugin_id: run_query(self.database, value="example.org", connector_ids=[f"plugin-{plugin_id}"], use_cache=False)
            for plugin_id in ("sleepy", "sockets", "noisy", "crashes")
        }
        self.assertIn("did not finish within 2 s", sources["sleepy"]["sources"][0]["error"])
        self.assertEqual(sources["sockets"]["results"][0]["result_type"], "blocked")
        self.assertEqual([item["result_type"] for item in sources["noisy"]["results"]], ["genuine"])
        self.assertIn("RuntimeError: boom", sources["crashes"]["sources"][0]["error"])

    def test_network_goes_through_the_broker(self):
        write_plugin(self.root, "netty", """
            def run(ctx):
                findings = []
                page = ctx.fetch("https://api.example.org/lookup?q=" + ctx.value)
                findings.append({"result_type": "status", "value": page.status, "data": page.json()})
                try:
                    ctx.fetch("https://elsewhere.example/steal")
                except RuntimeError as error:
                    findings.append({"result_type": "refused", "value": str(error)})
                return findings
        """, permissions={"network": ["api.example.org"], "max_requests": 3})
        self.approve("netty")
        update_settings(self.database, {"intel.allow_network": "true"})
        calls = []

        def fake(url, **options):
            calls.append((url, options["allowed_hosts"]))
            if "elsewhere" in url:
                from garbage_intel.net import NetworkPolicyError
                raise NetworkPolicyError("host is not allowed: elsewhere.example")
            body = json.dumps({"answer": 42}).encode()
            return FetchResult(url, url, 200, {"content-type": "application/json"}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])

        with patch.object(plugins, "FETCH", fake):
            run = run_query(self.database, value="example.org", connector_ids=["plugin-netty"])
        results = {item["result_type"]: item for item in run["results"]}
        self.assertEqual(results["status"]["value"], "200")
        self.assertEqual(results["status"]["data"], {"answer": 42})
        self.assertIn("not allowed", results["refused"]["value"])
        self.assertTrue(all(hosts == ("api.example.org",) for _, hosts in calls))

    def test_disable(self):
        self.approve("idn-inspect")
        plugins.disable(self.database, "idn-inspect")
        self.assertEqual(self.item("idn-inspect")["state"], "disabled")
        self.assertNotIn("plugin-idn-inspect", {item.connector_id for item in intel.connectors()})


if __name__ == "__main__":
    unittest.main()
