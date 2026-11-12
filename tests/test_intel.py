import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from garbage_intel import intel
from garbage_intel.api import create_server
from garbage_intel.errors import ModuleDisabledError, ValidationError
from garbage_intel.intel import (
    Connector,
    Finding,
    RateLimiter,
    detect_artifact,
    get_run,
    list_connectors,
    list_runs,
    register_connector,
    run_query,
    unregister_connector,
)
from garbage_intel.net import NetworkError
from garbage_intel.store import initialize
from garbage_intel.workspace import set_module_state, update_settings


class RuntimeTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()
        self.calls = []
        self.registered = []

    def tearDown(self):
        for connector_id in self.registered:
            unregister_connector(connector_id)
        intel.RATE_LIMITER.reset()
        self.temp_dir.cleanup()

    def add(self, connector_id, run, **options):
        register_connector(
            Connector(
                connector_id=connector_id,
                name=connector_id,
                description="test connector",
                accepts=options.pop("accepts", ("domain", "ipv4")),
                run=run,
                **options,
            )
        )
        self.registered.append(connector_id)


class DetectionTests(RuntimeTestCase):
    def test_detects_refanged_and_canonical_artifacts(self):
        self.assertEqual(detect_artifact("evil[.]example")["type"], "domain")
        self.assertEqual(detect_artifact("hxxps://a.example/x")["value"], "https://a.example/x")
        self.assertEqual(detect_artifact("cve-2024-3094"), {"type": "cve", "value": "CVE-2024-3094", "label": "CVE"})
        self.assertEqual(detect_artifact("AS15169")["type"], "asn")
        with self.assertRaises(ValidationError):
            detect_artifact("not an artifact at all")
        with self.assertRaises(ValidationError):
            detect_artifact("")


class RateLimiterTests(unittest.TestCase):
    def test_bucket_refills_over_time(self):
        now = [0.0]
        limiter = RateLimiter(clock=lambda: now[0])
        self.assertTrue(limiter.acquire("x", 2))
        self.assertTrue(limiter.acquire("x", 2))
        self.assertFalse(limiter.acquire("x", 2))
        now[0] += 30.0
        self.assertTrue(limiter.acquire("x", 2))
        self.assertTrue(limiter.acquire("other", 1))
        self.assertTrue(limiter.acquire("unlimited", 0))


class OrchestratorTests(RuntimeTestCase):
    def test_local_connectors_run_and_persist_provenance(self):
        run = run_query(self.database, value="8.8.8.8")
        self.assertEqual(run["query_type"], "ipv4")
        self.assertEqual(run["status"], "completed")
        sources = {item["connector_id"]: item for item in run["sources"]}
        self.assertEqual(sources["local-structure"]["status"], "ok")
        self.assertIn(sources["local-workspace"]["status"], {"ok", "empty"})
        self.assertGreater(run["result_count"], 0)
        self.assertEqual(get_run(self.database, run["id"])["id"], run["id"])
        self.assertEqual(list_runs(self.database)["total"], 1)

    def test_network_connectors_are_skipped_until_allowed(self):
        def remote(context):
            self.calls.append(context.query_value)
            return [Finding("record", "1.2.3.4", {"ttl": 60}, "https://api.example/x", "ab" * 32)]

        self.add("test-remote", remote, network=True)
        run = run_query(self.database, value="example.com", connector_ids=["test-remote"])
        self.assertEqual(run["sources"][0]["status"], "network-disabled")
        self.assertEqual(self.calls, [])
        availability = {
            item["connector_id"]: item["availability"]
            for item in list_connectors(self.database)["items"]
        }
        self.assertEqual(availability["test-remote"], "network-disabled")

        update_settings(self.database, {"intel.allow_network": "true"})
        run = run_query(self.database, value="example.com", connector_ids=["test-remote"])
        self.assertEqual(run["sources"][0]["status"], "ok")
        self.assertEqual(run["results"][0]["source_url"], "https://api.example/x")
        self.assertEqual(run["results"][0]["data"], {"ttl": 60})
        self.assertEqual(self.calls, ["example.com"])

    def test_cache_reuses_results_within_ttl(self):
        def counted(context):
            self.calls.append(context.query_value)
            return [Finding("record", "x")]

        self.add("test-cached", counted, ttl_seconds=600)
        first = run_query(self.database, value="example.com", connector_ids=["test-cached"])
        second = run_query(self.database, value="example.com", connector_ids=["test-cached"])
        third = run_query(
            self.database, value="example.com", connector_ids=["test-cached"], use_cache=False
        )
        self.assertFalse(first["sources"][0]["cached"])
        self.assertTrue(second["sources"][0]["cached"])
        self.assertFalse(third["sources"][0]["cached"])
        self.assertEqual(len(self.calls), 2)

    def test_errors_rate_limits_and_unsupported_types_are_isolated(self):
        def broken(context):
            raise NetworkError("connection to api.example failed")

        def crashing(context):
            raise RuntimeError("secret internal detail")

        self.add("test-broken", broken)
        self.add("test-crash", crashing)
        self.add("test-limited", lambda context: [Finding("x", "y")], rate_per_minute=1)
        self.add("test-hash-only", lambda context: [], accepts=("sha256",))
        run_query(self.database, value="example.com", connector_ids=["test-limited"])
        run = run_query(
            self.database,
            value="example.com",
            connector_ids=["test-broken", "test-crash", "test-limited", "test-hash-only"],
        )
        statuses = {item["connector_id"]: item for item in run["sources"]}
        self.assertEqual(run["status"], "completed-with-errors")
        self.assertEqual(statuses["test-broken"]["status"], "error")
        self.assertIn("api.example", statuses["test-broken"]["error"])
        self.assertEqual(statuses["test-crash"]["error"], "connector failed unexpectedly")
        self.assertEqual(statuses["test-limited"]["status"], "rate-limited")
        self.assertEqual(statuses["test-hash-only"]["status"], "unsupported")
        health = {
            item["connector_id"]: item["status"]
            for item in list_connectors(self.database)["items"]
        }
        self.assertEqual(health["test-broken"]["error_count"], 1)

    def test_input_validation(self):
        with self.assertRaises(ValidationError):
            run_query(self.database, value="example.com", query_type="ipv4")
        with self.assertRaises(ValidationError):
            run_query(self.database, value="example.com", connector_ids=["missing"])
        with self.assertRaises(ValidationError):
            run_query(self.database, value="example.com", connector_ids="local-structure")

    def test_module_gate(self):
        set_module_state(self.database, "intel-orchestrator", "disabled")
        with self.assertRaises(ModuleDisabledError):
            run_query(self.database, value="example.com")

    def test_registry_rejects_invalid_connectors(self):
        with self.assertRaises(ValueError):
            register_connector(
                Connector("Bad Id", "x", "x", ("domain",), lambda context: [])
            )
        with self.assertRaises(ValueError):
            register_connector(
                Connector("bad-type", "x", "x", ("phone",), lambda context: [])
            )


class IntelApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "intel.sqlite3"
        initialize(self.database)
        intel.RATE_LIMITER.reset()
        self.server = create_server(self.database, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {"Origin": f"http://127.0.0.1:{self.port}"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_routes(self):
        status, body = self.request("GET", "/api/intel/connectors")
        self.assertEqual(status, 200)
        self.assertFalse(body["network_allowed"])
        self.assertIn("local-structure", {item["connector_id"] for item in body["items"]})

        status, body = self.request("GET", "/api/intel/detect?value=evil%5B.%5Dexample")
        self.assertEqual((status, body["type"], body["value"]), (200, "domain", "evil.example"))

        status, run = self.request("POST", "/api/intel/runs", {"value": "1.1.1.1"})
        self.assertEqual(status, 201)
        self.assertEqual(run["query_type"], "ipv4")

        status, body = self.request("GET", f"/api/intel/runs/{run['id']}")
        self.assertEqual((status, body["id"]), (200, run["id"]))
        status, body = self.request("GET", "/api/intel/runs")
        self.assertEqual((status, body["total"]), (200, 1))

        status, body = self.request("POST", "/api/intel/runs", {"value": "x", "bogus": 1})
        self.assertEqual(status, 400)
        status, body = self.request("POST", "/api/intel/runs", {"value": "1.1.1.1", "use_cache": "yes"})
        self.assertEqual(status, 400)
        status, body = self.request(
            "GET", "/api/intel/runs/00000000-0000-0000-0000-000000000000"
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
