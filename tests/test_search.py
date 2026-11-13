"""Step 3: asynchronous runs, ranked full-text search, organisation sources."""

import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, delete_entity, update_entity
from garbage_intel.intel import Connector, Finding, get_run, recover_interrupted_runs, register_connector, run_query, unregister_connector
from garbage_intel.modules import intel_org_connectors as org
from garbage_intel.net import FetchResult
from garbage_intel.store import add_observation, create_investigation
from garbage_intel.workspace import fts_query, global_search, update_settings


def reply(url, status=200, payload=None, text=None, headers=None):
    body = text.encode() if text is not None else json.dumps(payload).encode()
    return FetchResult(url, url, status, headers or {"content-type": "application/json"}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "search.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        self.directory.cleanup()


class AsyncRunTests(Base):
    def test_background_run_reports_progress(self):
        release = threading.Event()

        def slow(context):
            release.wait(5)
            return [Finding("fact", "late answer")]

        register_connector(Connector("test-slow", "Slow", "test", ("domain",), slow))
        self.addCleanup(unregister_connector, "test-slow")
        run = run_query(self.database, value="example.org", connector_ids=["test-slow", "local-structure"], wait=False)
        self.assertEqual(run["status"], "running")
        self.assertEqual(run["progress"]["total"], 2)
        self.assertGreaterEqual(run["progress"]["pending"], 1)
        statuses = {item["connector_id"]: item["status"] for item in run["sources"]}
        self.assertEqual(statuses["test-slow"], "pending")
        release.set()
        for _ in range(100):
            run = get_run(self.database, run["id"])
            if run["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["progress"]["pending"], 0)
        self.assertIn("late answer", [item["value"] for item in run["results"]])
        self.assertEqual(run["result_count"], len(run["results"]))

    def test_synchronous_run_is_unchanged(self):
        run = run_query(self.database, value="example.org", connector_ids=["local-structure"])
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["progress"]["pending"], 0)

    def test_interrupted_runs_are_closed(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO intel_runs (id, query_type, query_value, status, connector_count, started_at) VALUES ('r1', 'domain', 'x.example', 'running', 1, '2026-01-01T00:00:00Z')"
            )
            connection.execute(
                """INSERT INTO intel_results (id, run_id, connector_id, status, cached, result_type, value, data_json,
                   source_url, response_sha256, error, elapsed_ms, fetched_at)
                   VALUES ('x1', 'r1', 'dns-doh', 'pending', 0, '', '', '{}', '', '', '', 0, '2026-01-01T00:00:00Z')"""
            )
        self.assertEqual(recover_interrupted_runs(self.database), 1)
        run = get_run(self.database, "r1")
        self.assertEqual(run["status"], "interrupted")
        self.assertEqual(run["sources"][0]["status"], "error")
        self.assertIn("restart", run["sources"][0]["error"])


class FullTextTests(Base):
    def setUp(self):
        super().setUp()
        self.case = create_investigation(self.database, "Operação Cobalto", "Campanha de phishing contra bancos")["id"]
        self.domain = create_entity(self.database, entity_type="domain", identifier="login-secure.example", name="login-secure.example", description="Página de login falsa")
        self.org = create_entity(self.database, entity_type="organization", name="Hosting Alpha", description="hospeda login-secure.example")
        add_observation(self.database, self.case, title="Nota", content="O kit de phishing usa login-secure.example e um formulário falso", source_reference="note://t", collection_basis="user-provided")

    def test_query_building(self):
        self.assertEqual(fts_query("login-secure.example"), '"login-secure.example"*')
        self.assertEqual(fts_query('a "OR" NEAR(b)'), '"a" "OR" "NEAR(b)"*')
        self.assertEqual(fts_query("  ...  "), "")

    def test_ranking_snippets_and_diacritics(self):
        result = global_search(self.database, "login-secure.example")
        self.assertEqual(result["engine"], "fts5")
        best = result["best"]
        # The entity whose name is the match outranks mentions in descriptions.
        self.assertEqual((best[0]["kind"], best[0]["id"]), ("entities", self.domain["id"]))
        self.assertIn("\x02", best[0]["title_marked"])
        kinds = {group["key"]: group["total"] for group in result["groups"]}
        self.assertEqual(kinds["entities"], 2)
        self.assertEqual(kinds["observations"], 1)
        observation = next(group for group in result["groups"] if group["key"] == "observations")["items"][0]
        self.assertIn("\x02login-secure.example\x03", observation["snippet"])
        self.assertEqual(global_search(self.database, "operacao")["best"][0]["id"], self.case)  # accent-insensitive
        self.assertEqual(global_search(self.database, "cobal")["best"][0]["id"], self.case)  # prefix
        self.assertEqual(global_search(self.database, '"OR" ("')["engine"], "fts5")  # operators are literal, no syntax error

    def test_index_follows_updates_and_deletes(self):
        update_entity(self.database, self.org["id"], {"name": "Bulletproof Beta"})
        self.assertEqual(global_search(self.database, "bulletproof")["best"][0]["id"], self.org["id"])
        delete_entity(self.database, self.org["id"], force=True)
        self.assertEqual(global_search(self.database, "bulletproof")["total"], 0)

    def test_falls_back_without_the_index(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TABLE search_index")
        result = global_search(self.database, "login-secure")
        self.assertEqual(result["engine"], "like")
        self.assertGreater(result["total"], 0)


class OrganisationConnectorTests(Base):
    def setUp(self):
        super().setUp()
        update_settings(self.database, {"intel.allow_network": "true", "intel.allow_target_contact": "true"})

    def test_github_target(self):
        self.assertEqual(org.github_target("https://github.com/mitre-attack/attack-stix-data"), ("mitre-attack", "attack-stix-data"))
        self.assertEqual(org.github_target("https://github.com/cisagov"), ("cisagov", ""))
        self.assertEqual(org.github_target("https://github.com/x/y.git"), ("x", "y"))
        self.assertIsNone(org.github_target("https://github.com/topics/osint"))
        self.assertIsNone(org.github_target("https://gitlab.com/a/b"))

    def test_github_organisation_and_people(self):
        pages = {
            "/users/cisagov": {"login": "cisagov", "type": "Organization"},
            "/orgs/cisagov": {"login": "cisagov", "name": "CISA", "blog": "www.cisa.gov", "public_repos": 300, "location": "United States"},
            "/orgs/cisagov/repos": [{"html_url": "https://github.com/cisagov/kev-data", "full_name": "cisagov/kev-data", "homepage": "https://www.cisa.gov/kev", "language": None, "license": {"spdx_id": "CC0-1.0"}}],
            "/users/octocat": {"login": "octocat", "type": "User", "name": "Some Person", "location": "Somewhere"},
        }

        def fake(url, **options):
            self.assertEqual(options["allowed_hosts"], ("api.github.com",))
            path = url.replace(org.GITHUB_API, "").split("?")[0]
            return reply(url, payload=pages[path]) if path in pages else reply(url, 404, {})

        with patch.object(org, "FETCH", fake):
            run = run_query(self.database, value="https://github.com/cisagov", connector_ids=["github"])
            values = {(item["result_type"], item["value"]) for item in run["results"]}
            self.assertIn(("website", "https://www.cisa.gov"), values)
            self.assertIn(("repository", "https://github.com/cisagov/kev-data"), values)
            self.assertIn(("repo-homepage", "https://www.cisa.gov/kev"), values)
            person = run_query(self.database, value="https://github.com/octocat", connector_ids=["github"])
            self.assertEqual([item["value"] for item in person["results"]], ["personal account; not collected"])
            self.assertNotIn("Some Person", json.dumps(person))

    def test_github_rate_limit(self):
        with patch.object(org, "FETCH", lambda url, **options: reply(url, 403, {}, headers={"x-ratelimit-remaining": "0"})):
            run = run_query(self.database, value="https://github.com/cisagov/x", connector_ids=["github"])
        self.assertEqual(run["sources"][0]["status"], "error")
        self.assertIn("rate-limited", run["sources"][0]["error"])

    def test_security_txt(self):
        text = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:security@example.org
Contact: https://example.org/report
Expires: 2099-01-01T00:00:00Z
Encryption: https://example.org/pgp.txt
Policy: https://example.org/disclosure
Preferred-Languages: en, pt
-----BEGIN PGP SIGNATURE-----
"""
        parsed = org.parse_security_txt(text)
        self.assertTrue(parsed["signed"])
        self.assertFalse(parsed["expired"])
        self.assertEqual(parsed["fields"]["contact"], ["mailto:security@example.org", "https://example.org/report"])
        with patch.object(org, "FETCH", lambda url, **options: reply(url, text=text, headers={"content-type": "text/plain; charset=utf-8"})):
            run = run_query(self.database, value="example.org", connector_ids=["security-txt"])
        values = {(item["result_type"], item["value"]) for item in run["results"]}
        self.assertIn(("security-contact-email", "security@example.org"), values)
        self.assertIn(("security-policy", "https://example.org/disclosure"), values)
        html = "<html>Contact: nobody</html>"
        with patch.object(org, "FETCH", lambda url, **options: reply(url, text=html, headers={"content-type": "text/html"})):
            run = run_query(self.database, value="example.org", connector_ids=["security-txt"], use_cache=False)
        self.assertEqual([item["value"] for item in run["results"]], ["not published"])


if __name__ == "__main__":
    unittest.main()
