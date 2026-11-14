"""End-to-end checks.

`WorkflowTests` drives a real server over HTTP through a whole case: create,
link entities, attach evidence, follow its custody, monitor an artifact,
report, package and import into a second workspace.

`FrontendContractTests` reads the shipped web files and checks that they
agree with the backend: every script is served, every navigation entry has a
view, an icon and a known module, and every API path the interface calls has
a route.
"""

import base64
import hashlib
import http.client
import itertools
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path

from garbage_intel import intel
from garbage_intel.api import _STATIC_FILES, ROUTES, create_server
from garbage_intel.db import DEFAULT_MODULES
from garbage_intel.intel import Connector, Finding, register_connector, unregister_connector
from garbage_intel.store import initialize

WEB = Path(__file__).resolve().parent.parent / "web"


class Server:
    def __init__(self, directory: str, name: str):
        self.database = Path(directory) / name
        initialize(self.database)
        self.server = create_server(self.database, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.port = self.server.server_port

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, payload=None, raw=False):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Origin": f"http://127.0.0.1:{self.port}"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        if raw:
            return response.status, data, dict(response.getheaders())
        return response.status, json.loads(data)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = Server(self.directory.name, "first.sqlite3")
        self.addCleanup(self.app.close)
        intel.RATE_LIMITER.reset()
        self.published = ["mail.example.org"]
        register_connector(
            Connector("e2e-subdomains", "E2E subdomains", "test", ("domain",),
                      lambda context: [Finding("subdomain", name) for name in self.published])
        )
        self.addCleanup(unregister_connector, "e2e-subdomains")

    def ok(self, method, path, payload=None, expected=(200, 201)):
        status, body = self.app.request(method, path, payload)
        self.assertIn(status, expected, f"{method} {path} -> {status}: {body}")
        return body

    def test_case_from_creation_to_imported_copy(self):
        case = self.ok("POST", "/api/investigations", {"name": "E2E infra", "description": "end to end", "objective": "Map example.org"})
        case_id = case["id"]

        # Entities and a relationship, both linked to the case.
        domain = self.ok("POST", "/api/entities", {"entity_type": "domain", "name": "example.org", "identifier": "example.org"})
        address = self.ok("POST", "/api/entities", {"entity_type": "ipv4", "name": "192.0.2.10", "identifier": "192.0.2.10"})
        for entity in (domain, address):
            self.ok("POST", f"/api/investigations/{case_id}/entities", {"entity_id": entity["id"]})
        self.ok("POST", "/api/relationships", {
            "source_entity_id": domain["id"], "target_entity_id": address["id"], "relationship_type": "hosted-on",
            "investigation_id": case_id, "source_reference": "https://dns.example/answer",
        })
        graph = self.ok("GET", f"/api/graph?investigation_id={case_id}")
        self.assertEqual({node["name"] for node in graph["nodes"]}, {"example.org", "192.0.2.10"})
        self.assertEqual(len(graph["edges"]), 1)

        # Evidence: recorded, verified, accessed, annotated; the chain holds.
        content = b"captured page for example.org\n"
        evidence = self.ok("POST", f"/api/investigations/{case_id}/evidence", {
            "title": "Captured page", "original_name": "page.txt", "source_reference": "https://example.org/",
            "content_base64": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest(),
        })
        self.assertTrue(self.ok("POST", f"/api/evidence/{evidence['id']}/verify", {}).get("verified", True))
        status, downloaded, _ = self.app.request("GET", f"/api/evidence/{evidence['id']}/download", raw=True)
        self.assertEqual((status, downloaded), (200, content))
        self.ok("POST", f"/api/evidence/{evidence['id']}/notes", {"body": "Seen on the public home page."})
        chain = self.ok("GET", f"/api/evidence/{evidence['id']}/custody")
        self.assertTrue(chain["intact"])
        self.assertEqual([event["action"] for event in chain["events"]][:2], ["recorded", "verified"])

        # Search finds the case records.
        found = self.ok("GET", "/api/search?q=example")
        hits = {item["title"] for group in found["groups"] for item in group["items"]} | {item["title"] for item in found["best"]}
        self.assertIn("example.org", hits)
        self.assertIn("E2E infra", hits)

        # Monitoring: baseline, then a new subdomain shows up and notifies.
        monitor = self.ok("POST", "/api/monitors", {"name": "Subdomains", "value": "example.org", "connectors": ["e2e-subdomains"], "interval_minutes": 60, "investigation_id": case_id})
        self.assertEqual(self.ok("POST", f"/api/monitors/{monitor['id']}/run", {})["status"], "baseline")
        self.published.append("vpn.example.org")
        changed = self.ok("POST", f"/api/monitors/{monitor['id']}/run", {})
        self.assertEqual(([item["value"] for item in changed["added"]], changed["removed_count"]), (["vpn.example.org"], 0))
        inbox = self.ok("GET", "/api/notifications?unread=1")
        self.assertEqual(inbox["unread"], 1)
        self.ok("POST", "/api/notifications/read", {"ids": "all"})

        # Report with chosen sections, in every format.
        report = self.ok("GET", f"/api/investigations/{case_id}/report")
        self.assertEqual(report["investigation"]["objective"], "Map example.org")
        for file_format, marker in (("html", b"<html"), ("markdown", b"# "), ("json", b"{"), ("csv", b",")):
            status, body, headers = self.app.request("GET", f"/api/investigations/{case_id}/export?format={file_format}&sections=summary,entities,custody,methodology", raw=True)
            self.assertEqual(status, 200, body[:200])
            self.assertIn(marker, body[:400].lower() if file_format == "html" else body[:400])
            self.assertIn("attachment", headers.get("Content-Disposition", ""))

        # Package the case and import it into a separate workspace.
        status, raw_package, _ = self.app.request("GET", f"/api/investigations/{case_id}/package", raw=True)
        self.assertEqual(status, 200)
        package = json.loads(raw_package)
        second = Server(self.directory.name, "second.sqlite3")
        self.addCleanup(second.close)
        status, preview = second.request("POST", "/api/cases/import", {"package": package})
        self.assertEqual(status, 200, preview)
        status, imported = second.request("POST", "/api/cases/import", {"package": package, "commit": True})
        self.assertEqual(status, 201, imported)
        new_case = imported.get("investigation_id") or imported.get("id") or imported["investigation"]["id"]
        status, copy = second.request("GET", f"/api/investigations/{new_case}/report")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(item["name"] for item in copy["entities"]), ["192.0.2.10", "example.org"])
        self.assertEqual(len(copy["relationships"]), 1)
        self.assertEqual(len(copy["evidence"]), 1)
        status, copied_file, _ = second.request("GET", f"/api/evidence/{copy['evidence'][0]['id']}/download", raw=True)
        self.assertEqual((status, copied_file), (200, content))

        # Archiving hides the case from the default list but keeps it.
        self.ok("POST", f"/api/investigations/{case_id}/archive", {"archived": True})
        listed = self.ok("GET", "/api/investigations")
        self.assertNotIn(case_id, [item["id"] for item in listed if not item.get("archived_at")])


class FrontendContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = (WEB / "index.html").read_text(encoding="utf-8")
        cls.scripts = {path.name: path.read_text(encoding="utf-8") for path in WEB.glob("*.js")}
        cls.app = cls.scripts["app.js"]

    def test_every_script_is_served_and_exists(self):
        referenced = re.findall(r'<script[^>]+src="/([^"]+)"', self.index)
        self.assertGreater(len(referenced), 10)
        for name in referenced:
            self.assertIn(name, _STATIC_FILES, f"{name} is not in _STATIC_FILES")
            self.assertTrue((WEB / name).is_file(), f"{name} is missing")
        for name in re.findall(r'<link[^>]+href="/([^"]+)"', self.index):
            self.assertIn(name, _STATIC_FILES)
        # report.js is loaded by the printable report page, not the app shell.
        printable = (Path(__file__).resolve().parent.parent / "garbage_intel" / "reporting.py").read_text(encoding="utf-8")
        unreferenced = {name for name in self.scripts if name not in referenced and f'src=\\"/{name}\\"' not in printable}
        self.assertEqual(unreferenced, set(), "scripts shipped but never loaded")

    def navigation(self):
        block = self.app[self.app.index("G.NAV = [") : self.app.index("];", self.app.index("G.NAV = ["))]
        return [dict(re.findall(r'(\w+): "([^"]*)"', item)) for item in re.findall(r"\{ view: [^}]+\}", block)]

    def test_navigation_entries_have_views_icons_and_modules(self):
        views = set()
        for source in self.scripts.values():
            views.update(re.findall(r"G\.views\.(\w+)\s*=", source))
        icons = set(re.findall(r'^\s{2}"?([\w-]+)"?:\s*"M', self.app[self.app.index("const ICON_PATHS") :], re.M))
        modules = {row[0] for row in DEFAULT_MODULES}
        entries = self.navigation()
        self.assertGreater(len(entries), 15)
        for entry in entries:
            self.assertIn(entry["view"], views, f"no renderer for #{entry['view']}")
            self.assertIn(entry["icon"], icons, f"no icon {entry['icon']}")
            if "module" in entry:
                self.assertIn(entry["module"], modules, f"unknown module {entry['module']}")
        used = set(re.findall(r'data-icon="([\w-]+)"', self.index))
        for source in self.scripts.values():
            used.update(re.findall(r'"data-icon":\s*"([\w-]+)"', source))
        self.assertEqual(used - icons, set(), "icons used but not defined")

    def test_every_api_path_called_by_the_interface_has_a_route(self):
        samples = ("00000000-0000-4000-8000-000000000000", "example", "domain", "1", "T1059")
        patterns = [pattern for _, pattern, _, _ in ROUTES]
        calls = set()
        for name, source in self.scripts.items():
            for match in re.finditer(r'["`](/api/[^"`\s]*)["`]', source):
                calls.add((name, match.group(1)))
        self.assertGreater(len(calls), 100)
        missing = []
        for name, path in sorted(calls):
            path = re.split(r"\?|\$\{(?:parameters|query|params|search)\}", path)[0].rstrip("/") or path
            template = re.sub(r"\$\{[^}]*\}", "{}", path)
            if template.endswith("{}") and not template.endswith("/{}"):
                template = template[:-2]  # a trailing "${query}" is a query string
            if not any(
                pattern.fullmatch(template.format(*values))
                for values in itertools.product(samples, repeat=template.count("{}"))
                for pattern in patterns
            ):
                missing.append(f"{name}: {path}")
        self.assertEqual(missing, [], "interface calls without a backend route")


if __name__ == "__main__":
    unittest.main()
