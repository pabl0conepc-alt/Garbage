"""Foundation: module registry corrections, transforms and entity resolution."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import intel, transforms
from garbage_intel.db import initialize
from garbage_intel.entities import (
    create_entity,
    create_relationship,
    get_entity,
    link_entity_to_investigation,
)
from garbage_intel.errors import ModuleDisabledError, ValidationError
from garbage_intel.intel import Connector, Finding, register_connector, run_query, unregister_connector
from garbage_intel.resolution import (
    dismiss_pair,
    find_candidates,
    merge_entities,
    organization_key,
    registrable_parts,
)
from garbage_intel.store import create_investigation
from garbage_intel.transforms import entity_history, list_transforms, run_transforms
from garbage_intel.workspace import list_modules, set_module_state, update_settings


def _dns(context):
    return [
        Finding("dns-a", "192.0.2.10", {"record": "A"}, "https://dns.example/resolve"),
        Finding("dns-a", "192.0.2.11", {"record": "A"}, "https://dns.example/resolve"),
        Finding("dns-ns", "ns1.example.net.", {"record": "NS"}, "https://dns.example/resolve"),
        Finding("dns-txt", "v=spf1 -all", {"record": "TXT"}, "https://dns.example/resolve"),
        Finding("dns-cname", "bad_name.example", {"record": "CNAME"}, "https://dns.example/resolve"),
    ]


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "foundation.sqlite3")
        initialize(self.database)
        intel.RATE_LIMITER.reset()

    def tearDown(self):
        self.directory.cleanup()


class RegistryTests(Base):
    def test_legacy_planned_rows_are_corrected(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE module_registry SET state = 'planned' WHERE module_id IN ('nvd-connector', 'external-osint-connectors')")
            connection.execute("DELETE FROM schema_migrations WHERE version = 8")
        initialize(self.database)
        states = {item["module_id"]: item["state"] for item in list_modules(self.database)["items"]}
        self.assertEqual(states["nvd-connector"], "enabled")
        self.assertEqual(states["external-osint-connectors"], "enabled")
        for module_id in ("transforms", "entity-resolution", "attack-matrix", "yara-rules", "analytics", "cti-export"):
            self.assertEqual(states[module_id], "enabled")
        self.assertEqual(states["media-forensics"], "planned")

    def test_connector_module_gates_runs(self):
        register_connector(Connector("test-remote", "Remote", "test", ("domain",), lambda context: [Finding("fact", "x")], network=True))
        self.addCleanup(unregister_connector, "test-remote")
        update_settings(self.database, {"intel.allow_network": "true"})
        set_module_state(self.database, "external-osint-connectors", "disabled")
        run = run_query(self.database, value="example.org", connector_ids=["test-remote"])
        self.assertEqual(run["sources"][0]["status"], "module-disabled")
        listed = {item["connector_id"]: item for item in intel.list_connectors(self.database)["items"]}
        self.assertEqual(listed["test-remote"]["availability"], "module-disabled")
        self.assertEqual(listed["nvd"]["module_id"], "nvd-connector")
        set_module_state(self.database, "external-osint-connectors", "enabled")
        run = run_query(self.database, value="example.org", connector_ids=["test-remote"], use_cache=False)
        self.assertEqual(run["sources"][0]["status"], "ok")

    def test_new_modules_gate_their_features(self):
        set_module_state(self.database, "transforms", "disabled")
        with self.assertRaises(ModuleDisabledError):
            list_transforms(self.database)
        set_module_state(self.database, "entity-resolution", "disabled")
        with self.assertRaises(ModuleDisabledError):
            find_candidates(self.database)


class TransformTests(Base):
    def setUp(self):
        super().setUp()
        register_connector(Connector("test-dns", "Test DNS", "test", ("domain",), _dns))
        self.addCleanup(unregister_connector, "test-dns")
        patcher = patch.dict(transforms.TRANSFORM_OUTPUTS, {"test-dns": ("dns-a", "dns-ns", "dns-cname")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.case = create_investigation(self.database, "Infra")["id"]
        self.domain = create_entity(self.database, entity_type="domain", identifier="login.example", name="login.example")

    def test_listing_matches_the_entity(self):
        listing = list_transforms(self.database, entity_id=self.domain["id"])
        self.assertEqual(listing["artifact"], {"type": "domain", "value": "login.example"})
        ids = {item["transform_id"]: item for item in listing["items"]}
        self.assertIn("test-dns", ids)
        self.assertNotIn("nvd", ids)  # CVE only
        self.assertEqual(ids["test-dns"]["kind"], "pivot")
        self.assertEqual(ids["test-dns"]["outputs"][0], {"result_type": "dns-a", "entity_type": "ipv4", "relationship_type": "hosted-on"})
        self.assertEqual(ids["local-structure"]["kind"], "enrichment")
        self.assertIsNone(ids["test-dns"]["estimate_ms"])

    def test_people_are_never_inputs(self):
        person = create_entity(self.database, entity_type="person", name="Fulano")
        listing = list_transforms(self.database, entity_id=person["id"])
        self.assertEqual(listing["items"], [])
        self.assertIn("people", listing["unsupported_reason"])
        with self.assertRaises(ValidationError):
            run_transforms(self.database, entity_id=person["id"], transform_ids=["local-structure"])

    def test_run_creates_linked_entities_and_logs(self):
        result = run_transforms(
            self.database,
            entity_id=self.domain["id"],
            transform_ids=["test-dns", "local-structure"],
            investigation_id=self.case,
        )
        logs = {item["transform_id"]: item for item in result["items"]}
        dns = logs["test-dns"]
        self.assertEqual(dns["status"], "ok")
        self.assertEqual(dns["result_count"], 5)
        self.assertEqual(dns["created_count"], 3)  # two IPs and the nameserver
        self.assertEqual(dns["relationship_count"], 3)
        events = [event["event"] for event in dns["log"]]
        self.assertEqual(events, ["input", "source", "promoted"])
        self.assertEqual(dns["log"][-1]["skipped"], 1)  # bad_name.example is not a valid domain
        self.assertEqual(logs["local-structure"]["created_count"], 0)
        detail = get_entity(self.database, self.domain["id"])
        kinds = sorted((item["other_type"], item["relationship_type"]) for item in detail["relationships"])
        self.assertEqual(kinds, [("domain", "uses"), ("ipv4", "hosted-on"), ("ipv4", "hosted-on")])
        self.assertTrue(all(item["investigation_id"] == self.case for item in detail["relationships"]))
        history = entity_history(self.database, self.domain["id"])
        self.assertEqual(history["total"], 2)
        self.assertEqual(history["items"][0]["parameters"], {"max_new_entities": 25, "promote": True, "use_cache": True})

        again = run_transforms(self.database, entity_id=self.domain["id"], transform_ids=["test-dns"], investigation_id=self.case)
        self.assertEqual(again["items"][0]["created_count"], 0)
        self.assertEqual(again["items"][0]["relationship_count"], 0)
        self.assertEqual(again["items"][0]["log"][-1]["reused"], 3)

    def test_parameters(self):
        result = run_transforms(
            self.database,
            entity_id=self.domain["id"],
            transform_ids=["test-dns"],
            parameters={"max_new_entities": 1},
        )
        log = result["items"][0]["log"]
        self.assertEqual(log[2], {"event": "limit", "kept": 1, "found": 4})
        self.assertEqual(result["created_count"], 1)
        quiet = run_transforms(self.database, entity_id=self.domain["id"], transform_ids=["test-dns"], parameters={"promote": False})
        self.assertEqual(quiet["items"][0]["log"][-1], {"event": "not-promoted", "count": 4})
        for bad in ({"promote": "yes"}, {"max_new_entities": 0}, {"depth": 2}):
            with self.assertRaises(ValidationError):
                run_transforms(self.database, entity_id=self.domain["id"], transform_ids=["test-dns"], parameters=bad)
        with self.assertRaises(ValidationError):
            run_transforms(self.database, entity_id=self.domain["id"], transform_ids=["nvd"])
        with self.assertRaises(ValidationError):
            run_transforms(self.database, entity_id=self.domain["id"], transform_ids=["no-such"])

    def test_identifier_must_match_type(self):
        odd = create_entity(self.database, entity_type="other", identifier="AS64500", name="AS64500")
        self.assertEqual(list_transforms(self.database, entity_id=odd["id"])["artifact"]["type"], "asn")
        organization = create_entity(self.database, entity_type="organization", name="Hosting Alpha")
        self.assertIn("identifier", list_transforms(self.database, entity_id=organization["id"])["unsupported_reason"])


class ResolutionTests(Base):
    def entity(self, kind, identifier="", name=""):
        return create_entity(self.database, entity_type=kind, identifier=identifier, name=name or identifier)

    def test_helpers(self):
        self.assertEqual(organization_key("Hosting Álpha, Ltda."), "hosting alpha")
        self.assertEqual(organization_key("ACME Corp Inc"), "acme")
        self.assertEqual(registrable_parts("www.example.com.br"), ("example", "com.br"))
        self.assertEqual(registrable_parts("example.org"), ("example", "org"))

    def test_levels(self):
        address = self.entity("ipv4", "192.0.2.1")
        indicator = self.entity("ioc", "192.0.2.1")
        bare = self.entity("domain", "example.org")
        www = self.entity("domain", "www.example.org")
        other_suffix = self.entity("domain", "example.net")
        page = self.entity("url", "https://example.org/login/")
        page_variant = self.entity("url", "http://www.example.org/login")
        alpha = self.entity("organization", name="Hosting Alpha Ltda")
        alpha_short = self.entity("organization", name="Hosting Alpha")
        alfa = self.entity("organization", name="Hosting Alfa")
        self.entity("person", name="Fulano")
        self.entity("person", name="Fulano de Tal")
        result = find_candidates(self.database)
        pairs = {frozenset(entity["id"] for entity in item["entities"]): item for item in result["items"]}

        def level(first, second):
            item = pairs.get(frozenset((first["id"], second["id"])))
            return item and (item["level"], item["rule"])

        self.assertEqual(level(address, indicator), ("exact", "same-artifact"))
        self.assertEqual(level(bare, www), ("probable", "www-prefix"))
        self.assertEqual(level(page, page_variant), ("probable", "url-variant"))
        self.assertEqual(level(bare, other_suffix), ("weak", "same-label-other-suffix"))
        self.assertEqual(level(alpha, alpha_short), ("probable", "organization-name"))
        self.assertEqual(level(alpha_short, alfa), ("weak", "similar-organization-name"))
        self.assertFalse(any(entity["entity_type"] == "person" for item in result["items"] for entity in item["entities"]))
        self.assertEqual(result["counts"]["exact"], 1)
        self.assertTrue(all(item["level"] == "weak" for item in find_candidates(self.database, level="weak")["items"]))

        dismiss_pair(self.database, bare["id"], other_suffix["id"], note="registrantes diferentes")
        remaining = {frozenset(entity["id"] for entity in item["entities"]) for item in find_candidates(self.database)["items"]}
        self.assertNotIn(frozenset((bare["id"], other_suffix["id"])), remaining)

    def test_scope_by_case(self):
        case = create_investigation(self.database, "Escopo")["id"]
        first = self.entity("ipv4", "198.51.100.7")
        second = self.entity("other", "198.51.100.7")
        link_entity_to_investigation(self.database, case, first["id"])
        self.assertEqual(find_candidates(self.database, investigation_id=case)["items"], [])
        link_entity_to_investigation(self.database, case, second["id"])
        self.assertEqual(len(find_candidates(self.database, investigation_id=case)["items"]), 1)

    def test_merge(self):
        case = create_investigation(self.database, "Fusão")["id"]
        keep = self.entity("ipv4", "192.0.2.1")
        merge = self.entity("ioc", "192.0.2.1")
        domain = self.entity("domain", "example.org")
        other = self.entity("domain", "example.com")
        link_entity_to_investigation(self.database, case, merge["id"])
        create_relationship(self.database, source_entity_id=domain["id"], target_entity_id=keep["id"], relationship_type="hosted-on")
        create_relationship(self.database, source_entity_id=domain["id"], target_entity_id=merge["id"], relationship_type="hosted-on")
        create_relationship(self.database, source_entity_id=other["id"], target_entity_id=merge["id"], relationship_type="hosted-on")
        create_relationship(self.database, source_entity_id=keep["id"], target_entity_id=merge["id"], relationship_type="related-to")
        result = merge_entities(self.database, keep_id=keep["id"], merge_id=merge["id"], note="mesmo IP", level="exact")
        self.assertEqual(result["moved"]["relationships"], 1)
        self.assertEqual(result["moved"]["dropped_relationships"], 2)  # duplicate edge and self-loop
        self.assertEqual(result["moved"]["cases"], 1)
        self.assertEqual(result["aliases"][0]["entity_type"], "ioc")
        self.assertEqual(result["aliases"][0]["merged_from_id"], merge["id"])
        neighbours = sorted(item["other_name"] for item in result["entity"]["relationships"])
        self.assertEqual(neighbours, ["example.com", "example.org"])
        self.assertEqual([item["id"] for item in result["entity"]["investigations"]], [case])
        with self.assertRaises(Exception):
            get_entity(self.database, merge["id"])
        with self.assertRaises(ValidationError):
            merge_entities(self.database, keep_id=keep["id"], merge_id=keep["id"])


if __name__ == "__main__":
    unittest.main()
