import tempfile
import unittest
from pathlib import Path

from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, link_entity_to_investigation
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.store import (
    add_observation,
    build_report,
    create_investigation,
)
from garbage_intel.workspace import (
    case_coverage,
    get_settings,
    global_search,
    inspect_local_indicator,
    list_activities,
    list_modules,
    overview,
    set_indicator_assessment,
    set_module_state,
    triage_indicators,
    unified_indicators,
    update_settings,
)


class WorkspaceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "intel.sqlite3")
        initialize(self.database)
        self.investigation = create_investigation(
            self.database,
            "Indicator case",
            "threat.example infrastructure review",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def seed(self):
        observation = add_observation(
            self.database,
            self.investigation["id"],
            "Resolved address",
            "threat.example resolved to 203.0.113.20 during the review.",
            "https://example.test/dns",
            "public",
            "2026-01-02T03:04:05Z",
        )
        domain = create_entity(
            self.database,
            entity_type="domain",
            identifier="threat.example",
            source_reference="https://example.test/dns",
            collection_basis="public",
        )
        address = create_entity(
            self.database, entity_type="ipv4", identifier="203.0.113.20"
        )
        for entity in (domain, address):
            link_entity_to_investigation(
                self.database, self.investigation["id"], entity["id"]
            )
        return observation, domain, address

    def test_module_registry_gates_real_behaviour(self):
        modules = list_modules(self.database)
        states = {item["module_id"]: item["state"] for item in modules["items"]}
        self.assertEqual(states["indicator-engine"], "enabled")
        self.assertEqual(states["nvd-connector"], "planned")

        self.seed()
        report = build_report(self.database, self.investigation["id"])
        self.assertGreater(len(report["indicators"]), 0)

        set_module_state(self.database, "indicator-engine", "disabled")
        gated = build_report(self.database, self.investigation["id"])
        self.assertEqual(gated["indicators"], [])
        self.assertEqual(gated["correlations"], [])
        self.assertFalse(gated["options"]["indicator_engine"])
        self.assertTrue(
            any("indicator engine is disabled" in item for item in gated["limitations"])
        )

        set_module_state(self.database, "indicator-engine", "enabled")
        self.assertGreater(
            len(build_report(self.database, self.investigation["id"])["indicators"]),
            0,
        )
        with self.assertRaisesRegex(ConflictError, "planned modules"):
            set_module_state(self.database, "nvd-connector", "enabled")
        with self.assertRaisesRegex(ConflictError, "core module"):
            set_module_state(self.database, "settings", "disabled")
        with self.assertRaisesRegex(ValidationError, "module state"):
            set_module_state(self.database, "entities", "unknown")

    def test_settings_are_persisted_and_change_reports(self):
        settings = get_settings(self.database)
        self.assertEqual(settings["values"]["interface.theme"], "dark")
        self.assertEqual(settings["values"]["report.include_limitations"], "true")

        updated = update_settings(
            self.database,
            {
                "interface.theme": "contrast",
                "board.autosave_delay_ms": 800,
                "report.include_limitations": False,
            },
        )
        self.assertEqual(updated["values"]["interface.theme"], "contrast")
        self.assertEqual(updated["values"]["board.autosave_delay_ms"], "800")
        report = build_report(self.database, self.investigation["id"])
        self.assertEqual(report["limitations"], [])

        with self.assertRaisesRegex(ValidationError, "unknown settings"):
            update_settings(self.database, {"unknown.setting": "value"})
        with self.assertRaisesRegex(ValidationError, "between 3 and 20"):
            update_settings(self.database, {"search.result_limit": 999})
        with self.assertRaisesRegex(ValidationError, "must be one of"):
            update_settings(self.database, {"interface.density": "tiny"})

    def test_unified_indicators_merge_origins_and_keep_assessments(self):
        self.seed()
        indicators = unified_indicators(self.database)
        by_key = {
            (item["type"], item["value"]): item for item in indicators["items"]
        }
        address = by_key[("ipv4", "203.0.113.20")]
        self.assertEqual(address["origin_count"], 2)
        self.assertEqual(
            {origin["origin_type"] for origin in address["origins"]},
            {"observation", "entity"},
        )
        self.assertIn(("domain", "threat.example"), by_key)

        assessed = set_indicator_assessment(
            self.database,
            indicator_type="ipv4",
            value="203.0.113.20",
            verification_status="verified",
            note="Confirmed by the public registry.",
        )
        self.assertEqual(assessed["verification_status"], "verified")
        refreshed = {
            (item["type"], item["value"]): item
            for item in unified_indicators(self.database)["items"]
        }
        self.assertEqual(
            refreshed[("ipv4", "203.0.113.20")]["verification_status"], "verified"
        )
        self.assertIn(
            "public registry",
            refreshed[("ipv4", "203.0.113.20")]["assessment_note"],
        )

        filtered = unified_indicators(self.database, indicator_type="domain")
        self.assertEqual(
            [item["value"] for item in filtered["items"]], ["threat.example"]
        )
        with self.assertRaisesRegex(ValidationError, "indicator type must be"):
            unified_indicators(self.database, indicator_type="unknown")

    def test_local_inspector_matches_indicator_origins_and_cooccurrence(self):
        self.seed()
        result = inspect_local_indicator(self.database, value="203.0.113.20")
        self.assertEqual(result["kind"], "ipv4")
        self.assertGreaterEqual(result["match_count"], 2)
        self.assertIsNotNone(result["local"]["indicator"])
        self.assertEqual(result["local"]["indicator"]["origin_count"], 2)
        self.assertEqual(len(result["local"]["entities"]), 1)
        self.assertIn(
            ("domain", "threat.example"),
            {(item["type"], item["value"]) for item in result["local"]["cooccurring"]},
        )

        filename = inspect_local_indicator(self.database, value="report.pdf")
        self.assertEqual(filename["kind"], "filename")
        self.assertEqual(filename["match_count"], 0)

    def test_text_triage_is_gated_and_does_not_persist_observations(self):
        before = len(build_report(self.database, self.investigation["id"])["observations"])
        result = triage_indicators(
            self.database,
            text="hxxps://threat[.]example/a and 203.0.113.20",
        )
        self.assertEqual(result["unique_count"], 2)
        after = len(build_report(self.database, self.investigation["id"])["observations"])
        self.assertEqual(before, after)

        set_module_state(self.database, "indicator-engine", "disabled")
        with self.assertRaisesRegex(ConflictError, "disabled"):
            triage_indicators(self.database, text="203.0.113.20")

    def test_case_coverage_reports_factual_attention_items(self):
        self.seed()
        coverage = case_coverage(self.database, self.investigation["id"])
        checks = {check["key"]: check for check in coverage["checks"]}
        self.assertEqual(checks["evidence-integrity"]["status"], "attention")
        self.assertEqual(checks["source-records"]["status"], "attention")
        self.assertEqual(checks["observation-sources"]["status"], "ok")
        self.assertEqual(checks["entity-links"]["status"], "ok")
        self.assertEqual(coverage["summary"]["total"], len(coverage["checks"]))
        self.assertIn("not", coverage["disclaimer"].lower())

    def test_global_search_groups_and_activity_log(self):
        self.seed()
        results = global_search(self.database, "threat.example")
        self.assertGreaterEqual(results["total"], 1)
        keys = {group["key"]: group for group in results["groups"]}
        self.assertIn("entities", keys)
        self.assertEqual(keys["entities"]["total"], 1)
        self.assertEqual(keys["indicators"]["total"], 1)
        self.assertIn("observations", keys)

        short = global_search(self.database, "a")
        self.assertEqual(short["total"], 0)
        self.assertIn("two characters", short["message"])

        activities = list_activities(self.database)
        self.assertGreater(activities["total"], 0)
        self.assertTrue(
            any(item["action"] == "observation" for item in activities["items"])
        )

    def test_overview_metrics_match_the_database(self):
        observation, domain, address = self.seed()
        snapshot = overview(self.database)
        self.assertEqual(snapshot["totals"]["investigations"], 1)
        self.assertEqual(snapshot["totals"]["open"], 1)
        self.assertEqual(snapshot["totals"]["observations"], 1)
        self.assertEqual(snapshot["totals"]["entities"], 2)
        self.assertEqual(snapshot["totals"]["unique_indicators"], 2)
        self.assertEqual(snapshot["totals"]["correlations"], 0)
        self.assertEqual(snapshot["collection_basis"], {"public": 1})
        self.assertEqual(snapshot["indicator_mix"], {"ipv4": 1, "domain": 1})
        self.assertEqual(
            snapshot["recent_investigations"][0]["id"], self.investigation["id"]
        )
        self.assertEqual(
            snapshot["recent_investigations"][0]["observation_count"], 1
        )
        self.assertEqual(
            snapshot["recent_investigations"][0]["entity_count"], 2
        )
        self.assertGreaterEqual(len(snapshot["recent_activity"]), 1)
        self.assertEqual(observation["investigation_id"], self.investigation["id"])
        self.assertEqual(domain["entity_type"], "domain")
        self.assertEqual(address["entity_type"], "ipv4")


if __name__ == "__main__":
    unittest.main()
