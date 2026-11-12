import unittest

from garbage_intel.modules.correlation import correlate_indicators
from garbage_intel.modules.indicator_tools import inspect_value, triage_text
from garbage_intel.modules.indicators import extract_indicators, refang_text


class IndicatorPrecisionTests(unittest.TestCase):
    def test_refangs_common_analyst_notation(self):
        self.assertEqual(
            refang_text("hxxps://evil[.]example/a and admin[at]corp[.]example"),
            "https://evil.example/a and admin@corp.example",
        )

    def test_extracts_ipv6_cidr_defanged_values_and_ignores_noise(self):
        text = (
            "hxxps://evil[.]example/login and admin[at]corp[.]example; "
            "IPv6 2001:db8::1, range 203.0.113.0/24, 2001:db8::/32. "
            "Do not treat report.pdf or 12:30:45 as infrastructure."
        )
        findings = extract_indicators(
            [{"id": "observation-1", "content": text}], deduplicate=False
        )
        values = {(finding["type"], finding["value"]) for finding in findings}
        self.assertIn(("url", "https://evil.example/login"), values)
        self.assertIn(("email", "admin@corp.example"), values)
        self.assertIn(("ipv6", "2001:db8::1"), values)
        self.assertIn(("cidr", "203.0.113.0/24"), values)
        self.assertIn(("cidr", "2001:db8::/32"), values)
        self.assertNotIn(("domain", "evil.example"), values)
        self.assertNotIn(("domain", "corp.example"), values)
        self.assertNotIn(("domain", "report.pdf"), values)
        self.assertNotIn(("ipv6", "12:30:45"), values)

    def test_ipv4_mapped_ipv6_stays_one_indicator(self):
        for text, expected in (
            ("::ffff:192.0.2.1", "::ffff:c000:201"),
            ("2001:db8::192.0.2.1", "2001:db8::c000:201"),
        ):
            findings = extract_indicators([{"id": "mapped", "content": text}])
            self.assertEqual(
                [(finding["type"], finding["value"]) for finding in findings],
                [("ipv6", expected)],
            )
            inspected = inspect_value(text)
            facts = {fact["label"]: fact["value"] for fact in inspected["facts"]}
            self.assertEqual(inspected["kind"], "ipv6")
            if text.startswith("::ffff:"):
                self.assertEqual(facts["Embedded IPv4"], "192.0.2.1")
                self.assertEqual(facts["Form"], "IPv4-mapped")

    def test_ipv4_embedded_cidr_is_one_network(self):
        findings = extract_indicators(
            [{"id": "mapped-network", "content": "::ffff:192.0.2.0/120"}]
        )
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [("cidr", "::ffff:c000:200/120")],
        )
        self.assertNotIn(("ipv4", "192.0.2.0"), {
            (finding["type"], finding["value"]) for finding in findings
        })

    def test_scoped_ipv6_is_preserved_and_inspected(self):
        findings = extract_indicators(
            [{"id": "zone", "content": "fe80::1%eth0"}]
        )
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [("ipv6", "fe80::1%eth0")],
        )
        inspected = inspect_value("fe80::1%eth0")
        facts = {fact["label"]: fact["value"] for fact in inspected["facts"]}
        self.assertEqual(inspected["kind"], "ipv6")
        self.assertEqual(facts["Zone"], "eth0")
        self.assertEqual(facts["Compressed"], "fe80::1")
        self.assertIn("Reverse pointer", facts)

    def test_ipv6_url_keeps_brackets_when_canonicalized(self):
        findings = extract_indicators(
            [{"id": "url", "content": "https://[2001:db8::1]:8443/a"}]
        )
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [("url", "https://[2001:db8::1]:8443/a")],
        )
        inspected = inspect_value("https://[2001:db8::1]:8443/a")
        self.assertEqual(inspected["kind"], "url")
        self.assertEqual(inspected["canonical"], "https://[2001:db8::1]:8443/a")
        facts = {fact["label"]: fact["value"] for fact in inspected["facts"]}
        self.assertEqual(facts["Host"], "[2001:db8::1]")
        self.assertEqual(facts["Host kind"], "IPv6")

    def test_bare_ipv6_url_keeps_its_closing_bracket(self):
        findings = extract_indicators(
            [{"id": "bare", "content": "(https://[2001:db8::1])"}]
        )
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [("url", "https://[2001:db8::1]/")],
        )

    def test_url_credentials_do_not_become_an_email(self):
        findings = extract_indicators(
            [
                {
                    "id": "observation-2",
                    "content": "https://user:pass@evil.example:8443/a?q=1",
                }
            ]
        )
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [("url", "https://user:pass@evil.example:8443/a?q=1")],
        )

    def test_correlation_reports_independent_source_strength(self):
        findings = []
        for observation_id, reference in (
            ("a", "https://a.example/report"),
            ("b", "https://b.example/report"),
            ("c", "https://c.example/report"),
        ):
            findings.extend(
                extract_indicators(
                    [
                        {
                            "id": observation_id,
                            "content": "203.0.113.8",
                            "source_reference": reference,
                        }
                    ]
                )
            )
        correlation = correlate_indicators(findings)[0]
        self.assertEqual(correlation["observation_count"], 3)
        self.assertEqual(correlation["independent_source_count"], 3)
        self.assertEqual(correlation["strength"], "high")
        self.assertEqual(correlation["match_method"], "exact-normalized-value")

    def test_correlation_does_not_call_one_source_independent(self):
        findings = extract_indicators(
            [
                {
                    "id": "a",
                    "content": "203.0.113.8",
                    "source_reference": "https://one.example/report",
                },
                {
                    "id": "b",
                    "content": "203.0.113.8",
                    "source_reference": "https://one.example/report",
                },
            ]
        )
        correlation = correlate_indicators(findings)[0]
        self.assertEqual(correlation["observation_count"], 2)
        self.assertEqual(correlation["independent_source_count"], 1)
        self.assertEqual(correlation["strength"], "low")
        self.assertIn("not independent", correlation["note"])


class TextTriageTests(unittest.TestCase):
    def test_counts_repeated_occurrences_and_groups_values(self):
        result = triage_text(
            "https://example.org/a https://example.org/a and 203.0.113.9"
        )
        self.assertEqual(result["indicator_count"], 3)
        self.assertEqual(result["unique_count"], 2)
        self.assertEqual(result["counts"]["url"], 1)
        self.assertEqual(result["counts"]["ipv4"], 1)
        url = next(item for item in result["items"] if item["type"] == "url")
        self.assertEqual(url["count"], 2)
        self.assertIn("example.org", url["contexts"][0])

    def test_reports_defanged_input_and_does_not_store_text(self):
        result = triage_text("hxxp://evil[.]example/a")
        self.assertTrue(result["defanged"])
        self.assertEqual(result["unique_count"], 1)
        self.assertNotIn("text", result)
        self.assertEqual(len(result["sha256"]), 64)

    def test_empty_or_non_string_text_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            triage_text("  ")
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            triage_text(None)


class IndicatorInspectionTests(unittest.TestCase):
    def test_inspects_ipv4_scope_without_reputation_claim(self):
        result = inspect_value("203.0.113.4")
        self.assertEqual(result["kind"], "ipv4")
        self.assertEqual(result["canonical"], "203.0.113.4")
        labels = {fact["label"]: fact["value"] for fact in result["facts"]}
        self.assertEqual(labels["Global"], "no")
        self.assertTrue(any("not globally routable" in item for item in result["warnings"]))
        self.assertIn("no dns", " ".join(result["limitations"]).lower())

    def test_inspects_defanged_url_and_explains_credentials(self):
        result = inspect_value("hxxps://user:pass@evil[.]example:8443/a?q=1")
        self.assertEqual(result["kind"], "url")
        self.assertTrue(result["defanged"])
        self.assertIn("evil.example", result["canonical"])
        self.assertIn("credentials", " ".join(result["warnings"]))
        labels = {fact["label"]: fact["value"] for fact in result["facts"]}
        self.assertEqual(labels["Port"], "8443")
        self.assertEqual(labels["Query parameters"], "1")

    def test_classifies_filename_idn_and_asn(self):
        filename = inspect_value("report.pdf")
        self.assertEqual(filename["kind"], "filename")
        domain = inspect_value("münchen.de")
        self.assertEqual(domain["kind"], "domain")
        self.assertEqual(domain["canonical"], "xn--mnchen-3ya.de")
        asn = inspect_value("AS64500")
        self.assertEqual(asn["kind"], "asn")

    def test_multiple_and_unknown_values_are_explicit(self):
        multiple = inspect_value("203.0.113.4 and example.org")
        self.assertEqual(multiple["kind"], "multiple")
        self.assertEqual(len(multiple["candidates"]), 2)
        unknown = inspect_value("not an indicator")
        self.assertEqual(unknown["kind"], "unknown")
        self.assertTrue(unknown["warnings"])

    def test_rejects_empty_values(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            inspect_value("")


if __name__ == "__main__":
    unittest.main()
