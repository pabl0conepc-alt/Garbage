import unittest

from garbage_intel.modules.indicators import extract_indicators
from garbage_intel.modules.correlation import correlate_indicators


class IndicatorExtractionTests(unittest.TestCase):
    def test_extracts_indicators_with_source_provenance(self):
        digest = "a" * 64
        observation = {
            "id": "observation-1",
            "content": (
                "Observed 203.0.113.8 contacting Threat.Example; "
                f"SHA-256 {digest}. Also invalid 999.999.999.999."
            ),
            "source_reference": "https://example.test/report",
            "collection_basis": "public",
            "observed_at": "2025-01-02T03:04:05Z",
            "recorded_at": "2025-01-03T03:04:05Z",
        }

        findings = extract_indicators([observation])
        self.assertEqual(
            [(finding["type"], finding["value"]) for finding in findings],
            [
                ("ipv4", "203.0.113.8"),
                ("domain", "threat.example"),
                ("sha256", digest),
            ],
        )
        self.assertEqual(findings[0]["source_observation_id"], "observation-1")
        self.assertEqual(findings[0]["collection_basis"], "public")
        self.assertEqual(findings[0]["verification_status"], "not-verified")

    def test_deduplicates_repeated_matches_per_observation(self):
        findings = extract_indicators(
            [
                {
                    "id": "observation-2",
                    "content": "203.0.113.8 and 203.0.113.8",
                }
            ]
        )
        self.assertEqual(len(findings), 1)

    def test_exact_value_correlation_keeps_both_sources(self):
        findings = extract_indicators(
            [
                {
                    "id": "source-a",
                    "content": "203.0.113.8",
                    "source_reference": "https://a.example/report",
                    "collection_basis": "public",
                },
                {
                    "id": "source-b",
                    "content": "203.0.113.8",
                    "source_reference": "https://b.example/report",
                    "collection_basis": "authorized",
                },
            ]
        )

        correlations = correlate_indicators(findings)
        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0]["match_method"], "exact-normalized-value")
        self.assertEqual(correlations[0]["observation_count"], 2)
        self.assertEqual(
            [source["source_observation_id"] for source in correlations[0]["sources"]],
            ["source-a", "source-b"],
        )


if __name__ == "__main__":
    unittest.main()
