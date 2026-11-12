import math
import os
import random
import struct
import unittest
from pathlib import Path

from garbage_intel import native
from garbage_intel.modules import hardening
from garbage_intel.modules.file_intel import analyze_bytes
from garbage_intel.modules.lookalikes import find_domain_lookalikes

ROOT = Path(__file__).resolve().parent.parent
BUILD = Path(os.environ.get("GARBAGE_NATIVE_DIR", ROOT / "native" / "build"))
NATIVE_BUILT = all(
    any((BUILD / name).is_file() for name in names)
    for names in (
        ("libgarbage_c.so", "libgarbage_c.dylib", "garbage_c.dll"),
        ("libgarbage_cpp.so", "libgarbage_cpp.dylib", "garbage_cpp.dll"),
        ("libgarbage_rust.so", "libgarbage_rust.dylib", "garbage_rust.dll"),
    )
)


def pe_sample() -> bytes:
    data = bytearray(0x40 + 24 + 0xF0 + 40)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x44, 0x8664)
    struct.pack_into("<H", data, 0x46, 0)
    struct.pack_into("<H", data, 0x54, 0xF0)
    struct.pack_into("<H", data, 0x56, 0x22)
    optional = 0x58
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<H", data, optional + 70, 0x0140)
    directory = optional + 112
    struct.pack_into("<I", data, directory + 5 * 8, 0x2000)
    struct.pack_into("<I", data, directory + 5 * 8 + 4, 12)
    data.extend(b"__security_check_cookie\x00")
    return bytes(data)


@unittest.skipUnless(NATIVE_BUILT, "native libraries are not built")
class NativeEngineTests(unittest.TestCase):
    def test_all_engines_report_their_abi(self):
        status = native.native_status()
        self.assertTrue(all(status["engines"].values()), status)

    def test_native_entropy_matches_python(self):
        data = bytes(range(256)) * 7
        expected = 0.0
        for count in {value: data.count(value) for value in set(data)}.values():
            probability = count / len(data)
            expected -= probability * math.log2(probability)
        self.assertAlmostEqual(native.entropy(data), expected, places=9)

    def test_elf_hardening_matches_python_fallback(self):
        candidates = [Path("/bin/ls"), Path("/usr/bin/env"), Path("/bin/sh")]
        path = next(
            (
                item
                for item in candidates
                if item.is_file() and item.read_bytes()[:4] == b"\x7fELF"
            ),
            None,
        )
        if path is None:
            self.skipTest("no ELF sample on this host")
        data = path.read_bytes()
        native_result = hardening.describe_hardening("elf", data)
        original = native._C
        native._C = None
        try:
            fallback = hardening.describe_hardening("elf", data)
        finally:
            native._C = original
        self.assertEqual(native_result["engine"], "c-native")
        self.assertEqual(fallback["engine"], "python-fallback")
        self.assertEqual(
            [(item["key"], item["status"]) for item in native_result["checks"]],
            [(item["key"], item["status"]) for item in fallback["checks"]],
        )

    def test_pe_hardening_matches_python_fallback(self):
        data = pe_sample()
        native_result = hardening.describe_hardening("pe", data)
        original = native._C
        native._C = None
        try:
            fallback = hardening.describe_hardening("pe", data)
        finally:
            native._C = original
        self.assertEqual(native_result["engine"], "c-native")
        self.assertEqual(
            [(item["key"], item["status"]) for item in native_result["checks"]],
            [(item["key"], item["status"]) for item in fallback["checks"]],
        )
        self.assertEqual(
            next(item for item in native_result["checks"] if item["key"] == "aslr")[
                "status"
            ],
            "enabled",
        )

    def test_truncated_binary_is_rejected_by_both_paths(self):
        self.assertIsNone(hardening.describe_hardening("elf", b"\x7fELF"))
        self.assertIsNone(hardening.describe_hardening("pe", b"MZ"))

    def test_file_analysis_exposes_hardening(self):
        data = pe_sample()
        analysis = analyze_bytes(data, "sample.exe")
        self.assertEqual(analysis["format"], "pe")
        self.assertIn("hardening", analysis)
        self.assertEqual(analysis["hardening"]["format"], "pe")
        self.assertTrue(analysis["hardening"]["checks"])

    def test_graph_metrics_match_python_fallback(self):
        rng = random.Random(7)
        nodes = [{"id": f"node-{index}"} for index in range(12)]
        edges = []
        for index in range(18):
            source = rng.randrange(len(nodes))
            target = rng.randrange(len(nodes))
            edges.append(
                {
                    "source_entity_id": nodes[source]["id"],
                    "target_entity_id": nodes[target]["id"],
                }
            )
        edges.append(
            {
                "source_entity_id": nodes[1]["id"],
                "target_entity_id": nodes[1]["id"],
            }
        )
        native_result = native.graph_metrics(nodes, edges)
        original = native._CPP
        native._CPP = None
        try:
            fallback = native.graph_metrics(nodes, edges)
        finally:
            native._CPP = original
        self.assertEqual(native_result["engine"], "cpp-native")
        self.assertEqual(fallback["engine"], "python-fallback")
        for key in (
            "nodes",
            "edges",
            "components",
            "isolates",
            "self_loops",
            "reciprocal_edges",
            "degree_sum",
            "max_degree",
            "max_degree_node",
        ):
            self.assertEqual(native_result[key], fallback[key], key)
        self.assertAlmostEqual(native_result["density"], fallback["density"], places=12)

    def test_rust_distance_and_skeleton_match_python(self):
        pairs = [
            ("paypal.com", "paypa1.com"),
            ("google.com", "googel.com"),
            ("example.com", "example.org"),
            ("a.example", "ab.example"),
            ("short", "muchlonger"),
        ]
        for left, right in pairs:
            native_distance = native.domain_distance(left, right, 3)
            original = native._RUST
            native._RUST = None
            try:
                fallback_distance = native.python_domain_distance(left, right, 3)
                fallback_skeleton = native.python_domain_skeleton(left)
            finally:
                native._RUST = original
            self.assertEqual(native_distance, fallback_distance, (left, right))
            self.assertEqual(native.domain_skeleton(left), fallback_skeleton)

    def test_lookalikes_use_rust_and_fall_back_cleanly(self):
        candidates = ["paypa1.com", "pay-pal.com", "example.com", "paypal.co"]
        native_result = find_domain_lookalikes("paypal.com", candidates)
        self.assertEqual(native_result["engine"], "rust-native")
        original = native._RUST
        native._RUST = None
        try:
            fallback = find_domain_lookalikes("paypal.com", candidates)
        finally:
            native._RUST = original
        self.assertEqual(fallback["engine"], "python-fallback")
        self.assertEqual(native_result["items"], fallback["items"])


if __name__ == "__main__":
    unittest.main()
