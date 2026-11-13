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


class GraphAnalyticsReferenceTests(unittest.TestCase):
    """The Python reference algorithms, checked against hand-computed values."""

    # Two triangles joined by the bridge 2-3, a duplicate edge, a self-loop
    # and the isolate 6.
    N = 7
    SOURCES = [0, 1, 2, 3, 4, 5, 2, 0, 4]
    TARGETS = [1, 2, 0, 4, 5, 3, 3, 1, 4]

    def test_centrality(self):
        degree, betweenness, harmonic = native.python_centrality(self.N, self.SOURCES, self.TARGETS)
        self.assertAlmostEqual(degree[2], 3 / 6)
        self.assertAlmostEqual(degree[6], 0.0)
        # Node 2 lies on the 6 shortest paths between {0, 1} and {3, 4, 5};
        # there are (n-1)(n-2)/2 = 15 pairs it could lie between.
        self.assertAlmostEqual(betweenness[2], 6 / 15)
        self.assertAlmostEqual(betweenness[3], 6 / 15)
        self.assertAlmostEqual(betweenness[0], 0.0)
        self.assertAlmostEqual(harmonic[2], (1 + 1 + 1 + 0.5 + 0.5) / 6)

    def test_communities_and_modularity(self):
        labels, modularity = native.python_communities(self.N, self.SOURCES, self.TARGETS)
        self.assertEqual(labels, [0, 0, 0, 1, 1, 1, 2])
        # m = 7 simple edges; each triangle: 3 internal edges, degree sum 7.
        expected = 2 * (3 / 7 - (7 / 14) ** 2)
        self.assertAlmostEqual(modularity, expected)

    def test_shortest_path(self):
        self.assertEqual(native.python_shortest_path(self.N, self.SOURCES, self.TARGETS, 0, 5), [0, 2, 3, 5])
        self.assertEqual(native.python_shortest_path(self.N, self.SOURCES, self.TARGETS, 0, 6), [])
        self.assertEqual(native.python_shortest_path(self.N, self.SOURCES, self.TARGETS, 4, 4), [4])

    def test_empty_and_edgeless_graphs(self):
        self.assertEqual(native.python_communities(0, [], []), ([], 0.0))
        self.assertEqual(native.python_communities(3, [], []), ([0, 1, 2], 0.0))
        self.assertEqual(native.python_centrality(1, [], []), ([0.0], [0.0], [0.0]))

    def test_graph_analytics_payload(self):
        nodes = [{"id": f"n{index}"} for index in range(self.N)]
        edges = [
            {"source_entity_id": f"n{s}", "target_entity_id": f"n{t}"}
            for s, t in zip(self.SOURCES, self.TARGETS)
        ]
        result = native.graph_analytics(nodes, edges)
        self.assertEqual(result["communities"], 3)
        self.assertEqual(result["nodes"]["n6"]["community_size"], 1)
        path = native.shortest_path(nodes, edges, "n0", "n5")
        self.assertEqual((path["path"], path["hops"]), (["n0", "n2", "n3", "n5"], 3))
        self.assertEqual(native.shortest_path(nodes, edges, "n0", "missing")["path"], [])


@unittest.skipUnless(
    NATIVE_BUILT and native._CPP_ANALYTICS is not None, "C++ graph analytics are not built"
)
class GraphAnalyticsParityTests(unittest.TestCase):
    def test_cpp_matches_python_exactly_on_random_graphs(self):
        generator = random.Random(11)
        for _ in range(150):
            count = generator.randint(1, 50)
            edges = generator.randint(0, count * 4)
            sources = [generator.randrange(count) for _ in range(edges)]
            targets = [generator.randrange(count) for _ in range(edges)]
            degree, betweenness, harmonic, labels, modularity = native._native_analytics(count, sources, targets)
            self.assertEqual(
                (degree, betweenness, harmonic),
                tuple(list(values) for values in native.python_centrality(count, sources, targets)),
            )
            python_labels, python_modularity = native.python_communities(count, sources, targets)
            self.assertEqual(labels, python_labels)
            self.assertAlmostEqual(modularity, python_modularity, places=12)
            start, goal = generator.randrange(count), generator.randrange(count)
            self.assertEqual(
                native._native_path(count, sources, targets, start, goal),
                native.python_shortest_path(count, sources, targets, start, goal),
            )

    def test_invalid_indexes_are_rejected(self):
        values = (ctypes_array := __import__("ctypes").c_double * 2)()
        u32 = __import__("ctypes").c_uint32
        status = native._CPP_ANALYTICS.gi_graph_centrality(
            2, (u32 * 1)(0), (u32 * 1)(9), 1, values, ctypes_array(), ctypes_array()
        )
        self.assertEqual(status, -2)
