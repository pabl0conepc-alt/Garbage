"""Phase 6: TLSH and ssdeep similarity digests.

Reference digests and scores were recorded on 2026-11-12 with py-tlsh 5.0.0
and the ssdeep 2.14.1 command line over the deterministic inputs below.
"""

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import native
from garbage_intel.modules import fuzzy_hash
from garbage_intel.modules.file_intel import analyze_file, similar_file_analyses
from garbage_intel.store import initialize


def sample(name, size):
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{name}:{counter}".encode()).digest()
        counter += 1
    return out[:size]


def words(size):
    vocabulary = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf"]
    seed = hashlib.sha256(b"text").digest()
    out = []
    index = 0
    while sum(len(word) + 1 for word in out) < size:
        out.append(vocabulary[hashlib.sha256(seed + index.to_bytes(4, "little")).digest()[0] % 7])
        index += 1
    return b" ".join(out)[:size]


def flipped(data, positions):
    changed = bytearray(data)
    for position in positions:
        changed[position] ^= 0xFF
    return bytes(changed)


BASE = sample("e", 60000)
CASES = {
    "random-50": (
        sample("a", 50),
        "T100900226B4C82452F164F84912299456E028144D542DE2041048859405179288035462",
        "3:2tVrJBoiuq5Mls64mGdBD:2nrJTuq2s64mUD",
    ),
    "random-1000": (
        sample("b", 1000),
        "T18611C8988BB1279077E802D9A7580168CFB6D790383D6150359BFA6B0F7392F491C183",
        "24:eEZUXQgAyV9PEW4Sv440Fq0n/mSOKuipU1P84x+BjFG:e1iyVaW0/mIuiwEJBjFG",
    ),
    "random-70000": (
        sample("c", 70000),
        "T1826302C65090167C6F63810CA7F88A5C4B35941C4258F4B26FE7BAFBD1FB490196E4B9",
        "1536:HTAPwsjqvhqF71DpZ6AQcb9mpQ69hqcjEtfjOxwYnZ3/rH:vtvwFpjP9mZxULOxwKZvD",
    ),
    "text-20000": (
        words(20000),
        "T196923509255B63F36E95D1083343A832B68E953F6E2E9B239A9773318CDC4F5242CF59",
        "96:TpcuZAHf0J0WAt8lW1EC0fqkC0uK0A0o1bfHWMDAIbVBwg2G7P3LcC5IasvPkZCD:U",
    ),
    # Ends in zero bytes, so the final rolling hash is 0 and ssdeep keeps the
    # last overflow character instead of the running hash.
    "zeros-tail": (
        sample("d", 5000) + b"\0" * 16,
        "T11DA16CB0F117C80A468E69B68D5AE6492D4B920E97668352724EA2DD3332F9163C8176",
        "96:J9G0xQz/iaXDRQOnoBHwjfYuVn4d7L9gVRTdViHiH3NpNKaV8fnugkP4e:+IaXVQKoBHwjfTn8LSRTiC3PNjmnufN",
    ),
    "base-60000": (
        BASE,
        "T1E143029E878CCCD02DDB0B2488B3F246EBFC7966754E8B9B26BDC9594F064F75424602",
        "1536:xhi3CJs0RtvrjGmg5YepglIVJexZdcg6tdVpGLp+EEg/OwW1p7:7Ses0TGmg0lWJPXW4gG37",
    ),
    "edit-60000": (
        flipped(BASE, (5000, 20000, 41000)),
        "T1E243029E878CCCD02DDB0B2488B3F246EBFC7966754E8B9B26BDC9594F064F75424602",
        "1536:xhi39Js0RtvrjGmg5vepglIVJexZdcg6tdSpGLp+EEg/OwW1p7:7SHs0TGmgrlWJPgW4gG37",
    ),
    "variant-60000": (
        flipped(BASE, range(0, 60000, 1500)),
        "T1C943029E878CCCE02DDB0B2488B3F246EBFD7966754A8A9B26BDC9594F064F74420611",
        None,
    ),
}


class ReferenceDigestTests(unittest.TestCase):
    def test_python_matches_reference_digests(self):
        for name, (data, tlsh, ssdeep) in CASES.items():
            with self.subTest(name=name):
                self.assertEqual(fuzzy_hash.python_tlsh(data), tlsh)
                if ssdeep:
                    self.assertEqual(fuzzy_hash.python_ssdeep(data), ssdeep)

    def test_reference_scores(self):
        base, edit, variant = (CASES[name] for name in ("base-60000", "edit-60000", "variant-60000"))
        self.assertEqual(fuzzy_hash.tlsh_distance(base[1], edit[1]), 1)
        self.assertEqual(fuzzy_hash.tlsh_distance(base[1], variant[1]), 9)
        self.assertEqual(fuzzy_hash.tlsh_distance(base[1], base[1]), 0)
        self.assertEqual(fuzzy_hash.ssdeep_compare(base[2], edit[2]), 96)
        self.assertEqual(fuzzy_hash.ssdeep_compare(base[2], base[2]), 100)
        self.assertEqual(fuzzy_hash.ssdeep_compare(base[2], CASES["random-1000"][2]), 0)
        variant_ssdeep = fuzzy_hash.python_ssdeep(variant[0])
        self.assertEqual(fuzzy_hash.ssdeep_compare(base[2], variant_ssdeep), 0)

    def test_degenerate_inputs(self):
        self.assertIsNone(fuzzy_hash.python_tlsh(b"a" * 49))
        self.assertIsNone(fuzzy_hash.python_tlsh(b"\0" * 1000))
        self.assertIsNone(fuzzy_hash.python_tlsh(b"ab" * 500))
        self.assertEqual(fuzzy_hash.python_ssdeep(b"a"), "3:E:E")
        self.assertEqual(fuzzy_hash.python_ssdeep(b""), "3::")
        for bad in ("", "T1XYZ"):
            with self.assertRaises(ValueError):
                fuzzy_hash.tlsh_distance(bad, CASES["base-60000"][1])
        for bad in ("3:abc", "x:abc:def"):
            with self.assertRaises(ValueError):
                fuzzy_hash.ssdeep_compare(bad, "3:a:a")


@unittest.skipUnless(native._C_FUZZY is not None, "C similarity engine not built")
class NativeParityTests(unittest.TestCase):
    def test_native_matches_python(self):
        inputs = [data for data, _, _ in CASES.values()] + [b"", b"x" * 49, b"\0" * 4096, bytes(range(256)) * 3]
        for data in inputs:
            with self.subTest(size=len(data)):
                result = native.fuzzy_digests(data)
                self.assertEqual(result["tlsh"], fuzzy_hash.python_tlsh(data))
                self.assertEqual(result["ssdeep"], fuzzy_hash.python_ssdeep(data))
                self.assertEqual(result["engine"], "c-native")
        digests = [(tlsh, ssdeep or fuzzy_hash.python_ssdeep(data)) for data, tlsh, ssdeep in CASES.values()]
        for left_tlsh, left_ssdeep in digests:
            for right_tlsh, right_ssdeep in digests:
                self.assertEqual(native.fuzzy_compare("tlsh", left_tlsh, right_tlsh), fuzzy_hash.tlsh_distance(left_tlsh, right_tlsh))
                self.assertEqual(
                    native.fuzzy_compare("ssdeep", left_ssdeep, right_ssdeep),
                    fuzzy_hash.ssdeep_compare(left_ssdeep, right_ssdeep),
                )
        self.assertIsNone(native.fuzzy_compare("tlsh", "nope", CASES["base-60000"][1]))
        self.assertIsNone(native.fuzzy_compare("ssdeep", "3:a", "3:a:a"))


class WorkspaceSimilarityTests(unittest.TestCase):
    def test_similar_analyses_rank_variants_and_skip_unrelated(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "files.sqlite3")
            initialize(database)
            base = analyze_file(database, data=BASE, filename="base.bin")
            self.assertEqual(base["hashes"]["tlsh"], CASES["base-60000"][1])
            self.assertEqual(base["hashes"]["ssdeep"], CASES["base-60000"][2])
            edit = analyze_file(database, data=CASES["edit-60000"][0], filename="edit.bin")
            copy = analyze_file(database, data=BASE, filename="copy.bin")
            analyze_file(database, data=sample("unrelated", 60000), filename="other.bin")
            result = similar_file_analyses(database, base["analysis_id"])
            names = [item["file_name"] for item in result["items"]]
            self.assertEqual(names, ["copy.bin", "edit.bin"])
            self.assertTrue(result["items"][0]["exact"])
            self.assertEqual(result["items"][1]["tlsh_distance"], 1)
            self.assertEqual(result["items"][1]["ssdeep_score"], 96)
            self.assertEqual(result["compared"], 3)
            self.assertEqual(edit["similarity_engine"], copy["similarity_engine"])

    def test_python_fallback_is_bounded(self):
        with patch.object(native, "fuzzy_digests", lambda data: None):
            small = fuzzy_hash.similarity_digests(BASE)
            large = fuzzy_hash.similarity_digests(b"\1" + bytes(fuzzy_hash.PYTHON_FALLBACK_LIMIT))
        self.assertEqual(small["engine"], "python-fallback")
        self.assertEqual(small["tlsh"], CASES["base-60000"][1])
        self.assertEqual(large, {"tlsh": None, "ssdeep": None, "engine": "unavailable", "reason": "native-engine-required"})


if __name__ == "__main__":
    unittest.main()
