"""Phase 6: embedded signature scan (Rust engine and Python reference)."""

import gzip
import os
import random
import struct
import unittest
from pathlib import Path

from garbage_intel import native
from garbage_intel.modules import embedded_scan as es
from garbage_intel.modules.file_intel import analyze_bytes

FIXTURES = Path(__file__).parent / "fixtures"


def tiny_pe(machine=0x8664):
    pe = bytearray(0x80)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 60, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x44, machine)
    return bytes(pe)


def jpeg_with_payload():
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(200)
        + tiny_pe()
        + b"\x1f\x8b\x08\x00" + bytes(6)
        + b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
        + b"\xff\xd9"
    )


class ReferenceScanTests(unittest.TestCase):
    def test_hits_and_validation(self):
        hits, truncated = es.python_scan(jpeg_with_payload())
        self.assertFalse(truncated)
        self.assertEqual([(offset, es.KINDS[kind][0]) for offset, kind, _ in hits], [(0, "jpeg"), (211, "pe"), (339, "gzip"), (349, "pem")])
        self.assertEqual(hits[1][2], 0x8664)
        self.assertEqual(hits[3][2], 2)
        # Magic numbers without valid headers are ignored.
        self.assertEqual(es.python_scan(b"MZ" + bytes(100) + b"PK\x03\x04" + b"\xff" * 40 + b"%PDF-x")[0], [])

    def test_offset_magics(self):
        image = gzip.decompress((FIXTURES / "genisoimage-joliet.iso.gz").read_bytes())
        self.assertIn((0, 21, 0), es.python_scan(image)[0])
        tar = bytes(257) + b"ustar\x0000" + bytes(100)
        self.assertEqual(es.python_scan(tar)[0], [(0, 20, 0)])

    def test_cap(self):
        header = b"PK\x03\x04\x0a\x00\x00\x00\x00\x00" + bytes(16) + b"\x01\x00\x00\x00"
        hits, truncated = es.python_scan(header * (es.SCAN_CAP + 10))
        self.assertTrue(truncated)
        self.assertEqual(len(hits), es.SCAN_CAP)

    def test_grouping_and_findings(self):
        analysis = analyze_bytes(jpeg_with_payload(), "photo.jpg")
        kinds = [item["kind"] for item in analysis["embedded"]["items"]]
        self.assertEqual(kinds, ["jpeg", "pe", "gzip", "pem"])
        self.assertEqual(analysis["embedded"]["embedded_executables"], ["pe"])
        codes = {item["code"] for item in analysis["findings"]}
        self.assertTrue({"embedded-executable", "embedded-private-key"} <= codes)
        many = b"".join(b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + bytes(16) + b"\x01\x00\x00\x00a" for _ in range(5))
        grouped = es.scan_signatures(bytes(10) + many, "unknown")
        self.assertEqual([(item["kind"], item["count"]) for item in grouped["items"]], [("zip", 5)])
        self.assertEqual(es.scan_signatures(many, "zip")["items"], [])


@unittest.skipUnless(native._RUST_SIGNATURES is not None, "Rust signature engine not built")
class NativeParityTests(unittest.TestCase):
    def test_native_matches_reference(self):
        rng = random.Random(3)
        magics = [magic for magic, _ in es._RULES] + [b"ustar\x0000", b"\x01CD001\x01"]
        inputs = [b"", jpeg_with_payload(), gzip.decompress((FIXTURES / "genisoimage-joliet.iso.gz").read_bytes())]
        for _ in range(25):
            data = bytearray(os.urandom(rng.randrange(1000, 60000)))
            for _ in range(rng.randrange(1, 200)):
                magic = rng.choice(magics)
                position = rng.randrange(len(data))
                data[position : position + len(magic)] = magic
            inputs.append(bytes(data))
        for data in inputs:
            with self.subTest(size=len(data)):
                self.assertEqual(native.signature_scan(data), es.python_scan(data))


if __name__ == "__main__":
    unittest.main()
