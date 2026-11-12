import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from garbage_intel.db import initialize
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.evidence import (
    MAX_EVIDENCE_BYTES,
    add_evidence,
    delete_evidence,
    get_evidence,
    list_evidence,
    storage_directory,
    verify_evidence,
)
from garbage_intel.store import create_investigation, set_investigation_status


def png_bytes(width: int = 4, height: int = 2) -> bytes:
    raw = b"".join(b"\x00" + b"\x00" * (width * 3) for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class EvidenceManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "workspace" / "intel.sqlite3")
        initialize(self.database)
        self.investigation = create_investigation(self.database, "Evidence case")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stores_hash_and_image_metadata_and_verifies_integrity(self):
        data = png_bytes(6, 3)
        record = add_evidence(
            self.database,
            self.investigation["id"],
            title="Screenshot",
            evidence_type="image",
            description="Captured page copy.",
            original_name="capture.png",
            data=data,
            source_reference="https://example.test/page",
        )
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(record["size_bytes"], len(data))
        self.assertEqual(record["image_format"], "PNG")
        self.assertEqual(record["image_width"], 6)
        self.assertEqual(record["image_height"], 3)
        self.assertTrue(record["has_file"])
        self.assertEqual(record["integrity_status"], "unverified")
        self.assertNotIn("stored_name", record)

        listed = list_evidence(self.database, investigation_id=self.investigation["id"])
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["media_type"], "image/png")

        verified = verify_evidence(self.database, record["id"])
        self.assertTrue(verified["matches"])
        self.assertEqual(verified["integrity_status"], "verified")
        self.assertEqual(
            verified["evidence"]["sha256"], verified["computed_sha256"]
        )

        stored_files = list(storage_directory(self.database).iterdir())
        self.assertEqual(len(stored_files), 1)
        stored_files[0].write_bytes(b"tampered evidence")
        tampered = verify_evidence(self.database, record["id"])
        self.assertFalse(tampered["matches"])
        self.assertEqual(tampered["integrity_status"], "mismatch")

        removed = delete_evidence(self.database, record["id"])
        self.assertEqual(removed["removed_files"], 1)
        self.assertFalse(stored_files[0].exists())

    def test_original_name_cannot_escape_the_evidence_directory(self):
        record = add_evidence(
            self.database,
            self.investigation["id"],
            title="Path check",
            evidence_type="image",
            original_name="../../../outside.png",
            data=png_bytes(),
        )
        self.assertNotIn("stored_name", record)
        directory = storage_directory(self.database)
        files = list(directory.iterdir())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].is_file())
        self.assertFalse((Path(self.temp_dir.name) / "outside.png").exists())
        self.assertFalse((Path(self.temp_dir.name) / "workspace" / "outside.png").exists())

    def test_reference_only_evidence_and_size_limits(self):
        reference = add_evidence(
            self.database,
            self.investigation["id"],
            title="Registry entry",
            evidence_type="url",
            source_reference="https://example.test/registry/42",
            sha256="a" * 64,
        )
        self.assertFalse(reference["has_file"])
        self.assertEqual(reference["sha256"], "a" * 64)

        with self.assertRaisesRegex(ValidationError, "4 MiB limit"):
            add_evidence(
                self.database,
                self.investigation["id"],
                title="Too large",
                data=b"x" * (MAX_EVIDENCE_BYTES + 1),
            )
        with self.assertRaisesRegex(ValidationError, "not a recognised image"):
            add_evidence(
                self.database,
                self.investigation["id"],
                title="Fake image",
                evidence_type="image",
                original_name="fake.png",
                data=b"not an image",
            )
        with self.assertRaisesRegex(ValidationError, "provide sha256 or a source"):
            add_evidence(
                self.database,
                self.investigation["id"],
                title="Unanchored reference",
                evidence_type="url",
            )

    def test_closed_investigations_reject_new_evidence(self):
        set_investigation_status(
            self.database, self.investigation["id"], "closed"
        )
        with self.assertRaisesRegex(ConflictError, "investigation is closed"):
            add_evidence(
                self.database,
                self.investigation["id"],
                title="Blocked evidence",
                data=png_bytes(),
            )
        with self.assertRaisesRegex(ValidationError, "sha256 must be"):
            add_evidence(
                self.database,
                self.investigation["id"],
                title="Invalid digest",
                sha256="not-a-digest",
                source_reference="note://analyst",
            )

    def test_get_missing_evidence_raises(self):
        with self.assertRaisesRegex(Exception, "evidence not found"):
            get_evidence(self.database, "00000000-0000-0000-0000-000000000000")


if __name__ == "__main__":
    unittest.main()
