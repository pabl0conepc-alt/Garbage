import hashlib
import tempfile
import unittest
from pathlib import Path

from garbage_intel.modules.forensics import hash_file


class ForensicHashTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_hashes_one_file_without_reading_its_contents_into_the_result(self):
        contents = b"analyst-provided evidence"
        evidence = self.directory / "evidence.bin"
        evidence.write_bytes(contents)

        result = hash_file(evidence)
        self.assertEqual(result["sha256"], hashlib.sha256(contents).hexdigest())
        self.assertEqual(result["size_bytes"], len(contents))
        self.assertEqual(result["file_name"], "evidence.bin")
        self.assertNotIn("contents", result)

    def test_rejects_directories_and_symbolic_links(self):
        evidence = self.directory / "evidence.bin"
        evidence.write_text("data")
        link = self.directory / "link.bin"
        link.symlink_to(evidence)

        with self.assertRaisesRegex(ValueError, "regular file"):
            hash_file(self.directory)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            hash_file(link)


if __name__ == "__main__":
    unittest.main()
