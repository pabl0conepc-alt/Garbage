import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from garbage_intel.modules.document_metadata import get_document_metadata


class DocumentMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_returns_file_metadata_without_document_contents(self):
        document = self.directory / "report.txt"
        document.write_bytes(b"analyst-provided document")

        result = get_document_metadata(document)

        self.assertEqual(result["file_name"], "report.txt")
        self.assertEqual(result["suffix"], ".txt")
        self.assertEqual(result["media_type"], "text/plain")
        self.assertEqual(result["size_bytes"], len(b"analyst-provided document"))
        modified_at = datetime.fromisoformat(
            result["modified_at"].replace("Z", "+00:00")
        )
        self.assertIsNotNone(modified_at.tzinfo)
        self.assertEqual(modified_at.utcoffset().total_seconds(), 0)
        self.assertNotIn("contents", result)

    def test_rejects_missing_paths(self):
        with self.assertRaisesRegex(FileNotFoundError, "document does not exist"):
            get_document_metadata(self.directory / "missing.pdf")

    def test_rejects_directories(self):
        with self.assertRaisesRegex(ValueError, "regular file"):
            get_document_metadata(self.directory)

    def test_rejects_symbolic_links(self):
        document = self.directory / "report.txt"
        document.write_text("data")
        link = self.directory / "link.txt"
        try:
            link.symlink_to(document)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are not supported: {error}")

        with self.assertRaisesRegex(ValueError, "symbolic links"):
            get_document_metadata(link)


if __name__ == "__main__":
    unittest.main()
