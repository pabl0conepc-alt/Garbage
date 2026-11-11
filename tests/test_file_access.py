import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from garbage_intel.modules.file_access import (
    _require_regular_file,
    open_regular_file,
)


class SafeFileAccessTests(unittest.TestCase):
    def test_rejects_windows_reparse_points(self):
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_file_attributes=0x400,
        )
        with patch("garbage_intel.modules.file_access.os.name", "nt"):
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                _require_regular_file(metadata)

    def test_rejects_path_replaced_between_check_and_open(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.bin"
            replacement = Path(temp_dir) / "replacement.bin"
            path.write_bytes(b"original")
            replacement.write_bytes(b"replacement")
            real_open = os.open

            def replace_then_open(open_path, flags):
                Path(open_path).unlink()
                replacement.replace(open_path)
                return real_open(open_path, flags)

            with patch(
                "garbage_intel.modules.file_access.os.open",
                side_effect=replace_then_open,
            ):
                with self.assertRaisesRegex(ValueError, "changed while opening"):
                    open_regular_file(path)


if __name__ == "__main__":
    unittest.main()
