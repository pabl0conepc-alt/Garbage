import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.cli import main
from garbage_intel.platform_support import runtime_diagnostics


class PlatformSupportTests(unittest.TestCase):
    def test_linux_diagnostics_include_distribution_without_database_setup(self):
        with patch("garbage_intel.platform_support.platform.system", return_value="Linux"), patch(
            "garbage_intel.platform_support.platform.freedesktop_os_release",
            return_value={"PRETTY_NAME": "Example Linux"},
        ):
            result = runtime_diagnostics()

        self.assertEqual(result["platform"]["system"], "Linux")
        self.assertEqual(result["platform"]["distribution"], "Example Linux")
        self.assertTrue(result["platform"]["supported"])
        self.assertTrue(result["python"]["supported"])

    def test_windows_diagnostics_do_not_read_linux_distribution_metadata(self):
        with patch("garbage_intel.platform_support.platform.system", return_value="Windows"), patch(
            "garbage_intel.platform_support.platform.freedesktop_os_release",
            side_effect=AssertionError("not a Linux host"),
        ):
            result = runtime_diagnostics()

        self.assertEqual(result["platform"]["system"], "Windows")
        self.assertIsNone(result["platform"]["distribution"])
        self.assertTrue(result["platform"]["supported"])

    def test_doctor_does_not_create_the_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "not-created.sqlite3"
            with patch("sys.stdout"):
                status = main(["--database", str(database), "doctor"])

            self.assertEqual(status, 0)
            self.assertFalse(database.exists())


if __name__ == "__main__":
    unittest.main()
