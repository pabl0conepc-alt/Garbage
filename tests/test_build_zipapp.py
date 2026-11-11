import subprocess
import sys
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ZipappBuildTests(unittest.TestCase):
    def test_builds_runnable_archive_with_web_assets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "garbage.pyz"
            build = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "build_zipapp.py"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertTrue(output.is_file())

            version = subprocess.run(
                [sys.executable, str(output), "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertIn("garbage 0.1.0", version.stdout)

            with zipfile.ZipFile(output) as archive:
                self.assertIn("web/index.html", archive.namelist())

            server = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    str(output),
                    "serve",
                    "--port",
                    "0",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                address = server.stdout.readline().strip()
                self.assertIn("http://127.0.0.1:", address)
                with urllib.request.urlopen(
                    address.rsplit(" ", 1)[-1], timeout=5
                ) as page:
                    self.assertIn(b"GARBAGE", page.read())
            finally:
                server.terminate()
                server.wait(timeout=5)
                server.stdout.close()
                server.stderr.close()

    def test_refuses_to_overwrite_an_existing_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "existing.pyz"
            output.write_bytes(b"preserve")
            build = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "build_zipapp.py"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(build.returncode, 2)
            self.assertIn("output already exists", build.stderr)
            self.assertEqual(output.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
