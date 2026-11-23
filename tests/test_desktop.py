"""`garbage app`: the workstation in its own window.

The window engines are replaced by fakes that, while "open", request the
page from the server they were given, as a real window would.
"""

import sys
import tempfile
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from garbage_intel import desktop
from garbage_intel.store import initialize


def fetch(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "desktop.sqlite3")
        initialize(self.database)
        self.seen = {}

    def assert_stopped(self, url):
        with self.assertRaises((urllib.error.URLError, ConnectionError)):
            fetch(url)

    def test_webview_window_serves_the_interface_and_stops_on_close(self):
        fake = types.ModuleType("webview")
        fake.settings = {}

        def create_window(title, url, **options):
            self.seen.update(title=title, url=url, options=options)

        def start(**options):
            self.seen["start"] = options
            self.seen["page"] = fetch(self.seen["url"])
            self.seen["health"] = fetch(self.seen["url"] + "api/health")

        fake.create_window, fake.start = create_window, start
        with patch.dict(sys.modules, {"webview": fake}), patch.object(desktop, "_gui_options", return_value={"gui": "gtk"}):
            engine = desktop.run(self.database, engine="auto")
        self.assertEqual(engine, "webview")
        self.assertEqual(self.seen["title"], "GARBAGE")
        self.assertTrue(self.seen["url"].startswith("http://127.0.0.1:"))
        self.assertEqual(self.seen["page"][0], 200)
        self.assertIn("<html", self.seen["page"][1])
        self.assertEqual(self.seen["health"][0], 200)
        self.assertTrue(fake.settings["ALLOW_DOWNLOADS"])
        self.assertEqual(self.seen["start"], {"gui": "gtk"})
        self.assert_stopped(self.seen["url"])

    def test_browser_app_mode_uses_its_own_profile(self):
        test = self

        class FakeProcess:
            def __init__(self, arguments):
                test.seen["arguments"] = arguments

            def wait(self):
                url = next(item for item in test.seen["arguments"] if item.startswith("--app=")).removeprefix("--app=")
                test.seen["url"] = url
                test.seen["page"] = fetch(url)
                return 0

        with patch.object(desktop, "_webview", return_value=None), \
                patch.object(desktop, "find_browser", return_value="/opt/chromium/chrome"), \
                patch.object(desktop.subprocess, "Popen", FakeProcess):
            engine = desktop.run(self.database, engine="auto")
        self.assertEqual(engine, "browser")
        arguments = self.seen["arguments"]
        self.assertEqual(arguments[0], "/opt/chromium/chrome")
        profile = Path(self.directory.name).resolve() / ".garbage-window"
        self.assertIn(f"--user-data-dir={profile}", arguments)
        self.assertTrue(profile.is_dir())
        self.assertIn("--disable-sync", arguments)
        self.assertEqual(self.seen["page"][0], 200)
        self.assert_stopped(self.seen["url"])

    def test_requested_engine_missing_is_an_error_before_serving(self):
        with patch.object(desktop, "_webview", return_value=None), patch.object(desktop, "create_server") as server:
            with self.assertRaises(desktop.DesktopError):
                desktop.run(self.database, engine="webview")
        with patch.object(desktop, "find_browser", return_value=None), patch.object(desktop, "create_server") as later:
            with self.assertRaises(desktop.DesktopError):
                desktop.run(self.database, engine="browser")
        server.assert_not_called()
        later.assert_not_called()
        with self.assertRaises(ValueError):
            desktop.run(self.database, engine="electron")

    def test_find_browser_prefers_path_then_install_locations(self):
        with patch.object(desktop.shutil, "which", side_effect=lambda name: "/usr/bin/chromium" if name == "chromium" else None):
            self.assertEqual(desktop.find_browser(), "/usr/bin/chromium")
        with patch.object(desktop.shutil, "which", return_value=None), \
                patch.object(desktop, "_installed_browsers", return_value=[Path(self.database)]):
            self.assertEqual(desktop.find_browser(), self.database)
        with patch.object(desktop.shutil, "which", return_value=None), patch.object(desktop, "_installed_browsers", return_value=[]):
            self.assertIsNone(desktop.find_browser())


if __name__ == "__main__":
    unittest.main()
