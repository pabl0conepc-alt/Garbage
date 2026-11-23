"""ClamAV through clamd (INSTREAM over a socket) or clamscan."""

import socketserver
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel.db import initialize
from garbage_intel.modules import antivirus, file_intel

BAD = b"GARBAGE test sample"


class FakeClamd(socketserver.BaseRequestHandler):
    def handle(self):
        command = b""
        while not command.endswith(b"\0"):
            command += self.request.recv(1)
        if command == b"zPING\0":
            self.request.sendall(b"PONG\0")
        elif command == b"zVERSION\0":
            self.request.sendall(b"ClamAV 1.5.4/27800/Sat Nov 14 2026\0")
        elif command == b"zINSTREAM\0":
            data = b""
            while True:
                size = struct.unpack(">I", self._read(4))[0]
                if not size:
                    break
                data += self._read(size)
            reply = b"stream: Garbage.Test FOUND\0" if BAD in data else b"stream: OK\0"
            self.request.sendall(reply)

    def _read(self, size):
        chunk = b""
        while len(chunk) < size:
            chunk += self.request.recv(size - len(chunk))
        return chunk


class AntivirusTests(unittest.TestCase):
    def setUp(self):
        antivirus._ENGINE.clear()
        self.addCleanup(antivirus._ENGINE.clear)

    def test_verdicts(self):
        self.assertEqual(antivirus._verdict("stream: OK"), ("clean", ""))
        self.assertEqual(antivirus._verdict("stream: Win.Test.EICAR_HDB-1 FOUND"), ("infected", "Win.Test.EICAR_HDB-1"))
        self.assertEqual(antivirus._verdict("stdin: Garbage.Test.UNOFFICIAL FOUND\n"), ("infected", "Garbage.Test.UNOFFICIAL"))
        self.assertEqual(antivirus._verdict("stream: Size limit reached ERROR"), ("error", "Size limit reached"))

    def test_clamd_instream_in_chunks(self):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeClamd)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        address = f"tcp://127.0.0.1:{server.server_address[1]}"
        with patch.dict("os.environ", {"GARBAGE_CLAMD": address}):
            found = antivirus.engine(refresh=True)
            self.assertEqual((found["mode"], found["version"]), ("clamd", "ClamAV 1.5.4/27800/Sat Nov 14 2026"))
            infected = antivirus.scan(b"x" * (antivirus.CHUNK * 2 + 10) + BAD)
            clean = antivirus.scan(b"harmless")
        self.assertEqual((infected["status"], infected["signature"]), ("infected", "Garbage.Test"))
        self.assertEqual(clean["status"], "clean")

    def test_only_loopback_daemons(self):
        with self.assertRaises(OSError):
            antivirus._connect("tcp://192.0.2.1:3310", 1)

    def test_clamscan_and_missing_engine(self):
        class Done:
            returncode = 1
            stdout = b"stdin: Garbage.Test.UNOFFICIAL FOUND\n"
            stderr = b""

        with patch.object(antivirus, "_daemon", lambda: None), patch.object(antivirus.shutil, "which", lambda name: "/usr/bin/clamscan"), \
                patch.object(antivirus.subprocess, "run", lambda command, **options: Done()):
            result = antivirus.scan(BAD)
        self.assertEqual((result["status"], result["mode"], result["signature"]), ("infected", "clamscan", "Garbage.Test.UNOFFICIAL"))
        antivirus._ENGINE.clear()
        with patch.object(antivirus, "_daemon", lambda: None), patch.object(antivirus.shutil, "which", lambda name: None), \
                patch.dict("os.environ", {}, clear=False):
            self.assertEqual(antivirus.scan(BAD)["status"], "unavailable")

    def test_detection_becomes_the_first_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            database = str(Path(folder) / "av.sqlite3")
            initialize(database)
            with patch.object(antivirus, "scan", lambda data: {"status": "infected", "signature": "Garbage.Test", "engine": "ClamAV 1.5.4", "mode": "clamd"}):
                analysis = file_intel.analyze_file(database, data=b"some bytes", filename="x.bin")
        self.assertEqual(analysis["antivirus"]["signature"], "Garbage.Test")
        self.assertEqual(analysis["findings"][0]["code"], "antivirus-detection")


if __name__ == "__main__":
    unittest.main()
