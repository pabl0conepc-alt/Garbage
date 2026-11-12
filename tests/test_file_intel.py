import base64
import gzip
import http.client
import io
import json
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from garbage_intel.api import create_server
from garbage_intel.db import initialize
from garbage_intel.errors import ValidationError
from garbage_intel.modules.file_intel import (
    MAX_FILE_BYTES,
    analyze_bytes,
    analyze_file,
    get_file_analysis,
    list_file_analyses,
)
from garbage_intel.store import create_investigation
from garbage_intel.workspace import set_module_state


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def elf64_bytes() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 3)  # ET_DYN
    struct.pack_into("<H", header, 18, 62)  # x86-64
    struct.pack_into("<Q", header, 24, 0x1000)
    struct.pack_into("<Q", header, 32, 0)  # phoff
    struct.pack_into("<Q", header, 40, 0)  # shoff
    struct.pack_into("<H", header, 52, 64)
    struct.pack_into("<H", header, 54, 56)
    struct.pack_into("<H", header, 56, 0)
    struct.pack_into("<H", header, 58, 64)
    struct.pack_into("<H", header, 60, 0)
    struct.pack_into("<H", header, 62, 0)
    return bytes(header)


def pe64_bytes() -> bytes:
    data = bytearray(0x40 + 24 + 0xF0)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x44, 0x8664)
    struct.pack_into("<H", data, 0x46, 0)
    struct.pack_into("<I", data, 0x48, 0)
    struct.pack_into("<H", data, 0x54, 0xF0)
    struct.pack_into("<H", data, 0x56, 0x22)
    optional = 0x58
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<H", data, optional + 68, 3)
    return bytes(data)


def macho64_bytes() -> bytes:
    data = bytearray(32)
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, 0x0100000C)
    struct.pack_into("<I", data, 8, 0)
    struct.pack_into("<I", data, 12, 2)
    struct.pack_into("<I", data, 16, 0)
    struct.pack_into("<I", data, 20, 0)
    struct.pack_into("<I", data, 24, 0)
    struct.pack_into("<I", data, 28, 0)
    return bytes(data)


class FileIntelligenceTests(unittest.TestCase):
    def test_pdf_metadata_and_active_content_are_reported_without_execution(self):
        data = (
            b"%PDF-1.7\n"
            b"1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Page /JavaScript (app.alert) >> endobj\n"
            b"3 0 obj << /Title (Quarterly report) /Author (Analyst) /Producer (Writer) >> endobj\n"
            b"%%EOF"
        )
        analysis = analyze_bytes(data, "report.pdf")
        self.assertEqual(analysis["format"], "pdf")
        self.assertEqual(analysis["media_type"], "application/pdf")
        self.assertEqual(analysis["metadata"]["pdf"]["Title"], "Quarterly report")
        self.assertEqual(analysis["metadata"]["pdf"]["Author"], "Analyst")
        codes = {finding["code"] for finding in analysis["findings"]}
        self.assertIn("pdf-active-content", codes)
        self.assertTrue(any("not executed" in finding["message"] for finding in analysis["findings"]))
        self.assertEqual(analysis["hashes"]["sha256"].__len__(), 64)

    def test_ooxml_archive_lists_members_and_flags_traversal(self):
        data = zip_bytes(
            {
                "[Content_Types].xml": b"<Types/>",
                "word/document.xml": b"<w:document/>",
                "word/vbaProject.bin": b"macro",
                "docProps/core.xml": (
                    b'<?xml version="1.0"?>'
                    b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                    b'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                    b"<dc:title>Draft</dc:title><dc:creator>Analyst</dc:creator>"
                    b"</cp:coreProperties>"
                ),
                "../escape.txt": b"outside",
            }
        )
        analysis = analyze_bytes(data, "draft.docx")
        self.assertEqual(analysis["format"], "docx")
        self.assertEqual(analysis["structure"]["entry_count"], 5)
        names = {entry["name"] for entry in analysis["structure"]["entries"]}
        self.assertIn("../escape.txt", names)
        self.assertTrue(
            any(entry["path_traversal"] for entry in analysis["structure"]["entries"])
        )
        self.assertIn("document_properties", analysis["metadata"])
        self.assertEqual(analysis["metadata"]["document_properties"][0]["value"], "Draft")
        self.assertTrue(any("macro" in finding["message"].lower() for finding in analysis["findings"]))

    def test_gzip_preview_is_bounded_and_reports_bomb_risk(self):
        data = gzip.compress(b"\x00" * (2 * 1024 * 1024), mtime=0)
        analysis = analyze_bytes(data, "bomb.gz")
        self.assertEqual(analysis["format"], "gzip")
        gzip_info = analysis["structure"]["gzip"]
        self.assertLessEqual(gzip_info["decompressed_preview_bytes"], 1024 * 1024)
        self.assertTrue(gzip_info["decompressed_preview_truncated"])
        self.assertTrue(
            any("decompression limit" in finding["message"] for finding in analysis["findings"])
        )

    def test_binary_headers_are_parsed_statically(self):
        elf = analyze_bytes(elf64_bytes(), "sample.elf")
        self.assertEqual(elf["format"], "elf")
        self.assertEqual(elf["metadata"]["binary"]["bits"], 64)
        self.assertEqual(elf["metadata"]["binary"]["machine"], "x86-64")
        self.assertEqual(elf["metadata"]["binary"]["type"], "DYN")
        self.assertEqual(elf["structure"]["sections"], [])
        self.assertEqual(elf["hardening"]["format"], "elf")
        self.assertTrue(elf["hardening"]["checks"])

        pe = analyze_bytes(pe64_bytes(), "sample.exe")
        self.assertEqual(pe["format"], "pe")
        self.assertEqual(pe["metadata"]["binary"]["machine"], "x86-64")
        self.assertEqual(pe["metadata"]["binary"]["subsystem"], "Windows console")
        self.assertEqual(pe["hardening"]["format"], "pe")
        self.assertIn(
            "aslr", {check["key"] for check in pe["hardening"]["checks"]}
        )

        macho = analyze_bytes(macho64_bytes(), "sample.bin")
        self.assertEqual(macho["format"], "macho")
        self.assertEqual(macho["metadata"]["binary"]["cpu"], "AArch64")
        self.assertEqual(macho["metadata"]["binary"]["file_type"], "Executable")

    def test_strings_and_indicators_are_syntactic_only(self):
        data = b"Contact analyst@example.org or visit https://example.org/x at 203.0.113.9"
        analysis = analyze_bytes(data, "notes.txt")
        self.assertEqual(analysis["format"], "text")
        values = {(item["type"], item["value"]) for item in analysis["indicators"]}
        self.assertIn(("email", "analyst@example.org"), values)
        self.assertIn(("ipv4", "203.0.113.9"), values)
        self.assertIn(("url", "https://example.org/x"), values)
        # The host is already represented by each URL/email; emitting it again
        # would inflate indicator counts.
        self.assertNotIn(("domain", "example.org"), values)
        self.assertEqual(analysis["analysis_engine"], "python-stdlib")
        self.assertTrue(all("not a reputation" in item["note"] for item in analysis["indicators"]))

    def test_extension_mismatch_and_limits(self):
        data = zip_bytes({"file.txt": b"content"})
        analysis = analyze_bytes(data, "invoice.pdf")
        self.assertTrue(
            any(finding["code"] == "extension-mismatch" for finding in analysis["findings"])
        )
        with self.assertRaisesRegex(ValidationError, "must not be empty"):
            analyze_bytes(b"")
        with self.assertRaisesRegex(ValidationError, "4 MiB"):
            analyze_bytes(b"x" * (MAX_FILE_BYTES + 1))

    def test_persistent_history_and_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "intel.sqlite3")
            initialize(database)
            investigation = create_investigation(database, "File case")
            analysis = analyze_file(
                database,
                data=b"%PDF-1.7\n/Title (Persisted)\n",
                filename="persisted.pdf",
                investigation_id=investigation["id"],
            )
            self.assertEqual(analysis["file_name"], "persisted.pdf")
            self.assertEqual(analysis["investigation_id"], investigation["id"])
            listed = list_file_analyses(database, investigation_id=investigation["id"])
            self.assertEqual(listed["total"], 1)
            self.assertEqual(listed["items"][0]["sha256"], analysis["hashes"]["sha256"])
            fetched = get_file_analysis(database, analysis["analysis_id"])
            self.assertEqual(fetched["format"], "pdf")
            self.assertEqual(fetched["metadata"]["pdf"]["Title"], "Persisted")

            set_module_state(database, "file-intelligence", "disabled")
            self.assertEqual(list_file_analyses(database)["total"], 1)


class FileIntelligenceApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "intel.sqlite3"
        initialize(self.database)
        self.server = create_server(self.database, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Origin": f"http://127.0.0.1:{self.port}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    def test_analysis_round_trip_and_module_gate(self):
        status, investigation = self.request(
            "POST", "/api/investigations", {"name": "File API case"}
        )
        self.assertEqual(status, 201)
        content = base64.b64encode(b"%PDF-1.7\n/Title (API)\n").decode()
        status, analysis = self.request(
            "POST",
            "/api/intelligence/files",
            {
                "filename": "api.pdf",
                "content_base64": content,
                "investigation_id": investigation["id"],
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(analysis["format"], "pdf")
        self.assertEqual(analysis["metadata"]["pdf"]["Title"], "API")
        status, listed = self.request(
            "GET",
            f"/api/intelligence/files?investigation_id={investigation['id']}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(listed["total"], 1)
        status, fetched = self.request(
            "GET", f"/api/intelligence/files/{analysis['analysis_id']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(fetched["file_name"], "api.pdf")
        set_module_state(self.database, "file-intelligence", "disabled")
        status, error = self.request(
            "POST",
            "/api/intelligence/files",
            {"filename": "x.txt", "content_base64": base64.b64encode(b"x").decode()},
        )
        self.assertEqual(status, 409)
        self.assertIn("disabled", error["error"])

    def test_invalid_base64_is_rejected(self):
        status, error = self.request(
            "POST",
            "/api/intelligence/files",
            {"filename": "x.bin", "content_base64": "%%%"},
        )
        self.assertEqual(status, 400)
        self.assertIn("base64", error["error"])


if __name__ == "__main__":
    unittest.main()
