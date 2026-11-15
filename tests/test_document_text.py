"""Readable text from documents, and OCR when Tesseract is present."""

import io
import unittest
import zipfile
import zlib
from unittest.mock import patch

from garbage_intel.modules import document_text as dt
from garbage_intel.modules import file_intel

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
S = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'


def zipped(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def pdf(content, extra=b""):
    stream = zlib.compress(content)
    return (
        b"%PDF-1.4\n1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n"
        b"3 0 obj <</Type /Page /Parent 2 0 R /Contents 4 0 R>> endobj\n4 0 obj <</Length " + str(len(stream)).encode()
        + b" /Filter /FlateDecode>>\nstream\n" + stream + b"\nendstream\nendobj\n" + extra + b"trailer <</Root 1 0 R>>\n%%EOF"
    )


class OfficeTests(unittest.TestCase):
    def test_word_with_header_and_tabs(self):
        data = zipped({
            "word/document.xml": f"<w:document {W}><w:body><w:p><w:r><w:t>Contrato com</w:t><w:t xml:space='preserve'> contato@example.org</w:t></w:r></w:p>"
                                 f"<w:p><w:r><w:t>Valor</w:t><w:tab/><w:t>R$ 10</w:t></w:r></w:p></w:body></w:document>",
            "word/header1.xml": f"<w:hdr {W}><w:p><w:r><w:t>CONFIDENCIAL</w:t></w:r></w:p></w:hdr>",
        })
        text = dt.extract(data, "docx")
        self.assertEqual(text["content"], "Contrato com contato@example.org\nValor\tR$ 10\n\n[header1]\nCONFIDENCIAL")
        self.assertEqual(text["method"], "texto do Word")
        analysis = file_intel.analyze_bytes(data, "contrato.docx")
        self.assertIn("contato@example.org", [item["value"] for item in analysis["indicators"]])

    def test_excel_sheets_shared_strings_and_numbers(self):
        data = zipped({
            "xl/workbook.xml": f"<workbook {S}><sheets><sheet name='Pagamentos' sheetId='1'/></sheets></workbook>",
            "xl/sharedStrings.xml": f"<sst {S}><si><t>Fornecedor</t></si><si><t>ACME</t></si></sst>",
            "xl/worksheets/sheet1.xml": f"<worksheet {S}><sheetData><row><c t='s'><v>0</v></c><c><v>1500.5</v></c></row>"
                                        f"<row><c t='s'><v>1</v></c><c t='inlineStr'><is><t>pago</t></is></c></row></sheetData></worksheet>",
        })
        self.assertEqual(dt.extract(data, "xlsx")["content"], "[Pagamentos]\nFornecedor\t1500.5\nACME\tpago")

    def test_powerpoint_slides_in_order_with_notes(self):
        slide = lambda text: f"<p:sld xmlns:p='urn:p' {A}><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>"
        data = zipped({
            "ppt/presentation.xml": "<p/>",
            "ppt/slides/slide10.xml": slide("Décimo"),
            "ppt/slides/slide2.xml": slide("Segundo"),
            "ppt/notesSlides/notesSlide2.xml": slide("lembrar"),
        })
        self.assertEqual(dt.extract(data, "zip")["content"], "[Slide 1]\nSegundo\n(nota) lembrar\n\n[Slide 2]\nDécimo")

    def test_opendocument_epub_and_refused_entities(self):
        odt = zipped({"mimetype": "application/vnd.oasis.opendocument.text",
                      "content.xml": "<office:document-content xmlns:office='urn:o' xmlns:text='urn:oasis:names:tc:opendocument:xmlns:text:1.0'>"
                                     "<text:h>Título</text:h><text:p>Corpo</text:p></office:document-content>"})
        self.assertEqual(dt.extract(odt, "zip")["content"], "Título\nCorpo")
        epub = zipped({"mimetype": "application/epub+zip", "OEBPS/c1.xhtml": "<html><body><p>Capítulo</p><script>x()</script></body></html>"})
        self.assertEqual(dt.extract(epub, "epub")["content"], "Capítulo")
        bomb = zipped({"word/document.xml": f"<!DOCTYPE x [<!ENTITY a 'aaaa'>]><w:document {W}><w:body><w:p><w:r><w:t>&a;</w:t></w:r></w:p></w:body></w:document>"})
        self.assertEqual(dt.extract(bomb, "docx")["content"], "")


class PdfAndTextTests(unittest.TestCase):
    def test_pdf_text_layer_lines_and_words(self):
        data = pdf(b"BT /F1 12 Tf 72 712 Td (Ola \\(mundo\\)) Tj 0 -14 Td [(Segunda) -300 (linha)] TJ 120 0 Td (longe) Tj ET")
        text = dt.extract(data, "pdf", use_ocr=False)
        self.assertEqual(text["content"], "Ola (mundo)\nSegunda linha longe")
        self.assertEqual(text["parts"], 1)

    def test_pdf_identity_font_through_to_unicode(self):
        cmap = zlib.compress(b"/CIDInit begincmap 2 beginbfchar <0001> <0047> <0002> <006F> endbfchar 1 beginbfrange <0003> <0004> <0061> endbfrange endcmap")
        extra = b"5 0 obj <</Length " + str(len(cmap)).encode() + b" /Filter /FlateDecode>>\nstream\n" + cmap + b"\nendstream\nendobj\n"
        data = pdf(b"BT /F2 11 Tf <000100020003> Tj ET", extra)
        self.assertEqual(dt.extract(data, "pdf", use_ocr=False)["content"], "Goa")

    def test_rtf_html_and_plain(self):
        self.assertEqual(dt.extract(b"{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\\f0 Ol\\'e1 mundo\\par segunda}", "rtf")["content"], "Olá mundo\nsegunda")
        self.assertEqual(dt.extract(b"<p>Oi</p><style>p{}</style><div>tchau &amp; mais</div>", "html")["content"], "Oi\n\ntchau & mais")
        self.assertEqual(dt.extract("linha 1\r\nlinha 2".encode(), "text")["content"], "linha 1\nlinha 2")
        self.assertIsNone(dt.extract(b"\x7fELF", "elf"))


class OcrTests(unittest.TestCase):
    ENGINE = {"available": True, "binary": "tesseract", "version": "tesseract 5", "languages": ["eng", "por"], "pdf_pages": True}

    def test_image_ocr_when_installed_and_note_when_not(self):
        with patch.object(dt, "ocr_engine", lambda: self.ENGINE), patch.object(dt, "_ocr_images", lambda paths, engine: "TEXTO LIDO"):
            text = dt.extract(b"\x89PNG....", "png")
        self.assertEqual((text["content"], text["method"], text["note"]), ("TEXTO LIDO", "OCR", "OCR com tesseract 5"))
        with patch.object(dt, "ocr_engine", lambda: {"available": False, "reason": "Tesseract não está instalado"}):
            missing = dt.extract(b"\x89PNG....", "png")
        self.assertEqual((missing["content"], missing["note"]), ("", "Tesseract não está instalado"))

    def test_scanned_pdf_falls_back_to_ocr(self):
        data = pdf(b"q 100 0 0 100 0 0 cm /Im1 Do Q")
        with patch.object(dt, "ocr", lambda data, kind, engine=None: ("página escaneada", "OCR com tesseract 5 das 1 primeira(s) página(s)")):
            text = dt.extract(data, "pdf")
        self.assertEqual((text["content"], text["method"]), ("página escaneada", "OCR"))

    def test_languages_prefer_portuguese_and_english(self):
        calls = []

        class Done:
            stdout = b"ok"

        def run(command, **options):
            calls.append(command)
            return Done()

        with patch.object(dt.subprocess, "run", run):
            dt._ocr_images(["/tmp/x.png"], self.ENGINE)
        self.assertEqual(calls[0][-2:], ["-l", "por+eng"])


if __name__ == "__main__":
    unittest.main()
