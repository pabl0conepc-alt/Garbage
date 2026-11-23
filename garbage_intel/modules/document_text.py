"""Readable text out of documents and images, for the file analysis.

Office Open XML (Word, Excel, PowerPoint), OpenDocument, EPUB, PDF, RTF,
HTML and plain text are read with the standard library, in memory. Images,
and PDFs that carry no text layer, go through OCR when Tesseract is
installed (Poppler's pdftoppm renders PDF pages for it); both run as
separate processes on a temporary copy, with a time limit, and are skipped
when absent.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import zlib
from html.parser import HTMLParser
from typing import Any
from xml.etree import ElementTree

MAX_TEXT_CHARS = 200_000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_PDF_STREAMS = 4000
OCR_TIMEOUT_SECONDS = 60
OCR_MAX_PDF_PAGES = 5
OCR_IMAGE_KINDS = frozenset({"png", "jpeg", "gif", "bmp", "webp", "tiff"})

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
TEXT_NS = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"


def _xml(archive: zipfile.ZipFile, name: str) -> ElementTree.Element | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_MEMBER_BYTES:
        return None
    try:
        raw = archive.read(info)
        # No DTDs: entity tricks (billion laughs) are refused outright.
        if b"<!DOCTYPE" in raw[:2048] or b"<!ENTITY" in raw:
            return None
        return ElementTree.fromstring(raw)
    except (ElementTree.ParseError, zipfile.BadZipFile, RuntimeError, ValueError, OSError):
        return None


def _numbered(names: list[str], pattern: str) -> list[str]:
    found = []
    for name in names:
        match = re.fullmatch(pattern, name)
        if match:
            found.append((int(match.group(1)), name))
    return [name for _, name in sorted(found)]


# ---------------------------------------------------------------------------
# Office Open XML


def _word_paragraphs(root: ElementTree.Element) -> list[str]:
    lines = []
    for paragraph in root.iter(f"{W}p"):
        parts = []
        for node in paragraph.iter():
            if node.tag == f"{W}t" and node.text:
                parts.append(node.text)
            elif node.tag == f"{W}tab":
                parts.append("\t")
            elif node.tag in (f"{W}br", f"{W}cr"):
                parts.append("\n")
        line = "".join(parts).strip()
        if line:
            lines.append(line)
    return lines


def _docx(archive: zipfile.ZipFile) -> tuple[str, int]:
    names = archive.namelist()
    parts = ["word/document.xml"]
    parts += sorted(name for name in names if re.fullmatch(r"word/(header|footer)\d*\.xml", name))
    parts += [name for name in ("word/footnotes.xml", "word/endnotes.xml", "word/comments.xml") if name in names]
    blocks = []
    for name in parts:
        root = _xml(archive, name)
        if root is None:
            continue
        lines = _word_paragraphs(root)
        if lines:
            label = {"word/document.xml": ""}.get(name, f"[{name.split('/')[-1].removesuffix('.xml')}]")
            blocks.append("\n".join(([label] if label else []) + lines))
    return "\n\n".join(blocks), len(parts)


def _xlsx(archive: zipfile.ZipFile) -> tuple[str, int]:
    shared: list[str] = []
    strings = _xml(archive, "xl/sharedStrings.xml")
    if strings is not None:
        for item in strings.iter(f"{S}si"):
            shared.append("".join(node.text or "" for node in item.iter(f"{S}t")))
    sheet_names: list[str] = []
    workbook = _xml(archive, "xl/workbook.xml")
    if workbook is not None:
        sheet_names = [sheet.get("name", "") for sheet in workbook.iter(f"{S}sheet")]
    sheets = _numbered(archive.namelist(), r"xl/worksheets/sheet(\d+)\.xml")
    blocks = []
    for index, name in enumerate(sheets):
        root = _xml(archive, name)
        if root is None:
            continue
        rows = []
        for row in root.iter(f"{S}row"):
            cells = []
            for cell in row.iter(f"{S}c"):
                kind = cell.get("t", "")
                value = cell.find(f"{S}v")
                if kind == "s" and value is not None and (value.text or "").isdigit():
                    position = int(value.text)
                    cells.append(shared[position] if position < len(shared) else "")
                elif kind == "inlineStr":
                    cells.append("".join(node.text or "" for node in cell.iter(f"{S}t")))
                elif value is not None and value.text:
                    cells.append(value.text)
            if any(cell.strip() for cell in cells):
                rows.append("\t".join(cells))
        if rows:
            title = sheet_names[index] if index < len(sheet_names) and sheet_names[index] else f"Planilha {index + 1}"
            blocks.append(f"[{title}]\n" + "\n".join(rows))
    return "\n\n".join(blocks), len(sheets)


def _pptx(archive: zipfile.ZipFile) -> tuple[str, int]:
    names = archive.namelist()
    slides = _numbered(names, r"ppt/slides/slide(\d+)\.xml")
    blocks = []
    for number, name in enumerate(slides, start=1):
        lines = []
        for path in (name, name.replace("slides/slide", "notesSlides/notesSlide")):
            root = _xml(archive, path)
            if root is None:
                continue
            for paragraph in root.iter(f"{A}p"):
                line = "".join(node.text or "" for node in paragraph.iter(f"{A}t")).strip()
                if line:
                    lines.append(line if path == name else f"(nota) {line}")
        if lines:
            blocks.append(f"[Slide {number}]\n" + "\n".join(lines))
    return "\n\n".join(blocks), len(slides)


def _opendocument(archive: zipfile.ZipFile) -> tuple[str, int]:
    root = _xml(archive, "content.xml")
    if root is None:
        return "", 0
    lines = []
    for node in root.iter():
        if node.tag in (f"{TEXT_NS}p", f"{TEXT_NS}h"):
            line = "".join(node.itertext()).strip()
            if line:
                lines.append(line)
    return "\n".join(lines), 1


class _HtmlText(HTMLParser):
    BLOCKS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "td", "th"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style", "noscript", "template"):
            self.skip += 1
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript", "template") and self.skip:
            self.skip -= 1
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)


def html_text(markup: str) -> str:
    parser = _HtmlText()
    try:
        parser.feed(markup)
        parser.close()
    except (AssertionError, ValueError):
        pass
    return _tidy("".join(parser.parts))


def _epub(archive: zipfile.ZipFile) -> tuple[str, int]:
    pages = sorted(name for name in archive.namelist() if name.lower().endswith((".xhtml", ".html", ".htm")))
    blocks = []
    for name in pages[:300]:
        info = archive.getinfo(name)
        if info.file_size <= MAX_MEMBER_BYTES:
            text = html_text(archive.read(info).decode("utf-8", "replace"))
            if text:
                blocks.append(text)
    return "\n\n".join(blocks), len(pages)


# ---------------------------------------------------------------------------
# PDF text operators


_STREAM = re.compile(rb"<<(.{0,2000}?)>>\s*stream\r?\n", re.DOTALL)


def _pdf_streams(data: bytes) -> list[tuple[bytes, bytes]]:
    """(dictionary, decoded content) for each stream, Flate decoded when needed."""
    streams = []
    for match in _STREAM.finditer(data):
        if len(streams) >= MAX_PDF_STREAMS:
            break
        start = match.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end].rstrip(b"\r\n")
        header = match.group(1)
        if b"/FlateDecode" in header:
            try:
                raw = zlib.decompressobj().decompress(raw, MAX_MEMBER_BYTES)
            except zlib.error:
                continue
        elif b"/Filter" in header:
            continue  # images and other codecs carry no text operators
        streams.append((header, raw))
    return streams


def _unicode_map(streams: list[tuple[bytes, bytes]]) -> dict[bytes, str]:
    """ToUnicode CMaps of every font, merged: enough for Identity-H text."""
    mapping: dict[bytes, str] = {}

    def code(hex_text: bytes) -> bytes:
        return bytes.fromhex(hex_text.decode())

    def text(hex_text: bytes) -> str:
        try:
            return bytes.fromhex(hex_text.decode()).decode("utf-16-be", "replace")
        except ValueError:
            return ""

    for _, content in streams:
        if b"begincmap" not in content:
            continue
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", content, re.DOTALL):
            for source, target in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block):
                try:
                    mapping[code(source)] = text(target)
                except ValueError:
                    continue
        for block in re.findall(rb"beginbfrange(.*?)endbfrange", content, re.DOTALL):
            for low, high, target in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block):
                try:
                    first, last, base = int(low, 16), int(high, 16), int(target, 16)
                except ValueError:
                    continue
                width = len(low) // 2
                for offset in range(min(last - first + 1, 2048)):
                    mapping[(first + offset).to_bytes(width, "big")] = chr(base + offset) if base + offset < 0x110000 else ""
    return mapping


_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}


def _literal(raw: bytes) -> bytes:
    out = bytearray()
    index = 0
    while index < len(raw):
        char = raw[index:index + 1]
        if char == b"\\" and index + 1 < len(raw):
            following = raw[index + 1:index + 2]
            if following in _ESCAPES:
                out += _ESCAPES[following]
                index += 2
                continue
            octal = re.match(rb"[0-7]{1,3}", raw[index + 1:index + 4])
            if octal:
                out.append(int(octal.group(0), 8) & 0xFF)
                index += 1 + len(octal.group(0))
                continue
            index += 2
            continue
        out += char
        index += 1
    return bytes(out)


def _decode(raw: bytes, mapping: dict[bytes, str]) -> str:
    if mapping and len(raw) % 2 == 0 and raw[:2] in mapping:
        return "".join(mapping.get(raw[index:index + 2], "") for index in range(0, len(raw), 2))
    if mapping and all(raw[index:index + 1] in mapping for index in range(len(raw))):
        return "".join(mapping[raw[index:index + 1]] for index in range(len(raw)))
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


_TOKEN = re.compile(rb"\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>|\[|\]|BT|ET|Tf|T[dDj*J]|'|\"|-?\d*\.?\d+", re.DOTALL)


def _content_text(content: bytes, mapping: dict[bytes, str]) -> str:
    out: list[str] = []
    operands: list[float] = []
    font_size = 10.0
    since_move = 0  # characters drawn since the last positioning

    def emit(text: str) -> None:
        nonlocal since_move
        out.append(text)
        since_move += len(text)

    for match in _TOKEN.finditer(content):
        token = match.group(0)
        if token.startswith(b"("):
            emit(_decode(_literal(token[1:-1]), mapping))
        elif token.startswith(b"<"):
            hex_text = re.sub(rb"\s", b"", token[1:-1])
            if len(hex_text) % 2:
                hex_text += b"0"
            try:
                emit(_decode(bytes.fromhex(hex_text.decode()), mapping))
            except ValueError:
                pass
        elif token == b"Tf":
            if operands:
                font_size = abs(operands[-1]) or font_size
        elif token in (b"Td", b"TD"):
            if len(operands) >= 2 and abs(operands[-1]) > 0.5:
                out.append("\n")
            elif len(operands) >= 2:
                # A move wider than the text just drawn (glyphs about 0.8 em
                # at most) leaves a gap: a word break.
                if operands[-2] > since_move * font_size * 0.8 + font_size * 0.25 and out and not out[-1].endswith((" ", "\n")):
                    out.append(" ")
            since_move = 0
        elif token in (b"T*", b"'", b'"', b"ET"):
            out.append("\n")
            since_move = 0
        elif token[:1].isdigit() or token[:1] in (b"-", b"."):
            try:
                value = float(token)
            except ValueError:
                continue
            operands.append(value)
            operands = operands[-6:]
            # Large negative kerning inside TJ arrays separates words.
            if value < -200 and out and not out[-1].endswith(" "):
                out.append(" ")
            continue
        operands = []
    return "".join(out)


def _pdf(data: bytes) -> tuple[str, int]:
    streams = _pdf_streams(data)
    mapping = _unicode_map(streams)
    pages = len(re.findall(rb"/Type\s*/Page[^s]", data))
    blocks = []
    for header, content in streams:
        if b"begincmap" in content or b"BT" not in content:
            continue
        text = _content_text(content, mapping)
        if text.strip():
            blocks.append(text)
    return "\n".join(blocks), pages


# ---------------------------------------------------------------------------
# RTF, text


def _rtf(data: bytes) -> str:
    text = data.decode("latin-1")
    # Destinations that never show as text: fonts, colours, styles, pictures.
    text = re.sub(r"\{\\\*[^{}]*(\{[^{}]*\}[^{}]*)*\}", "", text)
    text = re.sub(r"\{\\(fonttbl|colortbl|stylesheet|info|pict)[^{}]*(\{[^{}]*\}[^{}]*)*\}", "", text)
    text = re.sub(r"\\'([0-9a-fA-F]{2})", lambda match: bytes([int(match.group(1), 16)]).decode("cp1252", "replace"), text)
    text = re.sub(r"\\u(-?\d+)\??", lambda match: chr(int(match.group(1)) % 65536), text)
    text = re.sub(r"\\(par|line|row)\b ?", "\n", text)
    text = re.sub(r"\\tab\b ?", "\t", text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)
    text = text.replace("\\{", "{").replace("\\}", "}").replace("\\\\", "\\")
    return text.replace("{", "").replace("}", "")


def _plain(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _tidy(text: str) -> str:
    lines = [re.sub(r"[ \u00a0]+", " ", line).strip(" ") for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    tidy = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", tidy).strip()


# ---------------------------------------------------------------------------
# OCR


_ENGINE: dict[str, Any] = {}


def ocr_engine() -> dict[str, Any]:
    """Whether OCR can run here, and with which languages (checked every 5 minutes)."""
    import time

    if _ENGINE and time.monotonic() - _ENGINE["checked"] < 300:
        return _ENGINE["engine"]
    engine = _probe_engine()
    _ENGINE.update(checked=time.monotonic(), engine=engine)
    return engine


def _probe_engine() -> dict[str, Any]:
    binary = os.environ.get("GARBAGE_TESSERACT") or shutil.which("tesseract")
    if not binary:
        return {"available": False, "reason": "Tesseract não está instalado"}
    try:
        listed = subprocess.run([binary, "--list-langs"], capture_output=True, text=True, timeout=15, check=False)
        version = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "reason": "Tesseract não respondeu"}
    languages = [line.strip() for line in (listed.stdout + listed.stderr).splitlines()[1:] if re.fullmatch(r"[a-z_]{3,10}", line.strip())]
    first = (version.stdout or version.stderr).splitlines()[:1]
    return {
        "available": True,
        "binary": binary,
        "version": first[0].strip() if first else "tesseract",
        "languages": languages,
        "pdf_pages": bool(os.environ.get("GARBAGE_PDFTOPPM") or shutil.which("pdftoppm")),
    }


def _ocr_images(paths: list[str], engine: dict[str, Any]) -> str:
    wanted = [code for code in ("por", "eng") if code in engine["languages"]] or engine["languages"][:1]
    texts = []
    for path in paths:
        command = [engine["binary"], path, "stdout"] + (["-l", "+".join(wanted)] if wanted else [])
        try:
            done = subprocess.run(command, capture_output=True, timeout=OCR_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        texts.append(done.stdout.decode("utf-8", "replace"))
    return "\n\n".join(text for text in texts if text.strip())


def ocr(data: bytes, kind: str, engine: dict[str, Any] | None = None) -> tuple[str, str]:
    """(text, note) by OCR of an image or of a PDF's first pages."""
    engine = engine or ocr_engine()
    if not engine.get("available"):
        return "", engine.get("reason", "OCR indisponível")
    with tempfile.TemporaryDirectory(prefix="garbage-ocr-") as folder:
        source = os.path.join(folder, f"input.{'pdf' if kind == 'pdf' else 'img'}")
        with open(source, "wb") as handle:
            handle.write(data)
        if kind != "pdf":
            return _ocr_images([source], engine), f"OCR com {engine['version']}"
        renderer = os.environ.get("GARBAGE_PDFTOPPM") or shutil.which("pdftoppm")
        if not renderer:
            return "", "PDF sem camada de texto; instale o Poppler (pdftoppm) para fazer OCR das páginas"
        try:
            subprocess.run(
                [renderer, "-r", "200", "-f", "1", "-l", str(OCR_MAX_PDF_PAGES), "-png", source, os.path.join(folder, "page")],
                capture_output=True, timeout=OCR_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "", "as páginas do PDF não puderam ser renderizadas"
        pages = sorted(os.path.join(folder, name) for name in os.listdir(folder) if name.startswith("page"))
        return _ocr_images(pages, engine), f"OCR com {engine['version']} das {len(pages)} primeira(s) página(s)"


# ---------------------------------------------------------------------------
# Entry point


def _zip_flavour(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            if "word/document.xml" in names:
                return "docx"
            if "xl/workbook.xml" in names:
                return "xlsx"
            if "ppt/presentation.xml" in names:
                return "pptx"
            if "mimetype" in names:
                mimetype = archive.read("mimetype")[:100]
                if mimetype.startswith(b"application/vnd.oasis.opendocument"):
                    return "odf"
                if mimetype.startswith(b"application/epub+zip"):
                    return "epub"
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError):
        return ""
    return ""


def extract(data: bytes, kind: str, *, use_ocr: bool = True) -> dict[str, Any] | None:
    """The readable text of a file, or None when the format has none."""
    method = ""
    parts = 0
    note = ""
    text = ""
    if kind in ("docx", "xlsx", "pptx", "zip", "epub"):
        flavour = _zip_flavour(data) or kind
        readers = {"docx": (_docx, "Word"), "xlsx": (_xlsx, "Excel"), "pptx": (_pptx, "PowerPoint"), "odf": (_opendocument, "OpenDocument"), "epub": (_epub, "EPUB")}
        if flavour not in readers:
            return None
        reader, label = readers[flavour]
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                text, parts = reader(archive)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return None
        method = f"texto do {label}"
    elif kind == "pdf":
        text, parts = _pdf(data)
        method = "camada de texto do PDF"
        if use_ocr and len(text.strip()) < 40:
            scanned, note = ocr(data, "pdf")
            if scanned.strip():
                text, method = scanned, "OCR"
            elif not text.strip():
                note = note or "o PDF não tem camada de texto"
    elif kind == "rtf":
        text, method = _rtf(data), "texto do RTF"
    elif kind in ("html", "xml"):
        text, method = html_text(_plain(data)), "texto da página"
    elif kind in ("text", "json"):
        text, method = _plain(data), "texto"
    elif kind in OCR_IMAGE_KINDS:
        if not use_ocr:
            return None
        text, note = ocr(data, kind)
        method = "OCR"
        if not text.strip():
            return {"content": "", "chars": 0, "words": 0, "method": method, "note": note or "nenhum texto reconhecido", "truncated": False, "parts": 0}
    else:
        return None
    text = _tidy(text)
    truncated = len(text) > MAX_TEXT_CHARS
    text = text[:MAX_TEXT_CHARS]
    return {
        "content": text,
        "chars": len(text),
        "words": len(text.split()),
        "method": method,
        "note": note,
        "truncated": truncated,
        "parts": parts,
    }
