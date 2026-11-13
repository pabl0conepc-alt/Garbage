"""Bounded, read-only file intelligence.

Nothing in this module executes a submitted file, extracts archive members to
disk, resolves parsed URLs, or evaluates embedded code. Parsers read only the
bytes supplied by the caller and stop at explicit limits.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import tarfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .. import native
from ..db import _connection, new_id, record_activity, utc_now
from ..errors import NotFoundError, ValidationError
from ..validation import clean_text
from .fuzzy_hash import similarity_digests, ssdeep_score, tlsh_compare
from .hardening import describe_hardening
from .imaging import inspect_image
from .indicators import extract_indicators

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 500
MAX_ARCHIVE_LISTED_BYTES = 200 * 1024 * 1024
MAX_DECOMPRESSED_PREVIEW = 1024 * 1024
MAX_STRINGS = 150
MAX_STRING_CHARS = 6000
MAX_SECTIONS = 96
MAX_IMPORTS = 80

_FORMAT_LABELS = {
    "pdf": "PDF document",
    "zip": "ZIP archive",
    "docx": "Word document (OOXML)",
    "xlsx": "Excel workbook (OOXML)",
    "pptx": "PowerPoint presentation (OOXML)",
    "epub": "EPUB publication",
    "jar": "Java archive",
    "apk": "Android package",
    "gzip": "GZIP stream",
    "tar": "TAR archive",
    "7z": "7-Zip archive",
    "rar": "RAR archive",
    "json": "JSON document",
    "xml": "XML document",
    "html": "HTML document",
    "text": "Plain text",
    "png": "PNG image",
    "jpeg": "JPEG image",
    "gif": "GIF image",
    "webp": "WebP image",
    "bmp": "BMP image",
    "elf": "ELF executable",
    "pe": "PE executable",
    "macho": "Mach-O executable",
    "ole": "OLE compound document",
    "sqlite": "SQLite database",
    "woff": "WOFF font",
    "woff2": "WOFF2 font",
    "ttf": "TrueType font",
    "otf": "OpenType font",
    "unknown": "Unrecognised binary",
}

_MEDIA_TYPES = {
    "pdf": "application/pdf",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "epub": "application/epub+zip",
    "jar": "application/java-archive",
    "apk": "application/vnd.android.package-archive",
    "gzip": "application/gzip",
    "tar": "application/x-tar",
    "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar",
    "json": "application/json",
    "xml": "application/xml",
    "html": "text/html",
    "text": "text/plain",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "bmp": "image/bmp",
    "elf": "application/x-elf",
    "pe": "application/vnd.microsoft.portable-executable",
    "macho": "application/x-mach-binary",
    "ole": "application/x-ole-storage",
    "sqlite": "application/vnd.sqlite3",
    "woff": "font/woff",
    "woff2": "font/woff2",
    "ttf": "font/ttf",
    "otf": "font/otf",
    "unknown": "application/octet-stream",
}

_EXTENSIONS = {
    "pdf": {"pdf"},
    "docx": {"docx", "docm"},
    "xlsx": {"xlsx", "xlsm"},
    "pptx": {"pptx", "pptm"},
    "zip": {"zip"},
    "epub": {"epub"},
    "jar": {"jar"},
    "apk": {"apk"},
    "gzip": {"gz", "gzip", "tgz"},
    "tar": {"tar"},
    "7z": {"7z"},
    "rar": {"rar"},
    "json": {"json"},
    "xml": {"xml"},
    "html": {"html", "htm"},
    "png": {"png"},
    "jpeg": {"jpg", "jpeg", "jpe"},
    "gif": {"gif"},
    "webp": {"webp"},
    "bmp": {"bmp"},
    "elf": {"elf", "so", "o", "bin"},
    "pe": {"exe", "dll", "sys", "scr", "cpl"},
    "macho": {"macho", "dylib"},
    "sqlite": {"sqlite", "sqlite3", "db"},
    "woff": {"woff"},
    "woff2": {"woff2"},
    "ttf": {"ttf"},
    "otf": {"otf"},
}

_ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
    258: "LoongArch",
}
_ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_PE_MACHINES = {
    0x014C: "x86",
    0x0200: "IA-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "AArch64",
    0x8664: "x86-64",
}
_PE_SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows console",
    7: "POSIX console",
    9: "Windows CE",
    10: "EFI application",
    16: "Windows boot",
}
_MACHO_CPU = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "AArch64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}
_MACHO_FILE_TYPES = {
    1: "Object",
    2: "Executable",
    3: "Fixed VM library",
    4: "Core",
    5: "Preloaded executable",
    6: "Dynamic library",
    7: "Dynamic linker",
    8: "Bundle",
    9: "Dynamic library stub",
    10: "DSYM",
    11: "Keystore bundle",
}


def _uint(data: bytes, offset: int, length: int, endian: str = "little") -> int:
    if offset < 0 or length <= 0 or offset + length > len(data):
        raise ValueError("truncated structure")
    return int.from_bytes(data[offset : offset + length], endian)


def _safe_uint(data: bytes, offset: int, length: int, endian: str = "little") -> int | None:
    try:
        return _uint(data, offset, length, endian)
    except ValueError:
        return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    native_value = native.entropy(data)
    if native_value is not None:
        return round(native_value, 3)
    counts = Counter(data)
    total = len(data)
    value = 0.0
    for count in counts.values():
        probability = count / total
        value -= probability * math.log2(probability)
    return round(value, 3)


def _timestamp(value: int) -> str:
    if value <= 0:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""


def _pdf_text(value: bytes) -> str:
    value = value.strip()
    if value.startswith(b"\xfe\xff"):
        try:
            return value[2:].decode("utf-16-be", errors="replace")[:500]
        except (UnicodeDecodeError, ValueError):
            return ""
    if value.startswith(b"\xff\xfe"):
        try:
            return value[2:].decode("utf-16-le", errors="replace")[:500]
        except (UnicodeDecodeError, ValueError):
            return ""
    return value.decode("latin-1", errors="replace")[:500]


def _pdf_metadata(data: bytes) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key in (b"Title", b"Author", b"Subject", b"Keywords", b"Creator", b"Producer"):
        match = re.search(rb"/" + key + rb"\s*\(([^)]{0,500})\)", data, re.DOTALL)
        if match:
            value = _pdf_text(match.group(1))
            if value:
                metadata[key.decode()] = value
        hex_match = re.search(rb"/" + key + rb"\s*<([0-9A-Fa-f]{0,998})>", data)
        if hex_match and key.decode() not in metadata:
            try:
                value = _pdf_text(bytes.fromhex(hex_match.group(1).decode()))
            except ValueError:
                value = ""
            if value:
                metadata[key.decode()] = value
    return metadata


def _zip_members(data: bytes) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    members: list[dict[str, Any]] = []
    flags: list[str] = []
    metadata: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            total_uncompressed = 0
            for info in infos[:MAX_ARCHIVE_ENTRIES]:
                name = info.filename.replace("\x00", "")[:300]
                parts = Path(name.replace("\\", "/")).parts
                traversal = (
                    name.startswith("/")
                    or ".." in parts
                    or bool(re.match(r"^[A-Za-z]:", name))
                )
                ratio = (
                    round(info.file_size / info.compress_size, 2)
                    if info.compress_size
                    else None
                )
                members.append(
                    {
                        "name": name,
                        "size_bytes": info.file_size,
                        "compressed_bytes": info.compress_size,
                        "ratio": ratio,
                        "encrypted": bool(info.flag_bits & 0x1),
                        "directory": info.is_dir(),
                        "path_traversal": traversal,
                    }
                )
                total_uncompressed += max(0, info.file_size)
                if traversal:
                    flags.append("archive path traversal pattern")
                if info.flag_bits & 0x1:
                    flags.append("encrypted archive member")
                if info.file_size > 8 * 1024 * 1024 and ratio and ratio > 100:
                    flags.append("high compression ratio")
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                flags.append("archive listing truncated")
            if total_uncompressed > MAX_ARCHIVE_LISTED_BYTES:
                flags.append("archive declares a very large uncompressed size")
            names = {info.filename for info in infos[:MAX_ARCHIVE_ENTRIES]}
            macro = any(
                name.lower().endswith(("vbaproject.bin", ".docm", ".xlsm", ".pptm"))
                for name in names
            )
            if macro:
                flags.append("Office macro project present")
            if "docProps/core.xml" in names:
                try:
                    info = archive.getinfo("docProps/core.xml")
                    if info.file_size <= 128 * 1024:
                        root = ElementTree.fromstring(archive.read(info))
                        wanted = {
                            "title": "title",
                            "creator": "creator",
                            "subject": "subject",
                            "description": "description",
                            "lastModifiedBy": "lastModifiedBy",
                            "created": "created",
                            "modified": "modified",
                        }
                        for element in root.iter():
                            tag = element.tag.rsplit("}", 1)[-1]
                            if tag in wanted and element.text:
                                metadata.append(
                                    {"key": wanted[tag], "value": element.text[:500]}
                                )
                except (ElementTree.ParseError, KeyError, OSError, ValueError):
                    flags.append("unreadable document properties")
    except (zipfile.BadZipFile, NotImplementedError, OSError, ValueError):
        flags.append("unreadable ZIP central directory")
    return members, sorted(set(flags)), metadata


def _zip_kind(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = {name.replace("\\", "/") for name in archive.namelist()[:MAX_ARCHIVE_ENTRIES]}
    except (zipfile.BadZipFile, NotImplementedError, OSError, ValueError):
        return "zip"
    if "mimetype" in names:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.read("mimetype")[:40] == b"application/epub+zip":
                    return "epub"
        except (zipfile.BadZipFile, KeyError, OSError, ValueError):
            pass
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return "apk"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    if "[Content_Types].xml" in names:
        if any(name.startswith("word/") for name in names):
            return "docx"
        if any(name.startswith("xl/") for name in names):
            return "xlsx"
        if any(name.startswith("ppt/") for name in names):
            return "pptx"
    return "zip"


def _tar_members(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    members: list[dict[str, Any]] = []
    flags: list[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            infos = archive.getmembers()
            for info in infos[:MAX_ARCHIVE_ENTRIES]:
                name = info.name.replace("\x00", "")[:300]
                parts = Path(name.replace("\\", "/")).parts
                traversal = name.startswith("/") or ".." in parts
                members.append(
                    {
                        "name": name,
                        "size_bytes": max(0, info.size),
                        "type": "directory"
                        if info.isdir()
                        else "symlink"
                        if info.issym()
                        else "hardlink"
                        if info.islnk()
                        else "file",
                        "path_traversal": traversal,
                        "mode": oct(info.mode & 0o7777),
                        "modified_at": _timestamp(info.mtime),
                    }
                )
                if traversal:
                    flags.append("archive path traversal pattern")
                if info.issym() or info.islnk():
                    flags.append("archive link member")
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                flags.append("archive listing truncated")
    except (tarfile.TarError, OSError, ValueError):
        flags.append("unreadable TAR headers")
    return members, sorted(set(flags))


def _gzip_structure(data: bytes) -> tuple[dict[str, Any], list[str]]:
    details: dict[str, Any] = {}
    flags: list[str] = []
    if len(data) < 10:
        return details, ["truncated GZIP header"]
    method = data[2]
    header_flags = data[3]
    details["compression_method"] = method
    details["original_modified_at"] = _timestamp(_safe_uint(data, 4, 4) or 0)
    details["operating_system"] = data[9]
    offset = 10
    if header_flags & 0x04 and offset + 2 <= len(data):
        extra_length = _safe_uint(data, offset, 2) or 0
        offset += 2 + extra_length
    if header_flags & 0x08:
        end = data.find(b"\x00", offset, min(len(data), offset + 512))
        if end >= 0:
            details["original_name"] = data[offset:end].decode("latin-1", errors="replace")
            offset = end + 1
    if header_flags & 0x10:
        end = data.find(b"\x00", offset, min(len(data), offset + 512))
        if end >= 0:
            offset = end + 1
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        preview = decompressor.decompress(data, MAX_DECOMPRESSED_PREVIEW)
        truncated = bool(decompressor.unconsumed_tail) or (
            len(preview) >= MAX_DECOMPRESSED_PREVIEW and not decompressor.eof
        )
        details["decompressed_preview_bytes"] = len(preview)
        details["decompressed_preview_truncated"] = truncated
        if preview:
            details["inner_magic_hex"] = preview[:16].hex()
        ratio = len(preview) / max(1, len(data))
        details["compression_ratio"] = round(ratio, 2)
        if len(preview) >= MAX_DECOMPRESSED_PREVIEW and truncated:
            flags.append("decompression limit reached; possible compression bomb")
    except zlib.error:
        flags.append("invalid DEFLATE stream")
    if header_flags & 0x01:
        details["encrypted_or_reserved_header_flag"] = True
    return details, flags


def _pdf_structure(data: bytes) -> tuple[dict[str, Any], dict[str, str], list[str], dict[str, bool]]:
    text = data.decode("latin-1", errors="replace")
    version_match = re.search(r"%PDF-(\d\.\d)", text[:16])
    page_count = len(re.findall(r"/Type\s*/Page(?![A-Za-z])", text))
    has = {
        "encrypted": bool(re.search(r"/Encrypt\b", text)),
        "javascript": bool(re.search(r"/(?:JavaScript|JS)\b", text)),
        "open_action": bool(re.search(r"/OpenAction\b", text)),
        "launch_action": bool(re.search(r"/Launch\b", text)),
        "embedded_files": bool(re.search(r"/(?:EmbeddedFile|Filespec)\b", text)),
        "linearized": "/Linearized" in text,
    }
    structure = {
        "version": version_match.group(1) if version_match else "",
        "approximate_page_count": page_count,
        "objects_declared": len(re.findall(r"\b\d+\s+\d+\s+obj\b", text)),
        "has_xref": "xref" in text or "/XRef" in text,
    }
    flags = [key for key, value in has.items() if value]
    return structure, _pdf_metadata(data), flags, has


def _elf_structure(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str]]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("truncated ELF header")
    bits = 64 if data[4] == 2 else 32
    endian = "little" if data[5] == 1 else "big"
    e_type = _uint(data, 16, 2, endian)
    e_machine = _uint(data, 18, 2, endian)
    e_entry = _uint(data, 24, 8 if bits == 64 else 4, endian)
    e_phoff = _uint(data, 32, 8 if bits == 64 else 4, endian)
    e_shoff = _uint(data, 40, 8 if bits == 64 else 4, endian)
    e_phentsize = _uint(data, 54, 2, endian)
    e_phnum = _uint(data, 56, 2, endian)
    e_shentsize = _uint(data, 58, 2, endian)
    e_shnum = _uint(data, 60, 2, endian)
    e_shstrndx = _uint(data, 62, 2, endian)
    interpreter = ""
    if e_phoff and e_phnum and e_phentsize >= (56 if bits == 64 else 32):
        for index in range(min(e_phnum, 64)):
            base = e_phoff + index * e_phentsize
            if base + e_phentsize > len(data):
                break
            p_type = _uint(data, base, 4, endian)
            if bits == 64:
                p_offset = _uint(data, base + 8, 8, endian)
                p_filesz = _uint(data, base + 32, 8, endian)
            else:
                p_offset = _uint(data, base + 4, 4, endian)
                p_filesz = _uint(data, base + 16, 4, endian)
            if p_type == 3 and p_offset + min(p_filesz, 512) <= len(data):
                interpreter = (
                    data[p_offset : p_offset + min(p_filesz, 512)]
                    .split(b"\x00", 1)[0]
                    .decode("utf-8", errors="replace")[:300]
                )
                break
    sections: list[dict[str, Any]] = []
    section_names: dict[int, str] = {}
    if e_shoff and e_shnum and e_shentsize:
        string_offset = 0
        string_size = 0
        if e_shstrndx < min(e_shnum, MAX_SECTIONS):
            base = e_shoff + e_shstrndx * e_shentsize
            if base + e_shentsize <= len(data):
                if bits == 64:
                    string_offset = _uint(data, base + 24, 8, endian)
                    string_size = _uint(data, base + 32, 8, endian)
                else:
                    string_offset = _uint(data, base + 16, 4, endian)
                    string_size = _uint(data, base + 20, 4, endian)
        string_table = (
            data[string_offset : string_offset + min(string_size, 200_000)]
            if string_offset and string_offset < len(data)
            else b""
        )
        for index in range(min(e_shnum, MAX_SECTIONS)):
            base = e_shoff + index * e_shentsize
            if base + e_shentsize > len(data):
                break
            if bits == 64:
                name_offset = _uint(data, base, 4, endian)
                section_type = _uint(data, base + 4, 4, endian)
                flags = _uint(data, base + 8, 8, endian)
                offset = _uint(data, base + 24, 8, endian)
                size = _uint(data, base + 32, 8, endian)
                entry_size = _uint(data, base + 56, 8, endian)
            else:
                name_offset = _uint(data, base, 4, endian)
                section_type = _uint(data, base + 4, 4, endian)
                flags = _uint(data, base + 8, 4, endian)
                offset = _uint(data, base + 16, 4, endian)
                size = _uint(data, base + 20, 4, endian)
                entry_size = _uint(data, base + 36, 4, endian)
            name = ""
            if string_table and name_offset < len(string_table):
                raw_name = string_table[name_offset:].split(b"\x00", 1)[0]
                name = raw_name.decode("utf-8", errors="replace")[:100]
            section_names[index] = name
            sections.append(
                {
                    "name": name,
                    "type": section_type,
                    "flags": flags,
                    "offset": offset,
                    "size_bytes": size,
                    "entry_size": entry_size,
                }
            )
    needed: list[str] = []
    dynamic = next((item for item in sections if item["name"] == ".dynamic"), None)
    dynstr = next((item for item in sections if item["name"] == ".dynstr"), None)
    if dynamic and dynstr:
        table = data[dynstr["offset"] : dynstr["offset"] + min(dynstr["size_bytes"], 200_000)]
        entry_size = 16 if bits == 64 else 8
        count = min(dynamic["size_bytes"] // entry_size, 400)
        for index in range(count):
            base = dynamic["offset"] + index * entry_size
            if base + entry_size > len(data):
                break
            tag = _uint(data, base, 8 if bits == 64 else 4, endian)
            value = _uint(data, base + (8 if bits == 64 else 4), 8 if bits == 64 else 4, endian)
            if tag == 1 and value < len(table):
                library = table[value:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                if library and library not in needed:
                    needed.append(library[:200])
            if len(needed) >= MAX_IMPORTS:
                break
    header = {
        "bits": bits,
        "endian": endian,
        "type": _ELF_TYPES.get(e_type, str(e_type)),
        "machine": _ELF_MACHINES.get(e_machine, f"machine {e_machine}"),
        "entry_point": hex(e_entry),
        "interpreter": interpreter,
        "needed_libraries": needed,
        "section_count": e_shnum,
        "program_header_count": e_phnum,
    }
    flags: list[str] = []
    if e_type == 3:
        flags.append("shared object or PIE executable")
    if any(section["name"] == ".symtab" for section in sections):
        flags.append("symbol table present")
    return header, sections, flags, needed


def _pe_rva(data: bytes, sections: list[dict[str, Any]], rva: int) -> int | None:
    for section in sections:
        start = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + max(1, size):
            return section["raw_pointer"] + (rva - start)
    return None


def _pe_structure(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str]]:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("truncated DOS header")
    pe_offset = _uint(data, 0x3C, 4)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    machine = _uint(data, pe_offset + 4, 2)
    section_count = _uint(data, pe_offset + 6, 2)
    timestamp = _uint(data, pe_offset + 8, 4)
    optional_size = _uint(data, pe_offset + 20, 2)
    characteristics = _uint(data, pe_offset + 22, 2)
    optional_offset = pe_offset + 24
    magic = _safe_uint(data, optional_offset, 2)
    bits = 32 if magic == 0x10B else 64 if magic == 0x20B else 0
    entry_rva = _safe_uint(data, optional_offset + 16, 4) or 0 if bits else 0
    subsystem = _safe_uint(data, optional_offset + 68, 2) or 0 if bits else 0
    section_offset = optional_offset + optional_size
    sections: list[dict[str, Any]] = []
    for index in range(min(section_count, MAX_SECTIONS)):
        base = section_offset + index * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
        sections.append(
            {
                "name": name,
                "virtual_size": _uint(data, base + 8, 4),
                "virtual_address": _uint(data, base + 12, 4),
                "raw_size": _uint(data, base + 16, 4),
                "raw_pointer": _uint(data, base + 20, 4),
                "characteristics": _uint(data, base + 36, 4),
            }
        )
    imports: list[str] = []
    if bits and optional_size >= (96 if bits == 32 else 112):
        directory_base = optional_offset + (96 if bits == 32 else 112)
        import_rva = _safe_uint(data, directory_base, 4) or 0
        import_size = _safe_uint(data, directory_base + 4, 4) or 0
        import_offset = _pe_rva(data, sections, import_rva) if import_rva else None
        if import_offset is not None:
            for index in range(64):
                base = import_offset + index * 20
                if base + 20 > len(data):
                    break
                name_rva = _uint(data, base + 12, 4)
                first_thunk = _uint(data, base + 16, 4)
                original_thunk = _uint(data, base + 0, 4)
                if not name_rva:
                    break
                name_offset = _pe_rva(data, sections, name_rva)
                if name_offset is None or name_offset >= len(data):
                    continue
                dll = data[name_offset:].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
                if dll and dll not in imports:
                    imports.append(dll[:200])
                thunk_rva = original_thunk or first_thunk
                thunk_offset = _pe_rva(data, sections, thunk_rva) if thunk_rva else None
                if thunk_offset is not None:
                    step = 8 if bits == 64 else 4
                    for thunk_index in range(40):
                        entry_offset = thunk_offset + thunk_index * step
                        if entry_offset + step > len(data):
                            break
                        value = _uint(data, entry_offset, step)
                        if value == 0:
                            break
                        high_bit = 1 << (step * 8 - 1)
                        if value & high_bit:
                            continue
                        hint_offset = _pe_rva(data, sections, value)
                        if hint_offset is None or hint_offset + 2 >= len(data):
                            continue
                        function = (
                            data[hint_offset + 2 :]
                            .split(b"\x00", 1)[0]
                            .decode("latin-1", errors="replace")
                        )
                        if function:
                            label = f"{dll}!{function}"[:300]
                            if label not in imports:
                                imports.append(label)
                        if len(imports) >= MAX_IMPORTS:
                            break
                if len(imports) >= MAX_IMPORTS:
                    break
    header = {
        "bits": bits,
        "machine": _PE_MACHINES.get(machine, f"machine 0x{machine:04x}"),
        "characteristics": hex(characteristics),
        "is_dll": bool(characteristics & 0x2000),
        "is_executable": bool(characteristics & 0x0002),
        "compile_timestamp": _timestamp(timestamp),
        "subsystem": _PE_SUBSYSTEMS.get(subsystem, str(subsystem)),
        "entry_point_rva": hex(entry_rva),
        "section_count": section_count,
        "import_directory_declared_bytes": import_size,
        "imports": imports[:MAX_IMPORTS],
    }
    flags: list[str] = []
    if header["is_dll"]:
        flags.append("DLL characteristics")
    if any(section["raw_size"] and section["raw_size"] > section["virtual_size"] * 4 for section in sections):
        flags.append("section raw size exceeds virtual size")
    return header, sections, flags, imports


def _macho_structure(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], list[str]]:
    if len(data) < 4:
        raise ValueError("truncated Mach-O header")
    endian = "little"
    magic = int.from_bytes(data[:4], "little")
    if magic in {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}:
        if magic in {0xCEFAEDFE, 0xCFFAEDFE}:
            endian = "big"
            magic = int.from_bytes(data[:4], "big")
        bits = 64 if magic in {0xFEEDFACF, 0xCFFAEDFE} else 32
        cpu = _uint(data, 4, 4, endian)
        file_type = _uint(data, 12, 4, endian)
        command_count = _uint(data, 16, 4, endian)
        command_bytes = _uint(data, 20, 4, endian)
        offset = 32 if bits == 64 else 28
        segments: list[dict[str, Any]] = []
        libraries: list[str] = []
        entry = ""
        for _ in range(min(command_count, 128)):
            if offset + 8 > len(data):
                break
            command = _uint(data, offset, 4, endian)
            command_size = _uint(data, offset + 4, 4, endian)
            if command_size < 8 or offset + command_size > len(data):
                break
            if command in {0x1, 0x19}:
                name = data[offset + 8 : offset + 24].split(b"\x00", 1)[0]
                segments.append(
                    {
                        "name": name.decode("latin-1", errors="replace"),
                        "vm_size": _safe_uint(data, offset + 32, 8 if bits == 64 else 4, endian),
                        "file_size": _safe_uint(data, offset + 48, 8 if bits == 64 else 4, endian)
                        if bits == 64
                        else _safe_uint(data, offset + 36, 4, endian),
                    }
                )
            elif command in {0xC, 0xD, 0x18, 0x1F, 0x20, 0x23} and command_size >= 24:
                name_offset = _uint(data, offset + 8, 4, endian)
                start = offset + name_offset
                if 0 < name_offset < command_size and start < len(data):
                    library = data[start : offset + command_size].split(b"\x00", 1)[0]
                    libraries.append(library.decode("utf-8", errors="replace")[:300])
            elif command == 0x80000028 and command_size >= 24:
                entry = hex(_uint(data, offset + 16, 8, endian))
            offset += command_size
        header = {
            "bits": bits,
            "endian": endian,
            "cpu": _MACHO_CPU.get(cpu, f"cpu 0x{cpu:x}"),
            "file_type": _MACHO_FILE_TYPES.get(file_type, str(file_type)),
            "load_commands": command_count,
            "load_command_bytes": command_bytes,
            "segments": segments[:MAX_SECTIONS],
            "libraries": libraries[:MAX_IMPORTS],
            "main_entry": entry,
        }
        flags: list[str] = []
        if file_type in {2, 6}:
            flags.append("Mach-O executable or dynamic library")
        return header, segments, flags, libraries
    big_magic = int.from_bytes(data[:4], "big")
    if big_magic in {0xCAFEBABE, 0xCAFEBABF}:
        count = _uint(data, 4, 4, "big")
        stride = 32 if big_magic == 0xCAFEBABF else 20
        architectures: list[dict[str, Any]] = []
        for index in range(min(count, 32)):
            base = 8 + index * stride
            if base + stride > len(data):
                break
            cpu = _uint(data, base, 4, "big")
            offset = _uint(data, base + 8, 4, "big")
            size = _uint(data, base + 12, 4, "big")
            architectures.append(
                {
                    "cpu": _MACHO_CPU.get(cpu & 0xFFFFFFFF, f"cpu 0x{cpu:x}"),
                    "offset": offset,
                    "size": size,
                }
            )
        return (
            {"fat_binary": True, "architecture_count": count, "architectures": architectures},
            architectures,
            ["universal (fat) Mach-O binary"],
            [],
        )
    raise ValueError("not a Mach-O binary")


def _text_kind(data: bytes) -> str | None:
    if not data:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return None
    printable = sum(1 for character in text[:4096] if character.isprintable() or character in "\r\n\t")
    if printable / max(1, len(text[:4096])) < 0.85:
        return None
    stripped = text.lstrip()
    lower = stripped[:2048].lower()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(text)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
    if lower.startswith("<!doctype html") or lower.startswith("<html") or "<html" in lower[:512]:
        return "html"
    if stripped.startswith("<?xml") or re.match(r"<[A-Za-z][^>]*>", stripped[:200]):
        return "xml"
    return "text"


def detect_format(data: bytes, filename: str = "") -> dict[str, str]:
    if not data:
        raise ValidationError("file must not be empty")
    header = data[:512]
    kind = "unknown"
    if header.startswith(b"%PDF-"):
        kind = "pdf"
    elif header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        kind = _zip_kind(data)
    elif header.startswith(b"\x1f\x8b"):
        kind = "gzip"
    elif len(header) >= 262 and header[257:262] == b"ustar":
        kind = "tar"
    elif header.startswith(b"\x7fELF"):
        kind = "elf"
    elif header.startswith(b"MZ"):
        pe_offset = _safe_uint(data, 0x3C, 4)
        kind = (
            "pe"
            if pe_offset is not None
            and pe_offset + 4 <= len(data)
            and data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
            else "unknown"
        )
    elif header.startswith(b"\xfe\xed\xfa\xce") or header.startswith(b"\xce\xfa\xed\xfe"):
        kind = "macho"
    elif (
        header.startswith(b"\xfe\xed\xfa\xcf")
        or header.startswith(b"\xcf\xfa\xed\xfe")
        or header.startswith(b"\xca\xfe\xba\xbe")
        or header.startswith(b"\xca\xfe\xba\xbf")
    ):
        kind = "macho"
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "png"
    elif header.startswith(b"\xff\xd8\xff"):
        kind = "jpeg"
    elif header.startswith((b"GIF87a", b"GIF89a")):
        kind = "gif"
    elif header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        kind = "webp"
    elif header.startswith(b"BM"):
        kind = "bmp"
    elif header.startswith(b"SQLite format 3\x00"):
        kind = "sqlite"
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        kind = "ole"
    elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
        kind = "7z"
    elif header.startswith(b"Rar!\x1a\x07"):
        kind = "rar"
    elif header.startswith(b"wOFF"):
        kind = "woff"
    elif header.startswith(b"wOF2"):
        kind = "woff2"
    elif header.startswith(b"\x00\x01\x00\x00"):
        kind = "ttf"
    elif header.startswith(b"OTTO"):
        kind = "otf"
    else:
        text_kind = _text_kind(data)
        if text_kind:
            kind = text_kind
    image = inspect_image(data)
    if image and kind in {"unknown", "text"}:
        kind = str(image["format"]).lower()
    return {
        "id": kind,
        "label": _FORMAT_LABELS.get(kind, kind),
        "media_type": _MEDIA_TYPES.get(kind, "application/octet-stream"),
    }


def _extract_strings(data: bytes) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    used = 0
    truncated = False
    for match in re.finditer(rb"[\x20-\x7e]{4,300}", data):
        value = match.group().decode("latin-1", errors="replace")
        if value in seen:
            continue
        if len(found) >= MAX_STRINGS or used + len(value) > MAX_STRING_CHARS:
            truncated = True
            break
        seen.add(value)
        found.append({"offset": match.start(), "encoding": "ascii", "value": value})
        used += len(value)
    if len(found) < MAX_STRINGS:
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,300}", data):
            value = match.group().decode("utf-16-le", errors="replace")
            if value in seen:
                continue
            if len(found) >= MAX_STRINGS or used + len(value) > MAX_STRING_CHARS:
                truncated = True
                break
            seen.add(value)
            found.append({"offset": match.start(), "encoding": "utf-16le", "value": value})
            used += len(value)
    found.sort(key=lambda item: item["offset"])
    return {"count": len(found), "truncated": truncated, "items": found}


def _indicators_from_strings(strings: list[dict[str, Any]]) -> list[dict[str, str]]:
    content = "\n".join(item["value"] for item in strings["items"])[:MAX_STRING_CHARS]
    findings = extract_indicators(
        [
            {
                "id": "file-strings",
                "content": content,
                "source_reference": "",
                "collection_basis": "",
                "observed_at": "",
                "recorded_at": "",
            }
        ]
    )
    unique: dict[tuple[str, str], dict[str, str]] = {}
    for finding in findings:
        unique.setdefault(
            (finding["type"], finding["value"]),
            {
                "type": finding["type"],
                "value": finding["value"],
                "note": "Syntactic match in extracted strings; not a reputation result.",
            },
        )
    return list(unique.values())[:200]


def _extension_mismatch(filename: str, kind: str) -> bool:
    suffix = Path(filename).suffix.lower().lstrip(".")
    if not suffix:
        return False
    expected = _EXTENSIONS.get(kind)
    if not expected:
        return False
    if suffix in expected:
        return False
    specific = {
        "pdf", "docx", "xlsx", "pptx", "zip", "gz", "tar", "png", "jpg", "jpeg",
        "gif", "webp", "exe", "dll", "elf", "so", "json", "xml", "html", "htm",
    }
    return suffix in specific


def analyze_bytes(data: bytes, filename: str = "") -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray)):
        raise ValidationError("file content must be bytes")
    data = bytes(data)
    if not data:
        raise ValidationError("file must not be empty")
    if len(data) > MAX_FILE_BYTES:
        raise ValidationError("file exceeds the 4 MiB analysis limit")
    safe_name = clean_text(filename, "file name", max_length=300) or "unnamed"
    safe_name = Path(safe_name.replace("\\", "/")).name
    detected = detect_format(data, safe_name)
    kind = detected["id"]
    entropy = _entropy(data)
    strings = _extract_strings(data)
    structure: dict[str, Any] = {}
    metadata: dict[str, Any] = {
        "file_name": safe_name,
        "extension": Path(safe_name).suffix.lower(),
    }
    findings: list[dict[str, str]] = []
    flags: list[str] = []
    imports: list[str] = []

    if kind in {"zip", "docx", "xlsx", "pptx", "epub", "jar", "apk"}:
        members, archive_flags, office_metadata = _zip_members(data)
        structure = {
            "archive_type": "zip",
            "entries": members,
            "entry_count": len(members),
            "listing_limit": MAX_ARCHIVE_ENTRIES,
        }
        flags.extend(archive_flags)
        if office_metadata:
            metadata["document_properties"] = office_metadata
    elif kind == "tar":
        members, archive_flags = _tar_members(data)
        structure = {
            "archive_type": "tar",
            "entries": members,
            "entry_count": len(members),
            "listing_limit": MAX_ARCHIVE_ENTRIES,
        }
        flags.extend(archive_flags)
    elif kind == "gzip":
        gzip_details, archive_flags = _gzip_structure(data)
        structure = {"archive_type": "gzip", "gzip": gzip_details}
        flags.extend(archive_flags)
    elif kind == "pdf":
        pdf_structure, pdf_metadata, pdf_flags, active = _pdf_structure(data)
        structure = pdf_structure
        metadata["pdf"] = pdf_metadata
        flags.extend(pdf_flags)
        if active["javascript"] or active["open_action"] or active["launch_action"]:
            findings.append(
                {
                    "level": "warning",
                    "code": "pdf-active-content",
                    "message": "The document declares JavaScript, an open action or a launch action. It was not executed.",
                }
            )
        if active["encrypted"]:
            findings.append(
                {
                    "level": "note",
                    "code": "pdf-encrypted",
                    "message": "The PDF declares encryption; content and metadata may be incomplete.",
                }
            )
    elif kind == "elf":
        header, sections, binary_flags, imports = _elf_structure(data)
        structure = {"header": header, "sections": sections}
        flags.extend(binary_flags)
        metadata["binary"] = header
    elif kind == "pe":
        header, sections, binary_flags, imports = _pe_structure(data)
        structure = {"header": header, "sections": sections}
        flags.extend(binary_flags)
        metadata["binary"] = header
        if header.get("compile_timestamp"):
            metadata["compile_timestamp"] = header["compile_timestamp"]
    elif kind == "macho":
        header, sections, binary_flags, imports = _macho_structure(data)
        structure = {"header": header, "segments": sections}
        flags.extend(binary_flags)
        metadata["binary"] = header
    elif kind in {"png", "jpeg", "gif", "webp", "bmp"}:
        image = inspect_image(data)
        if image:
            structure = {"image": image}
            metadata["image"] = image
    elif kind in {"json", "xml", "html", "text"}:
        encoded = data[:4096].decode("utf-8", errors="replace")
        structure = {
            "line_count_estimate": data.count(b"\n") + (0 if data.endswith(b"\n") else 1),
            "first_bytes_utf8": encoded[:300],
            "bom": data.startswith(b"\xef\xbb\xbf"),
        }
    elif kind == "ole":
        findings.append(
            {
                "level": "note",
                "code": "legacy-ole",
                "message": "Legacy OLE compound document; structured parsing is limited to format identification.",
            }
        )

    if len(data) > 1024 and entropy >= 7.2:
        findings.append(
            {
                "level": "warning",
                "code": "high-entropy",
                "message": "High byte entropy is consistent with compressed, packed or encrypted content; it is not proof of maliciousness.",
            }
        )
    if kind in {"elf", "pe", "macho"}:
        findings.append(
            {
                "level": "info",
                "code": "executable-static-only",
                "message": "Executable structure was parsed statically. The file was not executed, emulated or detonated.",
            }
        )
    if _extension_mismatch(safe_name, kind):
        findings.append(
            {
                "level": "warning",
                "code": "extension-mismatch",
                "message": f"The filename extension does not match the detected {detected['label']} structure.",
            }
        )
    if flags:
        findings.append(
            {
                "level": "note",
                "code": "structural-note",
                "message": "Structural notes: " + "; ".join(sorted(set(flags))),
            }
        )
    indicators = _indicators_from_strings(strings)
    hardening = describe_hardening(kind, data)
    similarity = similarity_digests(data)
    return {
        "file_name": safe_name,
        "format": kind,
        "format_label": detected["label"],
        "media_type": detected["media_type"],
        "size_bytes": len(data),
        "hashes": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "tlsh": similarity["tlsh"],
            "ssdeep": similarity["ssdeep"],
        },
        "similarity_engine": similarity["engine"],
        "magic_hex": data[:16].hex(),
        "entropy": entropy,
        "metadata": metadata,
        "structure": structure,
        "strings": strings,
        "indicators": indicators,
        "imports": imports,
        "hardening": hardening,
        "findings": findings,
        "limitations": [
            "Static, read-only inspection only; no execution, emulation or sandbox detonation.",
            "Archive members are listed, never extracted to disk.",
            "Parsers cover bounded headers and central directories; malformed files can hide fields.",
            "Embedded indicators are syntactic string matches, not reputation or attribution.",
            "Hashes identify these exact bytes and do not establish safety or provenance.",
            "TLSH and ssdeep measure byte-level resemblance; a close digest is not shared authorship or intent.",
        ],
        "analysis_engine": "python-stdlib",
    }


# ---------------------------------------------------------------------------
# Persistence


def _ensure_analysis_table(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS file_analyses (
               id TEXT PRIMARY KEY,
               investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
               file_name TEXT NOT NULL,
               format TEXT NOT NULL,
               media_type TEXT NOT NULL,
               size_bytes INTEGER NOT NULL,
               sha256 TEXT NOT NULL,
               analysis_json TEXT NOT NULL,
               created_at TEXT NOT NULL
           )"""
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS file_analyses_case_created "
        "ON file_analyses(investigation_id, created_at DESC)"
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(file_analyses)")}
    for column in ("tlsh", "ssdeep"):
        if column not in columns:
            connection.execute(f"ALTER TABLE file_analyses ADD COLUMN {column} TEXT")


def analyze_file(
    database: str,
    *,
    data: bytes,
    filename: str = "",
    investigation_id: str | None = None,
) -> dict[str, Any]:
    analysis = analyze_bytes(data, filename)
    if investigation_id:
        investigation_id = clean_text(
            investigation_id, "investigation id", max_length=100
        ) or None
    analysis_id = new_id()
    created_at = utc_now()
    analysis_payload = {
        **analysis,
        "analysis_id": analysis_id,
        "investigation_id": investigation_id,
        "created_at": created_at,
    }
    with _connection(database) as connection:
        _ensure_analysis_table(connection)
        if investigation_id:
            row = connection.execute(
                "SELECT id, name FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"investigation not found: {investigation_id}")
        connection.execute(
            """INSERT INTO file_analyses
               (id, investigation_id, file_name, format, media_type,
                size_bytes, sha256, analysis_json, created_at, tlsh, ssdeep)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                analysis_id,
                investigation_id,
                analysis["file_name"][:300],
                analysis["format"][:64],
                analysis["media_type"][:200],
                analysis["size_bytes"],
                analysis["hashes"]["sha256"],
                json.dumps(analysis_payload, ensure_ascii=False, sort_keys=True),
                created_at,
                analysis["hashes"]["tlsh"],
                analysis["hashes"]["ssdeep"],
            ),
        )
        record_activity(
            connection,
            action="analysis",
            target_type="file",
            target_id=analysis_id,
            investigation_id=investigation_id,
            summary=f"File analysed: {analysis['file_name']} ({analysis['format_label']})",
        )
    return analysis_payload


def list_file_analyses(
    database: str,
    *,
    investigation_id: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    limit = max(1, min(200, int(limit)))
    with _connection(database) as connection:
        _ensure_analysis_table(connection)
        clauses: list[str] = []
        parameters: list[Any] = []
        if investigation_id:
            clauses.append("a.investigation_id = ?")
            parameters.append(investigation_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total = connection.execute(
            f"SELECT COUNT(*) FROM file_analyses a {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""SELECT a.id, a.investigation_id, a.file_name, a.format,
                       a.media_type, a.size_bytes, a.sha256, a.created_at,
                       i.name AS investigation_name
                FROM file_analyses a
                LEFT JOIN investigations i ON i.id = a.investigation_id
                {where}
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT ?""",
            [*parameters, limit],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "limit": limit,
    }


def get_file_analysis(database: str, analysis_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        _ensure_analysis_table(connection)
        row = connection.execute(
            """SELECT id, investigation_id, file_name, format, media_type,
                      size_bytes, sha256, analysis_json, created_at
               FROM file_analyses WHERE id = ?""",
            (analysis_id,),
        ).fetchone()
    if row is None:
        raise NotFoundError(f"file analysis not found: {analysis_id}")
    try:
        payload = json.loads(row["analysis_json"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("stored file analysis is unreadable") from exc
    if not isinstance(payload, dict):
        raise ValidationError("stored file analysis is invalid")
    return payload


# ---------------------------------------------------------------------------
# Similarity across the workspace

SIMILARITY_SCAN_LIMIT = 5000
TLSH_CLOSE_DISTANCE = 100


def similar_file_analyses(database: str, analysis_id: str, *, limit: int = 20) -> dict[str, Any]:
    """Rank stored analyses by TLSH distance and ssdeep score against one.

    Identical SHA-256 values are reported as exact copies. A candidate is kept
    when its TLSH distance is at most ``TLSH_CLOSE_DISTANCE`` or its ssdeep
    score is above zero; nothing here implies a shared origin."""
    limit = max(1, min(100, int(limit)))
    with _connection(database) as connection:
        _ensure_analysis_table(connection)
        target = connection.execute(
            "SELECT id, sha256, tlsh, ssdeep FROM file_analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
        if target is None:
            raise NotFoundError(f"file analysis not found: {analysis_id}")
        rows = connection.execute(
            """SELECT a.id, a.investigation_id, a.file_name, a.format, a.size_bytes,
                      a.sha256, a.tlsh, a.ssdeep, a.created_at, i.name AS investigation_name
               FROM file_analyses a
               LEFT JOIN investigations i ON i.id = a.investigation_id
               WHERE a.id != ?
               ORDER BY a.created_at DESC LIMIT ?""",
            (analysis_id, SIMILARITY_SCAN_LIMIT),
        ).fetchall()
    matches = []
    for row in rows:
        exact = row["sha256"] == target["sha256"]
        distance = tlsh_compare(target["tlsh"], row["tlsh"]) if target["tlsh"] and row["tlsh"] else None
        score = ssdeep_score(target["ssdeep"], row["ssdeep"]) if target["ssdeep"] and row["ssdeep"] else None
        if not exact and (distance is None or distance > TLSH_CLOSE_DISTANCE) and not score:
            continue
        item = {key: row[key] for key in row.keys() if key not in {"tlsh", "ssdeep"}}
        item.update({"exact": exact, "tlsh_distance": distance, "ssdeep_score": score})
        matches.append(item)
    matches.sort(
        key=lambda item: (
            not item["exact"],
            item["tlsh_distance"] if item["tlsh_distance"] is not None else 10_000,
            -(item["ssdeep_score"] or 0),
        )
    )
    return {
        "analysis_id": analysis_id,
        "has_digests": bool(target["tlsh"] or target["ssdeep"]),
        "compared": len(rows),
        "items": matches[:limit],
        "thresholds": {"tlsh_max_distance": TLSH_CLOSE_DISTANCE, "ssdeep_min_score": 1},
        "note": "Byte-level resemblance only; not shared authorship, purpose or verdict.",
    }
