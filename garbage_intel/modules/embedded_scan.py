"""Embedded signature scan: where other formats start inside a file.

In the spirit of binwalk's signature scan, but list-only: nothing is carved or
extracted. Each magic number is checked against a few header fields so that
random bytes rarely qualify. The Rust engine (``native/rust/src/signatures.rs``)
implements the same rules; ``python_scan`` is the reference and the fallback.

A hit says "these bytes look like the start of X". It does not say the
embedded object is complete, valid or harmful.
"""

from __future__ import annotations

import re
from typing import Any

SCAN_CAP = 65536
MAX_REPORTED = 200

# kind id -> (short name, label). Ids are part of the native ABI.
KINDS: dict[int, tuple[str, str]] = {
    1: ("zip", "ZIP local file header"),
    2: ("gzip", "GZIP stream"),
    3: ("bzip2", "BZIP2 stream"),
    4: ("xz", "XZ stream"),
    5: ("7z", "7-Zip archive"),
    6: ("rar", "RAR archive"),
    7: ("zstd", "Zstandard frame"),
    8: ("cab", "Microsoft Cabinet"),
    9: ("pe", "PE executable"),
    10: ("elf", "ELF executable"),
    11: ("macho", "Mach-O executable"),
    12: ("pdf", "PDF document"),
    13: ("png", "PNG image"),
    14: ("jpeg", "JPEG image"),
    15: ("gif", "GIF image"),
    16: ("ole", "OLE compound file"),
    17: ("sqlite", "SQLite database"),
    18: ("squashfs", "SquashFS filesystem"),
    19: ("cpio", "CPIO archive (newc)"),
    20: ("tar", "TAR archive"),
    21: ("iso", "ISO 9660 image"),
    22: ("uimage", "U-Boot legacy image"),
    23: ("dex", "Android DEX bytecode"),
    24: ("java-class", "Java class file"),
    25: ("macho-fat", "Mach-O universal binary"),
    26: ("rtf", "RTF document"),
    27: ("lnk", "Windows shortcut"),
    28: ("pem", "PEM block"),
    29: ("wasm", "WebAssembly module"),
}
EXECUTABLE_KINDS = {"pe", "elf", "macho", "macho-fat", "dex", "java-class", "wasm"}
CONTAINER_KINDS = {"zip", "gzip", "bzip2", "xz", "7z", "rar", "zstd", "cab", "ole", "squashfs", "cpio", "tar", "iso", "uimage"}
PEM_LABELS = {1: "certificate", 2: "private key", 3: "public key", 4: "other"}

_ZIP_METHODS = {0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99}
_JPEG_MARKERS = {0xE0, 0xE1, 0xE2, 0xDB, 0xEE, 0xC0, 0xC4, 0xFE}
_LNK = bytes.fromhex("4c0000000114020000000000c000000000000046")
_HEX = frozenset(b"0123456789abcdefABCDEF")
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]{1,40})-----")


def _u16le(data: bytes, offset: int) -> int:
    return data[offset] | data[offset + 1] << 8


def _u16be(data: bytes, offset: int) -> int:
    return data[offset] << 8 | data[offset + 1]


def _u32le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u32be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _zip(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 30 > len(d) or _u16le(d, p + 4) > 63 or _u16le(d, p + 8) not in _ZIP_METHODS:
        return None
    name = _u16le(d, p + 26)
    return (1, name) if 1 <= name <= 512 else None


def _gzip(d: bytes, p: int) -> tuple[int, int] | None:
    return (2, 0) if p + 10 <= len(d) and d[p + 3] & 0xE0 == 0 else None


def _bzip2(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 10 <= len(d) and 0x31 <= d[p + 3] <= 0x39 and d[p + 4 : p + 10] == b"\x31\x41\x59\x26\x53\x59":
        return (3, d[p + 3] - 0x30)
    return None


def _xz(d: bytes, p: int) -> tuple[int, int] | None:
    return (4, 0) if p + 8 <= len(d) and d[p + 6] == 0 and d[p + 7] & 0xF0 == 0 else None


def _7z(d: bytes, p: int) -> tuple[int, int] | None:
    return (5, d[p + 7]) if p + 8 <= len(d) and d[p + 6] == 0 else None


def _rar(d: bytes, p: int) -> tuple[int, int] | None:
    return (6, 5 if d[p + 6] == 1 else 4) if p + 7 <= len(d) and d[p + 6] in (0, 1) else None


def _zstd(d: bytes, p: int) -> tuple[int, int] | None:
    return (7, 0) if p + 5 <= len(d) and d[p + 4] & 0x08 == 0 else None


def _cab(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 26 <= len(d) and d[p + 4 : p + 8] == b"\0\0\0\0" and _u32le(d, p + 8) >= 36 and d[p + 24] == 3 and d[p + 25] == 1:
        return (8, 0)
    return None


def _pe(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 64 > len(d):
        return None
    header = _u32le(d, p + 60)
    if not 4 <= header <= 0x1000 or p + header + 24 > len(d) or d[p + header : p + header + 4] != b"PE\0\0":
        return None
    return (9, _u16le(d, p + header + 4))


def _elf(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 20 > len(d) or d[p + 4] not in (1, 2) or d[p + 5] not in (1, 2) or d[p + 6] != 1:
        return None
    return (10, _u16le(d, p + 18) if d[p + 5] == 1 else _u16be(d, p + 18))


def _macho(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 8 > len(d):
        return None
    cpu = _u32be(d, p + 4) if d[p] == 0xFE else _u32le(d, p + 4)
    return (11, cpu & 0xFFFFFF) if cpu & 0xFFFFFF in (7, 12, 18) else None


def _pdf(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 8 <= len(d) and 0x30 <= d[p + 5] <= 0x39 and d[p + 6] == 0x2E and 0x30 <= d[p + 7] <= 0x39:
        return (12, 0)
    return None


def _png(d: bytes, p: int) -> tuple[int, int] | None:
    return (13, _u32be(d, p + 16)) if p + 20 <= len(d) and d[p + 12 : p + 16] == b"IHDR" else None


def _jpeg(d: bytes, p: int) -> tuple[int, int] | None:
    return (14, 0) if p + 4 <= len(d) and d[p + 3] in _JPEG_MARKERS else None


def _gif(d: bytes, p: int) -> tuple[int, int] | None:
    return (15, 0) if p + 6 <= len(d) and d[p + 3 : p + 6] in (b"87a", b"89a") else None


def _ole(d: bytes, p: int) -> tuple[int, int] | None:
    return (16, 0) if p + 30 <= len(d) and d[p + 28 : p + 30] == b"\xfe\xff" else None


def _sqlite(d: bytes, p: int) -> tuple[int, int] | None:
    return (17, 0)


def _squashfs(d: bytes, p: int) -> tuple[int, int] | None:
    return (18, 4) if p + 30 <= len(d) and _u16le(d, p + 28) == 4 else None


def _cpio(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 14 <= len(d) and d[p + 5] in (0x31, 0x32) and all(byte in _HEX for byte in d[p + 6 : p + 14]):
        return (19, 0)
    return None


def _class_or_fat(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 8 > len(d):
        return None
    major = _u16be(d, p + 6)
    if 45 <= major <= 70:
        return (24, major)
    count = _u32be(d, p + 4)
    return (25, count) if 1 <= count <= 20 else None


def _dex(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 8 <= len(d) and all(0x30 <= byte <= 0x39 for byte in d[p + 4 : p + 7]) and d[p + 7] == 0:
        return (23, 0)
    return None


def _uimage(d: bytes, p: int) -> tuple[int, int] | None:
    if p + 64 <= len(d) and _u32be(d, p + 12) > 0 and d[p + 28] <= 30 and d[p + 30] <= 10:
        return (22, _u32be(d, p + 12))
    return None


def _pem(d: bytes, p: int) -> tuple[int, int] | None:
    match = _PEM.match(d, p)
    if not match:
        return None
    label = match.group(1)
    if label == b"CERTIFICATE":
        category = 1
    elif b"PRIVATE KEY" in label:
        category = 2
    elif b"PUBLIC KEY" in label:
        category = 3
    else:
        category = 4
    return (28, category)


# (magic, validator). Scanned at every position where the magic occurs.
_RULES = (
    (b"PK\x03\x04", _zip),
    (b"\x1f\x8b\x08", _gzip),
    (b"BZh", _bzip2),
    (b"\xfd7zXZ\x00", _xz),
    (b"7z\xbc\xaf\x27\x1c", _7z),
    (b"Rar!\x1a\x07", _rar),
    (b"\x28\xb5\x2f\xfd", _zstd),
    (b"MSCF", _cab),
    (b"MZ", _pe),
    (b"\x7fELF", _elf),
    (b"\xfe\xed\xfa\xce", _macho),
    (b"\xfe\xed\xfa\xcf", _macho),
    (b"\xce\xfa\xed\xfe", _macho),
    (b"\xcf\xfa\xed\xfe", _macho),
    (b"%PDF-", _pdf),
    (b"\x89PNG\r\n\x1a\n", _png),
    (b"\xff\xd8\xff", _jpeg),
    (b"GIF8", _gif),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", _ole),
    (b"SQLite format 3\x00", _sqlite),
    (b"hsqs", _squashfs),
    (b"07070", _cpio),
    (b"\x27\x05\x19\x56", _uimage),
    (b"dex\n", _dex),
    (b"\xca\xfe\xba\xbe", _class_or_fat),
    (b"{\\rtf", lambda d, p: (26, 0)),
    (_LNK, lambda d, p: (27, 0)),
    (b"-----BEGIN ", _pem),
    (b"\x00asm\x01\x00\x00\x00", lambda d, p: (29, 0)),
)


def python_scan(data: bytes) -> tuple[list[tuple[int, int, int]], bool]:
    """Return ``[(offset, kind, extra)]`` sorted by offset and kind, plus a
    truncation flag. Hits are accepted in match-position order up to
    ``SCAN_CAP`` so the result matches the native engine."""
    hits: list[tuple[int, int, int, int]] = []  # (match position, kind, offset, extra)
    for magic, validate in _RULES:
        position = data.find(magic)
        while position != -1:
            found = validate(data, position)
            if found:
                hits.append((position, found[0], position, found[1]))
            position = data.find(magic, position + 1)
    # Formats identified by a magic away from their start.
    position = data.find(b"ustar")
    while position != -1:
        if position >= 257 and position + 8 <= len(data) and (data[position + 5 : position + 8] == b"\x0000" or data[position + 5 : position + 8] == b"  \x00"):
            hits.append((position, 20, position - 257, 0))
        position = data.find(b"ustar", position + 1)
    position = data.find(b"\x01CD001\x01", 0x8000)
    while position != -1:
        hits.append((position + 1, 21, position - 0x8000, 0))
        position = data.find(b"\x01CD001\x01", position + 1)
    hits.sort(key=lambda item: (item[0], item[1]))
    truncated = len(hits) > SCAN_CAP
    result = sorted((offset, kind, extra) for _, kind, offset, extra in hits[:SCAN_CAP])
    return result, truncated


def scan_signatures(data: bytes, file_format: str = "") -> dict[str, Any]:
    """Grouped, labelled scan result for the analysis payload."""
    from .. import native

    native_result = native.signature_scan(data)
    engine = "rust-native"
    if native_result is None:
        native_result = python_scan(data)
        engine = "python-fallback"
    raw, truncated = native_result
    zip_family = file_format in {"zip", "docx", "xlsx", "pptx", "epub", "jar", "apk"}
    items: list[dict[str, Any]] = []
    zip_run: dict[str, Any] | None = None
    for offset, kind, extra in raw:
        name, label = KINDS.get(kind, ("unknown", "Unknown"))
        if name == "zip":
            if zip_family:
                continue
            if zip_run is not None:
                zip_run["count"] += 1
                continue
            zip_run = {"offset": offset, "kind": name, "label": label, "detail": "", "count": 1}
            items.append(zip_run)
            continue
        detail = ""
        if name == "pem":
            detail = PEM_LABELS.get(extra, "")
        elif name in {"png", "uimage"} and extra:
            detail = f"{'width' if name == 'png' else 'data bytes'}: {extra}"
        elif name == "java-class":
            detail = f"class file version {extra}"
        elif name == "macho-fat":
            detail = f"{extra} architecture(s)"
        elif name == "bzip2":
            detail = f"block size {extra}00k"
        items.append({"offset": offset, "kind": name, "label": label, "detail": detail, "count": 1})
    for item in items:
        if item["kind"] == "zip" and item["count"] > 1:
            item["detail"] = f"{item['count']} local headers from here on"
    embedded = [item for item in items if item["offset"] > 0]
    return {
        "engine": engine,
        "items": items[:MAX_REPORTED],
        "total": len(items),
        "truncated": truncated or len(items) > MAX_REPORTED,
        "embedded_executables": sorted({item["kind"] for item in embedded if item["kind"] in EXECUTABLE_KINDS}),
        "embedded_containers": sorted({item["kind"] for item in embedded if item["kind"] in CONTAINER_KINDS}),
        "private_keys": sum(1 for item in items if item["kind"] == "pem" and item["detail"] == "private key"),
    }
