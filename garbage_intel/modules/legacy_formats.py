"""Read-only parsers for formats often used to deliver content on Windows:
OLE compound files (legacy Office, MSI, Outlook), VBA macro projects,
shortcut (LNK) files, ISO 9660 images and RTF documents.

Written from the public specifications ([MS-CFB], [MS-OLEPS], [MS-OVBA],
[MS-SHLLINK], ECMA-119 and the RTF 1.9.1 specification). Every parser works on
the bytes in memory, follows chains with loop and length guards and returns
partial results with notes instead of raising on malformed input. Macro source
is decompressed for reading only; nothing is executed or written to disk.

Keyword matches below are static heuristics. They show what a macro or
shortcut *could* do, not what it did or who wrote it.
"""

from __future__ import annotations

import re
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

MAX_STREAMS = 400
MAX_MACRO_SOURCE = 64 * 1024
MAX_DECOMPRESSED = 2 * 1024 * 1024
MAX_ISO_ENTRIES = 300
MAX_RTF_OBJECTS = 20

_FREE, _END = 0xFFFFFFFF, 0xFFFFFFFE
_MSI_CLSID = "000c1084-0000-0000-c000-000000000046"


class FormatError(ValueError):
    """The bytes do not follow the expected structure."""


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise FormatError("truncated")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise FormatError("truncated")
    return struct.unpack_from("<I", data, offset)[0]


def _filetime(value: int) -> str | None:
    if not value or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    if not 1980 <= moment.year <= 2100:
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(text: str, limit: int = 500) -> str:
    return "".join(character for character in text if character.isprintable())[:limit]


# ---------------------------------------------------------------------------
# OLE compound file binary format


class CompoundFile:
    """Directory tree and stream reader for one compound file."""

    def __init__(self, data: bytes) -> None:
        if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or len(data) < 512:
            raise FormatError("not a compound file")
        self.data = data
        self.notes: list[str] = []
        self.major_version = _u16(data, 26)
        sector_shift = _u16(data, 30)
        mini_shift = _u16(data, 32)
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise FormatError("unsupported sector size")
        self.sector_size = 1 << sector_shift
        self.mini_size = 1 << mini_shift
        self.mini_cutoff = _u32(data, 56) or 4096
        self.root_clsid = str(uuid.UUID(bytes_le=data[8:24])) if data[8:24].strip(b"\0") else ""
        self.fat = self._load_fat()
        self.entries = self._load_directory(_u32(data, 48))
        root = self.entries[0] if self.entries else None
        if root is None or root["type"] != 5:
            raise FormatError("missing root entry")
        self.root_clsid = root["clsid"] or self.root_clsid
        self.mini_fat = self._chain_bytes(_u32(data, 60))
        self.mini_stream = self._chain_bytes(root["start"])[: root["size"]]
        self.streams = self._walk()

    def _sector(self, number: int) -> bytes:
        offset = (number + 1) * self.sector_size
        if offset + self.sector_size > len(self.data):
            chunk = self.data[offset : offset + self.sector_size]
            if not chunk:
                raise FormatError("sector outside file")
            return chunk.ljust(self.sector_size, b"\0")
        return self.data[offset : offset + self.sector_size]

    def _load_fat(self) -> list[int]:
        per_sector = self.sector_size // 4
        fat_sectors = [_u32(self.data, 76 + 4 * index) for index in range(109)]
        difat, seen = _u32(self.data, 68), set()
        for _ in range(_u32(self.data, 72)):
            if difat in (_FREE, _END) or difat in seen:
                break
            seen.add(difat)
            values = struct.unpack(f"<{per_sector}I", self._sector(difat))
            fat_sectors.extend(values[:-1])
            difat = values[-1]
        fat: list[int] = []
        for number in fat_sectors[: _u32(self.data, 44)]:
            if number in (_FREE, _END):
                continue
            try:
                fat.extend(struct.unpack(f"<{per_sector}I", self._sector(number)))
            except FormatError:
                self.notes.append("FAT sector outside the file")
                break
        return fat

    def _chain(self, start: int, table: list[int]) -> list[int]:
        chain, seen = [], set()
        current = start
        while current not in (_FREE, _END) and current < len(table):
            if current in seen:
                self.notes.append("sector chain loop")
                break
            seen.add(current)
            chain.append(current)
            current = table[current]
            if len(chain) > len(self.data) // self.mini_size + 1:
                break
        return chain

    def _chain_bytes(self, start: int) -> bytes:
        if start in (_FREE, _END):
            return b""
        return b"".join(self._sector(number) for number in self._chain(start, self.fat))

    def _load_directory(self, start: int) -> list[dict[str, Any]]:
        raw = self._chain_bytes(start)
        entries = []
        for offset in range(0, min(len(raw), 128 * 4096), 128):
            record = raw[offset : offset + 128]
            if len(record) < 128:
                break
            name_length = _u16(record, 64)
            kind = record[66]
            size = struct.unpack_from("<Q", record, 120)[0]
            if self.major_version == 3:
                size &= 0xFFFFFFFF
            clsid = record[80:96]
            entries.append(
                {
                    "name": record[: max(0, min(64, name_length) - 2)].decode("utf-16-le", errors="replace"),
                    "type": kind,
                    "left": _u32(record, 68),
                    "right": _u32(record, 72),
                    "child": _u32(record, 76),
                    "clsid": str(uuid.UUID(bytes_le=clsid)) if clsid.strip(b"\0") else "",
                    "created": _filetime(struct.unpack_from("<Q", record, 100)[0]),
                    "modified": _filetime(struct.unpack_from("<Q", record, 108)[0]),
                    "start": _u32(record, 116),
                    "size": size,
                }
            )
        return entries

    def _walk(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        seen: set[int] = set()
        stack = [(self.entries[0]["child"], "")]
        while stack and len(found) < MAX_STREAMS:
            index, prefix = stack.pop()
            if index >= len(self.entries) or index in seen:
                continue
            seen.add(index)
            entry = self.entries[index]
            stack.append((entry["left"], prefix))
            stack.append((entry["right"], prefix))
            if entry["type"] not in (1, 2):
                continue
            path = f"{prefix}{entry['name']}"
            found.append({**entry, "path": path, "storage": entry["type"] == 1})
            if entry["type"] == 1:
                stack.append((entry["child"], path + "/"))
        found.sort(key=lambda item: item["path"])
        return found

    def stream(self, path: str) -> bytes:
        entry = next((item for item in self.streams if item["path"] == path and not item["storage"]), None)
        if entry is None:
            raise FormatError(f"no stream {path}")
        if entry["size"] < self.mini_cutoff:
            mini_table = list(struct.unpack(f"<{len(self.mini_fat) // 4}I", self.mini_fat[: len(self.mini_fat) // 4 * 4]))
            parts = []
            for number in self._chain(entry["start"], mini_table):
                offset = number * self.mini_size
                parts.append(self.mini_stream[offset : offset + self.mini_size])
            return b"".join(parts)[: entry["size"]]
        return self._chain_bytes(entry["start"])[: entry["size"]]


_SUMMARY_FIELDS = {
    2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template",
    8: "last_saved_by", 9: "revision", 11: "last_printed", 12: "created", 13: "last_saved",
    14: "pages", 15: "words", 16: "characters", 18: "application", 19: "security",
}
_MSI_FIELDS = {3: "product", 4: "manufacturer", 7: "platform_languages", 9: "package_code", 14: "installer_version", 15: "source_flags"}
_DOCUMENT_FIELDS = {2: "category", 14: "manager", 15: "company"}


def _property_set(raw: bytes, names: dict[int, str]) -> dict[str, Any]:
    if len(raw) < 48 or _u16(raw, 0) != 0xFFFE:
        return {}
    section = _u32(raw, 44)
    count = min(_u32(raw, section + 4), 200)
    codepage = "cp1252"
    values: dict[int, Any] = {}
    for index in range(count):
        identifier = _u32(raw, section + 8 + index * 8)
        offset = section + _u32(raw, section + 12 + index * 8)
        kind = _u32(raw, offset) & 0xFFFF
        try:
            if kind == 2:
                values[identifier] = struct.unpack_from("<h", raw, offset + 4)[0]
            elif kind == 3:
                values[identifier] = struct.unpack_from("<i", raw, offset + 4)[0]
            elif kind == 30:
                size = min(_u32(raw, offset + 4), 4096)
                values[identifier] = raw[offset + 8 : offset + 8 + size].split(b"\0", 1)[0]
            elif kind == 31:
                size = min(_u32(raw, offset + 4), 2048)
                values[identifier] = raw[offset + 8 : offset + 8 + size * 2].decode("utf-16-le", errors="replace").split("\0", 1)[0]
            elif kind == 64:
                values[identifier] = ("filetime", struct.unpack_from("<Q", raw, offset + 4)[0])
        except (FormatError, struct.error):
            continue
    if isinstance(values.get(1), int):
        codepage = {65001: "utf-8", 1200: "utf-16-le"}.get(values[1] & 0xFFFF, f"cp{values[1] & 0xFFFF}")
    result: dict[str, Any] = {}
    for identifier, name in names.items():
        value = values.get(identifier)
        if value is None:
            continue
        if isinstance(value, bytes):
            try:
                value = value.decode(codepage, errors="replace")
            except LookupError:
                value = value.decode("latin-1")
            value = _clean(value)
        elif isinstance(value, tuple):
            value = _filetime(value[1]) if name != "edit_time" else value[1]
        if value not in (None, ""):
            result[name] = value
    return result


_MSI_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_stream_name(name: str) -> str:
    """Decode the packed stream names Windows Installer uses for tables."""
    out = []
    for character in name:
        code = ord(character)
        if 0x3800 <= code < 0x4800:
            code -= 0x3800
            out.append(_MSI_ALPHABET[code & 0x3F])
            out.append(_MSI_ALPHABET[(code >> 6) & 0x3F])
        elif 0x4800 <= code < 0x4840:
            out.append(_MSI_ALPHABET[code - 0x4800])
        elif code == 0x4840:
            out.append("!")
        else:
            out.append(character)
    return "".join(out)


def ole_kind(compound: CompoundFile) -> str:
    names = {item["path"].split("/")[0] for item in compound.streams}
    if compound.root_clsid == _MSI_CLSID:
        return "msi"
    if "WordDocument" in names:
        return "doc"
    if names & {"Workbook", "Book"}:
        return "xls"
    if "PowerPoint Document" in names:
        return "ppt"
    if "__properties_version1.0" in names or any(name.startswith("__substg1.0_") for name in names):
        return "msg"
    return "ole"


# ---------------------------------------------------------------------------
# VBA projects


def ovba_decompress(data: bytes) -> bytes:
    """[MS-OVBA] 2.4.1 compressed container."""
    if not data or data[0] != 1:
        raise FormatError("not a compressed container")
    out = bytearray()
    position = 1
    while position + 2 <= len(data) and len(out) < MAX_DECOMPRESSED:
        header = _u16(data, position)
        chunk_end = min(len(data), position + (header & 0x0FFF) + 3)
        position += 2
        chunk_start = len(out)
        if not header & 0x8000:
            out += data[position : position + 4096]
            position += 4096
            continue
        while position < chunk_end:
            flags = data[position]
            position += 1
            for bit in range(8):
                if position >= chunk_end:
                    break
                if not flags >> bit & 1:
                    out.append(data[position])
                    position += 1
                    continue
                if position + 2 > chunk_end:
                    position = chunk_end
                    break
                token = _u16(data, position)
                position += 2
                bit_count = max((len(out) - chunk_start - 1).bit_length(), 4)
                offset = (token >> (16 - bit_count)) + 1
                length = (token & (0xFFFF >> bit_count)) + 3
                if offset > len(out) - chunk_start:
                    raise FormatError("copy token before chunk start")
                for _ in range(length):
                    out.append(out[-offset])
        position = chunk_end
    return bytes(out[:MAX_DECOMPRESSED])


_VBA_AUTOEXEC = (
    "AutoOpen", "Auto_Open", "Document_Open", "DocumentOpen", "Workbook_Open", "Workbook_Activate",
    "AutoClose", "Auto_Close", "Document_Close", "AutoExec", "AutoNew", "Document_New",
)
_VBA_SUSPICIOUS = {
    "process": ("Shell", "WScript.Shell", "ShellExecute", "Run(", ".Exec(", "CreateProcess", "MacScript"),
    "objects": ("CreateObject", "GetObject", "CallByName"),
    "network": ("URLDownloadToFile", "XMLHTTP", "WinHttp", "InternetOpen", "Net.WebClient", "http://", "https://"),
    "files": ("ADODB.Stream", "SaveToFile", "Open ", "Kill ", "FileCopy", "Scripting.FileSystemObject"),
    "native": ('Lib "', "VirtualAlloc", "RtlMoveMemory", "CreateThread", "WriteProcessMemory"),
    "obfuscation": ("Chr(", "ChrW(", "StrReverse", "Base64", "FromBase64String", "Xor"),
    "scripting": ("PowerShell", "cmd.exe", "cmd /c", "mshta", "rundll32", "regsvr32", "certutil", "wscript", "cscript"),
    "environment": ("Environ", "ExecuteExcel4Macro", "Application.Run"),
}


def _vba_keywords(source: str) -> dict[str, Any]:
    lower = source.lower()
    autoexec = sorted({word for word in _VBA_AUTOEXEC if re.search(rf"\b{re.escape(word.lower())}\b", lower)})
    suspicious = {
        category: sorted({word for word in words if word.lower() in lower})
        for category, words in _VBA_SUSPICIOUS.items()
    }
    return {"autoexec": autoexec, "suspicious": {key: value for key, value in suspicious.items() if value}}


def _vba_dir(raw: bytes) -> tuple[str, list[dict[str, Any]]]:
    data = ovba_decompress(raw)
    codepage = "cp1252"
    modules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    position = 0
    while position + 6 <= len(data):
        identifier = _u16(data, position)
        size = _u32(data, position + 2)
        body = data[position + 6 : position + 6 + size]
        position += 6 + size
        if identifier == 0x0009:  # PROJECTVERSION: size field is fixed at 4, payload is 6.
            position += 2
        elif identifier == 0x0003 and size == 2:
            codepage = f"cp{_u16(body, 0)}"
        elif identifier == 0x0019:
            current = {"name": body.decode(codepage, errors="replace"), "stream": "", "offset": 0, "type": "standard"}
            modules.append(current)
        elif identifier == 0x001A and current is not None:
            current["stream"] = body.decode(codepage, errors="replace")
        elif identifier == 0x0031 and current is not None and size == 4:
            current["offset"] = _u32(body, 0)
        elif identifier == 0x0022 and current is not None:
            current["type"] = "document-or-class"
        elif identifier == 0x0010:
            break
    return codepage, modules


def vba_projects(compound: CompoundFile) -> list[dict[str, Any]]:
    projects = []
    for entry in compound.streams:
        if entry["storage"] or entry["name"].lower() != "dir" or not entry["path"].lower().endswith("vba/dir"):
            continue
        base = entry["path"][: -len("dir")]
        project: dict[str, Any] = {"storage": base.rstrip("/"), "modules": [], "notes": []}
        try:
            codepage, modules = _vba_dir(compound.stream(entry["path"]))
        except (FormatError, LookupError) as exc:
            project["notes"].append(f"unreadable dir stream: {exc}")
            projects.append(project)
            continue
        for module in modules[:100]:
            item = {"name": _clean(module["name"], 120), "stream": _clean(module["stream"], 120), "type": module["type"]}
            try:
                code = ovba_decompress(compound.stream(base + module["stream"])[module["offset"] :])
                source = code.decode(codepage, errors="replace").replace("\r\n", "\n")
            except (FormatError, LookupError) as exc:
                item.update({"source": "", "source_bytes": 0, "error": str(exc)})
                project["modules"].append(item)
                continue
            item.update(
                {
                    "source": source[:MAX_MACRO_SOURCE],
                    "source_bytes": len(code),
                    "truncated": len(source) > MAX_MACRO_SOURCE,
                    "lines": source.count("\n") + 1 if source else 0,
                    **_vba_keywords(source),
                }
            )
            project["modules"].append(item)
        projects.append(project)
    return projects


def analyse_compound(data: bytes) -> dict[str, Any]:
    compound = CompoundFile(data)
    kind = ole_kind(compound)
    streams = [
        {
            "path": item["path"] if kind != "msi" else msi_stream_name(item["path"]),
            "size_bytes": item["size"] if not item["storage"] else None,
            "storage": item["storage"],
            "modified": item["modified"],
        }
        for item in compound.streams
    ]
    result: dict[str, Any] = {
        "container": "ole",
        "kind": kind,
        "root_clsid": compound.root_clsid,
        "major_version": compound.major_version,
        "streams": streams,
        "stream_count": sum(1 for item in streams if not item["storage"]),
        "notes": list(dict.fromkeys(compound.notes)),
    }
    names = _SUMMARY_FIELDS if kind != "msi" else {**_SUMMARY_FIELDS, **_MSI_FIELDS}
    for path, fields, key in (
        ("\x05SummaryInformation", names, "summary"),
        ("\x05DocumentSummaryInformation", _DOCUMENT_FIELDS, "document_summary"),
    ):
        try:
            properties = _property_set(compound.stream(path), fields)
        except FormatError:
            continue
        if properties:
            result[key] = properties
    if kind == "msi":
        tables = sorted(item["path"][1:] for item in streams if item["path"].startswith("!") and not item["storage"])
        result["msi_tables"] = tables
        result["msi_custom_actions"] = "CustomAction" in tables
        result["msi_binary_streams"] = sum(1 for item in streams if item["path"].startswith("Binary."))
    result["vba"] = vba_projects(compound)
    result["ole_objects"] = sorted(
        {item["path"] for item in compound.streams if item["name"] in ("\x01Ole10Native", "\x01CompObj", "ObjectPool")}
    )[:50]
    return result


# ---------------------------------------------------------------------------
# Shell link (LNK)

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_LNK_FLAGS = (
    "has_target_id_list", "has_link_info", "has_name", "has_relative_path", "has_working_dir",
    "has_arguments", "has_icon_location", "is_unicode", "force_no_link_info", "has_exp_string",
    "run_in_separate_process", "unused1", "has_darwin_id", "run_as_user", "has_exp_icon",
    "no_pidl_alias", "unused2", "run_with_shim_layer", "force_no_link_track", "enable_target_metadata",
)
_SHOW = {1: "normal", 3: "maximized", 7: "minimized"}
_DRIVE_TYPES = {0: "unknown", 1: "no-root", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}
_EXTRA_BLOCKS = {
    0xA0000001: "environment-variables", 0xA0000002: "console", 0xA0000003: "tracker",
    0xA0000004: "console-codepage", 0xA0000005: "special-folder", 0xA0000006: "darwin",
    0xA0000007: "icon-environment", 0xA0000008: "shim", 0xA0000009: "property-store",
    0xA000000B: "known-folder", 0xA000000C: "vista-id-list",
}
_LNK_RISKY = re.compile(
    r"powershell|pwsh|cmd(?:\.exe)?\s*/[ck]|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|"
    r"msiexec|curl|wget|https?://|\\\\[\w.-]+\\|-e(?:nc|ncodedcommand)?\s|frombase64",
    re.IGNORECASE,
)


def _cstring(data: bytes, offset: int, wide: bool = False) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    if wide:
        end = offset
        while end + 1 < len(data) and data[end : end + 2] != b"\0\0":
            end += 2
        return _clean(data[offset:end].decode("utf-16-le", errors="replace"))
    return _clean(data[offset:].split(b"\0", 1)[0].decode("cp1252", errors="replace"))


def analyse_lnk(data: bytes) -> dict[str, Any]:
    if len(data) < 76 or _u32(data, 0) != 0x4C or data[4:20] != _LNK_CLSID:
        raise FormatError("not a shell link")
    flags_value = _u32(data, 20)
    flags = {name: bool(flags_value >> bit & 1) for bit, name in enumerate(_LNK_FLAGS) if not name.startswith("unused")}
    result: dict[str, Any] = {
        "flags": [name for name, value in flags.items() if value],
        "file_attributes": _u32(data, 24),
        "target_created": _filetime(struct.unpack_from("<Q", data, 28)[0]),
        "target_accessed": _filetime(struct.unpack_from("<Q", data, 36)[0]),
        "target_modified": _filetime(struct.unpack_from("<Q", data, 44)[0]),
        "target_size": _u32(data, 52),
        "icon_index": struct.unpack_from("<i", data, 56)[0],
        "show_command": _SHOW.get(_u32(data, 60), str(_u32(data, 60))),
        "notes": [],
    }
    position = 76
    if flags["has_target_id_list"]:
        position += 2 + _u16(data, position)
    if flags["has_link_info"] and not flags["force_no_link_info"]:
        info_size = _u32(data, position)
        info = data[position : position + info_size]
        try:
            header_size = _u32(info, 4)
            info_flags = _u32(info, 8)
            if info_flags & 1:
                volume = _u32(info, 12)
                label_offset = _u32(info, volume + 12)
                result["volume"] = {
                    "drive_type": _DRIVE_TYPES.get(_u32(info, volume + 4), "unknown"),
                    "serial": f"{_u32(info, volume + 8):08X}",
                    "label": _cstring(info, volume + _u32(info, volume + 16), True)
                    if label_offset == 0x14
                    else _cstring(info, volume + label_offset),
                }
                result["local_base_path"] = (
                    _cstring(info, _u32(info, 28), True) if header_size >= 0x24 and _u32(info, 28) else _cstring(info, _u32(info, 16))
                )
            if info_flags & 2:
                network = _u32(info, 20)
                result["network_share"] = _cstring(info, network + _u32(info, network + 8))
            suffix = _cstring(info, _u32(info, 24))
            if suffix:
                result["path_suffix"] = suffix
        except FormatError:
            result["notes"].append("truncated link info")
        position += info_size
    wide = flags["is_unicode"]
    for flag, key in (
        ("has_name", "description"), ("has_relative_path", "relative_path"), ("has_working_dir", "working_dir"),
        ("has_arguments", "arguments"), ("has_icon_location", "icon_location"),
    ):
        if not flags[flag]:
            continue
        try:
            count = _u16(data, position)
        except FormatError:
            result["notes"].append("truncated string data")
            break
        size = count * (2 if wide else 1)
        raw = data[position + 2 : position + 2 + size]
        text = raw.decode("utf-16-le" if wide else "cp1252", errors="replace")
        result[key] = _clean(text, 4096)
        if key == "arguments":
            result["arguments_length"] = len(text)
        position += 2 + size
    blocks = []
    while position + 8 <= len(data) and len(blocks) < 32:
        size = _u32(data, position)
        if size < 8:
            break
        signature = _u32(data, position + 4)
        block = data[position : position + size]
        name = _EXTRA_BLOCKS.get(signature, f"0x{signature:08X}")
        blocks.append(name)
        if signature == 0xA0000003 and len(block) >= 0x60:
            result["machine_id"] = _clean(block[16:32].split(b"\0", 1)[0].decode("ascii", errors="replace"))
            object_id = uuid.UUID(bytes_le=block[48:64])
            result["droid_object_id"] = str(object_id)
            if object_id.version == 1:
                result["droid_mac"] = ":".join(f"{object_id.node:012x}"[index : index + 2] for index in range(0, 12, 2))
                try:
                    stamp = datetime(1582, 10, 15, tzinfo=timezone.utc) + timedelta(microseconds=object_id.time // 10)
                    result["droid_time"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
                except OverflowError:
                    pass
        elif signature == 0xA0000001 and len(block) >= 788:
            result["environment_target"] = _cstring(block, 268, True) or _cstring(block, 8)
        position += size
    result["extra_blocks"] = blocks
    command = " ".join(str(result.get(key, "")) for key in ("local_base_path", "relative_path", "arguments", "environment_target"))
    result["risky_command"] = sorted(
        {re.sub(r"\s+", " ", match.group(0).lower()).strip() for match in _LNK_RISKY.finditer(command)}
    )[:20]
    # Long whitespace runs push the real command out of the Properties dialog.
    result["padded_arguments"] = bool(re.search(r"\s{50,}", str(result.get("arguments", ""))))
    return result


# ---------------------------------------------------------------------------
# ISO 9660

_RISKY_EXTENSIONS = {"exe", "dll", "scr", "com", "pif", "lnk", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "msi", "cpl", "iso", "img", "vhd", "jar"}


def _iso_date(raw: bytes) -> str | None:
    text = raw[:14].decode("ascii", errors="replace")
    if not text.isdigit() or text.startswith("0000"):
        return None
    return f"{text[0:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}"


def _record_date(raw: bytes) -> str | None:
    if len(raw) < 7 or raw[1] == 0:
        return None
    try:
        moment = datetime(1900 + raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
    except ValueError:
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


def analyse_iso(data: bytes) -> dict[str, Any]:
    if len(data) < 0x8800 or data[0x8001:0x8006] != b"CD001":
        raise FormatError("not an ISO 9660 image")
    block = 2048
    primary = None
    joliet = None
    boot = False
    for index in range(16, 64):
        offset = index * block
        descriptor = data[offset : offset + block]
        if len(descriptor) < block or descriptor[1:6] != b"CD001":
            break
        kind = descriptor[0]
        if kind == 255:
            break
        if kind == 0:
            boot = boot or descriptor[7:30].startswith(b"EL TORITO SPECIFICATION")
        elif kind == 1 and primary is None:
            primary = descriptor
        elif kind == 2 and descriptor[88:91] in (b"%/@", b"%/C", b"%/E"):
            joliet = descriptor
    if primary is None:
        raise FormatError("missing primary volume descriptor")
    logical = struct.unpack_from("<H", primary, 128)[0] or block
    text = lambda start, end: _clean(primary[start:end].decode("ascii", errors="replace").strip())
    result: dict[str, Any] = {
        "system_id": text(8, 40),
        "volume_id": text(40, 72),
        "volume_set_id": text(190, 318),
        "publisher": text(318, 446),
        "preparer": text(446, 574),
        "application": text(574, 702),
        "created": _iso_date(primary[813:830]),
        "modified": _iso_date(primary[830:847]),
        "logical_block_size": logical,
        "declared_size_bytes": struct.unpack_from("<I", primary, 80)[0] * logical,
        "joliet": joliet is not None,
        "el_torito_boot": boot,
        "notes": [],
    }
    if result["declared_size_bytes"] > len(data):
        result["notes"].append("image is larger than the analysed bytes; listing may be partial")
    descriptor = joliet or primary
    wide = joliet is not None
    entries: list[dict[str, Any]] = []
    queue = [(struct.unpack_from("<I", descriptor, 158)[0], struct.unpack_from("<I", descriptor, 166)[0], "", 0)]
    seen: set[int] = set()
    while queue and len(entries) < MAX_ISO_ENTRIES:
        extent, size, prefix, depth = queue.pop(0)
        if extent in seen or depth > 6:
            continue
        seen.add(extent)
        raw = data[extent * logical : extent * logical + min(size, 256 * 1024)]
        position = 0
        while position < len(raw) and len(entries) < MAX_ISO_ENTRIES:
            length = raw[position]
            if length == 0:
                position = (position // logical + 1) * logical
                continue
            record = raw[position : position + length]
            position += length
            if len(record) < 34:
                break
            name_length = record[32]
            name_raw = record[33 : 33 + name_length]
            if name_raw in (b"\0", b"\1"):
                continue
            name = name_raw.decode("utf-16-be" if wide else "ascii", errors="replace").split(";", 1)[0].rstrip(".")
            directory = bool(record[25] & 2)
            path = f"{prefix}{name}"
            child_extent = struct.unpack_from("<I", record, 2)[0]
            child_size = struct.unpack_from("<I", record, 10)[0]
            extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            entries.append(
                {
                    "path": _clean(path, 300) + ("/" if directory else ""),
                    "size_bytes": None if directory else child_size,
                    "recorded": _record_date(record[18:25]),
                    "hidden": bool(record[25] & 1),
                    "risky_extension": not directory and extension in _RISKY_EXTENSIONS,
                }
            )
            if directory:
                queue.append((child_extent, child_size, path + "/", depth + 1))
    result["entries"] = entries
    result["entry_count"] = len(entries)
    result["risky_entries"] = [item["path"] for item in entries if item["risky_extension"]][:50]
    if len(entries) >= MAX_ISO_ENTRIES:
        result["notes"].append("listing truncated")
    return result


# ---------------------------------------------------------------------------
# RTF

_RTF_CONTROL = re.compile(rb"\\[a-zA-Z]{1,32}-?\d{0,10} ?|\\'[0-9a-fA-F]{2}|[{}\s]")
_HEX_RUN = re.compile(rb"[0-9a-fA-F]+")


def _ole1_object(raw: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        info["format_id"] = _u32(raw, 4)
        class_length = _u32(raw, 8)
        info["class_name"] = _clean(raw[12 : 12 + class_length].split(b"\0", 1)[0].decode("latin-1"), 100)
        position = 12 + class_length
        for _ in range(2):  # topic and item names
            position += 4 + _u32(raw, position)
        native_size = _u32(raw, position)
        native = raw[position + 4 : position + 4 + native_size]
        info["native_size"] = native_size
        if native.startswith(b"\xd0\xcf\x11\xe0"):
            try:
                inner = CompoundFile(native)
                info["embedded_ole"] = {"kind": ole_kind(inner), "streams": [item["path"] for item in inner.streams][:30]}
            except FormatError:
                info["embedded_ole"] = {"kind": "unreadable", "streams": []}
        if info["class_name"].lower() == "package" and len(native) > 6:
            parts = native[2:].split(b"\0", 2)
            info["package_label"] = _clean(parts[0].decode("cp1252", errors="replace"), 260)
            if len(parts) > 1:
                info["package_source_path"] = _clean(parts[1].decode("cp1252", errors="replace"), 260)
    except FormatError:
        info["truncated"] = True
    return info


def analyse_rtf(data: bytes) -> dict[str, Any]:
    if not data.startswith(b"{\\rt"):
        raise FormatError("not RTF")
    result: dict[str, Any] = {
        "standard_header": data.startswith(b"{\\rtf1"),
        "objects": [],
        "object_count": len(re.findall(rb"\\object(?![a-z])", data)),
        "auto_update_objects": bool(re.search(rb"\\objupdate(?![a-z])", data)),
        "linked_objects": bool(re.search(rb"\\objautlink(?![a-z])|OLE2Link", data, re.IGNORECASE)),
        "binary_runs": len(re.findall(rb"\\bin\d*", data)),
        "object_classes": sorted({_clean(match.decode("latin-1").strip(), 80) for match in re.findall(rb"\\objclass\s+([^}\\]{1,80})", data)}),
        "remote_templates": [],
        "fields": [],
        "notes": [],
    }
    for match in re.finditer(rb"\\\*\\template\s+([^}]{1,500})", data):
        result["remote_templates"].append(_clean(match.group(1).decode("latin-1").strip(), 300))
    for match in re.finditer(rb"\\fldinst\s*\{?[^{}]{0,40}?\b(HYPERLINK|INCLUDEPICTURE|INCLUDETEXT|DDEAUTO|DDE)\b\s*\"?([^\"}\s\\]{1,300})", data, re.IGNORECASE):
        result["fields"].append({"type": match.group(1).decode("ascii").upper(), "target": _clean(match.group(2).decode("latin-1"), 300)})
    result["fields"] = result["fields"][:50]
    for match in list(re.finditer(rb"\\objdata(?![a-z])", data))[:MAX_RTF_OBJECTS]:
        depth = 1
        position = match.end()
        while position < len(data) and depth > 0:
            depth += {ord("{"): 1, ord("}"): -1}.get(data[position], 0)
            position += 1
        body = _RTF_CONTROL.sub(b"", data[match.end() : position - 1])
        hex_text = b"".join(_HEX_RUN.findall(body))
        if len(hex_text) % 2:
            hex_text = hex_text[:-1]
        raw = bytes.fromhex(hex_text.decode("ascii"))
        result["objects"].append({"offset": match.start(), "data_bytes": len(raw), **_ole1_object(raw)})
    classes = {item.lower() for item in result["object_classes"]} | {
        str(item.get("class_name", "")).lower() for item in result["objects"]
    }
    result["equation_editor"] = any(name.startswith("equation") for name in classes)
    return result


# ---------------------------------------------------------------------------


def detect_legacy(data: bytes) -> str | None:
    """Refined format id for compound files, LNK, RTF and ISO images."""
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        try:
            return ole_kind(CompoundFile(data))
        except (FormatError, struct.error):
            return "ole"
    if len(data) >= 76 and data[:4] == b"L\0\0\0" and data[4:20] == _LNK_CLSID:
        return "lnk"
    if data.startswith(b"{\\rt"):
        return "rtf"
    if len(data) >= 0x8800 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    return None
