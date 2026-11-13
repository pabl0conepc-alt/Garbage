"""Small writers that build test inputs for the legacy format parsers.

They follow the same public specifications as the parsers but are kept
deliberately simple (version 3 compound files, literal-only VBA compression).
Their output was cross-checked with olefile and pylnk3 when written.
"""

import struct
import uuid

SECTOR = 512
MINI = 64
END, FREE, FAT_SECTOR = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD


def ovba_compress_literal(data: bytes) -> bytes:
    """[MS-OVBA] compressed container that uses only literal tokens."""
    out = bytearray(b"\x01")
    for start in range(0, len(data), 4096):
        chunk = data[start : start + 4096]
        if len(chunk) == 4096:
            # Literal tokens would not fit in 4098 bytes; store it raw.
            out += struct.pack("<H", 0x3FFF) + chunk
            continue
        if len(chunk) > 3640:
            raise ValueError("final chunk too long for literal-only compression")
        body = bytearray()
        for group in range(0, len(chunk), 8):
            body.append(0)
            body += chunk[group : group + 8]
        out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3))
        out += body
    return bytes(out)


MODIFIED_FILETIME = 133_500_000_000_000_000  # 2024-01-21


def compound_file(streams: dict, root_clsid: str = "") -> bytes:
    """Build a version 3 compound file from {"a/b/c": bytes}."""
    tree = {"": {"children": {}, "data": None}}
    for path, data in streams.items():
        node = tree[""]
        parts = path.split("/")
        for part in parts[:-1]:
            node = node["children"].setdefault(part, {"children": {}, "data": None})
        node["children"][parts[-1]] = {"children": {}, "data": data}

    entries = []

    def add(name, node):
        index = len(entries)
        entries.append({"name": name, "node": node, "child": FREE, "right": FREE, "start": END, "size": 0})
        names = sorted(node["children"], key=lambda item: (len(item), item.upper()))
        previous = None
        for child_name in names:
            child_index = add(child_name, node["children"][child_name])
            if previous is None:
                entries[index]["child"] = child_index
            else:
                entries[previous]["right"] = child_index
            previous = child_index
        return index

    add("Root Entry", tree[""])

    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes) -> int:
        if not data:
            return END
        first = len(sectors)
        count = (len(data) + SECTOR - 1) // SECTOR
        for index in range(count):
            sectors.append(data[index * SECTOR : (index + 1) * SECTOR].ljust(SECTOR, b"\0"))
            fat.append(first + index + 1 if index < count - 1 else END)
        return first

    mini_stream = bytearray()
    mini_fat: list[int] = []
    for entry in entries[1:]:
        data = entry["node"]["data"]
        if data is None:
            continue
        entry["size"] = len(data)
        if len(data) < 4096:
            if not data:
                continue
            first = len(mini_stream) // MINI
            count = (len(data) + MINI - 1) // MINI
            mini_stream += data.ljust(count * MINI, b"\0")
            mini_fat.extend(first + index + 1 if index < count - 1 else END for index in range(count))
            entry["start"] = first
        else:
            entry["start"] = place(data)
    entries[0]["start"] = place(bytes(mini_stream))
    entries[0]["size"] = len(mini_stream)
    mini_fat_start = place(b"".join(struct.pack("<I", value) for value in mini_fat))

    directory = bytearray()
    for entry in entries:
        name = entry["name"].encode("utf-16-le") + b"\0\0"
        kind = 5 if entry is entries[0] else (2 if entry["node"]["data"] is not None else 1)
        clsid = uuid.UUID(root_clsid).bytes_le if (entry is entries[0] and root_clsid) else b"\0" * 16
        directory += name.ljust(64, b"\0") + struct.pack("<HBB", len(name), kind, 1)
        directory += struct.pack("<III", FREE, entry["right"], entry["child"]) + clsid
        directory += struct.pack("<IQQIQ", 0, 0, MODIFIED_FILETIME if kind == 2 else 0, entry["start"], entry["size"])
    directory_start = place(bytes(directory).ljust(((len(directory) + SECTOR - 1) // SECTOR) * SECTOR, b"\0"))

    fat_count = 1
    while (len(sectors) + fat_count) > fat_count * (SECTOR // 4):
        fat_count += 1
    fat_first = len(sectors)
    fat.extend([FAT_SECTOR] * fat_count)
    fat.extend([FREE] * (fat_count * (SECTOR // 4) - len(fat)))
    for index in range(fat_count):
        sectors.append(b"".join(struct.pack("<I", value) for value in fat[index * 128 : (index + 1) * 128]))

    header = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16)
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIIIIIIII", 0, fat_count, directory_start, 0, 4096, mini_fat_start if mini_fat else END, (len(mini_fat) * 4 + SECTOR - 1) // SECTOR, END, 0)
    difat = [fat_first + index for index in range(fat_count)] + [FREE] * (109 - fat_count)
    header += b"".join(struct.pack("<I", value) for value in difat)
    return bytes(header) + b"".join(sectors)


def vba_project(modules: dict, codepage: int = 1252) -> dict:
    """Streams for a VBA storage: {"VBA/dir": ..., "VBA/<module>": ...}."""
    def record(identifier: int, body: bytes) -> bytes:
        return struct.pack("<HI", identifier, len(body)) + body

    dir_stream = record(0x0001, struct.pack("<I", 1)) + record(0x0003, struct.pack("<H", codepage))
    dir_stream += struct.pack("<HI", 0x0009, 4) + struct.pack("<IH", 0x5A2D59B1, 6)  # PROJECTVERSION quirk
    dir_stream += record(0x000F, struct.pack("<H", len(modules)))
    streams = {}
    for name, source in modules.items():
        encoded = name.encode("cp1252")
        dir_stream += record(0x0019, encoded) + record(0x0047, name.encode("utf-16-le"))
        dir_stream += record(0x001A, encoded) + record(0x0032, name.encode("utf-16-le"))
        dir_stream += record(0x0031, struct.pack("<I", 16)) + record(0x0021, b"") + record(0x002B, b"")
        streams[f"VBA/{name}"] = b"\x01\x02" * 8 + ovba_compress_literal(source.encode("cp1252"))
    dir_stream += record(0x0010, b"")
    streams["VBA/dir"] = ovba_compress_literal(dir_stream)
    streams["VBA/_VBA_PROJECT"] = b"\xcc\x61\xff\xff\x00\x00\x00"
    streams["PROJECT"] = b'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
    return streams


def summary_information(properties: dict) -> bytes:
    """Property set stream with string (VT_LPSTR) and FILETIME values."""
    values = []
    for identifier, value in sorted(properties.items()):
        if isinstance(value, int) and value > 1 << 40:
            values.append((identifier, struct.pack("<IQ", 64, value)))
        elif isinstance(value, int):
            values.append((identifier, struct.pack("<Ii", 3, value)))
        else:
            raw = value.encode("cp1252") + b"\0"
            raw = struct.pack("<II", 30, len(raw)) + raw
            values.append((identifier, raw.ljust((len(raw) + 3) // 4 * 4, b"\0")))
    values.insert(0, (1, struct.pack("<Ih", 2, 1252) + b"\0\0"))
    table = bytearray()
    body = bytearray()
    offset = 8 + 8 * len(values)
    for identifier, raw in values:
        table += struct.pack("<II", identifier, offset + len(body))
        body += raw
    section = struct.pack("<II", 8 + len(table) + len(body), len(values)) + table + body
    header = struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\0" * 16 + struct.pack("<I", 1)
    header += uuid.UUID("f29f85e0-4ff9-1068-ab91-08002b27b3d9").bytes_le + struct.pack("<I", 48)
    return header + section


def msi_name(name: str, table: bool = True) -> str:
    """Encode a Windows Installer stream name (inverse of the parser)."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
    out = [chr(0x4840)] if table else []
    index = 0
    while index < len(name):
        first = alphabet.index(name[index])
        if index + 1 < len(name) and name[index + 1] in alphabet:
            out.append(chr(0x3800 + first + (alphabet.index(name[index + 1]) << 6)))
            index += 2
        else:
            out.append(chr(0x4800 + first))
            index += 1
    return "".join(out)


def shell_link(target: str, arguments: str, working_dir: str = "", machine: str = "ws-fixture", icon: str = "") -> bytes:
    """Unicode LNK with LinkInfo (local path), strings and a tracker block."""
    flags = 0x2 | 0x10 * bool(working_dir) | 0x20 | 0x40 * bool(icon) | 0x80
    header = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")
    header += struct.pack("<II", flags, 0x20)
    header += struct.pack("<QQQ", 133500000000000000, 133500000000000000, 133600000000000000)
    header += struct.pack("<IiIH", 4096, 0, 7, 0) + b"\0" * 10
    volume = struct.pack("<IIII", 0x10 + 6, 3, 0x1234ABCD, 0x10) + b"DATA\0\0"
    base_path = target.encode("cp1252") + b"\0"
    info_header = 0x1C
    volume_offset = info_header
    path_offset = volume_offset + len(volume)
    suffix_offset = path_offset + len(base_path)
    info_body = volume + base_path + b"\0"
    info = struct.pack("<IIIIIII", info_header + len(info_body), info_header, 1, volume_offset, path_offset, 0, suffix_offset) + info_body
    strings = b""
    for value in (working_dir, arguments, icon):
        if value:
            strings += struct.pack("<H", len(value)) + value.encode("utf-16-le")
    object_id = uuid.UUID(fields=(0x11223344, 0x5566, 0x11EE, 0x80, 0x01, 0x0050569A1B2C))
    tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine.encode("ascii").ljust(16, b"\0")
    tracker += uuid.uuid4().bytes_le + object_id.bytes_le + uuid.uuid4().bytes_le + object_id.bytes_le
    return header + info + strings + tracker + struct.pack("<I", 0)
