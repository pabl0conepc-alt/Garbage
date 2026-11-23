"""EXIF metadata from analyst-supplied images: camera, software, capture
time, orientation and GPS position.

Reads the TIFF structure embedded in JPEG (APP1 ``Exif``), PNG (``eXIf``),
WebP (``EXIF`` chunk) and bare TIFF files. Every offset is bounds-checked and
IFD loops are capped, so a hostile file can only produce an empty result.
GPS values are what the device wrote: they can be absent, coarse, stale or
edited, and the result says so.
"""

from __future__ import annotations

import struct
from typing import Any

MAX_ENTRIES = 512
MAX_IFDS = 8

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
_IFD0_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software", 0x0132: "modified_at", 0x0112: "orientation", 0x013B: "artist_present"}
_EXIF_TAGS = {0x9003: "captured_at", 0x9011: "offset_time", 0xA431: "body_serial_present", 0xA434: "lens_model"}
_EXIF_POINTER = 0x8769
_GPS_POINTER = 0x8825


class _Tiff:
    def __init__(self, data: bytes) -> None:
        if data[:2] == b"II":
            self.order = "<"
        elif data[:2] == b"MM":
            self.order = ">"
        else:
            raise ValueError("not a TIFF header")
        if struct.unpack(self.order + "H", data[2:4])[0] != 42:
            raise ValueError("bad TIFF magic")
        self.data = data

    def u16(self, offset: int) -> int:
        return struct.unpack_from(self.order + "H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from(self.order + "I", self.data, offset)[0]

    def entries(self, offset: int) -> dict[int, Any]:
        if offset <= 0 or offset + 2 > len(self.data):
            return {}
        count = min(self.u16(offset), MAX_ENTRIES)
        values: dict[int, Any] = {}
        for index in range(count):
            entry = offset + 2 + index * 12
            if entry + 12 > len(self.data):
                break
            tag, kind, number = self.u16(entry), self.u16(entry + 2), self.u32(entry + 4)
            size = _TYPE_SIZES.get(kind)
            if size is None or number > 4096:
                continue
            total = size * number
            start = entry + 8 if total <= 4 else self.u32(entry + 8)
            if start + total > len(self.data):
                continue
            values[tag] = self._value(kind, number, start)
        return values

    def _value(self, kind: int, number: int, start: int) -> Any:
        data = self.data
        if kind == 2:
            return data[start:start + number].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if kind in (1, 7):
            return list(data[start:start + number])
        if kind == 3:
            return [self.u16(start + 2 * index) for index in range(number)]
        if kind in (4, 9):
            return [self.u32(start + 4 * index) for index in range(number)]
        rationals = []
        for index in range(number):
            numerator, denominator = struct.unpack_from(self.order + ("ii" if kind == 10 else "II"), data, start + 8 * index)
            rationals.append(numerator / denominator if denominator else None)
        return rationals


def _tiff_block(data: bytes) -> bytes | None:
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 4 <= len(data):
            if data[offset] != 0xFF:
                return None
            marker = data[offset + 1]
            if marker in (0xD9, 0xDA):
                return None
            length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
            if length < 2:
                return None
            segment = data[offset + 4:offset + 2 + length]
            if marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
                return segment[6:]
            offset += 2 + length
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        offset = 8
        while offset + 12 <= len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            kind = data[offset + 4:offset + 8]
            if kind == b"eXIf":
                return data[offset + 8:offset + 8 + length]
            if kind == b"IEND":
                return None
            offset += 12 + length
        return None
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        offset = 12
        while offset + 8 <= len(data):
            kind = data[offset:offset + 4]
            length = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            if kind == b"EXIF":
                block = data[offset + 8:offset + 8 + length]
                return block[6:] if block.startswith(b"Exif\x00\x00") else block
            offset += 8 + length + (length & 1)
        return None
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return data
    return None


def _degrees(values: Any, reference: Any) -> float | None:
    if not isinstance(values, list) or len(values) < 3 or any(value is None for value in values[:3]):
        return None
    degrees = values[0] + values[1] / 60 + values[2] / 3600
    if isinstance(reference, str) and reference.upper() in ("S", "W"):
        degrees = -degrees
    return round(degrees, 7)


def _gps(tiff: _Tiff, offset: int) -> dict[str, Any] | None:
    tags = tiff.entries(offset)
    latitude = _degrees(tags.get(2), tags.get(1))
    longitude = _degrees(tags.get(4), tags.get(3))
    if latitude is None or longitude is None:
        return None
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180) or (latitude == 0 and longitude == 0):
        return {"valid": False, "reason": "coordinates out of range or zero"}
    result: dict[str, Any] = {"valid": True, "latitude": latitude, "longitude": longitude}
    altitude = tags.get(6)
    if isinstance(altitude, list) and altitude and altitude[0] is not None:
        below = tags.get(5) == [1]
        result["altitude_m"] = round(-altitude[0] if below else altitude[0], 1)
    stamp, date = tags.get(7), tags.get(29)
    if isinstance(stamp, list) and len(stamp) == 3 and None not in stamp and isinstance(date, str):
        result["gps_time_utc"] = f"{date.replace(':', '-')}T{int(stamp[0]):02d}:{int(stamp[1]):02d}:{int(stamp[2]):02d}Z"
    error = tags.get(31)
    if isinstance(error, list) and error and error[0] is not None:
        result["horizontal_error_m"] = round(error[0], 1)
    if isinstance(tags.get(18), str) and tags[18]:
        result["datum"] = tags[18][:20]
    return result


def parse_exif(data: bytes) -> dict[str, Any] | None:
    """EXIF summary of an image, or None when it carries no EXIF block."""
    block = _tiff_block(data)
    if not block:
        return None
    try:
        tiff = _Tiff(block)
        ifd0_offset = tiff.u32(4)
        ifd0 = tiff.entries(ifd0_offset)
    except (ValueError, struct.error):
        return None
    result: dict[str, Any] = {}
    for tag, name in _IFD0_TAGS.items():
        if tag in ifd0:
            value = ifd0[tag]
            if name == "orientation":
                value = value[0] if isinstance(value, list) and value else None
            elif name == "artist_present":
                value = bool(value)
            if value not in (None, "", []):
                result[name] = value[:120] if isinstance(value, str) else value
    try:
        pointer = ifd0.get(_EXIF_POINTER)
        if isinstance(pointer, list) and pointer:
            exif = tiff.entries(pointer[0])
            for tag, name in _EXIF_TAGS.items():
                if tag in exif and exif[tag] not in (None, "", []):
                    value = exif[tag]
                    result[name] = bool(value) if name.endswith("_present") else (value[:120] if isinstance(value, str) else value)
        gps_pointer = ifd0.get(_GPS_POINTER)
        if isinstance(gps_pointer, list) and gps_pointer:
            gps = _gps(tiff, gps_pointer[0])
            if gps:
                result["gps"] = gps
    except struct.error:
        pass
    return result or None
