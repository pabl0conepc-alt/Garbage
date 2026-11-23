"""Bounded EXIF reader for JPEG photos: camera, timestamps and GPS position.

Only the APP1 ``Exif`` segment is parsed, with every offset checked against
the segment; nothing is decoded beyond the IFD0, Exif and GPS directories.
"""

from __future__ import annotations

from typing import Any

MAX_ENTRIES = 256
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

_IFD0_TAGS = {
    0x010F: "make",
    0x0110: "model",
    0x0112: "orientation",
    0x0131: "software",
    0x0132: "modified_at",
    0x013B: "artist",
    0x8298: "copyright",
}
_EXIF_TAGS = {
    0x9003: "taken_at",
    0x9004: "digitized_at",
    0x9010: "offset_time",
    0x9011: "offset_time_original",
    0xA420: "image_unique_id",
    0xA430: "camera_owner",
    0xA431: "body_serial",
    0xA433: "lens_make",
    0xA434: "lens_model",
    0xA435: "lens_serial",
}
_EXIF_POINTER = 0x8769
_GPS_POINTER = 0x8825


class _Reader:
    def __init__(self, tiff: bytes) -> None:
        if tiff[:2] == b"II":
            self.order = "little"
        elif tiff[:2] == b"MM":
            self.order = "big"
        else:
            raise ValueError("not a TIFF header")
        self.data = tiff
        if self.uint(2, 2) != 42:
            raise ValueError("bad TIFF magic")

    def uint(self, offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(self.data):
            raise ValueError("offset outside EXIF segment")
        return int.from_bytes(self.data[offset : offset + size], self.order)

    def sint(self, offset: int, size: int) -> int:
        value = self.uint(offset, size)
        return value - (1 << (8 * size)) if value >= 1 << (8 * size - 1) else value

    def directory(self, offset: int) -> dict[int, Any]:
        entries: dict[int, Any] = {}
        count = min(self.uint(offset, 2), MAX_ENTRIES)
        for index in range(count):
            entry = offset + 2 + index * 12
            tag, kind, number = self.uint(entry, 2), self.uint(entry + 2, 2), self.uint(entry + 4, 4)
            size = _TYPE_SIZES.get(kind)
            if size is None or number > 4096:
                continue
            location = entry + 8 if size * number <= 4 else self.uint(entry + 8, 4)
            try:
                entries[tag] = self.value(kind, number, location)
            except ValueError:
                continue
        return entries

    def value(self, kind: int, number: int, location: int) -> Any:
        if kind == 2:
            raw = self.data[location : location + number]
            if len(raw) < number:
                raise ValueError("string outside segment")
            return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
        if kind in (5, 10):
            values = []
            for index in range(number):
                read = self.sint if kind == 10 else self.uint
                numerator, denominator = read(location + index * 8, 4), read(location + index * 8 + 4, 4)
                values.append(numerator / denominator if denominator else 0.0)
            return values
        size = _TYPE_SIZES[kind]
        values = [self.uint(location + index * size, size) for index in range(number)]
        return values[0] if number == 1 else values


def _exif_segment(data: bytes) -> bytes | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    offset = 2
    while offset + 4 <= len(data) and data[offset] == 0xFF:
        marker = data[offset + 1]
        if marker == 0xDA:  # start of scan: no metadata follows
            return None
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if length < 2:
            return None
        body = data[offset + 4 : offset + 2 + length]
        if marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            return body[6:]
        offset += 2 + length
    return None


def _degrees(parts: Any, reference: Any, negative: str) -> float | None:
    if not isinstance(parts, list) or len(parts) != 3:
        return None
    value = parts[0] + parts[1] / 60 + parts[2] / 3600
    return round(-value if str(reference).upper() == negative else value, 7)


def read_exif(data: bytes) -> dict[str, Any] | None:
    """Return camera, time and GPS facts from a JPEG, or ``None`` without EXIF."""
    segment = _exif_segment(data)
    if not segment:
        return None
    try:
        reader = _Reader(segment)
        ifd0 = reader.directory(reader.uint(4, 4))
    except ValueError:
        return None
    result: dict[str, Any] = {}
    for tag, name in _IFD0_TAGS.items():
        if ifd0.get(tag) not in (None, ""):
            result[name] = ifd0[tag]
    try:
        if isinstance(ifd0.get(_EXIF_POINTER), int):
            exif = reader.directory(ifd0[_EXIF_POINTER])
            for tag, name in _EXIF_TAGS.items():
                if exif.get(tag) not in (None, ""):
                    result[name] = exif[tag]
        if isinstance(ifd0.get(_GPS_POINTER), int):
            gps = reader.directory(ifd0[_GPS_POINTER])
            latitude = _degrees(gps.get(2), gps.get(1), "S")
            longitude = _degrees(gps.get(4), gps.get(3), "W")
            if latitude is not None and longitude is not None and -90 <= latitude <= 90 and -180 <= longitude <= 180:
                position: dict[str, Any] = {
                    "latitude": latitude,
                    "longitude": longitude,
                    "map_url": f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}#map=17/{latitude}/{longitude}",
                }
                altitude = gps.get(6)
                if isinstance(altitude, list) and altitude:
                    position["altitude_m"] = round(-altitude[0] if gps.get(5) == 1 else altitude[0], 1)
                stamp = gps.get(7)
                if isinstance(stamp, list) and len(stamp) == 3 and gps.get(29):
                    position["utc"] = f"{gps[29]} {int(stamp[0]):02d}:{int(stamp[1]):02d}:{int(stamp[2]):02d}"
                result["gps"] = position
    except ValueError:
        pass
    return result or None
