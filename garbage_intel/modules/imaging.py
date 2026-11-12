"""Minimal, read-only image structure inspection using the standard library.

Only structural facts are reported: detected container format and pixel
dimensions. No facial recognition, geolocation or authenticity claim is made.
"""

from __future__ import annotations

import hashlib


def _uint(data: bytes, start: int, length: int, byteorder: str) -> int:
    if start < 0 or start + length > len(data):
        raise ValueError("truncated image structure")
    return int.from_bytes(data[start : start + length], byteorder)


def _png(data: bytes) -> dict[str, object] | None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 24:
        return None
    if data[12:16] != b"IHDR":
        return None
    return {
        "format": "PNG",
        "media_type": "image/png",
        "width": _uint(data, 16, 4, "big"),
        "height": _uint(data, 20, 4, "big"),
    }


def _gif(data: bytes) -> dict[str, object] | None:
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return None
    if len(data) < 10:
        return None
    return {
        "format": "GIF",
        "media_type": "image/gif",
        "width": _uint(data, 6, 2, "little"),
        "height": _uint(data, 8, 2, "little"),
    }


def _bmp(data: bytes) -> dict[str, object] | None:
    if not data.startswith(b"BM") or len(data) < 26:
        return None
    width = _uint(data, 18, 4, "little", )
    height = _uint(data, 22, 4, "little")
    # Signed dimensions: a negative height indicates a top-down bitmap.
    if width > 0x7FFFFFFF:
        width -= 0x100000000
    if height > 0x7FFFFFFF:
        height -= 0x100000000
    return {
        "format": "BMP",
        "media_type": "image/bmp",
        "width": abs(width),
        "height": abs(height),
    }


def _jpeg(data: bytes) -> dict[str, object] | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if offset + 4 > len(data):
            return None
        segment_length = _uint(data, offset + 2, 2, "big")
        if segment_length < 2:
            return None
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:
            if offset + 9 > len(data):
                return None
            height = _uint(data, offset + 5, 2, "big")
            width = _uint(data, offset + 7, 2, "big")
            return {
                "format": "JPEG",
                "media_type": "image/jpeg",
                "width": width,
                "height": height,
            }
        offset += 2 + segment_length
    return None


def _webp(data: bytes) -> dict[str, object] | None:
    if len(data) < 30 or not data.startswith(b"RIFF") or data[8:12] != b"WEBP":
        return None
    chunk = data[12:16]
    if chunk == b"VP8X":
        width = _uint(data, 24, 3, "little") + 1
        height = _uint(data, 27, 3, "little") + 1
        return {
            "format": "WebP",
            "media_type": "image/webp",
            "width": width,
            "height": height,
        }
    if chunk == b"VP8L" and len(data) >= 25:
        bits = _uint(data, 21, 4, "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return {
            "format": "WebP",
            "media_type": "image/webp",
            "width": width,
            "height": height,
        }
    if chunk == b"VP8 " and len(data) >= 30:
        width = _uint(data, 26, 2, "little") & 0x3FFF
        height = _uint(data, 28, 2, "little") & 0x3FFF
        return {
            "format": "WebP",
            "media_type": "image/webp",
            "width": width,
            "height": height,
        }
    return None


def inspect_image(data: bytes) -> dict[str, object] | None:
    """Return structural image facts, or None when the bytes are not an image."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    for detector in (_png, _gif, _jpeg, _bmp, _webp):
        try:
            result = detector(bytes(data))
        except (ValueError, IndexError):
            result = None
        if result is not None:
            return result
    return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
