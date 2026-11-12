import struct
import unittest
import zlib

from garbage_intel.modules.imaging import inspect_image, sha256_hex


def png_bytes(width: int, height: int) -> bytes:
    raw = b"".join(b"\x00" + b"\x00" * (width * 3) for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class ImageInspectionTests(unittest.TestCase):
    def test_reads_png_dimensions_and_digest(self):
        data = png_bytes(7, 3)
        result = inspect_image(data)
        self.assertEqual(result["format"], "PNG")
        self.assertEqual(result["media_type"], "image/png")
        self.assertEqual(result["width"], 7)
        self.assertEqual(result["height"], 3)
        self.assertEqual(len(sha256_hex(data)), 64)

    def test_reads_gif_bmp_jpeg_and_webp_headers(self):
        gif = b"GIF89a" + struct.pack("<HH", 12, 34) + b"\x00\x00\x00"
        self.assertEqual(inspect_image(gif)["width"], 12)
        self.assertEqual(inspect_image(gif)["height"], 34)

        bmp = b"BM" + b"\x00" * 16 + struct.pack("<i", 40) + struct.pack("<i", -20)
        bmp += b"\x00" * 8
        self.assertEqual(inspect_image(bmp)["format"], "BMP")
        self.assertEqual(inspect_image(bmp)["width"], 40)
        self.assertEqual(inspect_image(bmp)["height"], 20)

        jpeg = b"\xff\xd8\xff\xc0\x00\x11\x08\x00\x10\x00\x20" + b"\x00" * 12
        self.assertEqual(inspect_image(jpeg)["format"], "JPEG")
        self.assertEqual(inspect_image(jpeg)["width"], 32)
        self.assertEqual(inspect_image(jpeg)["height"], 16)

        webp = bytearray(b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"VP8X")
        webp += b"\x00\x00\x00\x00"
        webp += b"\x00\x00\x00\x00"
        webp += (63).to_bytes(3, "little")
        webp += (31).to_bytes(3, "little")
        self.assertEqual(inspect_image(bytes(webp))["format"], "WebP")
        self.assertEqual(inspect_image(bytes(webp))["width"], 64)
        self.assertEqual(inspect_image(bytes(webp))["height"], 32)

    def test_rejects_non_images_and_truncated_structures(self):
        self.assertIsNone(inspect_image(b"not an image"))
        self.assertIsNone(inspect_image(b""))
        self.assertIsNone(inspect_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 4))
        self.assertIsNone(inspect_image(b"GIF89a\x01"))


if __name__ == "__main__":
    unittest.main()
