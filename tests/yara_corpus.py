"""Deterministic inputs for the YARA conformance test (see test_yara.py)."""

import hashlib
import struct


def noise(label, size):
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:size]


def corpus():
    pe = bytearray(2048)
    pe[0:4] = b"MZ\x90\x00"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    pe[200:238] = bytes(byte ^ 0x35 for byte in b"This program cannot be run in DOS mode")
    marks = bytearray(noise("marks", 3000))
    marks[10:14] = b"MARK"
    marks[110:114] = b"MARK"
    for offset in (301, 501, 700, 905, 1001):
        marks[offset : offset + 4] = b"AAAA"
    return {
        "pe.bin": bytes(pe) + b"powershell -enc AAA cmd /c run.cmd https://evil.example/path " + "invoice".encode("utf-16-le"),
        "text.txt": b"Run PowerShell now\nline1\nline2\x00 Invoice_2024 invoice_2025 and invoice; cmd.exe xcmd htxxtp://a jpreg jqeg ABC AXC BEGIN\nEND",
        "marks.bin": bytes(marks),
        "png.bin": b"\x89PNG\r\n\x1a\n" + noise("png", 100),
        "xorurl.bin": noise("x1", 50) + bytes(byte ^ 7 for byte in b"http://x.example") + noise("x2", 50),
        "tiny.bin": b"MZ",
        "zeros.bin": b"\x00" * 2000,
        "aaaa.bin": b"AAAAAAAAAA" + b"MARK" + b"x" * 1200,
    }
