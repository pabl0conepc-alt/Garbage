"""ClamAV scan of an analysed file, when ClamAV is installed.

The running daemon (clamd) is preferred: the bytes go over its local socket
with the INSTREAM command and the signatures are already in memory. Without
a daemon, ``clamscan`` reads the bytes from standard input; it loads the
signature database on every call, so it is slower. Nothing is written to
disk and nothing leaves the machine.

``GARBAGE_CLAMD`` (a socket path or ``tcp://host:port`` on loopback) and
``GARBAGE_CLAMSCAN`` (a binary) override the defaults.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
import time
from typing import Any

SOCKETS = ("/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl", "/run/clamd.scan/clamd.sock", "/var/run/clamd.scan/clamd.sock", "tcp://127.0.0.1:3310")
DAEMON_TIMEOUT_SECONDS = 60
CLAMSCAN_TIMEOUT_SECONDS = 180
CHUNK = 64 * 1024
_ENGINE: dict[str, Any] = {}


def _connect(address: str, timeout: float) -> socket.socket:
    if address.startswith("tcp://"):
        host, _, port = address[6:].rpartition(":")
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise OSError("clamd must listen on this machine")
        return socket.create_connection((host, int(port)), timeout=timeout)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(address)
    return connection


def _ask(address: str, command: bytes, payload: bytes | None = None, timeout: float = DAEMON_TIMEOUT_SECONDS) -> str:
    with _connect(address, timeout) as connection:
        connection.sendall(b"z" + command + b"\0")
        if payload is not None:
            for start in range(0, len(payload), CHUNK):
                piece = payload[start:start + CHUNK]
                connection.sendall(struct.pack(">I", len(piece)) + piece)
            connection.sendall(struct.pack(">I", 0))
        reply = b""
        while not reply.endswith(b"\0"):
            part = connection.recv(4096)
            if not part:
                break
            reply += part
    return reply.rstrip(b"\0").decode("utf-8", "replace").strip()


def _daemon() -> str | None:
    candidates = [os.environ["GARBAGE_CLAMD"]] if os.environ.get("GARBAGE_CLAMD") else list(SOCKETS)
    for address in candidates:
        if not address.startswith("tcp://") and not os.path.exists(address):
            continue
        try:
            if _ask(address, b"PING", timeout=3) == "PONG":
                return address
        except (OSError, ValueError):
            continue
    return None


def engine(refresh: bool = False) -> dict[str, Any]:
    """Which ClamAV is available (checked again after five minutes)."""
    if _ENGINE and not refresh and time.monotonic() - _ENGINE["checked"] < 300:
        return _ENGINE["engine"]
    found: dict[str, Any] = {"available": False, "reason": "ClamAV não está instalado"}
    address = _daemon()
    if address:
        try:
            found = {"available": True, "mode": "clamd", "address": address, "version": _ask(address, b"VERSION", timeout=5)}
        except OSError:
            address = None
    if not address:
        binary = os.environ.get("GARBAGE_CLAMSCAN") or shutil.which("clamscan")
        if binary:
            try:
                version = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20, check=False).stdout.strip()
                found = {"available": True, "mode": "clamscan", "binary": binary, "version": version or "ClamAV"}
            except (OSError, subprocess.SubprocessError):
                found = {"available": False, "reason": "clamscan não respondeu"}
    _ENGINE.update(checked=time.monotonic(), engine=found)
    return found


def _verdict(line: str) -> tuple[str, str]:
    """("clean" | "infected" | "error", signature or error)."""
    text = line.strip()
    found = re.search(r":\s*(.+?)\s+FOUND$", text, re.MULTILINE)
    if found:
        return "infected", found.group(1)[:200]
    if re.search(r":\s*OK$", text, re.MULTILINE):
        return "clean", ""
    error = re.search(r":\s*(.+?)\s+ERROR$", text, re.MULTILINE)
    return "error", (error.group(1) if error else text)[:200]


def scan(data: bytes) -> dict[str, Any]:
    found = engine()
    if not found.get("available"):
        return {"status": "unavailable", "reason": found.get("reason", ""), "engine": "ClamAV"}
    started = time.monotonic()
    try:
        if found["mode"] == "clamd":
            status, detail = _verdict(_ask(found["address"], b"INSTREAM", data))
        else:
            done = subprocess.run(
                [found["binary"], "--no-summary", "--stdout", "-"],
                input=data, capture_output=True, timeout=CLAMSCAN_TIMEOUT_SECONDS, check=False,
            )
            output = done.stdout.decode("utf-8", "replace")
            status, detail = _verdict(output) if done.returncode in (0, 1) else ("error", (done.stderr.decode("utf-8", "replace") or output).strip()[:200])
    except (OSError, subprocess.SubprocessError) as exc:
        status, detail = "error", str(exc)[:200]
    return {
        "status": status,
        "signature": detail if status == "infected" else "",
        "error": detail if status == "error" else "",
        "engine": found.get("version", "ClamAV"),
        "mode": found["mode"],
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
