"""Loopback-only HTTP API for the local evidence ledger."""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .store import (
    add_observation,
    build_report,
    build_timeline,
    create_investigation,
    list_investigations,
    set_investigation_status,
)
from .reporting import render_html_report
from .modules.cisa_kev import CisaKevError, list_cached, refresh_cisa_kev


MAX_BODY_BYTES = 1024 * 1024
_INVESTIGATION_ID = re.compile(r"[0-9a-fA-F-]{36}")
_WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def _read_web_asset(filename: str) -> bytes:
    executable = Path(sys.argv[0])
    if zipfile.is_zipfile(executable):
        with zipfile.ZipFile(executable) as archive:
            return archive.read(f"web/{filename}")
    return (_WEB_DIR / filename).read_bytes()


def create_server(database: str | Path, port: int = 8000) -> ThreadingHTTPServer:
    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "GARBAGE"
        sys_version = ""

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'",
            )
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, "application/json; charset=utf-8", body)

        def _error(self, status: int, message: str) -> None:
            self._json(status, {"error": message})

        def _allowed_local_request(self) -> bool:
            host_header = self.headers.get("Host", "")
            try:
                host = urlsplit(f"//{host_header}")
                if (
                    host.hostname not in {"127.0.0.1", "localhost"}
                    or host.port != self.server.server_port
                ):
                    return False
                origin_header = self.headers.get("Origin")
                if origin_header is None:
                    return True
                origin = urlsplit(origin_header)
                return (
                    origin.scheme == "http"
                    and origin.hostname == host.hostname
                    and origin.port == host.port
                )
            except ValueError:
                return False

        def _body(self) -> dict[str, object] | None:
            content_type = (
                self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            if content_type != "application/json":
                self._error(415, "Content-Type must be application/json")
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(400, "A valid Content-Length header is required")
                return None
            if length < 0:
                self._error(400, "Content-Length must not be negative")
                return None
            if length > MAX_BODY_BYTES:
                self._error(413, "Request body exceeds the 1 MiB limit")
                return None
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._error(400, "Request body is incomplete")
                return None
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._error(400, "Request body must be valid UTF-8 JSON")
                return None
            if not isinstance(payload, dict):
                self._error(400, "Request body must be a JSON object")
                return None
            return payload

        def _text(
            self, payload: dict[str, object], key: str, required: bool = True
        ) -> str | None:
            value = payload.get(key)
            if value is None and not required:
                return None
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a string")
            return value

        def _handle_value_error(self, error: ValueError) -> None:
            message = str(error)
            if message.startswith("investigation not found:"):
                status = 404
            elif message.startswith(
                ("investigation is closed", "investigation is cancelled")
            ):
                status = 409
            else:
                status = 400
            self._error(status, message)

        def do_GET(self) -> None:
            if not self._allowed_local_request():
                self._error(403, "Only loopback requests are allowed")
                return

            parsed_path = urlsplit(self.path)
            path = parsed_path.path
            if path == "/":
                self._static("index.html", "text/html; charset=utf-8")
                return
            if path == "/app.js":
                self._static("app.js", "text/javascript; charset=utf-8")
                return
            if path == "/style.css":
                self._static("style.css", "text/css; charset=utf-8")
                return
            if path == "/report.js":
                self._static("report.js", "text/javascript; charset=utf-8")
                return
            if path == "/api/health":
                self._json(200, {"status": "ok"})
                return
            if path == "/api/investigations":
                try:
                    self._json(200, list_investigations(database))
                except sqlite3.Error as exc:
                    self.log_error("Database operation failed: %s", exc)
                    self._error(500, "Database operation failed")
                return

            if path == "/api/intel/cisa-kev":
                query = parse_qs(parsed_path.query)
                try:
                    limit_value = query.get("limit", ["25"])[0]
                    try:
                        limit = int(limit_value)
                    except ValueError as exc:
                        raise ValueError("limit must be an integer") from exc
                    result = list_cached(
                        database,
                        search=query.get("search", [""])[0],
                        limit=limit,
                    )
                    self._json(200, result)
                except ValueError as exc:
                    status = 404 if "no CISA KEV cache" in str(exc) else 400
                    self._error(status, str(exc))
                return

            match = re.fullmatch(
                rf"/api/investigations/({_INVESTIGATION_ID.pattern})/timeline", path
            )
            if match:
                try:
                    self._json(200, build_timeline(database, match.group(1)))
                except ValueError as exc:
                    self._handle_value_error(exc)
                except sqlite3.Error as exc:
                    self.log_error("Database operation failed: %s", exc)
                    self._error(500, "Database operation failed")
                return

            match = re.fullmatch(
                rf"/api/investigations/({_INVESTIGATION_ID.pattern})/report", path
            )
            if match:
                try:
                    report = build_report(database, match.group(1))
                    self._json(200, report)
                except ValueError as exc:
                    self._handle_value_error(exc)
                except sqlite3.Error as exc:
                    self.log_error("Database operation failed: %s", exc)
                    self._error(500, "Database operation failed")
                return

            match = re.fullmatch(
                rf"/reports/({_INVESTIGATION_ID.pattern})", path
            )
            if match:
                try:
                    report = build_report(database, match.group(1))
                    self._send(
                        200,
                        "text/html; charset=utf-8",
                        render_html_report(report).encode("utf-8"),
                    )
                except ValueError as exc:
                    self._handle_value_error(exc)
                except sqlite3.Error as exc:
                    self.log_error("Database operation failed: %s", exc)
                    self._error(500, "Database operation failed")
                return
            self._error(404, "Not found")

        def do_POST(self) -> None:
            if not self._allowed_local_request():
                self._error(403, "Only same-origin loopback requests are allowed")
                return
            payload = self._body()
            if payload is None:
                return

            path = urlsplit(self.path).path
            try:
                if path == "/api/intel/cisa-kev/refresh":
                    force = payload.get("force", False)
                    if not isinstance(force, bool):
                        raise ValueError("force must be a boolean")
                    try:
                        result = refresh_cisa_kev(database, force=force)
                    except CisaKevError as exc:
                        status = (
                            429
                            if str(exc).startswith(
                                "CISA KEV refresh was rate-limited"
                            )
                            else 502
                        )
                        self._error(status, str(exc))
                        return
                    self._json(200, result)
                    return

                if path == "/api/investigations":
                    name = self._text(payload, "name")
                    description = self._text(payload, "description", required=False)
                    result = create_investigation(
                        database, name or "", description or ""
                    )
                    self._json(201, result)
                    return

                match = re.fullmatch(
                    rf"/api/investigations/({_INVESTIGATION_ID.pattern})/observations",
                    path,
                )
                if match:
                    observed_at = self._text(payload, "observed_at", required=False)
                    result = add_observation(
                        database,
                        match.group(1),
                        self._text(payload, "title") or "",
                        self._text(payload, "content") or "",
                        self._text(payload, "source_reference") or "",
                        self._text(payload, "collection_basis") or "",
                        observed_at,
                    )
                    self._json(201, result)
                    return
                self._error(404, "Not found")
            except ValueError as exc:
                self._handle_value_error(exc)
            except sqlite3.Error as exc:
                self.log_error("Database operation failed: %s", exc)
                self._error(500, "Database operation failed")

        def do_PATCH(self) -> None:
            if not self._allowed_local_request():
                self._error(403, "Only same-origin loopback requests are allowed")
                return
            payload = self._body()
            if payload is None:
                return
            match = re.fullmatch(
                rf"/api/investigations/({_INVESTIGATION_ID.pattern})",
                urlsplit(self.path).path,
            )
            if not match:
                self._error(404, "Not found")
                return
            try:
                result = set_investigation_status(
                    database,
                    match.group(1),
                    self._text(payload, "status") or "",
                )
                self._json(200, result)
            except ValueError as exc:
                self._handle_value_error(exc)
            except sqlite3.Error as exc:
                self.log_error("Database operation failed: %s", exc)
                self._error(500, "Database operation failed")

        def _static(self, filename: str, content_type: str) -> None:
            try:
                body = _read_web_asset(filename)
            except (OSError, KeyError, zipfile.BadZipFile):
                self._error(500, "Web interface asset is unavailable")
                return
            self._send(200, content_type, body)

        def log_message(self, format: str, *args: object) -> None:
            print(f"garbage-api: {format % args}", file=sys.stderr)

    server = ThreadingHTTPServer(("127.0.0.1", port), RequestHandler)
    server.daemon_threads = True
    return server


def serve(database: str | Path, port: int = 8000) -> None:
    server = create_server(database, port)
    print(f"GARBAGE local interface: http://127.0.0.1:{server.server_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
