"""Loopback-only HTTP API and web interface for the GARBAGE workspace."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .boards import get_board, save_board
from .db import _connection, module_enabled, require_module
from .entities import (
    create_entity,
    create_relationship,
    delete_entity,
    delete_relationship,
    get_entity,
    graph_path,
    graph_payload,
    link_entity_to_investigation,
    list_entities,
    list_relationships,
    relationship_types,
    unlink_entity_from_investigation,
    update_entity,
    update_relationship,
)
from .errors import (
    AppError,
    ConflictError,
    ModuleDisabledError,
    NotFoundError,
    ValidationError,
)
from .evidence import (
    MAX_EVIDENCE_BODY_BYTES,
    MAX_EVIDENCE_BYTES,
    add_evidence,
    delete_evidence,
    get_evidence,
    list_evidence,
    read_evidence_file,
    verify_evidence,
)
from .analytics import workspace_analytics
from .intel_keys import delete_key, list_keys, set_key
from .intel import (
    detect_artifact,
    get_run,
    list_connectors,
    list_runs,
    promote_results,
    record_run_observation,
    run_query,
)
from .modules.cisa_kev import CisaKevError, list_cached, refresh_cisa_kev
from .modules.file_intel import (
    MAX_FILE_BYTES,
    analyze_file,
    get_file_analysis,
    list_file_analyses,
    similar_file_analyses,
)
from .modules.yara_rules import (
    check_source,
    create_ruleset,
    delete_ruleset,
    get_ruleset,
    list_rulesets,
    test_source,
    update_ruleset,
)
from .reporting import (
    render_csv_report,
    render_html_report,
    render_markdown_report,
)
from .sources import (
    create_source,
    delete_source,
    get_source,
    link_source_to_entity,
    link_source_to_investigation,
    list_sources,
    unlink_source_from_entity,
    unlink_source_from_investigation,
    update_source,
)
from .store import (
    add_observation,
    build_report,
    build_timeline,
    create_investigation,
    delete_investigation,
    get_investigation,
    list_investigations,
    set_investigation_status,
    update_investigation,
)
from .workspace import (
    case_coverage,
    get_settings,
    global_search,
    inspect_local_indicator,
    list_activities,
    list_modules,
    overview,
    set_indicator_assessment,
    set_module_state,
    system_info,
    triage_indicators,
    unified_indicators,
    update_settings,
)


MAX_BODY_BYTES = 1024 * 1024
MAX_FILE_BODY_BYTES = 6 * 1024 * 1024
_ID_PATTERN = r"([0-9a-fA-F-]{36})"
_WEB_DIR = Path(__file__).resolve().parent.parent / "web"
_STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "views.js": "text/javascript; charset=utf-8",
    "views-intel.js": "text/javascript; charset=utf-8",
    "views-system.js": "text/javascript; charset=utf-8",
    "views-file.js": "text/javascript; charset=utf-8",
    "views-multisearch.js": "text/javascript; charset=utf-8",
    "views-yara.js": "text/javascript; charset=utf-8",
    "charts.js": "text/javascript; charset=utf-8",
    "views-analytics.js": "text/javascript; charset=utf-8",
    "board.js": "text/javascript; charset=utf-8",
    "graph.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
    "favicon.png": "image/png",
    "logo-mark.png": "image/png",
    "logo-line.png": "image/png",
    "report.js": "text/javascript; charset=utf-8",
}


def _read_web_asset(filename: str) -> bytes:
    executable = Path(sys.argv[0])
    if zipfile.is_zipfile(executable):
        with zipfile.ZipFile(executable) as archive:
            return archive.read(f"web/{filename}")
    return (_WEB_DIR / filename).read_bytes()


def _query_text(
    query: dict[str, list[str]], key: str, default: str = ""
) -> str:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def _query_int(
    query: dict[str, list[str]], key: str, default: int
) -> int:
    raw = _query_text(query, key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValidationError(f"{key} must be an integer") from exc


def _query_bool(query: dict[str, list[str]], key: str) -> bool:
    return _query_text(query, key, "").strip().lower() in {"true", "1", "yes"}


def _attachment_disposition(filename: str, *, inline: bool = False) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", filename).strip("-") or "garbage-export"
    mode = "inline" if inline else "attachment"
    return f'{mode}; filename="{safe}"'


def _report_filename(investigation_name: str, suffix: str) -> str:
    slug = (
        re.sub(r"[^A-Za-z0-9._-]+", "-", investigation_name).strip("-")[:60]
        or "investigation"
    )
    return f"{slug}-report.{suffix}"


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "GARBAGE"
    sys_version = ""

    def _send(
        self,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        for header, value in (extra_headers or {}).items():
            self.send_header(header, value)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def _error(self, status: int, message: str, code: str = "ERROR") -> None:
        self._json(status, {"error": message, "code": code})

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

    def _body(self, limit: int = MAX_BODY_BYTES) -> dict[str, object] | None:
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
        if length > limit:
            self._error(
                413,
                f"Request body exceeds the {limit // (1024 * 1024)} MiB limit",
            )
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
            raise ValidationError(f"{key} must be a string")
        return value

    def _module(self, module_id: str) -> None:
        with _connection(self.database_path) as connection:
            require_module(connection, module_id)

    def _module_enabled(self, module_id: str) -> bool:
        with _connection(self.database_path) as connection:
            return module_enabled(connection, module_id)

    def _handle_app_error(self, error: AppError) -> None:
        self._error(error.status, str(error), error.code)

    def _handle_value_error(self, error: ValueError) -> None:
        message = str(error)
        if message.startswith("investigation not found:"):
            self._error(404, message)
        elif message.startswith("no CISA KEV cache"):
            self._error(404, message)
        elif isinstance(error, CisaKevError):
            self._error(400, message)
        else:
            self._error(400, message)

    def _dispatch(self, method: str) -> None:
        if not self._allowed_local_request():
            self._error(403, "Only same-origin loopback requests are allowed")
            return
        parsed = urlsplit(self.path)
        if method == "GET":
            filename = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
            if filename in _STATIC_FILES:
                self._static(filename, _STATIC_FILES[filename])
                return
        for route_method, pattern, handler_name, limit in ROUTES:
            if route_method != method:
                continue
            match = pattern.fullmatch(parsed.path)
            if match is None:
                continue
            query = parse_qs(parsed.query)
            payload: dict[str, object] | None = None
            if method in {"POST", "PATCH", "PUT"}:
                payload = self._body(limit)
                if payload is None:
                    return
            try:
                getattr(self, handler_name)(match, query, payload)
            except ModuleDisabledError as error:
                self._handle_app_error(error)
            except AppError as error:
                self._handle_app_error(error)
            except ValueError as error:
                self._handle_value_error(error)
            except sqlite3.Error as error:
                self.log_error("Database operation failed: %s", error)
                self._error(500, "Database operation failed")
            return
        self._error(404, "Not found")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _static(self, filename: str, content_type: str) -> None:
        try:
            body = _read_web_asset(filename)
        except (OSError, KeyError, zipfile.BadZipFile):
            self._error(500, "Web interface asset is unavailable")
            return
        self._send(200, content_type, body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"garbage-api: {format % args}", file=sys.stderr)

    # --- health and workspace ------------------------------------------------

    def api_health(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._json(200, {"status": "ok", "version": __version__})

    def api_overview(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._json(200, overview(self.database_path))

    def api_system(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("settings")
        self._json(200, system_info(self.database_path))

    def api_search(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("global-search")
        raw_limit = _query_text(query, "limit", "").strip()
        limit: int | None = None
        if raw_limit:
            try:
                limit = int(raw_limit)
            except ValueError as exc:
                raise ValidationError("limit must be an integer") from exc
        self._json(
            200,
            global_search(
                self.database_path, _query_text(query, "q", ""), limit
            ),
        )

    def api_activities(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("activity-log")
        self._json(
            200,
            list_activities(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                limit=_query_int(query, "limit", 50),
                offset=_query_int(query, "offset", 0),
            ),
        )

    # --- investigations ------------------------------------------------------

    def api_investigations_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigations")
        self._json(200, list_investigations(self.database_path))

    def api_investigations_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("investigations")
        result = create_investigation(
            self.database_path,
            self._text(payload, "name") or "",
            self._text(payload, "description", required=False) or "",
        )
        self._json(201, result)

    def api_investigation_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigations")
        self._json(200, get_investigation(self.database_path, match.group(1)))

    def api_investigation_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("investigations")
        allowed = {"name", "description", "status"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported investigation fields: {', '.join(sorted(unknown))}"
            )
        if not payload:
            raise ValidationError("no investigation fields were provided")
        fields: dict[str, object] = {}
        if "name" in payload:
            fields["name"] = self._text(payload, "name") or ""
        if "description" in payload:
            fields["description"] = self._text(
                payload, "description", required=False
            ) or ""
        if "status" in payload:
            fields["status"] = self._text(payload, "status") or ""
        result = update_investigation(
            self.database_path, match.group(1), **fields
        )
        self._json(200, result)

    def api_investigation_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigations")
        self._json(
            200,
            delete_investigation(
                self.database_path,
                match.group(1),
                force=_query_bool(query, "force"),
            ),
        )

    def api_investigation_report(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("report-center")
        self._json(200, build_report(self.database_path, match.group(1)))

    def api_investigation_timeline(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigations")
        self._json(200, build_timeline(self.database_path, match.group(1)))

    def api_investigation_export(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("report-center")
        report = build_report(self.database_path, match.group(1))
        file_format = _query_text(query, "format", "html").strip().lower()
        if file_format == "json":
            body = json.dumps(report, ensure_ascii=False, indent=2)
            content_type = "application/json; charset=utf-8"
            suffix = "json"
        elif file_format == "csv":
            body = render_csv_report(report)
            content_type = "text/csv; charset=utf-8"
            suffix = "csv"
        elif file_format == "markdown":
            body = render_markdown_report(report)
            content_type = "text/markdown; charset=utf-8"
            suffix = "md"
        elif file_format == "html":
            body = render_html_report(report)
            content_type = "text/html; charset=utf-8"
            suffix = "html"
        else:
            raise ValidationError(
                "format must be one of: json, html, csv, markdown"
            )
        self._send(
            200,
            content_type,
            body.encode("utf-8"),
            {
                "Content-Disposition": _attachment_disposition(
                    _report_filename(report["investigation"]["name"], suffix)
                )
            },
        )

    def api_investigation_observations(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("investigations")
        observed_at = self._text(payload, "observed_at", required=False)
        result = add_observation(
            self.database_path,
            match.group(1),
            self._text(payload, "title") or "",
            self._text(payload, "content") or "",
            self._text(payload, "source_reference") or "",
            self._text(payload, "collection_basis") or "",
            observed_at,
        )
        self._json(201, result)

    # --- boards and graph ----------------------------------------------------

    def api_board_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigation-board")
        self._json(200, get_board(self.database_path, match.group(1)))

    def api_board_put(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("investigation-board")
        self._json(
            200, save_board(self.database_path, match.group(1), payload)
        )

    def api_graph(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationship-graph")
        self._json(
            200,
            graph_payload(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                entity_type=_query_text(query, "entity_type", "") or None,
                search=_query_text(query, "search", ""),
            ),
        )

    def api_graph_path(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationship-graph")
        start = _query_text(query, "from", "")
        goal = _query_text(query, "to", "")
        if not start or not goal:
            raise ValidationError("from and to are required")
        self._json(
            200,
            graph_path(
                self.database_path,
                start_id=start,
                goal_id=goal,
                investigation_id=_query_text(query, "investigation_id", "") or None,
            ),
        )

    def api_investigation_graph(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationship-graph")
        self._json(
            200,
            graph_payload(
                self.database_path,
                investigation_id=match.group(1),
                entity_type=_query_text(query, "entity_type", "") or None,
                search=_query_text(query, "search", ""),
            ),
        )

    # --- entities and relationships -----------------------------------------

    def api_entities_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("entities")
        self._json(
            200,
            list_entities(
                self.database_path,
                entity_type=_query_text(query, "entity_type", "") or None,
                search=_query_text(query, "search", ""),
                investigation_id=_query_text(query, "investigation_id", "") or None,
                limit=_query_int(query, "limit", 50),
                offset=_query_int(query, "offset", 0),
            ),
        )

    def api_entity_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("entities")
        allowed = {
            "entity_type",
            "name",
            "identifier",
            "description",
            "source_reference",
            "collection_basis",
            "confidence",
            "verification_status",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported entity fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            201,
            create_entity(
                self.database_path,
                entity_type=payload.get("entity_type"),
                name=payload.get("name", ""),
                identifier=payload.get("identifier", ""),
                description=payload.get("description", ""),
                source_reference=payload.get("source_reference", ""),
                collection_basis=payload.get("collection_basis", "user-provided"),
                confidence=payload.get("confidence", "unconfirmed"),
                verification_status=payload.get("verification_status", "not-verified"),
            ),
        )

    def api_entity_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("entities")
        self._json(200, get_entity(self.database_path, match.group(1)))

    def api_entity_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("entities")
        self._json(
            200, update_entity(self.database_path, match.group(1), payload)
        )

    def api_entity_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("entities")
        self._json(
            200,
            delete_entity(
                self.database_path, match.group(1), force=_query_bool(query, "force")
            ),
        )

    def api_relationships_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationships")
        self._json(
            200,
            {
                "items": list_relationships(
                    self.database_path,
                    investigation_id=_query_text(query, "investigation_id", "") or None,
                    entity_id=_query_text(query, "entity_id", "") or None,
                    relationship_type=_query_text(query, "type", "") or None,
                    limit=_query_int(query, "limit", 200),
                ),
                "types": relationship_types(),
            },
        )

    def api_relationship_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("relationships")
        allowed = {
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            "description",
            "source_reference",
            "confidence",
            "verification_status",
            "investigation_id",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported relationship fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            201,
            create_relationship(
                self.database_path,
                source_entity_id=payload.get("source_entity_id"),
                target_entity_id=payload.get("target_entity_id"),
                relationship_type=payload.get("relationship_type"),
                description=payload.get("description", ""),
                source_reference=payload.get("source_reference", ""),
                confidence=payload.get("confidence", "unconfirmed"),
                verification_status=payload.get("verification_status", "not-verified"),
                investigation_id=payload.get("investigation_id"),
            ),
        )

    def api_relationship_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("relationships")
        self._json(
            200,
            update_relationship(self.database_path, match.group(1), payload),
        )

    def api_relationship_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationships")
        self._json(
            200, delete_relationship(self.database_path, match.group(1))
        )

    def api_relationship_types(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("relationships")
        self._json(200, {"types": relationship_types()})

    def api_investigation_entity_link(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("entities")
        self._json(
            200,
            link_entity_to_investigation(
                self.database_path,
                match.group(1),
                self._text(payload, "entity_id") or "",
            ),
        )

    def api_investigation_entity_unlink(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("entities")
        self._json(
            200,
            unlink_entity_from_investigation(
                self.database_path, match.group(1), match.group(2)
            ),
        )

    def api_entity_source_link(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("source-manager")
        self._json(
            200,
            link_source_to_entity(
                self.database_path,
                match.group(1),
                self._text(payload, "source_id") or "",
            ),
        )

    def api_entity_source_unlink(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("source-manager")
        self._json(
            200,
            unlink_source_from_entity(
                self.database_path, match.group(1), match.group(2)
            ),
        )

    # --- sources -------------------------------------------------------------

    def api_sources_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("source-manager")
        self._json(
            200,
            list_sources(
                self.database_path,
                search=_query_text(query, "search", ""),
                category=_query_text(query, "category", "") or None,
                limit=_query_int(query, "limit", 50),
                offset=_query_int(query, "offset", 0),
            ),
        )

    def api_source_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("source-manager")
        allowed = {
            "title",
            "reference",
            "category",
            "description",
            "accessed_at",
            "verification_status",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported source fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            201,
            create_source(
                self.database_path,
                title=payload.get("title"),
                reference=payload.get("reference", ""),
                category=payload.get("category", "other"),
                description=payload.get("description", ""),
                accessed_at=payload.get("accessed_at"),
                verification_status=payload.get("verification_status", "not-verified"),
            ),
        )

    def api_source_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("source-manager")
        self._json(200, get_source(self.database_path, match.group(1)))

    def api_source_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("source-manager")
        self._json(
            200, update_source(self.database_path, match.group(1), payload)
        )

    def api_source_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("source-manager")
        self._json(200, delete_source(self.database_path, match.group(1)))

    def api_investigation_source_link(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("source-manager")
        self._json(
            200,
            link_source_to_investigation(
                self.database_path,
                match.group(1),
                self._text(payload, "source_id") or "",
            ),
        )

    def api_investigation_source_unlink(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("source-manager")
        self._json(
            200,
            unlink_source_from_investigation(
                self.database_path, match.group(1), match.group(2)
            ),
        )

    # --- evidence ------------------------------------------------------------

    def api_evidence_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        self._json(
            200,
            list_evidence(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                evidence_type=_query_text(query, "evidence_type", "") or None,
                search=_query_text(query, "search", ""),
                limit=_query_int(query, "limit", 50),
                offset=_query_int(query, "offset", 0),
            ),
        )

    def api_investigation_evidence_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("evidence")
        allowed = {
            "title",
            "evidence_type",
            "description",
            "source_reference",
            "original_name",
            "content_base64",
            "sha256",
            "acquired_at",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported evidence fields: {', '.join(sorted(unknown))}"
            )
        content = payload.get("content_base64")
        data: bytes | None = None
        if content is not None:
            if not isinstance(content, str):
                raise ValidationError("content_base64 must be a string")
            if len(content) > MAX_EVIDENCE_BODY_BYTES:
                raise ValidationError("encoded evidence exceeds the supported limit")
            try:
                data = base64.b64decode(content, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValidationError(
                    "content_base64 must be valid base64"
                ) from exc
            if len(data) > MAX_EVIDENCE_BYTES:
                raise ValidationError("evidence file exceeds the 4 MiB limit")
        record = add_evidence(
            self.database_path,
            match.group(1),
            title=payload.get("title"),
            evidence_type=payload.get("evidence_type", "file"),
            description=payload.get("description", ""),
            source_reference=payload.get("source_reference", ""),
            original_name=payload.get("original_name", ""),
            data=data,
            sha256=payload.get("sha256", ""),
            acquired_at=payload.get("acquired_at"),
            analyze_image=self._module_enabled("image-intelligence"),
        )
        self._json(201, record)

    def api_evidence_get_one(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        self._json(200, get_evidence(self.database_path, match.group(1)))

    def api_evidence_verify(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        self._json(200, verify_evidence(self.database_path, match.group(1)))

    def api_evidence_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        self._json(200, delete_evidence(self.database_path, match.group(1)))

    def api_evidence_download(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        data, _media_type, original_name, _is_image = read_evidence_file(
            self.database_path, match.group(1)
        )
        self._send(
            200,
            "application/octet-stream",
            data,
            {"Content-Disposition": _attachment_disposition(original_name)},
        )

    def api_evidence_preview(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("evidence")
        data, media_type, original_name, is_image = read_evidence_file(
            self.database_path, match.group(1)
        )
        if not is_image:
            raise ConflictError("preview is only available for image evidence")
        self._send(
            200,
            media_type,
            data,
            {"Content-Disposition": _attachment_disposition(original_name, inline=True)},
        )

    # --- file intelligence ----------------------------------------------------

    def api_file_analyses_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(
            200,
            list_file_analyses(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                limit=_query_int(query, "limit", 50),
            ),
        )

    def api_file_analysis_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("file-intelligence")
        allowed = {"filename", "content_base64", "investigation_id"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported file analysis fields: {', '.join(sorted(unknown))}"
            )
        content = payload.get("content_base64")
        if not isinstance(content, str) or not content:
            raise ValidationError("content_base64 is required")
        try:
            data = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidationError("content_base64 must be valid base64") from exc
        if len(data) > MAX_FILE_BYTES:
            raise ValidationError("file exceeds the 4 MiB analysis limit")
        filename = payload.get("filename", "")
        if not isinstance(filename, str):
            raise ValidationError("filename must be a string")
        investigation_id = payload.get("investigation_id") or None
        if investigation_id is not None and not isinstance(investigation_id, str):
            raise ValidationError("investigation_id must be a string")
        self._json(
            201,
            analyze_file(
                self.database_path,
                data=data,
                filename=filename,
                investigation_id=investigation_id,
            ),
        )

    def api_file_analysis_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(200, get_file_analysis(self.database_path, match.group(1)))

    def api_yara_list(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(200, list_rulesets(self.database_path))

    def api_yara_create(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("file-intelligence")
        unknown = set(payload) - {"name", "description", "source", "enabled"}
        if unknown:
            raise ValidationError(f"unsupported rule set fields: {', '.join(sorted(unknown))}")
        self._json(
            201,
            create_ruleset(
                self.database_path,
                name=payload.get("name"),
                description=payload.get("description", ""),
                source=payload.get("source"),
                enabled=payload.get("enabled", True),
            ),
        )

    def api_yara_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(200, get_ruleset(self.database_path, match.group(1)))

    def api_yara_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("file-intelligence")
        unknown = set(payload) - {"name", "description", "source", "enabled"}
        if unknown:
            raise ValidationError(f"unsupported rule set fields: {', '.join(sorted(unknown))}")
        if not payload:
            raise ValidationError("no rule set fields were provided")
        self._json(200, update_ruleset(self.database_path, match.group(1), **payload))

    def api_yara_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(200, delete_ruleset(self.database_path, match.group(1)))

    def api_yara_test(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("file-intelligence")
        unknown = set(payload) - {"source", "content_base64"}
        if unknown:
            raise ValidationError(f"unsupported test fields: {', '.join(sorted(unknown))}")
        source = payload.get("source")
        if not isinstance(source, str):
            raise ValidationError("source must be a string")
        content = payload.get("content_base64")
        if content in (None, ""):
            self._json(200, check_source(source))
            return
        if not isinstance(content, str):
            raise ValidationError("content_base64 must be a string")
        try:
            data = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidationError("content_base64 must be valid base64") from exc
        if not data or len(data) > MAX_FILE_BYTES:
            raise ValidationError("file must be between 1 byte and 4 MiB")
        self._json(200, test_source(source, data))

    def api_file_similar_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("file-intelligence")
        self._json(
            200,
            similar_file_analyses(
                self.database_path, match.group(1), limit=_query_int(query, "limit", 20)
            ),
        )

    # --- indicators, settings, modules, CISA KEV -----------------------------

    def api_indicators_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("indicator-engine")
        self._json(
            200,
            unified_indicators(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                indicator_type=_query_text(query, "type", "") or None,
                search=_query_text(query, "search", ""),
                limit=_query_int(query, "limit", 200),
            ),
        )

    def api_triage_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("indicator-engine")
        unknown = set(payload) - {"text"}
        if unknown:
            raise ValidationError(
                f"unsupported triage fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            200,
            triage_indicators(self.database_path, text=payload.get("text")),
        )

    def api_indicator_inspect(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("indicator-engine")
        value = _query_text(query, "value", "").strip()
        if not value:
            raise ValidationError("value is required")
        self._json(
            200,
            inspect_local_indicator(
                self.database_path,
                value=value,
                investigation_id=_query_text(query, "investigation_id", "") or None,
            ),
        )

    def api_investigation_coverage(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("investigations")
        self._json(200, case_coverage(self.database_path, match.group(1)))

    def api_indicator_assessment(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("indicator-engine")
        allowed = {"indicator_type", "value", "verification_status", "note"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported assessment fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            200,
            set_indicator_assessment(
                self.database_path,
                indicator_type=payload.get("indicator_type"),
                value=payload.get("value"),
                verification_status=payload.get("verification_status"),
                note=payload.get("note", ""),
            ),
        )

    def api_settings_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("settings")
        self._json(200, get_settings(self.database_path))

    def api_settings_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("settings")
        self._json(200, update_settings(self.database_path, payload))

    def api_modules_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("module-manager")
        self._json(200, list_modules(self.database_path))

    def api_module_patch(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("module-manager")
        unknown = set(payload) - {"state"}
        if unknown or "state" not in payload:
            raise ValidationError("provide a module state")
        self._json(
            200,
            set_module_state(self.database_path, match.group(1), payload["state"]),
        )

    def api_cisa_kev_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("cisa-kev")
        self._json(
            200,
            list_cached(
                self.database_path,
                search=_query_text(query, "search", ""),
                limit=_query_int(query, "limit", 25),
            ),
        )

    def api_cisa_kev_refresh(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("cisa-kev")
        force = payload.get("force", False)
        if not isinstance(force, bool):
            raise ValidationError("force must be a boolean")
        try:
            result = refresh_cisa_kev(self.database_path, force=force)
        except CisaKevError as exc:
            status = (
                429
                if str(exc).startswith("CISA KEV refresh was rate-limited")
                else 502
            )
            self._error(status, str(exc))
            return
        self._json(200, result)

    def api_intel_connectors(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        self._json(200, list_connectors(self.database_path))

    def api_analytics(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._json(
            200,
            workspace_analytics(
                self.database_path,
                investigation_id=_query_text(query, "investigation_id", "") or None,
                days=_query_int(query, "days", 30),
            ),
        )

    def api_intel_keys(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        self._json(200, list_keys(self.database_path))

    def api_intel_key_put(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("intel-orchestrator")
        unknown = set(payload) - {"key"}
        if unknown:
            raise ValidationError(f"unsupported key fields: {', '.join(sorted(unknown))}")
        self._json(200, set_key(self.database_path, match.group(1), payload.get("key")))

    def api_intel_key_delete(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        self._json(200, delete_key(self.database_path, match.group(1)))

    def api_intel_detect(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        value = _query_text(query, "value", "").strip()
        if not value:
            raise ValidationError("value is required")
        self._json(200, detect_artifact(value))

    def api_intel_runs_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        self._json(200, list_runs(self.database_path, limit=_query_int(query, "limit", 25)))

    def api_intel_run_get(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("intel-orchestrator")
        self._json(200, get_run(self.database_path, match.group(1)))

    def api_intel_runs_post(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("intel-orchestrator")
        allowed = {"value", "type", "connectors", "investigation_id", "use_cache"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValidationError(
                f"unsupported intel run fields: {', '.join(sorted(unknown))}"
            )
        use_cache = payload.get("use_cache", True)
        if not isinstance(use_cache, bool):
            raise ValidationError("use_cache must be a boolean")
        self._json(
            201,
            run_query(
                self.database_path,
                value=payload.get("value"),
                query_type=payload.get("type"),
                connector_ids=payload.get("connectors"),
                investigation_id=payload.get("investigation_id"),
                use_cache=use_cache,
            ),
        )

    def api_intel_run_record(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("intel-orchestrator")
        self._module("investigations")
        unknown = set(payload) - {"investigation_id", "connectors"}
        if unknown:
            raise ValidationError(
                f"unsupported record fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            201,
            record_run_observation(
                self.database_path,
                match.group(1),
                investigation_id=payload.get("investigation_id"),
                connector_ids=payload.get("connectors"),
            ),
        )

    def api_intel_run_promote(
        self, match: re.Match[str], query: dict[str, list[str]], payload: Any
    ) -> None:
        self._module("intel-orchestrator")
        self._module("entities")
        unknown = set(payload) - {"source_entity_id", "items", "investigation_id"}
        if unknown:
            raise ValidationError(
                f"unsupported promote fields: {', '.join(sorted(unknown))}"
            )
        self._json(
            201,
            promote_results(
                self.database_path,
                match.group(1),
                source_entity_id=payload.get("source_entity_id"),
                items=payload.get("items"),
                investigation_id=payload.get("investigation_id"),
            ),
        )

    def api_print_report(
        self, match: re.Match[str], query: dict[str, list[str]], payload: object
    ) -> None:
        self._module("report-center")
        report = build_report(self.database_path, match.group(1))
        self._send(
            200,
            "text/html; charset=utf-8",
            render_html_report(report).encode("utf-8"),
        )


ROUTES: tuple[tuple[str, re.Pattern[str], str, int], ...] = (
    ("GET", re.compile(r"^/api/health$"), "api_health", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/overview$"), "api_overview", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/search$"), "api_search", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/system$"), "api_system", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/activities$"), "api_activities", MAX_BODY_BYTES),
    (
        "GET",
        re.compile(r"^/api/investigations$"),
        "api_investigations_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/investigations$"),
        "api_investigations_post",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}$"),
        "api_investigation_get",
        MAX_BODY_BYTES,
    ),
    (
        "PATCH",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}$"),
        "api_investigation_patch",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}$"),
        "api_investigation_delete",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/report$"),
        "api_investigation_report",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/timeline$"),
        "api_investigation_timeline",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/export$"),
        "api_investigation_export",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/observations$"),
        "api_investigation_observations",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/board$"),
        "api_board_get",
        MAX_BODY_BYTES,
    ),
    (
        "PUT",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/board$"),
        "api_board_put",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/graph$"),
        "api_investigation_graph",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/graph$"), "api_graph", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/entities$"), "api_entities_get", MAX_BODY_BYTES),
    ("POST", re.compile(r"^/api/entities$"), "api_entity_post", MAX_BODY_BYTES),
    (
        "GET",
        re.compile(rf"^/api/entities/{_ID_PATTERN}$"),
        "api_entity_get",
        MAX_BODY_BYTES,
    ),
    (
        "PATCH",
        re.compile(rf"^/api/entities/{_ID_PATTERN}$"),
        "api_entity_patch",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/entities/{_ID_PATTERN}$"),
        "api_entity_delete",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/entities/{_ID_PATTERN}/sources$"),
        "api_entity_source_link",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/entities/{_ID_PATTERN}/sources/{_ID_PATTERN}$"),
        "api_entity_source_unlink",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/relationships$"),
        "api_relationships_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/relationships$"),
        "api_relationship_post",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/relationships/types$"),
        "api_relationship_types",
        MAX_BODY_BYTES,
    ),
    (
        "PATCH",
        re.compile(rf"^/api/relationships/{_ID_PATTERN}$"),
        "api_relationship_patch",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/relationships/{_ID_PATTERN}$"),
        "api_relationship_delete",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/sources$"), "api_sources_get", MAX_BODY_BYTES),
    ("POST", re.compile(r"^/api/sources$"), "api_source_post", MAX_BODY_BYTES),
    (
        "GET",
        re.compile(rf"^/api/sources/{_ID_PATTERN}$"),
        "api_source_get",
        MAX_BODY_BYTES,
    ),
    (
        "PATCH",
        re.compile(rf"^/api/sources/{_ID_PATTERN}$"),
        "api_source_patch",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/sources/{_ID_PATTERN}$"),
        "api_source_delete",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/evidence$"),
        "api_evidence_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/evidence$"),
        "api_investigation_evidence_post",
        MAX_EVIDENCE_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/evidence/{_ID_PATTERN}$"),
        "api_evidence_get_one",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/evidence/{_ID_PATTERN}$"),
        "api_evidence_delete",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/evidence/{_ID_PATTERN}/verify$"),
        "api_evidence_verify",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/evidence/{_ID_PATTERN}/download$"),
        "api_evidence_download",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/evidence/{_ID_PATTERN}/preview$"),
        "api_evidence_preview",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/entities$"),
        "api_investigation_entity_link",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/entities/{_ID_PATTERN}$"),
        "api_investigation_entity_unlink",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/sources$"),
        "api_investigation_source_link",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/sources/{_ID_PATTERN}$"),
        "api_investigation_source_unlink",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/intelligence/files$"),
        "api_file_analyses_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/intelligence/files$"),
        "api_file_analysis_post",
        MAX_FILE_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/intelligence/files/{_ID_PATTERN}$"),
        "api_file_analysis_get",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/intelligence/yara$"),
        "api_yara_list",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/intelligence/yara$"),
        "api_yara_create",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/intelligence/yara/test$"),
        "api_yara_test",
        MAX_FILE_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/intelligence/yara/{_ID_PATTERN}$"),
        "api_yara_get",
        MAX_BODY_BYTES,
    ),
    (
        "PATCH",
        re.compile(rf"^/api/intelligence/yara/{_ID_PATTERN}$"),
        "api_yara_patch",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(rf"^/api/intelligence/yara/{_ID_PATTERN}$"),
        "api_yara_delete",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/intelligence/files/{_ID_PATTERN}/similar$"),
        "api_file_similar_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/intelligence/text$"),
        "api_triage_post",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/intelligence/inspect$"),
        "api_indicator_inspect",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/api/investigations/{_ID_PATTERN}/coverage$"),
        "api_investigation_coverage",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/indicators$"), "api_indicators_get", MAX_BODY_BYTES),
    (
        "POST",
        re.compile(r"^/api/indicators/assessment$"),
        "api_indicator_assessment",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/settings$"), "api_settings_get", MAX_BODY_BYTES),
    ("PATCH", re.compile(r"^/api/settings$"), "api_settings_patch", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/modules$"), "api_modules_get", MAX_BODY_BYTES),
    (
        "PATCH",
        re.compile(r"^/api/modules/([A-Za-z0-9-]{1,64})$"),
        "api_module_patch",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/intel/connectors$"),
        "api_intel_connectors",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/analytics$"),
        "api_analytics",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(r"^/api/intel/keys$"),
        "api_intel_keys",
        MAX_BODY_BYTES,
    ),
    (
        "PUT",
        re.compile(r"^/api/intel/keys/([a-z0-9-]{2,40})$"),
        "api_intel_key_put",
        MAX_BODY_BYTES,
    ),
    (
        "DELETE",
        re.compile(r"^/api/intel/keys/([a-z0-9-]{2,40})$"),
        "api_intel_key_delete",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/intel/detect$"), "api_intel_detect", MAX_BODY_BYTES),
    ("GET", re.compile(r"^/api/intel/runs$"), "api_intel_runs_get", MAX_BODY_BYTES),
    ("POST", re.compile(r"^/api/intel/runs$"), "api_intel_runs_post", MAX_BODY_BYTES),
    (
        "GET",
        re.compile(rf"^/api/intel/runs/{_ID_PATTERN}$"),
        "api_intel_run_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/intel/runs/{_ID_PATTERN}/record$"),
        "api_intel_run_record",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(rf"^/api/intel/runs/{_ID_PATTERN}/promote$"),
        "api_intel_run_promote",
        MAX_BODY_BYTES,
    ),
    ("GET", re.compile(r"^/api/graph/path$"), "api_graph_path", MAX_BODY_BYTES),
    (
        "GET",
        re.compile(r"^/api/intel/cisa-kev$"),
        "api_cisa_kev_get",
        MAX_BODY_BYTES,
    ),
    (
        "POST",
        re.compile(r"^/api/intel/cisa-kev/refresh$"),
        "api_cisa_kev_refresh",
        MAX_BODY_BYTES,
    ),
    (
        "GET",
        re.compile(rf"^/reports/{_ID_PATTERN}$"),
        "api_print_report",
        MAX_BODY_BYTES,
    ),
)


def create_server(database: str | Path, port: int = 8000) -> ThreadingHTTPServer:
    class BoundRequestHandler(RequestHandler):
        database_path = database

    server = ThreadingHTTPServer(("127.0.0.1", port), BoundRequestHandler)
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
