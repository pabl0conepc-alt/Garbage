"""SQLite schema, connections, versioned migrations and registry defaults.

The schema is additive: legacy databases keep their rows and only gain tables,
columns and indexes. Nothing in this module drops or rewrites user data.
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .errors import ModuleDisabledError


SCHEMA_VERSION = 3

COLLECTION_BASES = ("public", "authorized", "user-provided")
INVESTIGATION_STATUSES = ("open", "closed", "cancelled")
ENTITY_TYPES = (
    "person",
    "username",
    "profile",
    "domain",
    "ipv4",
    "ipv6",
    "email",
    "organization",
    "file",
    "image",
    "hash",
    "url",
    "ioc",
    "other",
)
ENTITY_TYPE_LABELS = {
    "person": "Person",
    "username": "Username",
    "profile": "Public profile",
    "domain": "Domain",
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "email": "Email",
    "organization": "Organization",
    "file": "File",
    "image": "Image",
    "hash": "Hash",
    "url": "URL",
    "ioc": "Indicator",
    "other": "Other",
}
IOC_ENTITY_TYPES = (
    "domain",
    "ipv4",
    "ipv6",
    "email",
    "url",
    "hash",
    "username",
)
RELATIONSHIP_TYPES = (
    "associated-with",
    "belongs-to",
    "references",
    "hosted-on",
    "derived-from",
    "related-to",
    "connected-to",
    "communicates-with",
    "owns",
    "uses",
)
RELATIONSHIP_TYPE_LABELS = {
    "associated-with": "Associated with",
    "belongs-to": "Belongs to",
    "references": "References",
    "hosted-on": "Hosted on",
    "derived-from": "Derived from",
    "related-to": "Related to",
    "connected-to": "Connected to",
    "communicates-with": "Communicates with",
    "owns": "Owns",
    "uses": "Uses",
}
CONFIDENCE_LEVELS = ("unconfirmed", "possible", "probable", "confirmed")
VERIFICATION_STATUSES = ("not-verified", "verified", "disputed", "false-positive")
SOURCE_CATEGORIES = (
    "website",
    "documentation",
    "api",
    "public-database",
    "report",
    "file",
    "other",
)
EVIDENCE_TYPES = ("file", "document", "image", "hash", "note", "url")
BOARD_ELEMENT_KINDS = ("entity", "note", "text", "group")
BOARD_LAYERS = (
    "people",
    "accounts",
    "domains",
    "ips",
    "files",
    "notes",
    "groups",
    "other",
)
MODULE_STATES = ("available", "enabled", "disabled", "planned", "error")
ACTIVITY_LIMIT = 100

ENTITY_LAYER = {
    "person": "people",
    "username": "accounts",
    "profile": "accounts",
    "email": "accounts",
    "organization": "accounts",
    "domain": "domains",
    "url": "domains",
    "ipv4": "ips",
    "ipv6": "ips",
    "file": "files",
    "image": "files",
    "hash": "files",
    "ioc": "other",
    "other": "other",
}

DEFAULT_MODULES: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "investigations",
        "Investigations",
        "Create, edit and track investigation cases with a guarded evidence lifecycle.",
        "Workspace",
        "1.0.0",
        "enabled",
    ),
    (
        "activity-log",
        "Activity log",
        "Append-only record of workspace mutations and investigation events.",
        "Workspace",
        "1.0.0",
        "enabled",
    ),
    (
        "entities",
        "Entity manager",
        "Central registry of people, accounts, infrastructure and indicators.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "relationships",
        "Relationship engine",
        "Analyst-entered, provenance-carrying links between registered entities.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "investigation-board",
        "Investigation board",
        "Persisted visual workspace of entities, notes and connections.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "relationship-graph",
        "Relationship graph",
        "Graph projection of the shared relationship records.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "evidence",
        "Evidence manager",
        "Hash-preserved evidence with integrity re-verification.",
        "Evidence",
        "1.0.0",
        "enabled",
    ),
    (
        "image-intelligence",
        "Image intelligence",
        "Format, dimension and digest inspection of uploaded images.",
        "Evidence",
        "1.0.0",
        "enabled",
    ),
    (
        "file-intelligence",
        "File intelligence",
        "Bounded static inspection of documents, archives, images and executables with persistent history.",
        "Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "source-manager",
        "Source manager",
        "Reusable sources linked to investigations and entities.",
        "Evidence",
        "1.0.0",
        "enabled",
    ),
    (
        "indicator-engine",
        "Indicator engine",
        "Pattern extraction and exact-value correlation with provenance.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "cisa-kev",
        "CISA KEV connector",
        "Explicit, read-only refresh of the public CISA KEV catalog.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "report-center",
        "Report center",
        "Structured JSON, HTML, CSV and Markdown reports from real records.",
        "Output",
        "1.0.0",
        "enabled",
    ),
    (
        "global-search",
        "Global search",
        "Unified search across cases, entities, evidence and sources.",
        "System",
        "1.0.0",
        "enabled",
    ),
    (
        "module-manager",
        "Module manager",
        "Controlled registry of available and planned platform modules.",
        "System",
        "1.0.0",
        "enabled",
    ),
    (
        "settings",
        "Settings",
        "Persisted interface and reporting preferences with real effects.",
        "System",
        "1.0.0",
        "enabled",
    ),
    (
        "nvd-connector",
        "NVD CVE connector",
        "Planned descriptive NVD CVE metadata connector; not implemented.",
        "Threat Intelligence",
        "0.0.0",
        "planned",
    ),
    (
        "external-osint-connectors",
        "External OSINT connectors",
        "Planned authorized external lookups; no connector is implemented.",
        "Intelligence",
        "0.0.0",
        "planned",
    ),
    (
        "media-forensics",
        "Media forensics",
        "Planned deeper media analysis; only hashing and metadata exist today.",
        "Evidence",
        "0.0.0",
        "planned",
    ),
)

DEFAULT_SETTINGS: dict[str, str] = {
    "interface.theme": "dark",
    "interface.density": "comfortable",
    "interface.reduce_motion": "false",
    "board.autosave_delay_ms": "1200",
    "search.result_limit": "6",
    "report.include_limitations": "true",
    "report.include_raw_observations": "true",
}

SETTING_SCHEMA: tuple[dict[str, Any], ...] = (
    {
        "key": "interface.theme",
        "label": "Interface theme",
        "description": "Dark workstation palette or a higher-contrast variant.",
        "type": "choice",
        "options": ["dark", "contrast"],
    },
    {
        "key": "interface.density",
        "label": "Information density",
        "description": "Comfortable spacing or a compact layout for smaller screens.",
        "type": "choice",
        "options": ["comfortable", "compact"],
    },
    {
        "key": "interface.reduce_motion",
        "label": "Reduce motion",
        "description": "Disable panel and view transitions.",
        "type": "boolean",
        "options": ["true", "false"],
    },
    {
        "key": "board.autosave_delay_ms",
        "label": "Board autosave delay",
        "description": "Milliseconds of inactivity before the board state is saved.",
        "type": "integer",
        "options": ["300", "30000"],
    },
    {
        "key": "search.result_limit",
        "label": "Global search result limit",
        "description": "Maximum results per group in global search.",
        "type": "integer",
        "options": ["3", "20"],
    },
    {
        "key": "report.include_limitations",
        "label": "Include report limitations",
        "description": "Append explicit analytical limitations to generated reports.",
        "type": "boolean",
        "options": ["true", "false"],
    },
    {
        "key": "report.include_raw_observations",
        "label": "Include raw observations",
        "description": "Include full observation text in generated HTML reports.",
        "type": "boolean",
        "options": ["true", "false"],
    },
)

MAX_ARCHIVE_BYTES = 10 * 1024 * 1024

BASE_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    updated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    collection_basis TEXT NOT NULL CHECK (
        collection_basis IN ('public', 'authorized', 'user-provided')
    ),
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS observations_investigation_time
    ON observations(investigation_id, observed_at, recorded_at);

CREATE TABLE IF NOT EXISTS investigation_status_events (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed', 'cancelled')),
    changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    name TEXT NOT NULL,
    identifier TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    source_reference TEXT NOT NULL DEFAULT '',
    collection_basis TEXT NOT NULL DEFAULT 'user-provided',
    confidence TEXT NOT NULL DEFAULT 'unconfirmed',
    verification_status TEXT NOT NULL DEFAULT 'not-verified',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS entities_type_name ON entities(entity_type, name);
CREATE INDEX IF NOT EXISTS entities_identifier ON entities(identifier);
CREATE UNIQUE INDEX IF NOT EXISTS entities_unique_identifier
    ON entities(entity_type, identifier) WHERE identifier <> '';

CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
    target_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
    relationship_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source_reference TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'unconfirmed',
    verification_status TEXT NOT NULL DEFAULT 'not-verified',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS relationships_investigation
    ON relationships(investigation_id);
CREATE INDEX IF NOT EXISTS relationships_source
    ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS relationships_target
    ON relationships(target_entity_id);
CREATE UNIQUE INDEX IF NOT EXISTS relationships_unique_edge
    ON relationships(
        source_entity_id,
        target_entity_id,
        relationship_type,
        COALESCE(investigation_id, '')
    );

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    source_reference TEXT NOT NULL DEFAULT '',
    original_name TEXT NOT NULL DEFAULT '',
    stored_name TEXT NOT NULL DEFAULT '',
    media_type TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    acquired_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    integrity_status TEXT NOT NULL DEFAULT 'unverified',
    image_format TEXT,
    image_width INTEGER,
    image_height INTEGER
);

CREATE INDEX IF NOT EXISTS evidence_investigation
    ON evidence(investigation_id, recorded_at);
CREATE INDEX IF NOT EXISTS evidence_sha256 ON evidence(sha256);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    reference TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'other',
    description TEXT NOT NULL DEFAULT '',
    accessed_at TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'not-verified',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS sources_title ON sources(title);

CREATE TABLE IF NOT EXISTS investigation_entities (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    added_at TEXT NOT NULL,
    PRIMARY KEY (investigation_id, entity_id)
);

CREATE TABLE IF NOT EXISTS investigation_sources (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    added_at TEXT NOT NULL,
    PRIMARY KEY (investigation_id, source_id)
);

CREATE TABLE IF NOT EXISTS entity_sources (
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    added_at TEXT NOT NULL,
    PRIMARY KEY (entity_id, source_id)
);

CREATE TABLE IF NOT EXISTS boards (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL UNIQUE
        REFERENCES investigations(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'Investigation board',
    viewport_x REAL NOT NULL DEFAULT 0,
    viewport_y REAL NOT NULL DEFAULT 0,
    zoom REAL NOT NULL DEFAULT 1,
    layers TEXT NOT NULL DEFAULT '{}',
    revision INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS board_elements (
    id TEXT PRIMARY KEY,
    board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    element_kind TEXT NOT NULL,
    entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    x REAL NOT NULL DEFAULT 0,
    y REAL NOT NULL DEFAULT 0,
    width REAL NOT NULL DEFAULT 220,
    height REAL NOT NULL DEFAULT 120,
    layer TEXT NOT NULL DEFAULT 'other',
    z_index INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS board_elements_board ON board_elements(board_id);

CREATE TABLE IF NOT EXISTS board_connections (
    id TEXT PRIMARY KEY,
    board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    source_element_id TEXT NOT NULL
        REFERENCES board_elements(id) ON DELETE CASCADE,
    target_element_id TEXT NOT NULL
        REFERENCES board_elements(id) ON DELETE CASCADE,
    relationship_id TEXT REFERENCES relationships(id) ON DELETE SET NULL,
    label TEXT NOT NULL DEFAULT '',
    connection_type TEXT NOT NULL DEFAULT 'connected-to',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS board_connections_board
    ON board_connections(board_id);

CREATE TABLE IF NOT EXISTS activities (
    id TEXT PRIMARY KEY,
    investigation_id TEXT,
    actor TEXT NOT NULL DEFAULT 'analyst',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS activities_time ON activities(created_at DESC);
CREATE INDEX IF NOT EXISTS activities_investigation
    ON activities(investigation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS indicator_assessments (
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (indicator_type, value)
);

CREATE TABLE IF NOT EXISTS file_analyses (
    id TEXT PRIMARY KEY,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    format TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    analysis_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS file_analyses_case_created
    ON file_analyses(investigation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS module_registry (
    module_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'enabled',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id() -> str:
    return str(uuid.uuid4())


def normalize_timestamp(value: str | None) -> str:
    if value is None:
        return utc_now()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must not be empty")
    return value.strip()


_required_text = required_text


def connect(database: str | Path) -> sqlite3.Connection:
    path = Path(database)
    if str(database) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection(database: str | Path) -> Iterator[sqlite3.Connection]:
    connection = connect(database)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
    }


def _ensure_column(
    connection: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    if column not in _column_names(connection, table):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_ledger(connection: sqlite3.Connection) -> None:
    """Version 1: the pre-existing evidence ledger is already in place."""


def _migrate_file_intelligence(connection: sqlite3.Connection) -> None:
    """Version 3: persistent file analysis history."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS file_analyses (
               id TEXT PRIMARY KEY,
               investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
               file_name TEXT NOT NULL,
               format TEXT NOT NULL,
               media_type TEXT NOT NULL,
               size_bytes INTEGER NOT NULL,
               sha256 TEXT NOT NULL,
               analysis_json TEXT NOT NULL,
               created_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS file_analyses_case_created
               ON file_analyses(investigation_id, created_at DESC);"""
    )


def _migrate_workspace(connection: sqlite3.Connection) -> None:
    """Version 2: additive investigation workspace columns."""
    _ensure_column(
        connection, "investigations", "status", "TEXT NOT NULL DEFAULT 'open'"
    )
    _ensure_column(
        connection, "investigations", "updated_at", "TEXT NOT NULL DEFAULT ''"
    )
    connection.execute(
        "UPDATE investigations SET updated_at = created_at WHERE updated_at = ''"
    )


MIGRATIONS = (
    (1, "Baseline evidence ledger schema", _migrate_ledger),
    (2, "Investigation workspace tables and columns", _migrate_workspace),
    (3, "Persistent file intelligence analyses", _migrate_file_intelligence),
)


def initialize(database: str | Path) -> None:
    with _connection(database) as connection:
        connection.executescript(BASE_SCHEMA)
        applied = {
            row["version"]
            for row in connection.execute("SELECT version FROM schema_migrations")
        }
        for version, description, apply in MIGRATIONS:
            if version in applied:
                continue
            apply(connection)
            connection.execute(
                """INSERT INTO schema_migrations (version, description, applied_at)
                   VALUES (?, ?, ?)""",
                (version, description, utc_now()),
            )
        seed_registry(connection)


def seed_registry(connection: sqlite3.Connection) -> None:
    now = utc_now()
    connection.executemany(
        """INSERT OR IGNORE INTO module_registry
           (module_id, name, description, category, version, state, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [(*module, now) for module in DEFAULT_MODULES],
    )
    connection.executemany(
        """INSERT OR IGNORE INTO application_settings (key, value, updated_at)
           VALUES (?, ?, ?)""",
        [(key, value, now) for key, value in DEFAULT_SETTINGS.items()],
    )


def record_activity(
    connection: sqlite3.Connection,
    *,
    action: str,
    target_type: str,
    summary: str,
    target_id: str = "",
    investigation_id: str | None = None,
    actor: str = "analyst",
) -> None:
    connection.execute(
        """INSERT INTO activities
           (id, investigation_id, actor, action, target_type, target_id,
            summary, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id(),
            investigation_id,
            actor,
            action,
            target_type,
            target_id,
            summary,
            utc_now(),
        ),
    )


def module_state(connection: sqlite3.Connection, module_id: str) -> str:
    row = connection.execute(
        "SELECT state FROM module_registry WHERE module_id = ?", (module_id,)
    ).fetchone()
    if row is None:
        return "enabled"
    return str(row["state"])


def module_enabled(connection: sqlite3.Connection, module_id: str) -> bool:
    return module_state(connection, module_id) not in {"disabled", "planned", "error"}


def require_module(connection: sqlite3.Connection, module_id: str) -> None:
    state = module_state(connection, module_id)
    if state in {"disabled", "planned", "error"}:
        raise ModuleDisabledError(
            f"module is {state}: {module_id}; enable it in the module manager first"
        )


def setting_value(
    connection: sqlite3.Connection, key: str, default: str | None = None
) -> str:
    row = connection.execute(
        "SELECT value FROM application_settings WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return DEFAULT_SETTINGS.get(key, default or "")
    return str(row["value"])


def setting_bool(connection: sqlite3.Connection, key: str, default: bool) -> bool:
    value = setting_value(connection, key, "true" if default else "false")
    return value.strip().lower() in {"true", "1", "yes", "on"}


def setting_int(
    connection: sqlite3.Connection, key: str, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(setting_value(connection, key, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))
