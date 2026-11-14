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


SCHEMA_VERSION = 14

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
        "intel-orchestrator",
        "Multi-source intelligence",
        "Explicit fan-out of one artifact to registered connectors, with cache, rate limits, source status and provenance.",
        "Intelligence",
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
        "NIST NVD record of a CVE (description, CVSS, CWE, references) as a multi-source connector.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "external-osint-connectors",
        "External OSINT connectors",
        "Passive third-party sources (DNS, RDAP, CT, archives, routing, reputation) used by multi-source queries and transforms.",
        "Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "transforms",
        "Transforms",
        "Entity-to-entity transforms over the connectors, with parameters, per-run log, duration and enrichment history.",
        "Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "entity-resolution",
        "Entity resolution",
        "Exact, probable and weak duplicate candidates with analyst-approved, audited merges.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "attack-matrix",
        "MITRE ATT&CK",
        "Offline Enterprise ATT&CK matrix, technique detail and techniques linked to cases.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "yara-rules",
        "YARA rules",
        "Local YARA rule sets checked, tested and applied to file analyses.",
        "Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "analytics",
        "Analytics",
        "Workspace and case charts computed from stored records.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "taxii-feeds",
        "TAXII feeds",
        "TAXII 2.1 client: discovery, collections and paged pulls of STIX objects, with indicators written into cases.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "sigma-rules",
        "Sigma rules",
        "SigmaHQ detection rules downloaded on request and indexed by ATT&CK technique.",
        "Threat Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "plugins",
        "Local plugins",
        "Analyst-written transforms with a manifest, declared permissions and approval by code digest, run in a separate process.",
        "System",
        "1.0.0",
        "enabled",
    ),
    (
        "monitoring",
        "Monitoring",
        "Saved multi-source queries re-run on a schedule while the server runs, with differences between runs and in-app notifications.",
        "Intelligence",
        "1.0.0",
        "enabled",
    ),
    (
        "geoint",
        "GEOINT map",
        "Local map of EXIF GPS positions from analysed images and approximate network locations from queries.",
        "Analysis",
        "1.0.0",
        "enabled",
    ),
    (
        "cti-export",
        "CTI export",
        "STIX 2.1 bundles, MISP events and IOC CSV built from case records.",
        "Output",
        "1.0.0",
        "enabled",
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
    "intel.allow_network": "false",
    "intel.allow_target_contact": "false",
    "intel.max_workers": "4",
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
    {
        "key": "intel.allow_network",
        "label": "Allow intelligence connectors to use the network",
        "description": "When false, connectors that contact external services are skipped; local connectors still run.",
        "type": "boolean",
        "options": ["false", "true"],
    },
    {
        "key": "intel.allow_target_contact",
        "label": "Allow connectors to contact the target",
        "description": "When false, connectors that send a request or TLS handshake to the artifact's own servers are skipped. Requires network access too.",
        "type": "boolean",
        "options": ["false", "true"],
    },
    {
        "key": "intel.max_workers",
        "label": "Parallel connector workers",
        "description": "Maximum connectors queried at the same time for one artifact.",
        "type": "integer",
        "options": ["1", "16"],
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


def _migrate_intelligence_runs(connection: sqlite3.Connection) -> None:
    """Version 4: multi-source intelligence runs, results, cache and source status."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS intel_runs (
               id TEXT PRIMARY KEY,
               investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
               query_type TEXT NOT NULL,
               query_value TEXT NOT NULL,
               status TEXT NOT NULL,
               connector_count INTEGER NOT NULL DEFAULT 0,
               result_count INTEGER NOT NULL DEFAULT 0,
               started_at TEXT NOT NULL,
               finished_at TEXT NOT NULL DEFAULT ''
           );
           CREATE INDEX IF NOT EXISTS intel_runs_started
               ON intel_runs(started_at DESC);
           CREATE TABLE IF NOT EXISTS intel_results (
               id TEXT PRIMARY KEY,
               run_id TEXT NOT NULL REFERENCES intel_runs(id) ON DELETE CASCADE,
               connector_id TEXT NOT NULL,
               status TEXT NOT NULL,
               cached INTEGER NOT NULL DEFAULT 0,
               result_type TEXT NOT NULL DEFAULT '',
               value TEXT NOT NULL DEFAULT '',
               data_json TEXT NOT NULL DEFAULT '{}',
               source_url TEXT NOT NULL DEFAULT '',
               response_sha256 TEXT NOT NULL DEFAULT '',
               error TEXT NOT NULL DEFAULT '',
               elapsed_ms INTEGER NOT NULL DEFAULT 0,
               fetched_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS intel_results_run
               ON intel_results(run_id, connector_id);
           CREATE TABLE IF NOT EXISTS intel_cache (
               connector_id TEXT NOT NULL,
               query_type TEXT NOT NULL,
               query_value TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               fetched_at TEXT NOT NULL,
               expires_at TEXT NOT NULL,
               PRIMARY KEY (connector_id, query_type, query_value)
           );
           CREATE TABLE IF NOT EXISTS intel_source_status (
               connector_id TEXT PRIMARY KEY,
               last_status TEXT NOT NULL,
               last_error TEXT NOT NULL DEFAULT '',
               last_latency_ms INTEGER NOT NULL DEFAULT 0,
               last_run_at TEXT NOT NULL,
               success_count INTEGER NOT NULL DEFAULT 0,
               error_count INTEGER NOT NULL DEFAULT 0
           );"""
    )


def _migrate_file_engines(connection: sqlite3.Connection) -> None:
    """Version 5: YARA rule sets and similarity digests for file analyses."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS yara_rulesets (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL UNIQUE,
               description TEXT NOT NULL DEFAULT '',
               source TEXT NOT NULL,
               enabled INTEGER NOT NULL DEFAULT 1,
               rule_count INTEGER NOT NULL DEFAULT 0,
               rule_names TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
           );"""
    )
    _ensure_column(connection, "file_analyses", "tlsh", "TEXT")
    _ensure_column(connection, "file_analyses", "ssdeep", "TEXT")


def _migrate_api_keys(connection: sqlite3.Connection) -> None:
    """Version 6: the operator's own API keys for keyed connectors."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS intel_api_keys (
               provider_id TEXT PRIMARY KEY,
               secret TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
           );"""
    )


def _migrate_attack(connection: sqlite3.Connection) -> None:
    """Version 7: offline MITRE ATT&CK and techniques linked to cases."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS attack_meta (
               domain TEXT PRIMARY KEY,
               version TEXT NOT NULL,
               source_url TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               fetched_at TEXT NOT NULL
           );
           CREATE TABLE IF NOT EXISTS attack_tactics (
               id TEXT PRIMARY KEY,
               shortname TEXT NOT NULL,
               name TEXT NOT NULL,
               description TEXT NOT NULL DEFAULT '',
               url TEXT NOT NULL DEFAULT '',
               position INTEGER NOT NULL DEFAULT 0
           );
           CREATE TABLE IF NOT EXISTS attack_techniques (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               tactics TEXT NOT NULL DEFAULT '',
               platforms TEXT NOT NULL DEFAULT '',
               is_subtechnique INTEGER NOT NULL DEFAULT 0,
               description TEXT NOT NULL DEFAULT '',
               detection TEXT NOT NULL DEFAULT '',
               url TEXT NOT NULL DEFAULT ''
           );
           CREATE TABLE IF NOT EXISTS attack_objects (
               id TEXT PRIMARY KEY,
               kind TEXT NOT NULL,
               name TEXT NOT NULL,
               aliases TEXT NOT NULL DEFAULT '',
               description TEXT NOT NULL DEFAULT '',
               url TEXT NOT NULL DEFAULT ''
           );
           CREATE TABLE IF NOT EXISTS attack_relations (
               source_id TEXT NOT NULL,
               target_id TEXT NOT NULL,
               kind TEXT NOT NULL,
               PRIMARY KEY (source_id, target_id, kind)
           );
           CREATE INDEX IF NOT EXISTS attack_relations_target ON attack_relations(target_id, kind);
           CREATE TABLE IF NOT EXISTS case_techniques (
               id TEXT PRIMARY KEY,
               investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
               technique_id TEXT NOT NULL,
               note TEXT NOT NULL DEFAULT '',
               source TEXT NOT NULL DEFAULT 'analyst',
               created_at TEXT NOT NULL,
               UNIQUE (investigation_id, technique_id)
           );"""
    )


def _migrate_foundation(connection: sqlite3.Connection) -> None:
    """Version 8: transform runs, entity resolution and registry corrections."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS transform_runs (
               id TEXT PRIMARY KEY,
               transform_id TEXT NOT NULL,
               entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
               investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
               intel_run_id TEXT,
               status TEXT NOT NULL,
               result_count INTEGER NOT NULL DEFAULT 0,
               created_count INTEGER NOT NULL DEFAULT 0,
               reused_count INTEGER NOT NULL DEFAULT 0,
               relationship_count INTEGER NOT NULL DEFAULT 0,
               parameters_json TEXT NOT NULL DEFAULT '{}',
               log_json TEXT NOT NULL DEFAULT '[]',
               duration_ms INTEGER NOT NULL DEFAULT 0,
               started_at TEXT NOT NULL,
               finished_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS transform_runs_entity
               ON transform_runs(entity_id, started_at);
           CREATE TABLE IF NOT EXISTS resolution_decisions (
               pair_key TEXT PRIMARY KEY,
               entity_a TEXT NOT NULL,
               entity_b TEXT NOT NULL,
               decision TEXT NOT NULL,
               level TEXT NOT NULL DEFAULT '',
               rule TEXT NOT NULL DEFAULT '',
               note TEXT NOT NULL DEFAULT '',
               decided_at TEXT NOT NULL
           );
           CREATE TABLE IF NOT EXISTS entity_aliases (
               id TEXT PRIMARY KEY,
               entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
               entity_type TEXT NOT NULL,
               name TEXT NOT NULL,
               identifier TEXT NOT NULL DEFAULT '',
               merged_from_id TEXT NOT NULL,
               level TEXT NOT NULL DEFAULT '',
               note TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS entity_aliases_entity ON entity_aliases(entity_id);"""
    )
    # Both connectors were registered as planned before they were built.
    corrections = {
        row[0]: row for row in DEFAULT_MODULES if row[0] in {"nvd-connector", "external-osint-connectors"}
    }
    for module_id, (_, name, description, category, version, _state) in corrections.items():
        connection.execute(
            """UPDATE module_registry
               SET name = ?, description = ?, category = ?, version = ?,
                   state = 'enabled', updated_at = ?
               WHERE module_id = ? AND state = 'planned'""",
            (name, description, category, version, utc_now(), module_id),
        )

# Indexed records: (kind, table, title SQL, body SQL). Expressions use the
# NEW./OLD. row alias in triggers and the bare table in the backfill.
SEARCH_SOURCES = (
    ("investigations", "investigations", "{r}name", "{r}description"),
    ("entities", "entities", "{r}name", "{r}identifier || ' ' || {r}entity_type || ' ' || {r}description"),
    ("sources", "sources", "{r}title", "{r}reference || ' ' || {r}category || ' ' || {r}description"),
    ("evidence", "evidence", "{r}title", "{r}description || ' ' || {r}original_name || ' ' || {r}sha256 || ' ' || {r}evidence_type"),
    ("observations", "observations", "{r}title", "{r}content"),
    ("files", "file_analyses", "{r}file_name", "{r}format || ' ' || {r}sha256 || ' ' || {r}media_type"),
)


def fts5_available(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("CREATE VIRTUAL TABLE IF NOT EXISTS temp._fts5_probe USING fts5(x)")
        connection.execute("DROP TABLE IF EXISTS temp._fts5_probe")
        return True
    except sqlite3.OperationalError:
        return False


def _migrate_search_index(connection: sqlite3.Connection) -> None:
    """Version 9: FTS5 index over cases, entities, sources, evidence,
    observations and file analyses, kept current by triggers. Builds without
    FTS5 skip it; global search then falls back to LIKE."""
    if not fts5_available(connection):
        return
    connection.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
               kind UNINDEXED, ref_id UNINDEXED, title, body,
               tokenize = 'unicode61 remove_diacritics 2'
           )"""
    )
    for kind, table, title, body in SEARCH_SOURCES:
        _index_source(connection, kind, table, title, body)


def _index_source(connection: sqlite3.Connection, kind: str, table: str, title: str, body: str) -> None:
    """(Re)create the triggers that keep one table in the search index and
    reindex its rows."""
    new_title, new_body = title.format(r="NEW."), body.format(r="NEW.")
    connection.executescript(
        f"""DROP TRIGGER IF EXISTS search_{table}_insert;
            DROP TRIGGER IF EXISTS search_{table}_update;
            DROP TRIGGER IF EXISTS search_{table}_delete;
            CREATE TRIGGER search_{table}_insert AFTER INSERT ON {table} BEGIN
                INSERT INTO search_index (kind, ref_id, title, body)
                VALUES ('{kind}', NEW.id, {new_title}, {new_body});
            END;
            CREATE TRIGGER search_{table}_update AFTER UPDATE ON {table} BEGIN
                DELETE FROM search_index WHERE kind = '{kind}' AND ref_id = OLD.id;
                INSERT INTO search_index (kind, ref_id, title, body)
                VALUES ('{kind}', NEW.id, {new_title}, {new_body});
            END;
            CREATE TRIGGER search_{table}_delete AFTER DELETE ON {table} BEGIN
                DELETE FROM search_index WHERE kind = '{kind}' AND ref_id = OLD.id;
            END;"""
    )
    connection.execute("DELETE FROM search_index WHERE kind = ?", (kind,))
    connection.execute(
        f"""INSERT INTO search_index (kind, ref_id, title, body)
            SELECT '{kind}', id, {title.format(r="")}, {body.format(r="")} FROM {table}"""
    )


def _migrate_search_objective(connection: sqlite3.Connection) -> None:
    """Version 14: the case objective (version 12) joins the case's searchable
    text. Without FTS5 there is no index and the LIKE search covers it."""
    exists = connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'search_index'").fetchone()
    if exists:
        _index_source(connection, "investigations", "investigations", "{r}name", "{r}description || ' ' || {r}objective")


def _migrate_cti_feeds(connection: sqlite3.Connection) -> None:
    """Version 10: TAXII servers and objects, Sigma rules."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS taxii_servers (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               discovery_url TEXT NOT NULL,
               username TEXT NOT NULL DEFAULT '',
               password TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL,
               last_pull_at TEXT NOT NULL DEFAULT ''
           );
           CREATE TABLE IF NOT EXISTS taxii_objects (
               server_id TEXT NOT NULL REFERENCES taxii_servers(id) ON DELETE CASCADE,
               collection_id TEXT NOT NULL,
               object_id TEXT NOT NULL,
               type TEXT NOT NULL,
               name TEXT NOT NULL DEFAULT '',
               pattern TEXT NOT NULL DEFAULT '',
               modified TEXT NOT NULL DEFAULT '',
               raw_json TEXT NOT NULL,
               fetched_at TEXT NOT NULL,
               PRIMARY KEY (server_id, collection_id, object_id)
           );
           CREATE INDEX IF NOT EXISTS taxii_objects_type ON taxii_objects(type);
           CREATE TABLE IF NOT EXISTS taxii_pulls (
               id TEXT PRIMARY KEY,
               server_id TEXT NOT NULL,
               collection_id TEXT NOT NULL,
               started_at TEXT NOT NULL,
               finished_at TEXT NOT NULL,
               object_count INTEGER NOT NULL DEFAULT 0,
               page_count INTEGER NOT NULL DEFAULT 0,
               status TEXT NOT NULL,
               error TEXT NOT NULL DEFAULT ''
           );
           CREATE TABLE IF NOT EXISTS sigma_rules (
               id TEXT PRIMARY KEY,
               title TEXT NOT NULL,
               status TEXT NOT NULL DEFAULT '',
               level TEXT NOT NULL DEFAULT '',
               description TEXT NOT NULL DEFAULT '',
               tags TEXT NOT NULL DEFAULT '',
               techniques TEXT NOT NULL DEFAULT '',
               product TEXT NOT NULL DEFAULT '',
               category TEXT NOT NULL DEFAULT '',
               service TEXT NOT NULL DEFAULT '',
               references_json TEXT NOT NULL DEFAULT '[]',
               falsepositives_json TEXT NOT NULL DEFAULT '[]',
               date TEXT NOT NULL DEFAULT '',
               modified TEXT NOT NULL DEFAULT '',
               path TEXT NOT NULL DEFAULT '',
               raw TEXT NOT NULL DEFAULT ''
           );
           CREATE TABLE IF NOT EXISTS sigma_meta (
               version TEXT NOT NULL,
               source_url TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               rule_count INTEGER NOT NULL,
               fetched_at TEXT NOT NULL
           );"""
    )


def _migrate_plugins(connection: sqlite3.Connection) -> None:
    """Version 11: approvals of local plugins."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS plugin_registry (
               id TEXT PRIMARY KEY,
               enabled INTEGER NOT NULL DEFAULT 0,
               approved_sha256 TEXT NOT NULL DEFAULT '',
               approved_manifest_json TEXT NOT NULL DEFAULT '{}',
               approved_at TEXT NOT NULL DEFAULT '',
               last_error TEXT NOT NULL DEFAULT ''
           );"""
    )


def _migrate_cases(connection: sqlite3.Connection) -> None:
    """Version 12: case objective and archive flag, evidence custody chain
    and evidence notes."""
    _ensure_column(connection, "investigations", "objective", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(connection, "investigations", "archived_at", "TEXT NOT NULL DEFAULT ''")
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS evidence_events (
               id TEXT PRIMARY KEY,
               evidence_id TEXT NOT NULL,
               investigation_id TEXT NOT NULL,
               sequence INTEGER NOT NULL,
               action TEXT NOT NULL,
               actor TEXT NOT NULL DEFAULT 'analyst',
               detail TEXT NOT NULL DEFAULT '',
               sha256 TEXT NOT NULL DEFAULT '',
               occurred_at TEXT NOT NULL,
               previous_hash TEXT NOT NULL,
               entry_hash TEXT NOT NULL,
               UNIQUE (evidence_id, sequence)
           );
           CREATE INDEX IF NOT EXISTS evidence_events_evidence ON evidence_events(evidence_id, sequence);
           CREATE TABLE IF NOT EXISTS evidence_notes (
               id TEXT PRIMARY KEY,
               evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
               body TEXT NOT NULL,
               created_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS evidence_notes_evidence ON evidence_notes(evidence_id, created_at);"""
    )
    from .custody import backfill

    backfill(connection)


def _migrate_monitoring(connection: sqlite3.Connection) -> None:
    """Version 13: monitors, their runs and notifications."""
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS monitors (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               query_type TEXT NOT NULL,
               query_value TEXT NOT NULL,
               connectors_json TEXT NOT NULL,
               interval_minutes INTEGER NOT NULL,
               investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
               enabled INTEGER NOT NULL DEFAULT 1,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               next_run_at TEXT NOT NULL,
               last_run_at TEXT NOT NULL DEFAULT '',
               last_status TEXT NOT NULL DEFAULT ''
           );
           CREATE INDEX IF NOT EXISTS monitors_due ON monitors(enabled, next_run_at);
           CREATE TABLE IF NOT EXISTS monitor_runs (
               id TEXT PRIMARY KEY,
               monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
               intel_run_id TEXT NOT NULL DEFAULT '',
               trigger TEXT NOT NULL,
               status TEXT NOT NULL,
               added_count INTEGER NOT NULL DEFAULT 0,
               removed_count INTEGER NOT NULL DEFAULT 0,
               diff_json TEXT NOT NULL DEFAULT '{}',
               error TEXT NOT NULL DEFAULT '',
               started_at TEXT NOT NULL,
               finished_at TEXT NOT NULL
           );
           CREATE INDEX IF NOT EXISTS monitor_runs_monitor ON monitor_runs(monitor_id, started_at);
           CREATE TABLE IF NOT EXISTS notifications (
               id TEXT PRIMARY KEY,
               kind TEXT NOT NULL,
               monitor_id TEXT REFERENCES monitors(id) ON DELETE CASCADE,
               monitor_run_id TEXT NOT NULL DEFAULT '',
               title TEXT NOT NULL,
               body TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL,
               read_at TEXT NOT NULL DEFAULT ''
           );
           CREATE INDEX IF NOT EXISTS notifications_unread ON notifications(read_at, created_at);"""
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
    (4, "Multi-source intelligence runs and source status", _migrate_intelligence_runs),
    (5, "YARA rule sets and file similarity digests", _migrate_file_engines),
    (6, "Local API keys for keyed intelligence connectors", _migrate_api_keys),
    (7, "Offline MITRE ATT&CK and case techniques", _migrate_attack),
    (8, "Transforms, entity resolution and module registry corrections", _migrate_foundation),
    (9, "Full-text search index", _migrate_search_index),
    (10, "TAXII feeds and Sigma rules", _migrate_cti_feeds),
    (11, "Local plugin approvals", _migrate_plugins),
    (12, "Case objective and archive, evidence custody and notes", _migrate_cases),
    (13, "Monitors and notifications", _migrate_monitoring),
    (14, "Search index covers case objectives", _migrate_search_objective),
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
