# Database schema

Storage: SQLite 3, one file chosen by the analyst (`data/garbage.sqlite3` by
default). Foreign keys are enabled. The schema is migrated additively; no
migration drops user data.

Current schema version: **3** (`SCHEMA_VERSION` in `garbage_intel/db.py`).

## Tables

### `investigations`

`id`, `name`, `description`, `created_at`, `status`, `updated_at`

Primary case record. Status changes append to `investigation_status_events` so
the timeline survives later edits.

### `observations`

`id`, `investigation_id`, `title`, `content`, `source_reference`,
`collection_basis`, `observed_at`, `recorded_at`

Analyst notes and collected observations. `source_reference` and
`collection_basis` retain provenance.

### `investigation_status_events`

`id`, `investigation_id`, `status`, `changed_at`

Append-only status history.

### `entities`

`id`, `entity_type`, `name`, `identifier`, `description`, `source_reference`,
`collection_basis`, `confidence`, `verification_status`, `created_at`,
`updated_at`

Canonical entity registry shared by all cases. `entity_type` is validated
against the supported type list; `identifier` holds domains, IPs, hashes or
handles as appropriate.

### `relationships`

`id`, `investigation_id`, `source_entity_id`, `target_entity_id`,
`relationship_type`, `description`, `source_reference`, `confidence`,
`verification_status`, `created_at`, `updated_at`

Directed edges. Deletion protects against orphaned graph references and
relationship cycles where the type requires it.

### Link tables

- `investigation_entities`: `investigation_id`, `entity_id`, `added_at`
- `investigation_sources`: `investigation_id`, `source_id`, `added_at`
- `entity_sources`: `entity_id`, `source_id`, `added_at`

### `sources`

`id`, `title`, `reference`, `category`, `description`, `accessed_at`,
`verification_status`, `created_at`, `updated_at`

Provenance records for websites, documents, interviews or datasets. A source
reference is stored as text; it is not fetched automatically.

### `evidence`

`id`, `investigation_id`, `title`, `evidence_type`, `description`,
`source_reference`, `original_name`, `stored_name`, `media_type`, `size_bytes`,
`sha256`, `acquired_at`, `recorded_at`, `integrity_status`, `image_format`,
`image_width`, `image_height`

Metadata row for a file stored under the evidence directory. Stored bytes use a
generated name. `sha256` is recomputed by verification.

### `file_analyses`

`id`, `investigation_id`, `file_name`, `format`, `media_type`, `size_bytes`,
`sha256`, `analysis_json`, `created_at`, `tlsh`, `ssdeep`

Persistent File Intelligence history. `analysis_json` contains the complete
bounded result: hashes, entropy, strings, metadata, structure, findings,
indicators and limitations. Summary columns exist for listing and filtering.
`investigation_id` is optional and cascades on case deletion. `tlsh` and
`ssdeep` (migration 5) let the similarity search compare analyses without
parsing every JSON payload.

### `intel_api_keys`

`provider_id`, `secret`, `created_at`, `updated_at`

The operator's own provider keys. `secret` is plaintext like the rest of the
database (see SECURITY.md); the API never returns it, only a last-four hint.

### `yara_rulesets`

`id`, `name` (unique), `description`, `source`, `enabled`, `rule_count`,
`rule_names`, `created_at`, `updated_at`

Workspace YARA rule sets. `source` is compiled before every insert or update;
`rule_count` and `rule_names` are derived from the compiled set.

### `intel_runs`

`id`, `investigation_id`, `query_type`, `query_value`, `status`,
`connector_count`, `result_count`, `started_at`, `finished_at`

One explicit multi-source query. `investigation_id` is optional and set to
`NULL` when the case is deleted, so the audit record survives.

### `intel_results`

`id`, `run_id`, `connector_id`, `status`, `cached`, `result_type`, `value`,
`data_json`, `source_url`, `response_sha256`, `error`, `elapsed_ms`,
`fetched_at`

One row per finding, or one status-only row when a connector returned nothing,
failed or was skipped. Cascades with its run.

### `intel_cache`

`connector_id`, `query_type`, `query_value`, `payload_json`, `fetched_at`,
`expires_at`

Per-connector response cache honouring the connector's TTL.

### `intel_source_status`

`connector_id`, `last_status`, `last_error`, `last_latency_ms`, `last_run_at`,
`success_count`, `error_count`

Health record behind the source status panel.

### `boards`

`id`, `investigation_id`, `name`, `viewport_x`, `viewport_y`, `zoom`, `layers`,
`revision`, `created_at`, `updated_at`

One or more boards per case. `revision` implements optimistic concurrency.

### `board_elements`

`id`, `board_id`, `element_kind`, `entity_id`, `label`, `content`, `x`, `y`,
`width`, `height`, `layer`, `z_index`, `created_at`, `updated_at`

Cards, notes and groups. Entity-backed cards reference `entities`; free notes
store text in `content`.

### `board_connections`

`id`, `board_id`, `source_element_id`, `target_element_id`, `relationship_id`,
`label`, `connection_type`, `created_at`

Visual connections; optional link to a canonical relationship.

### `indicator_assessments`

`indicator_type`, `value`, `verification_status`, `note`, `updated_at`

Analyst assessment for an exact indicator value. Primary key is the type/value
pair. This is an assessment, not a reputation verdict.

### `activities`

`id`, `investigation_id`, `actor`, `action`, `target_type`, `target_id`,
`summary`, `created_at`

Append-only activity feed used by the dashboard and case timeline.

### `module_registry`

`module_id`, `name`, `description`, `category`, `version`, `state`, `updated_at`

Capability registry. States are `enabled`, `disabled` and `planned`. Planned
modules cannot be enabled, and API routes call `require_module` before doing
work.

### `transform_runs`

`id`, `transform_id`, `entity_id`, `investigation_id`, `intel_run_id`, `status`,
`result_count`, `created_count`, `reused_count`, `relationship_count`,
`parameters_json`, `log_json`, `duration_ms`, `started_at`, `finished_at`

One row per transform per run; the entity's enrichment history.

### `resolution_decisions`

`pair_key`, `entity_a`, `entity_b`, `decision` (`distinct` or `merged`),
`level`, `rule`, `note`, `decided_at`

### `entity_aliases`

`id`, `entity_id`, `entity_type`, `name`, `identifier`, `merged_from_id`,
`level`, `note`, `created_at`

What a merged entity was, kept on the entity it was merged into.

### `monitors`

`id`, `name`, `query_type`, `query_value`, `connectors_json`,
`interval_minutes`, `investigation_id`, `enabled`, `created_at`, `updated_at`,
`next_run_at`, `last_run_at`, `last_status`

### `monitor_runs`

`id`, `monitor_id`, `intel_run_id`, `trigger`, `status`, `added_count`,
`removed_count`, `diff_json` (added, removed, per-source status), `error`,
`started_at`, `finished_at`

### `notifications`

`id`, `kind` (`changed` or `error`), `monitor_id`,
`monitor_run_id`, `title`, `body`, `created_at`, `read_at` (empty while unread)

### `application_settings`

`key`, `value`, `updated_at`

Application-level preferences.

### `schema_migrations`

`version`, `description`, `applied_at`

Applied migration ledger used to make startup idempotent.

## Migration history

| Version | Description | Effect |
| --- | --- | --- |
| 1 | Baseline evidence ledger schema | Original tables, preserved |
| 2 | Investigation workspace tables and columns | Entities, sources, boards, activities, settings, module registry, extra evidence columns |
| 3 | Persistent file intelligence analyses | `file_analyses` and case/time index |
| 4 | Multi-source intelligence runs and source status | `intel_runs`, `intel_results`, `intel_cache`, `intel_source_status` |
| 5 | YARA rule sets and file similarity digests | `yara_rulesets`; `tlsh` and `ssdeep` columns on `file_analyses` |
| 6 | Local API keys for keyed intelligence connectors | `intel_api_keys` |
| 7 | Offline MITRE ATT&CK and case techniques | `attack_meta`, `attack_tactics`, `attack_techniques`, `attack_objects`, `attack_relations`, `case_techniques` |
| 8 | Transforms, entity resolution and module registry corrections | `transform_runs`, `resolution_decisions`, `entity_aliases`; `nvd-connector` and `external-osint-connectors` set to enabled where still `planned` |
| 9 | Full-text search index | `search_index` (FTS5, `unicode61 remove_diacritics 2`) over investigations, entities, sources, evidence, observations and file analyses, kept current by triggers; skipped where SQLite has no FTS5 |
| 10 | TAXII feeds and Sigma rules | `taxii_servers`, `taxii_objects`, `taxii_pulls`, `sigma_rules`, `sigma_meta` |
| 11 | Local plugin approvals | `plugin_registry` (enabled flag, approved code SHA-256 and manifest, time) |
| 12 | Case objective and archive, evidence custody and notes | `investigations.objective`, `investigations.archived_at`; `evidence_events` (hash-chained, kept after deletion) and `evidence_notes`; logs started for existing evidence |
| 13 | Monitors and notifications | `monitors`, `monitor_runs`, `notifications` |

Version 1 databases are upgraded in place. The application file format used by
the evidence folder is unchanged.

## Query and integrity notes

- All application SQL uses bound parameters.
- Foreign keys are declared with explicit `ON DELETE` behavior; deletion
  routines also clean dependent link rows.
- `file_analyses.analysis_json` is written only after a complete analysis; an
  invalid or oversized input is rejected before insertion.
- There is no encryption at rest. Protect the database file and evidence folder
  with operating-system permissions and, where appropriate, full-disk
  encryption.
