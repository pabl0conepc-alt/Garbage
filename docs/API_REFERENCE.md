# API reference

Base URL: `http://127.0.0.1:<port>/api` (default port `8765`).
The server binds loopback only and has no authentication. JSON requests must
send `Content-Type: application/json`; bodies are capped at 1 MiB except file
analysis (6 MiB).

Errors use HTTP status plus a JSON object:

```json
{"error": "human-readable message"}
```

Typical statuses: `400` validation, `403` foreign origin, `404` missing record,
`409` conflict/module state, `413` body too large, `415` wrong content type,
`500` unexpected server failure. Unknown fields in mutation payloads are
rejected where the handler validates an allowlist.

## Health and system

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Liveness and application version |
| GET | `/api/system` | Storage, counts and runtime information |
| GET | `/api/settings` | Read application settings |
| PATCH | `/api/settings` | Update allowlisted settings |
| GET | `/api/activities?limit=` | Recent activity |
| GET | `/api/overview` | Dashboard summary |
| GET | `/api/search?q=` | Grouped cross-record search |

## Investigations

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/investigations` | List cases |
| POST | `/api/investigations` | Create `{name, description?, status?}` |
| GET | `/api/investigations/{id}` | Full case |
| PATCH | `/api/investigations/{id}` | Update name/description/status |
| DELETE | `/api/investigations/{id}` | Delete case and dependents |
| GET | `/api/investigations/{id}/report` | Render report data |
| GET | `/api/investigations/{id}/timeline` | Ordered case timeline |
| GET | `/api/investigations/{id}/export?format=` | Export `json`, `csv`, `md` or HTML |
| POST | `/api/investigations/{id}/observations` | Add observation |
| GET | `/api/investigations/{id}/board` | Board state, creating default if needed |
| PUT | `/api/investigations/{id}/board` | Save board state with `revision` |
| GET | `/api/investigations/{id}/graph` | Case-scoped relationship graph |
| GET | `/api/investigations/{id}/coverage` | Factual case coverage checks |

Case membership:

| Method | Path |
| --- | --- |
| POST/DELETE | `/api/investigations/{id}/entities[/{entityId}]` |
| POST/DELETE | `/api/investigations/{id}/sources[/{sourceId}]` |

## Entities and relationships

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/entities?type=&q=` | List/filter entities |
| POST | `/api/entities` | Create entity |
| GET | `/api/entities/{id}` | Entity with sources and cases |
| PATCH | `/api/entities/{id}` | Update entity |
| DELETE | `/api/entities/{id}` | Delete entity and links |
| POST | `/api/entities/{id}/sources` | Link a source |
| DELETE | `/api/entities/{id}/sources/{sourceId}` | Unlink a source |
| GET | `/api/relationships?investigation_id=` | List relationships |
| POST | `/api/relationships` | Create relationship |
| GET | `/api/relationships/types` | Supported types |
| PATCH | `/api/relationships/{id}` | Update relationship |
| DELETE | `/api/relationships/{id}` | Delete relationship |
| GET | `/api/graph?investigation_id=` | Global or case graph payload |

Entity fields include `entity_type`, `name`, `identifier`, `description`,
`source_reference`, `collection_basis`, `confidence` and
`verification_status`. Relationship creation requires distinct source and target
entities and a supported type.

## Sources

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/sources?category=&q=` | List sources |
| POST | `/api/sources` | Create source |
| GET | `/api/sources/{id}` | Source with linked entities/cases |
| PATCH | `/api/sources/{id}` | Update source |
| DELETE | `/api/sources/{id}` | Delete source and links |

## Evidence

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/evidence?investigation_id=` | List evidence metadata |
| POST | `/api/investigations/{id}/evidence` | Upload base64 evidence |
| GET | `/api/evidence/{id}` | Evidence metadata |
| DELETE | `/api/evidence/{id}` | Delete record and stored bytes |
| POST | `/api/evidence/{id}/verify` | Recompute and compare SHA-256 |
| GET | `/api/evidence/{id}/download` | Download stored bytes |
| GET | `/api/evidence/{id}/preview` | Preview supported images |

Upload payload:

```json
{
  "title": "Capture",
  "evidence_type": "image",
  "description": "Optional context",
  "source_reference": "https://example.org/item",
  "original_name": "capture.png",
  "content_base64": "..."
}
```

Maximum decoded size is 4 MiB. The response includes `sha256` and
`integrity_status`.

## File intelligence

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/intelligence/files?investigation_id=&limit=` | Analysis history |
| POST | `/api/intelligence/files` | Analyse a base64 file |
| GET | `/api/intelligence/files/{id}` | Full persisted analysis |

Request:

```json
{
  "filename": "sample.pdf",
  "content_base64": "...",
  "investigation_id": "optional-case-uuid"
}
```

Response (abridged):

```json
{
  "analysis_id": "uuid",
  "investigation_id": null,
  "file_name": "sample.pdf",
  "format": "pdf",
  "format_label": "PDF document",
  "media_type": "application/pdf",
  "size_bytes": 1234,
  "hashes": {"sha256": "...", "sha1": "...", "md5": "..."},
  "entropy": 5.12,
  "magic_hex": "25 50 44 46",
  "metadata": {"pdf": {"Title": "..."}},
  "structure": {},
  "strings": {"count": 12, "items": [{"offset": 0, "value": "..."}], "truncated": false},
  "findings": [{"code": "...", "level": "note", "message": "..."}],
  "indicators": [{"type": "domain", "value": "example.org", "note": "..."}],
  "imports": [],
  "limitations": ["..."],
  "analysis_engine": "python-stdlib",
  "created_at": "..."
}
```

Limits: 4 MiB decoded, 500 archive entries, 1 MiB GZIP preview, 150 strings,
96 sections and 80 imports. Nothing is executed or extracted. Invalid base64 is
`400`; a disabled `file-intelligence` module is `409`.

## Indicators and CTI

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/indicators` | Aggregated indicators, correlations and assessments |
| POST | `/api/indicators/assessment` | Save analyst assessment |
| POST | `/api/intelligence/text` | In-memory text triage; no persistence |
| GET | `/api/intelligence/inspect?value=` | Offline facts and exact local matches |
| GET | `/api/intel/cisa-kev` | Cached CISA KEV catalogue |
| POST | `/api/intel/cisa-kev/refresh` | Explicit bounded refresh |

Indicator assessment payload: `{indicator_type, value, verification_status,
note}`. CISA refresh requires network access; failures are returned as
structured errors and do not delete the previous snapshot.

Text triage payload:

```json
{"text": "hxxps://evil[.]example/a and 203.0.113.9"}
```

Response includes `unique_count`, `indicator_count`, per-type `counts`, grouped
`items` with `count`/`contexts`, a SHA-256 of the submitted text, `defanged` and
`truncated`. The text itself is not echoed and is not written to the database.
The input is capped at 20,000 characters.

Value inspection accepts `value` (up to 2,000 characters) and an optional
`investigation_id` scope:

```json
{
  "kind": "url",
  "label": "URL",
  "canonical": "https://evil.example/a",
  "defanged": true,
  "facts": [{"label": "Scheme", "value": "https"}],
  "warnings": ["..."],
  "local": {
    "indicator": {"type": "url", "value": "...", "origins": []},
    "entities": [],
    "evidence": [],
    "file_analyses": [],
    "cooccurring": [{"type": "ipv4", "value": "203.0.113.9", "count": 1}]
  },
  "match_count": 1
}
```

`kind` is one of `ipv4`, `ipv6`, `cidr`, `domain`, `url`, `email`, `md5`,
`sha1`, `sha256`, `asn`, `filename`, `multiple` or `unknown`. IPv6 inspection
includes compressed/expanded forms, IPv4-mapped/6to4/Teredo details, scope and
zone facts; bracketed IPv6 URL hosts keep their brackets. Inspection makes no
network request. `local` contains exact matches only; co-occurrence is not a
proven relationship.

## Modules

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/modules` | Registry with states and counts |
| PATCH | `/api/modules/{module_id}` | Set `enabled` or `disabled` |

Enabling a `planned` module returns `409`. Built-in modules cannot be removed.

## Reports

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/reports/{investigationId}` | HTML case report |

HTML reports are printable and contain no remote scripts or styles.

## Static assets

`/` serves `web/index.html`; only allowlisted filenames under `web/` are served.
Unknown paths return `404`. All responses set `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and a
same-origin Content Security Policy.

## Non-goals

There are no write endpoints for website/domain/IP collection, OSINT connectors,
automation or native engines. Those capabilities are not implemented; the
module registry exposes them as `planned`.
