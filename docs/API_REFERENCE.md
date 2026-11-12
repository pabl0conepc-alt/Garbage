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
| GET | `/api/system` | Storage, counts, runtime and optional native-engine status |
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
| GET | `/api/graph?investigation_id=` | Graph payload with nodes, edges and structural metrics |

Entity fields include `entity_type`, `name`, `identifier`, `description`,
`source_reference`, `collection_basis`, `confidence` and
`verification_status`. Relationship creation requires distinct source and target
entities and a supported type. The graph response also carries `metrics`:
`engine`, `nodes`, `edges`, `components`, `isolates`, `self_loops`,
`reciprocal_edges`, `degree_sum`, `max_degree`, `max_degree_node` and `density`.
`engine` is `cpp-native` or `python-fallback`.

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
  "hardening": {
    "engine": "c-native",
    "format": "pe",
    "bits": 64,
    "enabled_count": 4,
    "missing_count": 2,
    "checks": [
      {"key": "aslr", "label": "ASLR / DYNAMIC_BASE", "status": "enabled", "detail": "..."}
    ]
  },
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

Domain inspection also returns `local.lookalikes`:
`{engine, items: [{value, distance, reason}], scanned}`. Candidates come only
from local records and are structural edit-distance matches, not registrations
or reputation claims.

`kind` is one of `ipv4`, `ipv6`, `cidr`, `domain`, `url`, `email`, `md5`,
`sha1`, `sha256`, `asn`, `filename`, `multiple` or `unknown`. IPv6 inspection
includes compressed/expanded forms, IPv4-mapped/6to4/Teredo details, scope and
zone facts; bracketed IPv6 URL hosts keep their brackets. Inspection makes no
network request. `local` contains exact matches only; co-occurrence is not a
proven relationship.

## Multi-source intelligence

Module: `intel-orchestrator`. One artifact is detected, then sent in parallel
to every registered connector that accepts its type.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/intel/connectors` | Registered connectors, availability and health |
| GET | `/api/intel/detect?value=` | Offline artifact detection (refangs input) |
| POST | `/api/intel/runs` | Run one artifact against the connectors |
| GET | `/api/intel/runs?limit=` | Recent runs |
| GET | `/api/intel/runs/{id}` | One run with per-source status and results |

Run payload: `{value, type?, connectors?, investigation_id?, use_cache?}`.
`type` is optional; when given it must match the detected type. Supported
types: `domain`, `ipv4`, `ipv6`, `cidr`, `url`, `email`, `md5`, `sha1`,
`sha256`, `asn`, `cve`.

Each source reports one status: `ok`, `empty`, `error`, `rate-limited`,
`network-disabled` or `unsupported`. Each result carries `connector_id`,
`result_type`, `value`, `data`, `source_url`, `response_sha256`, `cached`,
`elapsed_ms` and `fetched_at`.

Connectors that contact external services run only when the setting
`intel.allow_network` is `true` (default `false`). Outbound requests use
`garbage_intel/net.py`:

- HTTPS only by default, ports 80/443 only, no credentials in URLs.
- Every resolved address must be globally routable; any private, loopback,
  link-local, CGNAT, multicast or reserved answer refuses the request.
- The socket is pinned to the validated address (no DNS rebinding); TLS still
  verifies the hostname.
- Redirects are followed manually and revalidated; https→http is refused.
- Hard byte limit, single deadline, identity encoding and a fixed User-Agent.

Registered connectors:

| Connector | Accepts | Network | Source | Cache |
| --- | --- | --- | --- | --- |
| `local-structure` | all | no | syntax and structure only | — |
| `local-workspace` | all but CVE | no | local entities, evidence, analyses, indicators | — |
| `cisa-kev-local` | CVE | no | local CISA KEV snapshot | — |
| `dns-doh` | domain, URL, email | yes | Cloudflare DNS over HTTPS (A, AAAA, CNAME, MX, NS, TXT, CAA, SPF, DMARC) | 1 h |
| `cymru-asn` | IPv4, IPv6, ASN | yes | Team Cymru IP-to-ASN via DNS TXT | 24 h |
| `rdap` | domain, IP, CIDR, ASN | yes | rdap.org bootstrap → authoritative registry | 24 h |
| `crtsh` | domain, URL, email | yes | crt.sh Certificate Transparency (unexpired) | 24 h |
| `wayback` | domain, URL | yes | Internet Archive CDX (distinct captures, max 200) | 24 h |
| `first-epss` | CVE | yes | FIRST EPSS API | 24 h |

All network connectors are passive: they ask a public registry, resolver or
archive about the artifact and never contact the artifact's own servers. The
DNS resolver and the other sources see the queried value.

RDAP privacy rule: only organisation-level roles are stored (registrar, abuse,
sponsor, reseller, NOC). On IP network and ASN objects the registrant is the
address holder and is kept; on domain objects registrant, administrative and
technical contacts are never stored.

The HTTP client loads the system CA bundle when the interpreter's compiled-in
default is empty (standalone Python builds on NixOS), so TLS verification works
without `SSL_CERT_FILE`.

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

There are no write endpoints for website/domain/IP collection, OSINT
connectors or automation. Those collection capabilities are not implemented and
remain `planned`. Native C/C++/Rust helpers are local, read-only accelerators
behind existing endpoints; they never fetch or write data.
