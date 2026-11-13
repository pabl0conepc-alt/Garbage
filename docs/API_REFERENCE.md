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
| GET | `/api/search?q=` | Ranked cross-record search: `engine` (`fts5`, or `like` when SQLite lacks FTS5), `best` (top 8 by BM25, title weighted 8:1), and `groups` (investigations, entities, sources, evidence, observations, file analyses, indicators). FTS hits carry `title_marked` and `snippet` with matches between `\u0002` and `\u0003`. Terms are quoted, so operators are literal; the last term is a prefix; accents are ignored |

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
| GET | `/api/intelligence/files/{id}/similar?limit=` | Stored analyses ranked by TLSH distance and ssdeep score |
| GET | `/api/intelligence/yara` | YARA rule sets (without source) |
| POST | `/api/intelligence/yara` | Create a rule set: `name`, `source`, optional `description`, `enabled` |
| GET | `/api/intelligence/yara/{id}` | One rule set with source |
| PATCH | `/api/intelligence/yara/{id}` | Change any of `name`, `description`, `source`, `enabled` |
| DELETE | `/api/intelligence/yara/{id}` | Delete a rule set |
| POST | `/api/intelligence/yara/test` | Compile `source`; with `content_base64`, also scan that file without storing it |

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
  "hashes": {"sha256": "...", "sha1": "...", "md5": "...", "tlsh": "T1...", "ssdeep": "96:...:..."},
  "similarity_engine": "c-native",
  "embedded": {"engine": "rust-native", "items": [{"offset": 211, "kind": "pe", "label": "PE executable", "detail": "", "count": 1}], "total": 1, "truncated": false},
  "yara": {"rulesets": [{"ruleset": "Lab", "matches": [{"rule": "x", "tags": [], "meta": {}, "strings": []}], "error": ""}], "match_count": 1, "timed_out": false},
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

Formats with dedicated parsers: PDF, ZIP/OOXML (including `vbaProject.bin`),
TAR, GZIP, images, ELF, PE, Mach-O, OLE compound files (`doc`, `xls`, `ppt`,
`msg`, `msi` with summary properties, VBA source and MSI table names), LNK
shortcuts, ISO 9660 images and RTF documents. `structure.compound`,
`structure.lnk`, `structure.iso` and `structure.rtf` hold their results.

Similarity digests come from the C engine when built; the Python fallback stops
at 1 MiB (`similarity_engine: "unavailable"`). YARA rule sets run in a child
process with a 20 s deadline. The engine supports a documented subset of the
YARA language (no modules, no `base64`, jumps need an upper bound up to 65,536);
rule errors return `400` with the line number in the message.

### Images: EXIF and perceptual hashes

Image analyses (`png`, `jpeg`, `gif`, `webp`, `bmp`) carry `metadata.exif`
when the file has an EXIF block (JPEG APP1, PNG `eXIf`, WebP `EXIF`, TIFF):
make, model, lens, software, capture and modification times, orientation and
`gps` (`latitude`, `longitude`, `altitude_m`, `gps_time_utc`,
`horizontal_error_m`, `datum`, or `valid: false`). The author and body serial
number are reported only as present, never copied. Valid GPS adds an
`exif-gps` finding.

`POST /api/intelligence/files` accepts `perceptual: {phash, dhash}` (16 hex
digits each). The interface computes them in the browser from the decoded
image (as displayed, EXIF orientation applied) with the imagehash library's
definitions; the server stores them for images and ignores them otherwise.
`/similar` adds `phash_distance` and `dhash_distance` (bits out of 64) and
keeps a candidate when pHash is within 10 bits.

## Plugins

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/plugins` | Plugins directory, every folder with manifest or error, code SHA-256 and state (`invalid`, `disabled`, `enabled`, `changed`) |
| POST | `/api/plugins/rescan` | Re-read the folder and load approved, unchanged plugins |
| POST | `/api/plugins/{id}/enable` | `{sha256}`: approve exactly the listed code and permissions and load the plugin (`409` if it changed since listing) |
| POST | `/api/plugins/{id}/disable` | Unload and withdraw approval |

See `MODULE_DEVELOPMENT.md` section 8 for the manifest, the `run(ctx)`
contract and the isolation model.

## TAXII 2.1 feeds

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/api/taxii/servers` | List or add a server (`name`, `discovery_url` https, optional `username` and `password` for HTTP Basic; the password is never returned) |
| DELETE | `/api/taxii/servers/{id}` | Remove the server and its stored objects |
| GET | `/api/taxii/servers/{id}/discover` | Discovery document: title, `default` root and `api_roots` (absolute) |
| GET | `/api/taxii/servers/{id}/collections?api_root=` | Collections of one root (the root must be on the server's host) |
| POST | `/api/taxii/servers/{id}/pull` | `{api_root, collection_id, max_objects (1-20000), object_types?, added_after?}`: pages of 500 through `next`; returns counts by type and `status` `completed` or `partial` (an error after some pages) |
| GET | `/api/taxii/objects?server_id&collection_id&type&q&limit&offset` | Stored objects and counts by type |
| GET | `/api/taxii/object?server_id&collection_id&object_id` | One stored STIX object as received |
| POST | `/api/taxii/objects/to-case` | `{investigation_id, server_id, collection_id, object_ids}`: equality comparisons of the selected indicators' STIX patterns (domain, IP, URL, email, file hashes) become one observation in the case |

Requests go through the SSRF-safe fetcher, limited to the server's host, with
`Accept: application/taxii+json;version=2.1`; 502, 503 and 504 are retried
twice. MITRE's public server (`https://attack-taxii.mitre.org/taxii2/`) is
offered as a one-click example.

## Sigma rules

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/sigma` | Loaded release, rule count, counts by level and licence |
| POST | `/api/sigma/refresh` | Download the latest SigmaHQ `sigma_core.zip` (hosts pinned to GitHub release assets) and replace the stored set |
| GET | `/api/sigma/rules?technique&q&level&product&limit` | Search; `technique` matches sub-techniques too (`T1059` finds `T1059.001`) |
| GET | `/api/sigma/rules/{id}` | One rule with its full YAML |

`GET /api/attack/techniques/{id}` adds `sigma` (total and up to 15 rules)
when the set is loaded. Rules are SigmaHQ's under the Detection Rule License
1.1; the interface credits them on every rule. GARBAGE does not convert or
run them.

## Typosquatting

The `typosquat` connector (domain, network) generates candidates for the
registrable label (omission, repetition, transposition, QWERTY neighbour
replacement and insertion, ASCII homoglyphs, hyphenation, vowel swap, bit
flips, addition, subdomain dot) plus TLD swaps, one entry per spelling, and
asks Cloudflare's DNS-over-HTTPS resolver for NS records of up to 160 of
them (TLD swaps and homoglyphs first). NOERROR counts as existing, NXDOMAIN
as not. The candidates themselves are never contacted. Generation runs in
Rust (`gi_typosquat`) when built, with an identical Python reference.

## GEOINT

`GET /api/geoint?investigation_id=` returns `points` of two kinds: `photo`
(EXIF GPS of analysed images, `precision: device`) and `network` (newest
`geolocation` finding per artifact from IPinfo, `precision:
network-approximate`), with their source, time and case. Nothing is geocoded
or fetched. The map's base layer is `web/world.json`, built by
`tools/build_world_map.py` from Natural Earth 1:110m (public domain).

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
| POST | `/api/intel/runs` | Run one artifact against the connectors. With `"async": true` it answers `202` at once; sources still working are `pending`, each source's results are stored as soon as it answers, and `progress: {total, pending}` on `GET /api/intel/runs/{id}` shows how far it is. Runs left `running` by a restart become `interrupted` at startup |
| GET | `/api/intel/runs?limit=` | Recent runs |
| GET | `/api/intel/runs/{id}` | One run with per-source status and results |
| GET | `/api/intel/keys` | Key providers: `configured`, last-four `hint`, sign-up link (never the key) |
| PUT | `/api/intel/keys/{provider}` | Save the operator's key: `{key}` |
| DELETE | `/api/intel/keys/{provider}` | Remove a saved key |

Run payload: `{value, type?, connectors?, investigation_id?, use_cache?}`.
`type` is optional; when given it must match the detected type. Supported
types: `domain`, `ipv4`, `ipv6`, `cidr`, `url`, `email`, `md5`, `sha1`,
`sha256`, `asn`, `cve`.

Each source reports one status: `ok`, `empty`, `error`, `rate-limited`,
`network-disabled`, `target-contact-disabled`, `key-missing` or `unsupported`. Each result carries `connector_id`,
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
| `tls-certificate` | domain, URL, IP | **contacts target** | one TLS handshake on port 443 | 1 h |
| `web-fingerprint` | domain, URL, IP | **contacts target** | one HTTPS GET of the page and its same-host favicon | 1 h |
| `shodan-internetdb` | IP | yes | Shodan InternetDB: ports, hostnames, CPEs, tags, CVEs | 12 h |
| `ripestat` | IP, CIDR, ASN | yes | RIPEstat: origin AS, holder, announced prefixes, abuse contact | 6 h |
| `peeringdb` | ASN | yes | PeeringDB network record | 24 h |
| `ipinfo` | IP | yes (optional key) | IPinfo: network owner, reverse name, network location | 24 h |
| `circl-hashlookup` | MD5, SHA-1, SHA-256 | yes | CIRCL hashlookup known-software sets (NSRL and others) | 7 d |
| `urlscan` | domain, IP, URL, SHA-256 | yes (optional key) | urlscan.io public search; `relation` is `page` or `loaded-resource` | 1 h |
| `certspotter` | domain, URL | yes | Cert Spotter CT issuances and subdomains | 6 h |
| `nvd` | CVE | yes (optional key) | NVD CVE record: CVSS, CWE, references | 24 h |
| `osv` | CVE | yes | OSV.dev affected packages (follows the GHSA alias) | 24 h |
| `greynoise` | IPv4 | yes (optional key) | GreyNoise Community classification | 6 h |
| `otx` | IP, domain, URL, hashes, CVE | yes (optional key) | AlienVault OTX pulses, malware families, ATT&CK IDs | 6 h |
| `shodan` | IP | yes (optional key) | Shodan host: services, banners, TLS names, inferred CVEs | 12 h |
| `virustotal` | IP, domain, URL, hashes | **key required** | VirusTotal v3 detections, threat label, tags, context | 6 h |
| `abuseipdb` | IP | **key required** | AbuseIPDB 90-day reports and confidence score | 6 h |
| `urlhaus` | URL, domain, IPv4, MD5, SHA-256 | **key required** (abuse.ch) | URLhaus malware URLs and payloads | 1 h |
| `threatfox` | IPv4, domain, URL, MD5, SHA-256 | **key required** (abuse.ch) | ThreatFox IOCs and malware families | 1 h |
| `malwarebazaar` | MD5, SHA-1, SHA-256 | **key required** (abuse.ch) | MalwareBazaar sample record | 24 h |

Keys are stored by migration 6 in `intel_api_keys` on this machine, sent only
to their provider in its documented header (Shodan: query parameter, never
stored in result URLs) and replaced by `***` in error messages. A keyed
connector without a key reports `key-missing` and makes no request.

Connectors marked **contacts target** reach the artifact's own servers and run
only when both `intel.allow_network` and `intel.allow_target_contact` are
`true` (both default `false`); otherwise their status is
`target-contact-disabled`. They fetch over HTTPS only (an `http://` artifact is
upgraded), never guess paths or scan ports, and the web fingerprint refuses to
send a request over a TLS connection that fails verification. The certificate
connector still analyses an untrusted certificate by completing a second,
unverified handshake that sends no data.

Certificates are parsed by `modules/x509.py` (DER, no dependencies): names,
validity, SANs, key type and size, signature algorithm, SHA-256/SHA-1, SPKI pin
and AIA/CRL/SCT/EKU extensions. Favicon hashes use MurmurHash3 over base64 text
(Shodan `http.favicon.hash` compatible).

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

## Analytics

`GET /api/analytics?investigation_id=&days=` (`days` is 7, 30, 90 or 365)
returns `totals`; `activity` (`days` plus one series per action) and
`intel_runs_by_day`; `entity_types`, `relationship_types` and
`relationship_verification`; per-source `sources` (`results`, `runs`,
`errors`, `statuses`); `result_types`; `file_formats`, `finding_levels` and
`finding_codes`; and `evidence_types`. Scoped to one investigation when given.
Counts only; every number can be traced to rows elsewhere in the workspace.

## Graph analytics and pivot

Graph nodes and edges include `created_at`. The UI offers eight layouts (force,
community, hierarchical, radial, concentric by betweenness, columns by type,
circle, grid), node size by degree, betweenness or harmonic closeness, focus
on 1-3 hops, edge labels and direction arrows, an adjacency matrix ordered by
community, a recording timeline and a standalone SVG export of the visible
graph.

`GET /api/graph` now also returns `analytics`: `{engine, communities,
modularity, nodes: {id: {degree, betweenness, harmonic, community,
community_size}}}`, computed on the simple undirected graph (duplicates and
self-loops ignored). `GET /api/graph/path?from=&to=&investigation_id=` returns
the shortest chain of recorded relationships.

`POST /api/graph/import` with `{content, format: "graphml"|"json", file_name?,
investigation_id?, commit?}` previews (default, `200`) or commits (`201`) a
graph built elsewhere. JSON may be this app's export, Cytoscape (`elements`),
D3 (`nodes`/`links`) or a plain `nodes`/`edges` object; GraphML keys are read
by `attr.name`, and Maltego type names are mapped. Each node becomes an entity
or reuses the one with the same type and identifier (name for name-only
types); each edge becomes an unconfirmed, not-verified relationship that cites
`note://garbage/graph-import/{sha256 prefix}`. Unknown relationship labels map
to `related-to` and keep the original label in the description. Limits: 8 MiB,
2,000 nodes, 5,000 edges. A DTD or entity declaration is rejected before
parsing. The response counts new and existing entities and relationships,
invalid nodes and skipped edges, and lists up to 50 problems.

The graph view adds multi-selection (Shift+click, Shift+drag box, Ctrl+A),
pinned and hidden nodes (saved per case in the browser), undo and redo of
view changes, a minimap, type glyphs on nodes, PNG export at twice the screen
resolution (the CSP allows `blob:` images for this), GraphML and JSON export
with positions, and restoring a layout from a JSON export.

`POST /api/intel/runs/{id}/promote` with `{source_entity_id, investigation_id?,
items: [{result_id, entity_type?, relationship_type?}]}` turns selected findings
into entities (existing ones are reused) and relationships from the source
entity, with confidence `possible`, status `not-verified` and the finding's
source URL as reference. Duplicate relationships and unusable findings (null
MX, the source itself) are reported under `skipped`.

### Organisation sources

- `github` (URL on github.com): an organisation's public profile, site and up
  to 30 repositories, or one repository's metadata, homepage, licence and fork
  parent. A personal account returns only a notice; nothing about people is
  collected. Unauthenticated GitHub API (60 requests per hour per IP).
- `security-txt` (domain or URL, target contact): the RFC 9116 file at
  `/.well-known/security.txt`: contacts, policy, encryption key, expiry
  (and whether it has expired) and PGP signature. A non-text answer or one
  without `Contact:` is reported as not published.

## Transforms

A transform is a connector run from an entity. It accepts the entity's
canonical artifact, runs through the same gates, cache and rate limits as a
multi-source query, and turns declared result types into entities linked to
the input (confidence `possible`, status `not-verified`, source URL as
reference). Person, username and profile entities are never inputs.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/transforms?entity_id=` | Transforms for an entity (or all): `kind` (`pivot` or `enrichment`), `inputs`, `outputs` (`result_type`, `entity_type`, `relationship_type`), `availability`, `estimate_ms` (mean of real, uncached runs) and `estimate_samples` |
| POST | `/api/transforms/run` | `{entity_id, transforms: [ids], investigation_id?, parameters?}`; parameters are `use_cache` (true), `promote` (true) and `max_new_entities` (1-50, default 25). Returns one log per transform |
| GET | `/api/entities/{id}/transforms` | Enrichment history of the entity, newest first |

Each log holds `status`, `result_count`, `created_count`, `reused_count`,
`relationship_count`, `duration_ms`, `parameters` and `log`, a list of events:
`input`, `source` (status, count, cached, elapsed, error), `limit`,
`not-promoted` and `promoted`.

## Entity resolution

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/resolution/candidates?investigation_id=&level=` | Candidate duplicates with `level` (`exact`, `probable`, `weak`), `rule`, `detail` and both entities |
| POST | `/api/resolution/dismiss` | `{first, second, note?}`: the pair is distinct and is not proposed again |
| POST | `/api/resolution/merge` | `{keep_id, merge_id, note?, level?}`: moves relationships, case links, sources, board elements and transform history to `keep_id`, drops duplicate edges and self-loops, deletes `merge_id` and records it as an alias |
| GET | `/api/entities/{id}/aliases` | Entities merged into this one |

Rules: `same-artifact` (exact; same canonical value under different entity
types), `organization-name` (exact when the names are equal ignoring case,
otherwise probable; legal suffixes, accents and punctuation removed),
`www-prefix` and `url-variant` (probable), `same-label-other-suffix` and
`similar-organization-name` (weak). Person, username and profile entities are
never compared.

## Modules

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/modules` | Registry with states and counts |
| PATCH | `/api/modules/{module_id}` | Set `enabled` or `disabled` |

Enabling a `planned` module returns `409`. Built-in modules cannot be removed.

Disabling `external-osint-connectors`, `nvd-connector` or `cisa-kev` turns the
matching connectors off (`module-disabled` in runs and listings).
`transforms`, `entity-resolution`, `attack-matrix`, `yara-rules`, `analytics`
and `cti-export` gate their routes; with `yara-rules` disabled, file analyses
skip the YARA scan.

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
