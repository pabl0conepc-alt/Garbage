# OpenArchive feature matrix

Research date: 2026-11-12, updated 2026-11-14. This document is an inventory,
not a parity claim.
No OpenArchive source code was copied into GARBAGE.

## 1. Which project is "OpenArchive"?

There is no single obvious upstream that matches the request's full list of
OSINT, CTI, file-analysis and investigation features. The name resolves to at
least two unrelated projects.

| Candidate | What it is | Evidence | Licence |
| --- | --- | --- | --- |
| **OpenArchive Save** | A mobile media-preservation app for iOS and Android, with a Rust DWeb backend. This is the recognized OpenArchive project. | <https://www.open-archive.org/save>, <https://github.com/OpenArchive>, <https://github.com/OpenArchive/Save-app-ios>, <https://github.com/OpenArchive/Save-app-android> | GPL-3.0 for the mobile apps; individual repositories differ |
| **openarchive-server** | An unrelated Korean AI document-management package (OpenSQL/PostgreSQL + pgvector, OCR, chunking, embeddings, REST/MCP). | <https://pypi.org/project/openarchive-server> | MIT |
| **Other "OpenArchive" clones** | No maintained OSINT/CTI platform with this name was verified. Search results are dominated by the Save app and the package collision. | — | — |

### Scope decision

GARBAGE uses **OpenArchive Save** as the only OpenArchive reference, and only
for media-preservation functions. The request's OSINT, CTI, graph, board,
automation and binary-analysis scope is treated as **GARBAGE-native work**, not
as OpenArchive parity. Where a requested feature has no verified OpenArchive
implementation, the matrix says so.

This decision is documented so the work is auditable. If the intended reference
is `openarchive-server` or a private project, the matrix must be revised before
claiming any compatibility.

## 2. What Save actually does

Verified from the OpenArchive wiki and repository organization:

- Capture or select photos, video and audio on a phone.
- Add notes, location and project-folder context to individual or batch uploads.
- Send media to Nextcloud/WebDAV, the Internet Archive or other configured
  servers; the DWeb backend explores Veilid/Iroh replication.
- Compute SHA-256 hashes and optionally attach ProofMode capture evidence.
- Protect transport with TLS and optionally route through Orbot/Tor.
- Add Creative Commons licensing metadata.
- Organize uploads into project folders and control server access.
- It does **not** provide the archive itself, an investigation case manager,
  entity correlation, website/domain/IP reconnaissance, threat intelligence,
  binary analysis or automated OSINT.

## 3. Capability matrix

Status meanings:

- **Implemented** — backend, persistence and tests exist in this repository.
- **Partial** — a real subset exists; the missing part is named.
- **Planned** — documented but not implemented; no UI button claims otherwise.
- **N/A** — deliberately outside this local workstation's scope.

| Capability | OpenArchive Save status | GARBAGE status | Implementation | Improvement | Tests |
| --- | --- | --- | --- | --- | --- |
| SHA-256 media/file integrity | Yes, per upload | Implemented | `evidence.py`, `modules/file_intel.py`; SHA-256, SHA-1 and MD5 for analysis; evidence re-verification | Integrity is a first-class record with a verification status and activity entry | `test_evidence.py`, `test_file_intel.py` |
| Capture context / notes / metadata | Notes, location, project folders | Implemented (desktop) | Investigations, observations, sources, evidence acquisition context | Context is linked to cases, entities and reports rather than one upload | `test_store.py`, `test_workspace.py` |
| Project folders | Yes | Implemented equivalent | Investigations, case tabs, boards | Shared registry across cases; layered board and graph | `test_boards.py`, `test_entities.py` |
| Optional ProofMode capture proof | Yes | Planned | Not implemented; no sensor/notarization integration exists | Would need a verified ProofMode-compatible library and device capture | — |
| Upload to Internet Archive / WebDAV / Nextcloud | Yes | N/A (local only) | No remote upload or credentials | Local-first design; remote connectors are a separate security decision | — |
| Tor / Orbot transport | Yes | N/A | Loopback HTTP only | Deliberately not exposed remotely | `test_api.py` host/origin guards |
| Creative Commons licensing | Yes | Planned | Not implemented | Low priority for investigation records | — |
| Mobile capture client | Yes | N/A | No mobile app | Desktop investigation workstation | — |
| Media/file format identification | Not a Save feature | Implemented | `modules/file_intel.py`, `modules/imaging.py` | PDF, OOXML, ZIP/TAR/GZIP, images, ELF/PE/Mach-O | `test_file_intel.py`, `test_imaging.py` |
| File metadata extraction | Partial (media metadata) | Implemented | PDF properties, OOXML core properties, full EXIF with GPS (author and serial only as presence), archive listings, binary headers | Single analysis record with hashes, findings and limitations | `test_file_intel.py`, `test_geoint.py` |
| Archive inspection without extraction | No | Implemented | ZIP/OOXML/EPUB/JAR/APK central directories; TAR headers; GZIP preview cap | Traversal, encryption, macro and bomb indicators; no disk extraction | `test_file_intel.py` |
| Binary static analysis | No | Implemented (headers/sections/imports) | ELF, PE, Mach-O parsers in `modules/file_intel.py` | Architecture, entry point, sections, imports, compile timestamp, no execution | `test_file_intel.py` |
| Image intelligence | Media images | Implemented | Format, dimensions, hashes, EXIF, pHash/dHash and visually similar images; local map of GPS positions | No face recognition or invented geolocation | `test_imaging.py`, `test_geoint.py` |
| Entity registry | No | Implemented | `entities.py`, UI entity manager | Canonical records shared by cases, board and graph | `test_entities.py` |
| Relationship graph | No | Implemented | `entities.graph_payload`, `web/graph*.js` | Eight layouts (Barnes-Hut force above 200 nodes), multi-select, pin/hide, undo/redo, minimap, matrix and timeline views, path finding, PNG/SVG/GraphML/JSON export and import; up to 5,000 nodes, cut by degree with a notice | `test_entities.py`, `test_graph_io.py` |
| Investigation board | No | Implemented | `boards.py`, persisted layout with revisions | Entity cards, notes, groups, connections, layers, autosave, SVG export | `test_boards.py`, UI smoke |
| Source provenance | Partial (upload context) | Implemented | `sources.py`; source links to cases/entities | Access time and verification status | `test_sources` coverage in `test_api.py`/`test_workspace.py` |
| Exact-value indicator correlation | No | Implemented | `modules/indicators.py`, `modules/correlation.py` | Provenance retained; correlation is not attribution | `test_indicators.py` |
| Global search | No | Implemented (FTS5) | `workspace.global_search` | BM25 ranking, highlighted snippets, accent-insensitive prefix search, "best" group; LIKE fallback without FTS5 | `test_search.py`, `test_workspace.py` |
| SQLite FTS5 search | No | Implemented | Migrations 9 and 14, triggers keep the index current | Covers cases (with objective), entities, sources, evidence, observations and file analyses | `test_search.py`, `test_e2e.py` |
| CISA KEV metadata | No | Implemented | `modules/cisa_kev.py` | Explicit refresh, bounded download, hashed snapshot | `test_cisa_kev.py` |
| Website intelligence | No | Implemented | `tls-certificate`, `web-fingerprint`, `security-txt`, `wayback`, `urlscan` connectors through the SSRF-safe fetcher | Contacting the target has its own switch; passive sources are preferred | `test_intel_target.py`, `test_intel_connectors.py` |
| Domain / IP intelligence | No | Implemented | DNS over HTTPS, RDAP, Team Cymru, RIPEstat, PeeringDB, IPinfo, Shodan InternetDB, CT logs (crt.sh, Cert Spotter) | Per-source status, cache, rate limits, provenance | `test_intel_sources.py`, `test_intel_connectors.py` |
| OSINT connectors | No | Implemented (31) | `garbage_intel/modules/intel_*`; reputation (AbuseIPDB, GreyNoise, OTX, VirusTotal, URLhaus, ThreatFox, MalwareBazaar), vulnerabilities (NVD, EPSS, OSV, KEV), organisations (GitHub, security.txt) | Network off by default; keys local and never returned; people are out of scope | `test_intel*.py` |
| Automation engine | No | Partial | Transforms (typed connector runs from an entity) and monitors (saved queries on a schedule with differences and notifications) | No free-form flow runner: nothing executes arbitrary commands | `test_foundation.py`, `test_monitoring.py` |
| Plugin SDK | No | Implemented | `plugins.py`, `plugin_runner.py`, `examples/plugins/idn-inspect` | Manifest, declared permissions, approval by code SHA-256, separate process with brokered network; plugins become transforms | `test_plugins.py` |
| Native C / C++ / Rust engines | Rust backend exists for DWeb, not analysis | Optional helpers | C hardening, C++ graph metrics and Rust domain similarity with Python fallbacks | No downloaded libraries; native code never executes input | `native/README.md` |
| PDF report export | No | Partial | HTML, JSON, CSV and Markdown with chosen sections; the printable page prints to PDF from the browser | No native PDF writer (would need a dependency) | `test_cases.py`, `test_e2e.py` |
| STIX / TAXII / ATT&CK | No | Implemented | Offline ATT&CK with case techniques, TAXII 2.1 client with paged pull, Sigma rules, STIX 2.1 / MISP / IOC export with TLP | Imported indicators keep collection and object provenance | `test_attack.py`, `test_feeds.py`, `test_cti_export.py` |
| Case package and chain of custody | No | Implemented | `cases.py`, `custody.py` | Whole case with files in one digest-checked package; hash-chained custody log per evidence item | `test_cases.py`, `test_e2e.py` |
| Monitoring and notifications | No | Implemented | `monitoring.py` | Scheduled multi-source queries, differences per run, notification bell | `test_monitoring.py`, `test_e2e.py` |
| Entity resolution | No | Implemented | `resolution.py` | Exact, probable and weak candidates with the rule shown; analyst-approved merge with aliases | `test_foundation.py` |
| Authentication / TLS / remote deployment | N/A | N/A (local only) | Loopback server, no accounts | Must not be exposed remotely | `test_api.py` |

## 4. Deliberate non-goals

- No mobile capture, camera roll access, ProofMode notarization or remote
  upload parity.
- No credential theft, authentication bypass, account intrusion, doxxing or
  covert collection.
- No exploit execution, malware persistence, evasion or automated intrusion.
- No claim that a syntactic indicator is malicious, attributed or verified.

## 5. Resolution (2026-11-12)

The operator identified the reference as **openarchivex.net** ("OpenArchive
X"), a commercial OSINT and breach-search service. Its scope and what GARBAGE
adopts or refuses are recorded in [PLANO_OSINT_CSINT.md](PLANO_OSINT_CSINT.md).
The section below is kept for history.

## 6. Original open question

If the intended reference is **not** OpenArchive Save, stop and identify the
exact repository and commit before extending this matrix. The current matrix
cannot certify compatibility with an unnamed project.

## 7. OpenArchive X comparison (2026-11-14)

Functions announced on openarchivex.net (see
[PLANO_OSINT_CSINT.md](PLANO_OSINT_CSINT.md)) against what GARBAGE ships.
Only what both sides document is compared; nothing here measures the
commercial service.

| OpenArchive X | GARBAGE | Notes |
| --- | --- | --- |
| Multi-Source Search, 60+ sources | 31 connectors on infrastructure and threats, plus local plugins | Fewer sources by count; every one is public and lawful, cached, rate-limited and shown with its own status. Plugins add more without changing the core |
| Real-time source status | Per-source status while a query runs (pending, answered, empty, error, cached) | Elapsed time and the error text are kept with each source result |
| OSINT Pivot, recursive graph | Transforms from any entity, one hop at a time, with a cap on new entities | Each hop is approved by the analyst and logged in the entity's history |
| IP Lookup (geo, ASN, network) | RDAP, Team Cymru, RIPEstat, PeeringDB, IPinfo, InternetDB; approximate location on the GEOINT map | Location is marked approximate, with its source |
| Investigation Board | Board plus relationship graph, matrix and timeline | Layers, autosave, export and import |
| REST API, JSON/CSV export | Local REST API; JSON, CSV, Markdown, HTML, STIX 2.1, MISP, IOC lists, GraphML; case packages | Loopback only |
| — | Evidence custody, file intelligence, YARA, ATT&CK, Sigma, TAXII, monitoring, entity resolution, reports with methodology | Not announced by OpenArchive X |
| Breach databases, stealer logs | Not implemented | Personal data and stolen credentials; refused |
| Discord/Telegram/Roblox, phone, VIN, account "spider" | Not implemented | People tracking; refused |
| "No logs, no traces" | Not implemented | GARBAGE keeps an audit trail and provenance by design |
