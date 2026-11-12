# OpenArchive feature matrix

Research date: 2026-11-12. This document is an inventory, not a parity claim.
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
| File metadata extraction | Partial (media metadata) | Implemented (bounded) | PDF properties, OOXML core properties, EXIF-free image dimensions, archive listings, binary headers | Single analysis record with hashes, findings and limitations | `test_file_intel.py` |
| Archive inspection without extraction | No | Implemented | ZIP/OOXML/EPUB/JAR/APK central directories; TAR headers; GZIP preview cap | Traversal, encryption, macro and bomb indicators; no disk extraction | `test_file_intel.py` |
| Binary static analysis | No | Implemented (headers/sections/imports) | ELF, PE, Mach-O parsers in `modules/file_intel.py` | Architecture, entry point, sections, imports, compile timestamp, no execution | `test_file_intel.py` |
| Image intelligence | Media images | Implemented (structural) | Format, dimensions, hashes; EXIF extraction is limited | No face recognition or invented geolocation | `test_imaging.py` |
| Entity registry | No | Implemented | `entities.py`, UI entity manager | Canonical records shared by cases, board and graph | `test_entities.py` |
| Relationship graph | No | Implemented | `entities.graph_payload`, SVG graph UI | Filters, focus, layers, drag, pan/zoom, provenance | `test_entities.py`, UI smoke |
| Investigation board | No | Implemented | `boards.py`, persisted layout with revisions | Entity cards, notes, groups, connections, layers, autosave, SVG export | `test_boards.py`, UI smoke |
| Source provenance | Partial (upload context) | Implemented | `sources.py`; source links to cases/entities | Access time and verification status | `test_sources` coverage in `test_api.py`/`test_workspace.py` |
| Exact-value indicator correlation | No | Implemented | `modules/indicators.py`, `modules/correlation.py` | Provenance retained; correlation is not attribution | `test_indicators.py` |
| Global search | No | Implemented (LIKE) | `workspace.global_search` | Grouped results across records | `test_workspace.py` |
| SQLite FTS5 search | No | Planned | Not implemented; FTS5 availability is probed | Would add ranked full-text search with filters | — |
| CISA KEV metadata | No | Implemented | `modules/cisa_kev.py` | Explicit refresh, bounded download, hashed snapshot | `test_cisa_kev.py` |
| Website intelligence | No | Planned | No HTTP fetcher; SSRF-safe design required first | DNS/TLS/headers/robots/sitemap are not implemented | — |
| Domain / IP intelligence | No | Planned | No WHOIS/ASN/geoip connector | Requires authorized public sources and rate limits | — |
| OSINT connectors | No | Planned (`external-osint-connectors` state) | Registry entry only; cannot be enabled | No fake modules or results | `test_workspace.py` module gate |
| Automation engine | No | Planned | No flow runner or scheduler | Design must forbid arbitrary command execution | — |
| Plugin SDK | No | Partial (documented contract) | `docs/MODULE_DEVELOPMENT.md`; no dynamic loading | Allowlist and in-process contracts before code | — |
| Native C / C++ / Rust engines | Rust backend exists for DWeb, not analysis | Optional helpers | C hardening, C++ graph metrics and Rust domain similarity with Python fallbacks | No downloaded libraries; native code never executes input | `native/README.md` |
| PDF report export | No | Planned | HTML, JSON, CSV and Markdown exist | PDF requires a justified dependency or a print workflow | `test_reporting` coverage via API/CLI |
| STIX / TAXII / ATT&CK | No | Planned | Not implemented | No unverified feed integration | — |
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
