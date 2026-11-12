# Development status

Updated for branch `feature/garbage-universal-intelligence-platform`.

## Implemented and tested

### Core and workspace

- SQLite storage with additive migrations, now at schema version 3.
- Investigations with open/closed/cancelled lifecycle, append-only status
  events and read-only enforcement for closed cases.
- Observations with source reference, collection basis, observation time and
  recording time.
- Global search across records, activity feed, application settings and an
  auditable module registry.
- JSON/SQLite backup and validated, transactional JSON import.

### Intelligence records

- Entity registry with aliases, type, identifier, confidence and verification.
- Directed relationships with provenance, confidence, cycle-safe deletion and
  graph payloads.
- Source registry with verification state, case links and entity links.
- Exact-value indicator extraction (IPv4, domains, URLs, emails and hashes),
  deduplication, provenance and manual assessment.
- Cross-record correlation; explicitly a match, not attribution.

### Evidence and files

- Evidence upload with SHA-256 record, re-verification, download, safe image
  preview and deletion.
- Image structure inspection.
- File Intelligence:
  - bounded 4 MiB static analysis, no execution or extraction;
  - SHA-256/SHA-1/MD5, entropy, magic bytes and printable strings;
  - PDF metadata, page estimate and active-content declarations;
  - ZIP/OOXML/EPUB/JAR/APK central-directory listing with traversal, encryption
    and macro flags;
  - TAR listing and bounded GZIP preview;
  - PNG/JPEG/GIF/WebP/BMP dimensions;
  - ELF, PE and Mach-O headers, sections, imports and architecture;
  - findings and syntactic indicators;
  - persistent history, API, UI and optional evidence attachment.

### Investigation presentation

- Persisted board with cards, notes, groups, connections, layers, viewport,
  optimistic revisions, keyboard movement, autosave and SVG export.
- Relationship graph with filters, focus, search, pan/zoom, drag and layered
  export.
- Full workstation UI: overview, cases, case file, activity, entities,
  indicators, files, evidence, sources, reports, modules, settings, CISA KEV.
- Loading, empty and error states; command palette; global search; dialogs.

### CTI and distribution

- CISA KEV read-only connector with explicit refresh, fixed host, timeouts,
  byte cap, redirect restriction, conditional requests, content digest and
  offline cache.
- Loopback-only API with Host/Origin checks, body limits, static allowlist,
  CSP, `no-store`, `nosniff` and `no-referrer`.
- Python 3.10+ launchers for POSIX and PowerShell, plus a dependency-free
  zipapp builder.

## Verification performed

- `python3 -m unittest discover -s tests` — **84 tests passed**.
- `python3 -m compileall -q garbage_intel tests` — passed.
- `node --check` on all browser scripts — passed.
- jsdom route smoke with a seeded database — every route rendered, **0 failure
  records, 0 console errors**, including board and graph node/edge counts.
- `git diff --check` — run before the commit.

Not verified:

- Real-browser E2E, CSS visual regression, native file picker and drag-and-drop.
- Windows/macOS execution in this environment. The CI matrix is configured but
  was not observed running here.
- Any native component; none exists.
- PDF export; not implemented.

## Not implemented

- Website, domain, IP and DNS intelligence collectors.
- NVD, external OSINT, STIX/TAXII, ATT&CK or MISP connectors.
- Automation runner and dynamic plugin loader.
- Native C, C++ or Rust engines and their fallbacks.
- FTS5 ranked search.
- PDF report output.
- Full media forensics (EXIF/XMP/video/audio) and chain-of-custody notarization.
- Authentication, roles, TLS or remote deployment.

These are represented as `planned` modules or documented roadmap items; no UI
button claims they work.

## Platform and dependency status

- Python 3.10+ standard library only. No third-party Python dependency.
- Tested in this workspace on Linux with Python 3.14.x and SQLite 3.53.x.
- `gcc`, `g++` and `make` are available; `cargo`, `rustc` and `cmake` are not.
- Node.js is used only for syntax checks and a temporary jsdom smoke harness; it
  is not a runtime dependency.
- No system packages were installed for the project.

## OpenArchive note

OpenArchive is ambiguous. The recognized project, **OpenArchive Save**, is a
mobile media-preservation app (GPL-3.0); `openarchive-server` on PyPI is an
unrelated document platform (MIT). No verified OpenArchive OSINT platform was
found. GARBAGE claims no parity. The evidence and scope decision are recorded in
[docs/OPENARCHIVE_FEATURE_MATRIX.md](docs/OPENARCHIVE_FEATURE_MATRIX.md).

## Release state

Work is committed on `feature/garbage-universal-intelligence-platform` and
prepared for a pull request titled **Garbage — Universal Intelligence Platform**.
The pull request is not merged automatically.
