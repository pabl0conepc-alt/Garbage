# GARBAGE

GARBAGE is a local-first investigation workstation for structured case work:
sources, evidence, entities, relationships, timelines, boards, graph analysis,
indicator extraction and bounded static file intelligence, in one SQLite-backed
application.

It runs on Python 3.10+ with **no third-party Python dependencies**, serves a
vanilla HTML/CSS/JavaScript interface on loopback, and can be packaged as a
zipapp. There is no telemetry, no cloud account and no hidden collection.

> GARBAGE is for lawful, authorized analysis. It does not exploit systems,
> bypass authentication, execute submitted files or perform covert collection.
> It is not a multi-user service and must not be exposed to a network.

## What is implemented

| Area | Capability |
| --- | --- |
| Cases | Investigation lifecycle, observations, status timeline, report and JSON/CSV/Markdown/HTML export |
| Sources | Source registry with references, categories, access time and verification state; links to cases and entities |
| Entities | Canonical entity registry with aliases, confidence, verification and relationships |
| Analysis | IPv4, IPv6, CIDR, domain, URL, email and hash extraction with refanging, canonical values, provenance, cross-source correlation and manual assessment |
| Evidence | Upload, SHA-256 integrity record, verification, download and safe image preview |
| File intelligence | Bounded static analysis of PDF, OOXML/ZIP, TAR, GZIP, images, ELF, PE and Mach-O; hashes, entropy, strings, metadata, archive listing, findings and history; optional C scanner for ELF/PE hardening markers (PIE, NX, RELRO, bind-now, canary, Fortify, ASLR, CFG) |
| Board | Persisted investigation board with cards, notes, groups, connections, layers, autosave, conflict handling and SVG export |
| Graph | Relationship graph with type filters, focus, search, pan/zoom, drag and layered export; optional C++ metrics for components, density, isolates, degrees and reciprocal links |
| CTI | CISA KEV catalogue with explicit refresh, bounded download, provenance and offline cache |
| System | Global search, settings, activity log, module registry with capability gating |

The **module registry** is the source of truth. Modules without a tested backend
are marked `planned` and cannot be enabled; the UI does not show navigation for
them. Current planned modules are the NVD connector, external OSINT connectors
and expanded media forensics.

## Quick start

Clone the repository and run from its root.

Linux/macOS:

```sh
./scripts/run.sh doctor
./scripts/run.sh init
./scripts/run.sh serve --port 8765
```

Windows PowerShell:

```powershell
.\scripts\run.ps1 doctor
.\scripts\run.ps1 init
.\scripts\run.ps1 serve --port 8765
```

Open <http://127.0.0.1:8765/>. The same server exposes the JSON API at
`/api`. The server binds to loopback only and has no authentication.

Equivalent direct invocation:

```sh
python3 -m garbage_intel doctor
python3 -m garbage_intel init
python3 -m garbage_intel serve --port 8765
```

Select a different database with `--database PATH` or `GARBAGE_DATABASE`.
Evidence bytes are stored next to the database by default.

### Zipapp

```sh
python3 tools/build_zipapp.py
python3 dist/garbage.pyz doctor
python3 dist/garbage.pyz serve --port 8765
```

The build refuses to overwrite an existing output; pass `--output PATH` for a
new artifact. The zipapp still requires Python 3.10+ on the target machine.

## Using the interface

- **Overview** — counts, recent activity, case health and quick entry points.
- **Investigations** — create, edit, close and reopen cases; each case file has
  observations, sources, entities, evidence, indicator, timeline, report, board
  and graph tabs. **Coverage review** lists factual attention items such as
  observations without a source, unverified evidence or unassessed indicators;
  it is not a risk score.
- **Entities** — canonical records shared across cases, with aliases, source
  links and relationships.
- **Indicators** — extracted values grouped by type, with provenance and analyst
  assessment. **Text triage** (`T`) extracts indicators from pasted text in
  memory without storing it. **Inspect value** explains one URL, address, CIDR,
  domain, hash, email, ASN or filename and lists exact local matches,
  co-occurring values and structural domain lookalikes with a Rust fast path.
  **Cross-source matches** show observation count,
  independent source count and a corroboration strength. Matches are not
  reputation verdicts.
- **File intelligence** — select or drop a file up to 4 MiB; results include
  hashes, format, entropy, strings, metadata, structure, findings, binary
  hardening markers and embedded indicators. An analysis can be attached to an
  open case as evidence.
- **Evidence** — upload with acquisition context, verify integrity, preview
  supported images.
- **Sources** — record where material came from and how it was obtained.
- **Boards** — arrange entity-backed cards and notes, connect them, group them
  into layers and export the board as SVG.
- **Graph** — inspect recorded relationships; layout is client-side and derived
  only from stored entities and edges.
- **Threat intel** — view the cached CISA KEV catalogue and refresh it
  explicitly. Page loads never contact CISA.
- **Modules / Settings** — inspect capability state, storage and preferences.
- **Command palette** (`Ctrl/⌘ K` or `/`) — search local records or run quick actions
  such as creating a case, registering an entity, adding evidence and switching density.
- **Display menu** (◐) — persist theme, comfortable/compact density and reduced motion
  without opening Settings.
- **Keyboard shortcuts** (`?`) — search, new case, refresh and dialog controls.
- **Mobile navigation** — a slide-out drawer keeps every module reachable on small screens;
  dialogs become bottom sheets and tables scroll horizontally.

Closed or cancelled cases are read-only until reopened. Actions that mutate a
case report structured errors rather than silently succeeding.

## Indicator precision

- Common defanged notation (`hxxp`, `[.]`, `(.)`, `[:]`, `[at]`) is refanged
  before matching. Text triage reports whether the input was defanged.
- The host inside a URL or email is not emitted as a second domain indicator.
  The URL or email is the observed value, and duplication would inflate counts.
- A final label that is a common non-TLD file suffix (`report.pdf`, `image.png`)
  is treated as a filename, not a domain. Real TLDs such as `.zip`, `.md`, `.sh`
  and `.py` are not excluded.
- IPv6 and CIDR candidates are validated with `ipaddress`; clock times, MAC
  addresses and malformed ranges are rejected. IPv4-mapped IPv6 stays one
  value instead of becoming a bogus IPv6 fragment plus an IPv4 address.
- Bracketed IPv6 URLs keep their brackets when canonicalized, and scoped
  link-local values keep their zone for inspection.
- Correlation counts distinct observations and distinct source references.
  Two observations from the same source are not called independent evidence.
- All values remain syntactic. No DNS, WHOIS, reputation or attribution lookup
  is performed by the indicator tools.

## File intelligence limits

- 4 MiB decoded input.
- Base64 body up to 6 MiB; invalid base64 is rejected.
- 500 archive members listed, 1 MiB GZIP preview, 150 strings, 96 sections and
  80 imports.
- Nothing is executed, emulated, mounted or extracted. Archive path traversal
  and macros are reported, not followed.
- Binary parsing is header/section oriented; it is not disassembly, malware
  detonation or a safety verdict.
- Embedded indicators are syntactic string matches. They are not checked
  against reputation services and do not imply attribution.

## CLI

```sh
python3 -m garbage_intel init
python3 -m garbage_intel investigation create --name "Example investigation"
python3 -m garbage_intel investigation list
python3 -m garbage_intel observation add \
  --investigation-id INVESTIGATION_ID \
  --title "Public notice" \
  --content "A concise description." \
  --source-reference "https://example.org/notice" \
  --collection-basis public \
  --observed-at "2025-01-02T03:04:05Z"
python3 -m garbage_intel report --investigation-id INVESTIGATION_ID --format html
```

Collection basis must be `public`, `authorized` or `user-provided`. Reports are
escaped and printable. CSV exports prefix formula-like cells.

Backup and restore:

```sh
python3 -m garbage_intel backup --output archive.json
python3 -m garbage_intel --database restored.sqlite3 import --input archive.json
```

JSON imports are capped at 10 MiB, fully validated before changes, transactional
and refuse to overwrite existing records. SQLite backups are also available with
`backup --format sqlite`. Both formats refuse to replace an existing file.

CISA KEV:

```sh
python3 -m garbage_intel intel kev refresh
python3 -m garbage_intel intel kev status
python3 -m garbage_intel intel kev list --search "Example Vendor"
```

The connector uses the fixed public CISA feed, a 10-second timeout, a 10 MiB
response cap, HTTPS CISA-host redirects and a 15-minute freshness window.
`--force` bypasses the window but still performs one request. It does not scan
targets or take action.

Single-file hashing and document metadata (read-only):

```sh
python3 -m garbage_intel forensics hash-file \
  --investigation-id INVESTIGATION_ID --path /path/to/authorized/evidence.bin
python3 -m garbage_intel forensics document-metadata --path /path/to/document.pdf
```

## Architecture

```text
web/ (vanilla JS) ── same-origin JSON ──> garbage_intel/api.py
                                              │
                                              ├─ validation + module gate
                                              ├─ store / entities / sources / evidence / boards
                                              ├─ modules/ (indicators, hardening, lookalikes, imaging, file_intel, kev)
                                              ├─ optional native/ C, C++ and Rust helpers
                                              └─ SQLite + evidence files
```

- No framework, bundler or CDN.
- SQLite migrations are additive; schema version 3 adds file-analysis history.
- The HTTP server enforces loopback Host/Origin, a strict CSP, `no-store`,
  `nosniff`, `no-referrer` and bounded bodies.
- Reports and UI escape record content.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md).

## Testing

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q garbage_intel tests
for f in web/*.js; do node --check "$f"; done
```

Current result: **115 tests pass** with the native build present; without it,
the same suite passes with the nine native parity tests skipped. A temporary
jsdom smoke test rendered every route against a seeded database with zero error
states and zero console errors. There is no real-browser E2E test. See
[TESTING.md](docs/TESTING.md) for what is and is not verified.

Optional native helpers:

```sh
make -C native
make -C native check
```

Builds are optional; a missing library automatically uses the tested Python
fallback. See [native/README.md](native/README.md).

## Security and limitations

- Loopback only; no authentication, TLS or CSRF token. Do not expose it.
- No encryption at rest. Protect the database and evidence directory.
- Static analysis is not antivirus and does not prove a file is safe.
- No website/domain/IP collectors, external OSINT connectors, automation,
  plugin loader, FTS5 search or PDF export yet.
- Native helpers are optional and loaded only from an explicit build directory
  or `GARBAGE_NATIVE_DIR`; they are never downloaded. Missing, mismatched or
  malformed libraries fall back to Python. Native code does not execute input,
  open files or use the network.
- OpenArchive identity is ambiguous. The only verified reference is **OpenArchive
  Save**, a mobile media-preservation app. GARBAGE does not claim feature parity
  with it or with any unnamed project. Read
  [OPENARCHIVE_FEATURE_MATRIX.md](docs/OPENARCHIVE_FEATURE_MATRIX.md).

Report vulnerabilities privately; see [SECURITY.md](docs/SECURITY.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [OpenArchive feature matrix](docs/OPENARCHIVE_FEATURE_MATRIX.md)
- [Roadmap and phase status](docs/ROADMAP.md)
- [API reference](docs/API_REFERENCE.md)
- [Database schema](docs/DATABASE_SCHEMA.md)
- [Module development](docs/MODULE_DEVELOPMENT.md)
- [Testing](docs/TESTING.md)
- [Security](docs/SECURITY.md)
- [Installation](docs/INSTALLATION.md)
- [Development](docs/DEVELOPMENT.md)
- [Development status](DEVELOPMENT_STATUS.md)

## Licence and provenance

See the repository licence. GARBAGE is an independent implementation; no
OpenArchive source code is included. OpenArchive Save is GPL-3.0; its name and
links are used only for identification and comparison.
