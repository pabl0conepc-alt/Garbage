# Roadmap and phase status

This roadmap separates **implemented and tested** work from **planned** work.
The expansion plan after these phases (steps 1–8: foundation, visual
investigation, search, specialised intelligence, plugins, cases, monitoring,
refinement) is tracked in [AUDITORIA_PLATAFORMA.md](AUDITORIA_PLATAFORMA.md);
the phase sections below are kept as the record of the first build.
A phase is not complete because a page or button exists. The module registry
marks unimplemented capabilities as `planned` and refuses to enable them.

## Phase status at a glance

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Audit and baseline | Complete |
| 2 | Architecture and OpenArchive scope | Complete (documentation) |
| 3 | Core data and API | Complete |
| 4 | Entities, sources, relationships, search | Complete for the implemented scope |
| 5 | Evidence and file/media intelligence | Complete except OCR and video frames: documents, archives, images with EXIF/GPS and perceptual hashes, executables, YARA, custody |
| 6 | CTI/OSINT | Complete for infrastructure and threats: 31 connectors, transforms, ATT&CK, Sigma, TAXII 2.1, STIX/MISP export; people are out of scope — see [PLANO_OSINT_CSINT.md](PLANO_OSINT_CSINT.md) |
| 7 | Automation and plugin SDK | Complete: local plugins in a separate process, transforms, monitors on a schedule; no free-form flow runner by design |
| 8 | Native C/C++/Rust engines | Optional helpers implemented with tested Python fallbacks; no benchmark |
| 9 | Workstation UI | Complete for enabled modules; no UI for planned modules |
| 10 | Testing and hardening | 295 tests including an HTTP end-to-end case run and an interface/API contract check; browser accessibility audit; no automated real-browser suite |
| 11 | Documentation and release | Docs updated with each step; work lands as stacked pull requests |

## Phase 1 — audit

Delivered:

- Full inventory of the original Python/SQLite/vanilla-JS application.
- Baseline suite (47–48 tests at audit time) and known limitations recorded.
- Preservation of the v1 database shape and additive migrations.

## Phase 2 — architecture and reference scope

Delivered:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [OPENARCHIVE_FEATURE_MATRIX.md](OPENARCHIVE_FEATURE_MATRIX.md)
- Explicit decision that OpenArchive Save is the only verified reference and
  that OSINT/CTI scope is GARBAGE-native.

## Phase 3 — core

Delivered:

- Typed errors and shared validation.
- Additive schema v2/v3, settings and module registry.
- Investigation lifecycle, observations, timeline, report and export routes.
- Loopback host/origin enforcement, body caps and static asset allowlist.
- CLI and zipapp remain functional.

## Phase 4 — intelligence records

Delivered:

- Canonical entity registry with aliases, types, confidence and verification.
- Relationships with direction, confidence, provenance and cycle-safe deletion.
- Source registry, case links and entity links.
- Cross-record search grouped by record type.
- Indicator extraction with source provenance, refanging, IPv6/CIDR support,
  canonical comparison and exact-value correlation with independent-source
  strength.

Not delivered:

- Ranked FTS5 search.
- Bulk import formats (STIX, CSV mapping, MISP).

## Phase 5 — evidence and files

Delivered:

- Evidence upload, SHA-256 integrity, verification, download and preview.
- Image structure inspection.
- File Intelligence: bounded static analysis, 4 MiB cap, format detection,
  hashes, entropy, strings, PDF metadata, OOXML/archive listings, TAR/GZIP,
  image dimensions, ELF/PE/Mach-O headers/sections/imports, findings,
  indicators, persistence and history API/UI.
- Evidence attachment from an analysis (with its own integrity record).

Not delivered:

- Full EXIF/XMP/IPTC media forensics.
- Video/audio container parsing.
- Malware disassembly, emulation or execution.
- Native high-throughput engines.

## Phase 6 — CTI/OSINT

Delivered:

- Manual indicator assessment with confidence and rationale.
- Offline text triage, single-value inspection with local exact matches,
  co-occurrence and factual case coverage review.
- CISA KEV read-only catalogue: explicit refresh, bounded download, offline
  cache, provenance and failure reporting.
- Multi-source runtime (plan phase 1): SSRF-safe HTTP client, connector
  registry, per-connector rate limits, TTL cache, source health, persisted
  runs with provenance, API routes and the `intel.allow_network` gate.
- Public keyless connectors (plan phase 2): DNS over HTTPS, Team Cymru
  IP-to-ASN, RDAP (organisation-level only), crt.sh, Wayback CDX, FIRST EPSS
  and the local KEV snapshot.
- Target-contact connectors (plan phase 4): TLS certificate (own DER parser)
  and web fingerprint (security headers, cookies, technologies, favicon
  hash), behind a separate `intel.allow_target_contact` switch.
- Graph analytics and pivot (plan phase 5): degree, betweenness and harmonic
  centrality, deterministic Louvain communities and shortest paths in C++
  (bit-identical Python fallback); node pivot that promotes approved findings
  to entities and unverified relationships citing their source.

Not delivered:

- Website, domain, IP and DNS collectors.
- NVD connector (registered as planned).
- STIX/TAXII, MITRE ATT&CK, MISP.
- Any collection that would bypass authorization or rate limits.

## Phase 7 — automation and SDK

Not delivered. [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md) defines the
contract and safety constraints. There is intentionally no dynamic plugin
loader, scheduler or flow runner yet, because executing arbitrary code from a
workspace directory is a security boundary that needs explicit design and
tests.

## Phase 8 — native engines

Delivered as optional helpers with Python fallbacks:

- C: bounded ELF/PE hardening and entropy in `native/c/`.
- C++: graph components, isolates, degree, density and reciprocity in `native/cpp/`.
- Rust: bounded edit distance and domain skeleton in `native/rust/`.
- `tests.test_native` compares each engine with the Python path; the Ubuntu CI
  job builds all three. Missing or incompatible libraries fall back safely.
- No library is downloaded at runtime and no native code executes input.

## Phase 9 — UI

Delivered:

- Dark investigation workstation shell with responsive navigation.
- Overview, cases, case file, activity, entities, indicators, evidence,
  sources, reports, modules, settings, CISA KEV, file intelligence.
- Persisted board with layers, groups, notes, connections, keyboard movement,
  autosave, conflict handling and SVG export.
- Relationship graph with type filters, focus, search, pan/zoom, drag and
  layered SVG export.
- Global search and command palette with real quick actions, a persisted display
  menu, keyboard shortcuts, a mobile navigation drawer, bottom-sheet dialogs,
  functional compact density and loading/error/empty states.

Not delivered:

- Dedicated UI for planned modules (correctly absent).
- Browser E2E suite (no browser in this environment; jsdom smoke used).

## Phase 10 — tests

Delivered:

- 115 Python tests passing with native helpers (`make -C native`); 9 parity tests skip without the build.
- Compile checks for all Python files.
- `node --check` for all classic scripts.
- jsdom smoke over every route with a seeded database: 0 failure records,
  0 console errors.
- Manual cloud-browser inspection at desktop and mobile widths: no overflow,
  no console/CSP errors, command palette, display menu and drawer verified.
- API tests for module gating, invalid input, authentication-free loopback
  behavior, file-analysis limits and persistence.

Not delivered:

- Real-browser E2E and visual regression.
- Native builds on macOS/Windows; CI covers Ubuntu and other platforms use the Python fallback.
- Load/performance benchmarks.

## Phase 11 — documentation and release

Delivered:

- README, development status, architecture, OpenArchive matrix, API, schema,
  module guide, testing, security, installation and development docs.
- Branch `feature/garbage-universal-intelligence-platform`.

Pending:

- Commit, push and open the pull request. No merge.

## Recommended next increments

1. OCR and video frames as optional engines (Tesseract, ffmpeg) behind the
   `media-forensics` module, with the same bounded-input rules.
2. Threat-actor profiles: done from ATT&CK groups; still to add the
   intrusion sets and reports pulled from TAXII collections.
3. A real-browser test suite run in CI (the current end-to-end test stops at
   HTTP).
4. Native PDF output if a dependency-free writer proves good enough; until then
   the browser's print.
5. Notification delivery to a local command or file drop, never to a remote
   service by default.
