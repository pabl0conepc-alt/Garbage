# Development status

## Implemented

- Local SQLite core for investigations and sourced observations.
- Standard-library CLI for initialization, investigation management,
  observation capture, JSON reporting, and starting the local web/API server.
- Source reference, collection basis, observation time, and recording time are
  retained as provenance.
- Investigation create/list/show, status transitions (`open`, `closed`,
  `cancelled`), and a guarded evidence lifecycle. Closed/cancelled cases reject
  added observations until reopened. Existing pre-status SQLite databases are
  migrated to `open`.
- Chronological investigation timelines in the CLI, API, and browser UI,
  including creation, observation provenance, and new status transitions.
  Prior status-transition history cannot be reconstructed for databases created
  before this event log was added.
- Reports explicitly identify user-entered evidence as unverified and state
  that external collection is not implemented.
- Local pattern-based CTI extraction for IPv4 addresses, domain names, and
  MD5/SHA-1/SHA-256 strings; each finding links to its source observation and
  retains collection and time provenance. No reputation lookup is performed.
- Exact normalized-indicator correlation across observations, retaining every
  source record. This is a match, not attribution or an assessment of intent.
- Read-only SHA-256 and filesystem-metadata analysis for one explicitly named
  user-provided regular file; it rejects symlinks, does not recurse, and stores
  only the hash/metadata as a sourced observation.
- Read-only document metadata CLI for an explicit regular-file path; it reports
  filename, suffix, guessed media type, byte size, and UTC modified time
  without reading contents or initializing the investigation database.
- JSON, escaped HTML, and CSV report output; optional file exports are
  create-only and do not overwrite existing paths. CSV retains provenance,
  indicators, correlations, and limitations.
- Versioned JSON archive backup/import, preserving investigation, observation,
  provenance, and status-transition records. Imports are capped at 10 MiB,
  fully validated before database changes, transactional, and reject
  conflicting IDs. Consistent SQLite backups are also create-only.
- Manual CISA KEV JSON metadata connector in CLI, loopback API, and web UI.
  Uses fixed CISA HTTPS URL, a 10-second timeout, 10 MiB bounded response,
  CISA-only HTTPS redirects, schema/count/date validation, 15-minute local
  freshness suppression, conditional ETag/Last-Modified requests, and surfaced
  `Retry-After` without automatic retries. Cache provenance includes feed
  version/release time, retrieval time, source URL, and SHA-256 digest.
  It imports only descriptive/remediation metadata, omits external notes, and
  does not scan targets or trigger actions. The sidecar cache is not part of
  the investigation archive.
- Loopback-only HTTP API and vanilla HTML/CSS/JavaScript interface, including
  escaped printable HTML reports and status lifecycle actions.
- Focused standard-library tests for storage, API/CLI flows, provenance,
  timestamp handling, indicator extraction, and injection/host-origin guards.

## Not yet implemented

- OSINT and SOCMINT modules; digital forensics currently supports only explicit
  single-file hashing and metadata, not media/device recovery or forensic
  timeline analysis.
- Additional external connectors, indicator reputation checks, and advanced
  cross-source entity correlation.
- Richer investigation fields, entities, and relationships. Investigation
  timelines currently cover creation, observations, and status transitions.
- Import/export of formats beyond versioned JSON archives and CSV reports.
- CSV's current formula mitigation strips ASCII space/tab/CR/LF for detection;
  offline output confirms vertical-tab and NBSP prefixes remain before a
  formula marker. Formula interpretation is unverified: no LibreOffice,
  Gnumeric, or other local spreadsheet executable is available on this host.
  Do not characterize these prefixes as either exploitable or safe without a
  supported spreadsheet reproduction.
- Authentication, authorization roles, TLS, and safe remote/production
  deployment. The current HTTP server is deliberately local-only.
- Broader UI accessibility/e2e coverage, packaging, and deployment automation.

## Installation preflight

- Available: Python 3.14.8, SQLite 3.53.4, Node.js 24.21.0, npm 12.2.0.
- FastAPI, Flask, Django, Uvicorn, and pytest are already importable in the
  inspected environment, but the project has no dependency manifest and does
  not rely on them.
- This implementation uses only Python's standard library and browser-native
  APIs; no dependencies or system tools were installed.
- Connector assessment:
  [CISA's KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  publishes a versioned JSON feed and schema without authentication. Its
  curated CVE/remediation records are implemented with explicit refresh,
  bounded downloads, offline fixture tests, and feed provenance.
  [NVD's CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
  is a public read-only alternative with much broader records, richer matching
  semantics, and rate-limit considerations. The live endpoint returned JSON
  during assessment; the developer documentation page was not readable in
  this environment. Defer implementation until rate limits and data handling
  are verified; consume descriptive CVE metadata only, not exploit references.
- A production/remote backend may need a supported server framework, packaging,
  TLS, and deployment tooling. Before adding any such dependency/tool, provide
  its proposed version, install command, network/system effects, and wait for
  explicit user approval.

## Validation

- `python3 -m unittest discover -s tests -v` — 38 tests passed, including
  archive rollback and connector/API/CLI integration coverage.
- `python3 -m unittest discover -s tests -p 'test_cisa_kev.py' -v` — 6 offline
  connector tests passed (fixture parsing, bounds, cache interval, validators,
  rate-limit response, and redirect restriction).
- `python3 -m unittest discover -s tests -p 'test_document_metadata.py' -v` —
  4 tests passed independently.
- `node --check web/app.js` and `node --check web/report.js` — passed; browser
  smoke test confirmed the KEV controls are present without fetching on page
  load.
- `python3 -m garbage_intel --help` and focused backup/import/timeline/KEV help
  — passed.
- `python3 -m compileall -q garbage_intel tests` — passed.
- `git diff --check` — passed.

All checks ran in the inspected Python 3.14/SQLite environment. No third-party
dependencies or system tools were installed.
