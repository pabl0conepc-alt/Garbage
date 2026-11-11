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
- PowerShell and POSIX shell launchers with Python 3.10+ checks; `doctor`
  reports Python and OS/distribution compatibility without initializing data.
- Standard-library zipapp builder that bundles the CLI and web assets, refuses
  to overwrite its output, and runs with Python on Windows, macOS, and Linux.
- GitHub Actions test matrix for Windows, macOS, and Ubuntu on Python 3.10 and
  3.14, including a launcher smoke test for PowerShell or POSIX. The matrix is
  configured but has not been observed running from this worktree.
- Focused standard-library tests for storage, API/CLI flows, provenance,
  timestamp handling, indicator extraction, injection/host-origin guards,
  platform diagnostics, and zipapp builds.

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
- Signed native installers and release automation. The current distributable
  is a Python zipapp and still requires Python 3.10+ on the target machine.
- Broader UI accessibility/e2e coverage and deployment automation.

## Platform support status

- **Tested here:** Kali GNU/Linux Rolling, Python 3.14.8, SQLite 3.53.4. The
  full standard-library suite and zipapp build/run checks were executed here.
- **Supported by design, not tested here:** Windows, macOS, Debian, Ubuntu,
  Arch Linux, and NixOS. They use the same Python-standard-library code; the
  Windows/macOS/Ubuntu CI matrix is configured but not yet verified by a
  completed CI run. Other Linux distributions are expected to work with Python
  3.10+ and its SQLite module.
- No system packages, Python dependencies, or external tools were installed.

## Installation preflight

- Available: Python 3.14.8, SQLite 3.53.4, Node.js 24.21.0, npm 12.2.0.
- FastAPI, Flask, Django, Uvicorn, and pytest are already importable in the
  inspected environment, but the project has no dependency manifest and does
  not rely on them.
- This implementation uses only Python's standard library and browser-native
  APIs. The source launchers and zipapp builder need no dependencies or system
  tools; none were installed.
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

- `python3 -m unittest discover -s tests -v` — 47 tests passed, including
  archive rollback, connector/API/CLI integration, platform diagnostics, and
  zipapp build/run coverage.
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

All checks ran on Kali GNU/Linux Rolling with Python 3.14.8 and SQLite 3.53.4.
Windows and macOS support remains unverified until the configured CI matrix
runs. No third-party dependencies or system tools were installed.
