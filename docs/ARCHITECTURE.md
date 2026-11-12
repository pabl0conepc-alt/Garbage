# Architecture

## 1. What exists today

GARBAGE is a local-first investigation workstation. It deliberately keeps the
original zero-dependency Python standard-library design and adds capability in
small, testable modules.

```text
Garbage/
├── garbage_intel/
│   ├── cli.py                 Command line and launchers
│   ├── api.py                 Loopback HTTP router and static assets
│   ├── db.py                  SQLite schema, migrations, registry seeds
│   ├── store.py               Investigations, observations, reports, archives
│   ├── entities.py            Entity registry, relationships, graph payload
│   ├── sources.py             Source registry and links
│   ├── evidence.py            Evidence storage, hashing, verification
│   ├── boards.py              Persisted investigation board state
│   ├── workspace.py           Search, indicators, activity, settings, modules
│   ├── reporting.py           HTML/JSON/CSV/Markdown renderers
│   ├── validation.py          Shared input validation
│   ├── errors.py              Typed application errors
│   └── modules/
│       ├── indicators.py      Pattern extraction with provenance
│       ├── correlation.py     Exact-value correlations
│       ├── imaging.py         Image structure inspection
│       ├── file_intel.py      Bounded static file intelligence
│       └── cisa_kev.py        Explicit read-only CISA KEV connector
├── web/                       Vanilla HTML/CSS/JS workstation
├── tests/                     Standard-library unittest suite
├── docs/                      This documentation
├── scripts/                   POSIX and PowerShell launchers
└── tools/                     Zipapp builder
```

The flat package layout is intentional. The requested `core/python`,
`core/rust`, `core/cpp` tree is a target convention, not a reason to move
working modules and break imports, the zipapp builder or the existing tests.

## 2. Data model

SQLite is the single source of truth. The database is initialized and migrated
in `db.py`; migrations are additive and never drop user data.

Core tables:

- `investigations`, `observations`, `investigation_status_events`
- `entities`, `relationships`, `investigation_entities`
- `sources`, `investigation_sources`, `entity_sources`
- `evidence` (metadata plus a hashed file under a generated name)
- `boards`, `board_elements`, `board_connections`
- `activities`, `indicator_assessments`
- `file_analyses` (full static-analysis JSON plus summary columns)
- `module_registry`, `application_settings`, `schema_migrations`

See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) for columns and migration history.

## 3. Request flow

```text
Browser (web/*.js)
   │  same-origin fetch, JSON only
   ▼
api.RequestHandler (loopback Host/Origin check)
   │  module gate → validation → service function
   ▼
garbage_intel service modules
   │  one SQLite transaction per operation
   ▼
SQLite + evidence files + CISA sidecar cache
```

The HTTP layer is a thin router. It does not contain analysis logic. Each
service returns plain dictionaries; the renderers and UI never invent records.

### Module gating

Every route with a registered capability calls `require_module(...)`. The
module manager cannot enable a `planned` module, and disabling a module makes
its routes return HTTP 409. The UI removes the navigation entry at the same
time. This is why a page existing in navigation is not evidence of a backend:
the registry state must be `enabled`.

Current enabled capabilities include investigations, entities, relationships,
board, graph, evidence, image intelligence, file intelligence, source manager,
indicator engine, CISA KEV, reports, search, settings and the module manager.
`nvd-connector`, `external-osint-connectors` and `media-forensics` remain
explicitly `planned`.

## 4. Security boundaries

- Bind address is hard-coded to `127.0.0.1`.
- Host and, when present, Origin must match the bound loopback origin.
- JSON bodies are capped (1 MiB generally, 6 MiB for base64 file analysis).
- Evidence files are capped at 4 MiB; analysis is capped at 4 MiB.
- Evidence is stored under a generated name, with the original name retained
  only as metadata.
- File Intelligence never executes, emulates or extracts submitted content.
- Archive listings are bounded; GZIP preview is capped at 1 MiB.
- HTML reports and the UI escape record content.
- CSV cells that look like formulas are prefixed.
- There is no authentication, TLS or remote deployment support.

Detailed threats and limitations are in [SECURITY.md](SECURITY.md).

## 5. Frontend

The interface is a four-layer classic-script application:

- `app.js` — shell, router, API client, components, dialogs, global search.
- `views.js` — overview, investigation file, activity.
- `views-intel.js` — entities, indicators, evidence, sources, reports.
- `views-system.js` — modules, settings, CISA KEV.
- `views-file.js` — file intelligence.
- `board.js` — persisted board canvas.
- `graph.js` — relationship graph with a deterministic client-side layout.

No framework, bundler or CDN is used, preserving the zipapp model and the
Content Security Policy (`script-src 'self'`). Views render only API data.
Board and graph layout are the only client-side derived state; the board is
saved with optimistic revisions.

## 6. Multi-language contract

Python remains the reference implementation. Optional C, C++ and Rust helpers
are implemented in `native/`:

- C reads bounded ELF/PE headers for hardening markers and computes entropy.
- C++ computes graph components, isolates, degree, density and reciprocity.
- Rust computes bounded domain edit distance and a comparison skeleton.

The contract:

1. **C ABI is the stable boundary.** Native libraries export plain C functions
   with caller-owned buffers, explicit lengths, integer status codes and no
   Python objects.
2. **Python loads optionally.** `ctypes`/`cffi` loads a library from an explicit
   build directory or environment variable. A missing or mismatched library
   must fall back to the pure-Python implementation; it must never disable the
   application.
3. **Ownership and limits are documented.** Every function states buffer
   ownership, maximum input, error codes and thread-safety. No native function
   receives a path and opens it implicitly.
4. **Rust** handles bounded string similarity. It is a `cdylib` with no
   third-party crates and no Python object boundary.
5. **C++** handles graph metrics through `extern "C"` entry points with RAII
   and validated node indexes.
6. **C** handles byte-level ELF/PE readers. Every offset and length is bounded;
   input is never executed.
7. **Builds are reproducible and optional.** `make -C native` builds all three;
   `tests.test_native` compares native and Python results. CI builds on Ubuntu;
   every other platform runs the Python path unless a library is supplied.

No Rust or C/C++ toolchain is assumed by the runtime. The native directory is
never downloaded and a missing library simply selects the fallback.

## 7. Extension points

- New Python analysis: add `modules/<name>.py`, a registry row, API routes,
  tests and a view. Do not make it `enabled` until the route is real.
- New persistence: additive migration plus schema documentation.
- New connector: fixed allowlisted host, timeout, byte cap, redirect cap,
  explicit refresh, provenance and offline fixture tests.
- New native code: C ABI, optional loader, fallback, bounds tests and
  cross-platform build instructions.

## 8. Why not PostgreSQL, a framework or a bundled graph library?

At this scale, SQLite plus the standard library is faster to verify, simpler to
ship as a zipapp, and already supports the required transactions, foreign keys
and concurrency for a single analyst. FTS5 availability was probed, but the
search migration is not part of this change. A framework or distributed
database would add dependencies without a measured need.

## 9. Known architectural gaps

- Search uses `LIKE`, not FTS5; it is not ranked.
- Reports have no PDF renderer.
- No website/domain/IP collector exists, so no SSRF surface has been added.
- No automation runner or plugin loader exists.
- Native helpers have parity tests but no load/performance benchmark.
- No authentication, TLS or multi-user isolation.
