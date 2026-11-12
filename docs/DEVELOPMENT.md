# Development

## Setup

```sh
git clone <repository-url>
cd Garbage
python3 -m unittest discover -s tests -v
./scripts/run.sh serve --port 8765
```

No dependency installation is required. Do not add a framework or package
without a measured need and explicit approval.

## Repository layout

```text
garbage_intel/      Python package (stdlib + SQLite)
  modules/          bounded analysis and connector modules
web/                vanilla HTML/CSS/JS
tests/              unittest suite
docs/               architecture, API, schema, security, roadmap
scripts/            POSIX and PowerShell launchers
tools/              zipapp builder
```

## Checks

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q garbage_intel tests
for f in web/*.js; do node --check "$f"; done
git diff --check
```

Run all four before proposing a change. Do not report a check as passing if it
was skipped or unavailable.

### Focused tests

```sh
python3 -m unittest tests.test_file_intel -v
python3 -m unittest tests.test_entities tests.test_boards -v
```

Tests use temporary databases and evidence directories. Never point tests at a
real investigation database.

## Code conventions

- Python 3.10+ syntax, type hints on public functions, standard library only.
- Keep the HTTP layer thin: validation and routing in `api.py`, behavior in
  service modules.
- Raise the typed errors in `errors.py`; do not return ad-hoc error shapes.
- Use bound SQL parameters. Never interpolate record values into SQL.
- Bound loops, decompression, output and archive listings.
- Never execute or extract submitted files.
- UI uses classic scripts registered on `G.views`; no modules, bundler or CDN.
- Escape record text in the UI and reports.

## Database migrations

1. Add the column/table to `BASE_SCHEMA` for new databases.
2. Add an idempotent migration function and append it to `MIGRATIONS`.
3. Increment `SCHEMA_VERSION`.
4. Test both a fresh database and an upgrade from the previous version.
5. Update [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

Migrations are additive. Never drop or rewrite user records in a migration.
Preserve the JSON archive format and existing API response shapes
(`{"error": "..."}` for failures).

## Adding a module

Follow [MODULE_DEVELOPMENT.md](MODULE_DEVELOPMENT.md). Start with registry state
`planned`, implement persistence, API and UI, add tests, then enable it. A
navigation entry without a working route is a defect.

## UI development

- `web/app.js` — shell, router, API client, components.
- `web/views.js` — overview, case file, activity.
- `web/views-intel.js` — entities, indicators, evidence, sources, reports.
- `web/views-system.js` — modules, settings, CISA KEV.
- `web/views-file.js` — file intelligence.
- `web/board.js`, `web/graph.js` — canvas-style SVG work surfaces.

Register a view with `G.views.<name> = renderFunction` and add the route/nav in
`app.js`. Import components from `window.GARBAGE`; do not create globals.

### UI smoke testing

A temporary jsdom harness is useful for route rendering:

1. Install `jsdom` outside the repository (for example `/tmp/garbage-ui`).
2. Seed a temporary database with a case, entity, source, evidence, board and
   graph edge.
3. Start the API on loopback.
4. Load `web/index.html`, visit every hash route, and assert no `.error-state`,
   non-trivial text, expected board/graph counts and zero console errors.

jsdom verifies DOM behavior only. It does not verify CSS layout, file pickers,
drag-and-drop or real-browser timing. Do not describe it as browser E2E.

## Manual exploration

```sh
python3 -m garbage_intel --database /tmp/dev.sqlite3 init
python3 -m garbage_intel --database /tmp/dev.sqlite3 serve --port 8877
```

Use a disposable database. The API and UI are loopback-only; a remote cloud
browser cannot reach them.

## Release and pull request

- Branch: `feature/garbage-universal-intelligence-platform`.
- Commit logical changes; do not commit `.tmp/`, databases, evidence, caches or
  `__pycache__`.
- Re-run the full suite after the final edit.
- Push the branch and open the pull request. **Do not merge it automatically.**

## Native components

Before adding C, C++ or Rust, read the contract in
[ARCHITECTURE.md](ARCHITECTURE.md). Keep the Python implementation as the
fallback; add bounds/malformed tests and a benchmark before claiming a speedup.
This host lacks `cargo`, `rustc` and `cmake`.
