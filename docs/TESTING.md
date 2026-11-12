# Testing

## 1. Commands

From the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q garbage_intel tests
for f in web/*.js; do node --check "$f"; done
```

The suite uses only the Python standard library and creates temporary databases
and evidence directories. It does not need network access.

## 2. Current result

At the time of this change:

- **106 tests pass.**
- `compileall` completes without errors.
- `node --check` passes for every classic browser script.
- A jsdom route smoke test (temporary harness outside the repository) rendered
  every route against a seeded database with **0 failure records and 0 console
  errors**, including boards and graphs.
- A separate jsdom tool smoke exercised text triage, typed inspector output,
  case coverage and the case-scoped indicator tab with no application errors.
  The cloud browser preview returned a private-preview 403 before reaching the
  app, so this increment was not visually screenshotted.

The baseline before this work was 47–48 tests. New coverage includes entities,
relationships, boards, evidence verification, image inspection, workspace
search/activity/settings, module gating, file intelligence, indicator precision,
text triage, offline value inspection and case coverage.

## 3. What the tests cover

| Area | Files | Highlights |
| --- | --- | --- |
| Core records | `test_store.py`, `test_api.py` | Cases, observations, timeline, reports, exports, HTTP validation |
| Workspace | `test_workspace.py` | Search, activity, settings, module state gates |
| Entities and graph | `test_entities.py` | Aliases, confidence, relationships, cycle handling, graph payload |
| Sources | `test_entities.py`, API coverage | CRUD, case and entity links, provenance |
| Evidence | `test_evidence.py` | Upload limits, hashing, verification, download/preview, deletion |
| Boards | `test_boards.py` | Layout persistence, revisions, element/connection validation |
| Indicators | `test_indicators.py`, `test_indicator_tools.py` | Refanging, IPv4/IPv6/CIDR validation, IPv4-mapped and scoped IPv6, bracketed IPv6 URLs, filename and embedded-host suppression, triage counts, inspection, correlation strength |
| Imaging | `test_imaging.py` | PNG/JPEG/GIF/WebP dimensions, malformed input |
| File intelligence | `test_file_intel.py` | PDF, OOXML/ZIP traversal, GZIP bomb bound, ELF/PE/Mach-O, limits, API persistence and module gate |
| CISA KEV | `test_cisa_kev.py` | Bounded parsing, cache, failure handling |

## 4. What is not verified

- **No automated real-browser E2E or visual regression.** The UI is exercised
  with jsdom, which verifies DOM rendering and route behavior but not CSS layout,
  native file pickers or drag-and-drop. A manual cloud-browser inspection was
  also performed through a temporary loopback preview proxy, covering desktop
  and mobile layouts, command palette, display menu, shortcuts and drawer focus.
  That inspection is not a repeatable automated suite.
- **No native components.** No C, C++ or Rust library exists to test.
- **No performance/load benchmark.**
- **No authenticated or multi-user tests**, because authentication is not
  implemented.
- **No fuzzing.** Binary and archive parsers are bounded and covered by
  fixtures, but not fuzzed.
- **No PDF renderer test**, because PDF export is planned, not implemented.

Claims in the README and status document are limited to the checks above.

## 5. Temporary UI smoke harness

The jsdom harness used during development lives in `.tmp/` and depends on a
temporary installation in `/tmp/garbage-ui`. It is **not** a project dependency
and is removed before commit. It seeds a temporary SQLite database, starts the
loopback API, loads `web/index.html`, and visits each hash route.

To reproduce it, install `jsdom` outside the repository, seed a database with a
case, entity, source, evidence, board and graph, then load the page and assert:

- no `.error-state` node,
- non-trivial rendered text,
- expected board node/edge counts,
- no uncaught console errors.

## 6. Adding tests

- Use `unittest`, not a new framework.
- Use temporary directories; never write into the repository's data folder.
- Test both success and validation failure.
- Test module gating when adding a capability.
- For parsers, include malformed/truncated fixtures and verify no crash.
- Report skipped or unavailable checks explicitly; never describe an unrun test
  as passing.
