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

On 2026-11-14 (branch `feature/refinement`):

- **295 tests pass** with the optional native build; without it the native
  parity tests skip and the rest pass. A full run takes about four minutes.
- `node --check` passes for every browser script.
- `tools/a11y_audit.js`, run in a real browser on all 21 navigation screens
  and the detail screens (case, entity, graph, board, query run, monitor), in
  the dark and contrast themes, reports no issues.

Native tests build C, C++ and Rust helpers and compare entropy, ELF/PE
hardening, graph metrics, edit distance, lookalikes and typosquatting with the
Python fallback. They skip cleanly when `native/build` is absent.

## 3. What the tests cover

| Area | Files | Highlights |
| --- | --- | --- |
| End to end | `test_e2e.py` | A real server driven over HTTP through a whole case: entities and relationship, evidence upload, verification, download, notes and custody, search, a monitor detecting a change, report in four formats with sections, package and import into a second workspace, archive |
| Interface contract | `test_e2e.py` | Every script in `index.html` is served and exists; every navigation entry has a renderer, an icon and a known module; every icon used is defined; every `/api/...` path in the web code matches a backend route |
| Core records | `test_store.py`, `test_api.py` | Cases, observations, timeline, reports, exports, HTTP validation |
| Cases and custody | `test_cases.py` | Objective, archive, duplicate, package digest and import, hash-chained custody, report sections and methodology |
| Workspace and search | `test_workspace.py`, `test_search.py` | FTS5 ranking, snippets, accents, prefix, LIKE fallback, settings, activity, module gates |
| Entities and graph | `test_entities.py`, `test_graph_io.py`, `test_foundation.py` | Relationships, graph payload and its cut by degree, GraphML/JSON import, transforms, entity resolution |
| Multi-source intelligence | `test_intel*.py` | Connectors against recorded responses, gates, keys, cache, rate limits, async runs and recovery, target-contact switch |
| Monitoring | `test_monitoring.py` | Validation, baseline/unchanged/changed, a failed source is not "removed", notifications, scheduler, overlapping runs |
| CTI | `test_attack.py`, `test_feeds.py`, `test_cti_export.py`, `test_cisa_kev.py`, `test_typosquat.py` | ATT&CK, TAXII paging and retries, Sigma parsing, STIX/MISP/IOC export, KEV, typosquatting |
| Plugins | `test_plugins.py` | Manifest validation, approval by SHA-256, process isolation, brokered network, refused personal types |
| Files and media | `test_file_intel.py`, `test_imaging.py`, `test_geoint.py`, `test_yara.py`, `test_fuzzy_hash.py` | Parsers with malformed input, EXIF/GPS, perceptual hashes, map points, YARA, TLSH/ssdeep |
| Evidence and boards | `test_evidence.py`, `test_boards.py` | Upload limits, hashing, verification, preview, deletion; layout revisions |
| Native parity | `test_native.py` | C, C++ and Rust against Python fallbacks |

## 4. What is not verified

- **No automated real-browser suite.** `test_e2e.py` covers the HTTP side
  and the static contract between interface and API. The interface itself was
  checked by hand in a browser for each step, and the accessibility audit is a
  script run in the browser, not part of `unittest`.
- **Performance is measured, not benchmarked in CI.** On a 1,500-entity,
  2,139-relationship case: graph payload 0.22 s, force layout 1.1 s
  (8.6 s before Barnes-Hut), community layout 1.0 s (16.9 s), hover 26 ms
  (530 ms before), whole view about 2.7 s.
- **Native builds are verified on Linux**, not on macOS or Windows.
- **No authenticated or multi-user tests**, because there is no
  authentication.
- **No fuzzing.** Parsers are bounded and covered by malformed fixtures.
- **Live sources** are tested against recorded responses. Live runs were done
  by hand (for example TAXII against MITRE, Sigma from SigmaHQ, GitHub on a
  public organisation).

## 5. Accessibility audit

`tools/a11y_audit.js` runs in the browser console of a running GARBAGE page
(or through browser automation):

```js
const report = await garbageA11yAudit();          // every navigation screen
const one = await garbageA11yAudit(["#/graph"]);  // chosen routes
garbageA11yAuditPage();                           // the current page only
```

It reports controls without an accessible name, fields without a label,
images without alt text, duplicate ids, positive tabindex, skipped heading
levels and text below WCAG AA contrast. Disabled controls are exempt from the
contrast rule, as in WCAG. It only reads the page.

## 6. Adding tests

- Use `unittest`, not a new framework.
- Use temporary directories; never write into the repository's data folder.
- Test both success and validation failure.
- Test module gating when adding a capability.
- For parsers, include malformed/truncated fixtures and verify no crash.
- Report skipped or unavailable checks explicitly; never describe an unrun test
  as passing.
