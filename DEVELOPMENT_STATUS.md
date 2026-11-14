# Development status

Updated 2026-11-14, after step 8 of the expansion plan in
[docs/AUDITORIA_PLATAFORMA.md](docs/AUDITORIA_PLATAFORMA.md). Schema version
14. The feature list is in the [README](README.md); what each test covers is
in [docs/TESTING.md](docs/TESTING.md).

## Implemented and tested

- **Workspace:** cases with objective, archive, duplicate and package
  export/import; observations; activity log; settings; module registry; FTS5
  search with ranking and a LIKE fallback.
- **Records:** sources, entities with aliases, relationships, entity
  resolution with analyst-approved merges, evidence with hash-chained custody
  and notes.
- **Collection:** 31 multi-source connectors with gates, keys, cache, rate
  limits and async runs; transforms from entities; local plugins in a separate
  process; monitors on a schedule with differences and notifications.
- **Analysis:** graph with eight layouts (Barnes-Hut above 200 nodes), matrix
  and timeline views, path finding, import/export; board; analytics; indicator
  extraction and correlation; typosquatting.
- **Files and media:** bounded static analysis of documents, archives, images
  and executables; YARA; TLSH/ssdeep; EXIF with GPS; perceptual hashes; GEOINT
  map.
- **CTI:** ATT&CK offline, Sigma, TAXII 2.1, CISA KEV, NVD/EPSS/OSV, STIX 2.1,
  MISP and IOC export.
- **Reports:** chosen sections, generated methodology, graph picture, custody
  and techniques, in HTML, Markdown, JSON and CSV; PDF through the browser's
  print.
- **Native helpers:** C, C++ and Rust, each with a Python fallback and parity
  tests.

## Not implemented

- Expanded media forensics: OCR, video frames (module stays `planned`).
- Native PDF writer.
- Email or webhook delivery of notifications (would send case data out).
- Authentication, roles, TLS or remote deployment; the server is loopback
  only.
- Anything about people: person or username search, breach data, stealer
  logs, profile correlation. These are refused, not pending.

## Not verified

- No automated real-browser suite; the browser checks were done by hand and
  the accessibility audit is a browser script.
- Native builds only on Linux.
- Live sources are tested against recorded responses.

## Dependencies

- Python 3.10+ standard library only.
- Node.js only for `node --check`; it is not a runtime dependency.
- Optional native builds need gcc, g++, make and a Rust toolchain.
