# Module development

## 1. Current module model

Built-in modules are Python packages under `garbage_intel/modules/` (and a
few top-level services), registered in `DEFAULT_MODULES` in `db.py`. Analyst
code runs only as a **local plugin** (section 8): approved by digest and run
in a separate process, never imported into the server.

Registry row:

```python
(
    "module-id",          # stable, lowercase, hyphenated
    "Human name",
    "One-sentence behaviour.",
    "Category",
    "1.0.0",
    "enabled",            # enabled | disabled | planned
)
```

States:

- `enabled`: API routes are usable and the UI navigation entry appears.
- `disabled`: routes return `409`; data is retained.
- `planned`: cannot be enabled. This is the required state for anything without
  a tested backend. It prevents a page or button from implying capability.

`GET /api/modules` is the authoritative list. Only `media-forensics` is still
`planned` (OCR and video frames would need optional external tools).

## 2. Adding a Python module

1. Implement the analysis/collection in `garbage_intel/modules/<name>.py`.
   - Accept bytes or validated primitives, not arbitrary paths.
   - Bound every loop, output and decompression.
   - Return plain dictionaries.
   - Raise `ValidationError`/`NotFoundError`; never leak tracebacks.
2. Add persistence only through an additive migration in `db.py`. Update
   `DATABASE_SCHEMA.md`.
3. Add registry row with state `planned` first.
4. Add API routes:
   - call `self._module("<module-id>")`;
   - validate an allowlist of payload fields;
   - enforce body limits;
   - use bound SQL parameters;
   - return consistent JSON.
5. Add the UI view and navigation entry. The shell must hide the entry when the
   module is not enabled.
6. Add tests for success, malformed input, limits, persistence, module gating
   and, where applicable, foreign-origin rejection.
7. Change the state to `enabled` only after the tests pass. Update
   `OPENARCHIVE_FEATURE_MATRIX.md` and `ROADMAP.md`.

## 3. Connector rules (website/domain/IP/OSINT)

Not implemented yet. Any future connector must:

- Use an explicit fixed allowlist of destinations or an operator-configured,
  validated endpoint; no arbitrary URL fetch from a record.
- Resolve and reject loopback, link-local, private and metadata addresses
  (SSRF protection), including after redirects.
- Cap redirects, response bytes and total time.
- Send no credentials by default.
- Record the exact URL, retrieval time, status and content hash as provenance.
- Be explicitly triggered or scheduled with a visible interval; no hidden
  background scraping.
- Have offline fixture tests and a failure mode that never fabricates results.
- Respect robots.txt, terms and rate limits where applicable.

Collection must be lawful and authorized. No authentication bypass, scanning of
third parties without permission, or stealth.

## 4. Native modules (optional)

C, C++ and Rust helpers live in `native/` and are loaded through `ctypes`:

- C: bounded ELF/PE hardening scan and byte entropy (`native/c/`).
- C++: relationship graph components, isolates, degree, density and reciprocal
  edges (`native/cpp/`).
- Rust: bounded Damerau-Levenshtein distance and domain skeleton for lookalike
  analysis (`native/rust/`).

Build with `make -C native`; run parity tests with `make -C native check` or
`GARBAGE_NATIVE_DIR=... python3 -m unittest tests.test_native -v`. A missing
library, wrong ABI or missing symbol falls back to the Python reference. The
contract below applies to every native function.

### C ABI

```c
typedef struct {
    const unsigned char *data;
    size_t length;
} gi_buffer;

typedef struct {
    int status;            /* 0 success, negative error */
    char message[256];     /* NUL-terminated, ASCII */
} gi_result;

gi_result gi_scan_headers(gi_buffer input, char *output, size_t output_capacity,
                          size_t *output_length);
```

Rules:

- Caller owns all input and output memory.
- Every length is explicit; no NUL-terminated input assumption.
- No function opens files, spawns processes, executes data or calls the network.
- Output is bounded and returns a "buffer too small" status rather than
  overrunning.
- Errors are numeric with a fixed message buffer.
- Thread safety is documented per function.

### Loading and fallback

- `ctypes` (or `cffi`) loads a library only from an explicit build directory or
  `GARBAGE_NATIVE_DIR` environment variable.
- A missing library, symbol mismatch or ABI version mismatch logs a diagnostic
  and uses the pure-Python path.
- The Python path remains the reference implementation and must pass the same
  fixtures.
- No native library is downloaded at runtime.
- `GARBAGE_NATIVE_DIR` selects one explicit build directory; it is not merged
  with the repository default.
- The API/UI exposes which engine actually ran (`c-native`, `cpp-native`,
  `rust-native` or `python-fallback`).

### Language fit

- **C**: bounded byte/header readers.
- **C++**: large graph metrics and complex document parsers behind `extern "C"`.
- **Rust**: hashing, entropy, deduplication and parallel extraction. PyO3 is
  acceptable only if the fallback and packaging story is verified.

### Build and test

- Document compiler versions and commands.
- Build native code as optional, not required for `python -m garbage_intel`.
- Run the same parser fixtures against both implementations.
- Add malformed/truncated cases and a fuzz target where feasible.
- Do not claim a speedup without a benchmark.

The Ubuntu CI job installs a stable Rust toolchain, builds all three helpers and
runs `tests.test_native` so native and fallback results are compared. macOS keeps
the `.dylib` naming in `native/Makefile`; Windows remains fallback-only unless a
compatible build is supplied.

## 5. Automation rules (planned)

An automation runner must be declarative and allowlisted. It may not execute
shell commands, arbitrary Python, macros or downloaded scripts. Each step must
name a registered operation, validate its inputs, record provenance, respect
module state and stop on error. A dry-run mode is required before scheduling.

## 8. Local plugins

A plugin adds a transform without touching the server code. It lives in the
plugins directory (`GARBAGE_PLUGINS_DIR`, or `plugins/` next to the
database), one folder per plugin:

```
plugins/idn-inspect/
  plugin.json
  main.py
```

`plugin.json`:

```json
{
  "id": "idn-inspect",
  "name": "Inspetor de IDN",
  "version": "1.0.0",
  "description": "What it does, in one sentence.",
  "entry": "main.py",
  "accepts": ["domain", "url"],
  "outputs": [{"result_type": "ascii-lookalike", "entity_type": "domain", "relationship_type": "related-to"}],
  "permissions": {"network": [], "contacts_target": false, "max_requests": 10, "timeout_seconds": 10, "max_output_kb": 64}
}
```

- `accepts` uses the multi-source artifact types. `outputs` lists the result
  types that become entities when the plugin runs as a transform; person,
  username and profile are refused.
- `permissions.network` lists the only hosts `ctx.fetch` may reach (up to 10;
  empty means no network). Limits: 50 requests, 60 s, 1 MiB of output.

`main.py` exposes `run(ctx)`, which returns a list of findings
`{"result_type", "value", "data"?, "source_url"?}`. `ctx.type` and
`ctx.value` are the artifact; `ctx.fetch(url, headers=None)` performs a GET
through the server and returns an object with `status`, `headers`, `url`,
`body`, `text()` and `json()`.

Lifecycle: the Module manager lists every folder with its state (invalid,
not approved, active, changed). Approving records the SHA-256 of the
manifest and all `.py` files; any later edit sets the plugin to *changed*
and it stops running until approved again. An active plugin is the connector
`plugin-<id>`, available in the multi-source search and as a transform,
behind the same network and target-contact settings as built-in sources.

Isolation: each run is a fresh `python -I` process with a minimal
environment, the plugin folder as working directory, a time limit, an
address-space and CPU cap on POSIX, stdout reserved for the protocol and
`socket` replaced so the only network path is the brokered `ctx.fetch`
(SSRF-safe, host-restricted, credentials headers stripped). This contains
mistakes and runaway code; it is not a sandbox for hostile code, so approve
only plugins you have read. `examples/plugins/idn-inspect` is a complete,
offline example.

