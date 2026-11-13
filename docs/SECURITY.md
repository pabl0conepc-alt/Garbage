# Security

GARBAGE is a **local, single-analyst workstation**. It is not a hardened
multi-user service and must not be exposed directly to a network.

## 1. Threat model

Assets:

- Investigation records, notes and source provenance.
- Evidence bytes and their integrity records.
- Uploaded files submitted for static analysis.
- API keys or URLs an analyst may paste into source records.

Adversaries and hazards:

- Malicious files crafted to exploit a parser, archive bomb or path traversal.
- Malformed JSON, oversized bodies, invalid IDs and injection attempts.
- A local process or malicious webpage trying to reach the loopback API.
- A user pasting sensitive material into an unencrypted local database.
- Operator error: exposing the server, sharing the database or evidence folder.

Out of scope:

- Remote multi-user authentication and authorization.
- TLS termination and internet-facing deployment.
- Endpoint compromise or a malicious local user with filesystem access.
- Offensive operations, exploitation or unauthorized collection.

## 2. Implemented controls

### Network

- The HTTP server binds to `127.0.0.1` only; there is no bind-address option.
- Requests must carry a loopback `Host`. Cross-origin requests with a present
  `Origin` must match the bound origin; foreign origins receive 403.
- Response headers deny framing, MIME sniffing and referrer leakage, and set a
  same-origin Content Security Policy for the UI.
- Body limits: 1 MiB for ordinary JSON, 6 MiB for the base64 file-analysis
  endpoint. Oversized bodies receive 413.
- Static asset serving is an explicit allowlist; there is no directory traversal
  through the static handler.

### File intelligence

- Input is capped at 4 MiB **after** base64 decoding; base64 must be valid.
- Nothing is executed, emulated, mounted or automatically extracted.
- PDF, ZIP/OOXML, TAR, GZIP, image and executable handling is read-only.
- Archive member count is capped at 500; string output is capped; GZIP output
  is decompressed into a 1 MiB in-memory preview and never written to disk.
- Path-traversal names are reported, not followed.
- Binary parsers bound offsets and lengths against the actual buffer and stop at
  section/member limits. A parser exception is contained and reported as a
  limitation instead of crashing the request.
- Indicators are syntactic. The UI labels them as not reputation-checked.

### Evidence

- Evidence is capped at 4 MiB.
- Stored bytes use generated names; the original filename is metadata only.
- SHA-256 is computed at upload and re-checked by the verification route.
- Downloads and previews use explicit content types and attachment disposition
  where appropriate.
- Preview does not execute HTML or SVG as active content.

### Data handling

- SQL uses bound parameters.
- HTML report values and UI text are escaped.
- CSV exports prefix cells that begin with formula characters.
- Errors are structured and do not include Python tracebacks or secrets.
- The CISA KEV refresh is explicit, bounded, cached with a content hash and
  records its origin and failure state.

## 3. Known limitations

- **No authentication.** Any local process or user that can reach the loopback
  port can use the API.
- **No TLS and no encryption at rest.** The SQLite database, evidence folder and
  reports are plaintext on disk.
- **No CSRF token.** Origin checks reduce browser-driven cross-origin requests,
  but they are not a substitute for authentication.
- **No antivirus or sandbox.** Static analysis does not prove a file is safe.
- **Remote connectors are opt-in.** Third-party lookups run only with
  `intel.allow_network`; contact with the artifact's own servers also needs
  `intel.allow_target_contact`. All requests go through the SSRF-safe client in
  `net.py`.
- **API keys are stored in plaintext** in the workspace database, like every
  other record. They are never returned by the API, are sent only to their own
  provider and are removed from error text, but anyone who can read the
  database file can read them. Use keys you can revoke.
- **Optional native code.** C, C++ and Rust helpers parse only caller-supplied
  buffers with explicit bounds. A missing or incompatible library falls back to
  Python; builds are not downloaded. Native builds are memory-unsafe by nature,
  so their fixtures and parity tests matter; see `native/README.md`.
- **No audit log integrity.** Activity records are ordinary rows; an attacker
  with database write access can alter them.

## 4. Safe operating guidance

- Keep the server on loopback. Do not port-forward it, reverse-proxy it or bind
  it to `0.0.0.0`.
- Store the database and evidence folder on an encrypted volume if the material
  is sensitive.
- Treat every submitted file as untrusted even after analysis.
- Do not paste credentials into notes or source URLs.
- Back up the database and evidence directory before upgrades.
- Review the `planned` module states; do not enable a module merely to see a
  page.

## 5. Reporting a vulnerability

Do not open a public issue with exploit details or sensitive sample data.
Contact the repository owner privately with:

- affected version/commit,
- reproduction steps,
- impact,
- a minimal sample if safe to share.

There is no bug bounty or response-time guarantee.
