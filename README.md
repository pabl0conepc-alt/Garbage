# Garbage
GARBAGE is an open-source intelligence platform combining OSINT, Cyber Threat
Intelligence, SOCMINT and digital forensics into a unified ecosystem.

## Platforms and quick start

GARBAGE runs on Python 3.10 or newer and uses only the Python standard library.
The source launchers and zipapp work on Windows, macOS, and Linux, including
Kali, Debian, Ubuntu, Arch, and NixOS. This is support by design; see
`DEVELOPMENT_STATUS.md` for the platforms actually tested.

Clone or download the repository, then run commands from PowerShell on Windows:

```powershell
.\scripts\run.ps1 doctor
.\scripts\run.ps1 serve --port 8000
```

On macOS or Linux:

```sh
./scripts/run.sh doctor
./scripts/run.sh serve --port 8000
```

The launchers select a Python 3 interpreter, require version 3.10+, and run
from the repository directory. You can also use `py -3 -m garbage_intel` on
Windows or `python3 -m garbage_intel` on macOS/Linux. If Python is missing:

- Windows/macOS: install Python 3.10+ from [python.org](https://www.python.org/downloads/).
- Kali, Debian, or Ubuntu: `sudo apt install python3`.
- Arch Linux: `sudo pacman -S python`.
- NixOS: run `nix-shell -p python3 --run "python -m garbage_intel doctor"`.

Build a self-contained zipapp (Python standard library only):

```sh
python3 tools/build_zipapp.py
python3 dist/garbage.pyz doctor
python3 dist/garbage.pyz serve --port 8000
```

On Windows, use `py -3 tools\build_zipapp.py` and
`py -3 dist\garbage.pyz doctor`. The build refuses to overwrite an existing
output; choose another path with `--output PATH` or remove the old artifact
yourself. It bundles the CLI and web assets, but not Python itself. Database
paths are relative to the current directory unless `--database` or
`GARBAGE_DATABASE` is set. The development server remains loopback-only.

## Current implementation

The first working slice is a local evidence ledger built with Python's standard
library and SQLite. It records investigations and user-entered observations,
including a source reference, collection basis, observation time, and recording
time. Reports include local pattern-based detection of IPv4 addresses, domain
names, and MD5/SHA-1/SHA-256 strings; findings carry their observation
provenance and are not independently verified or reputation-checked.

Run the CLI from the repository root:

```sh
python3 -m garbage_intel init
python3 -m garbage_intel investigation create --name "Example investigation"
python3 -m garbage_intel investigation list
python3 -m garbage_intel investigation show --investigation-id INVESTIGATION_ID
python3 -m garbage_intel investigation timeline \
  --investigation-id INVESTIGATION_ID
python3 -m garbage_intel investigation set-status \
  --investigation-id INVESTIGATION_ID --status closed
```

Add an observation using the created investigation's ID:

```sh
python3 -m garbage_intel observation add \
  --investigation-id INVESTIGATION_ID \
  --title "Public notice" \
  --content "A concise description of the observation." \
  --source-reference "https://example.org/notice" \
  --collection-basis public \
  --observed-at "2025-01-02T03:04:05Z"
python3 -m garbage_intel report --investigation-id INVESTIGATION_ID
```

Set `GARBAGE_DATABASE` or pass `--database PATH` to select another SQLite
database. Collection basis must be `public`, `authorized`, or `user-provided`.
Only record information you are authorized to access and use.

Investigations may be `open`, `closed`, or `cancelled`. Closed and cancelled
investigations are read-only; set the status back to `open` to add evidence
again. Analyst notes can be recorded as observations with a `note://` source
reference and `user-provided` collection basis.

Reports default to JSON and can also be emitted as HTML or CSV:

```sh
python3 -m garbage_intel report \
  --investigation-id INVESTIGATION_ID --format csv
python3 -m garbage_intel report \
  --investigation-id INVESTIGATION_ID --format html --output report.html
```

`--output` creates a new file and refuses to overwrite an existing one.
CSV rows retain investigation/observation metadata and provenance; indicators,
correlations, and report limitations are encoded as JSON-valued columns.
Formula-like text cells are prefixed to reduce spreadsheet formula injection
when CSV is opened in spreadsheet software.

Create a versioned JSON archive and restore it into another database:

```sh
python3 -m garbage_intel backup --output archive.json
python3 -m garbage_intel --database restored.sqlite3 import --input archive.json
```

JSON import validates the complete archive before modifying the database, then
imports investigations, observations, and status history transactionally.
Existing records are never overwritten; conflicting IDs fail the import.
Archive inputs are limited to 10 MiB. A consistent SQLite file backup is also
available with `backup --format sqlite`; both backup formats refuse to replace
an existing destination.

## CISA KEV public metadata

The optional CISA Known Exploited Vulnerabilities connector fetches only the
fixed public CISA JSON feed when explicitly requested. It records catalog
version, source release time, fetch time, source URL, and a SHA-256 digest in a
local sidecar cache (`DATABASE.cisa-kev-cache.json`). Cached catalog data is
separate from investigations and is not included in investigation archives.
Descriptions, vendor/product names, due dates, and remediation actions are
retained; external notes/references are omitted.

```sh
python3 -m garbage_intel intel kev refresh
python3 -m garbage_intel intel kev status
python3 -m garbage_intel intel kev list --search "Example Vendor"
```

Refreshes less than 15 minutes apart use the cache without a network request;
`--force` bypasses that interval but still performs at most one HTTPS request.
The connector uses a 10-second timeout, a 10 MiB response limit, CISA-host-only
HTTPS redirects, ETag/Last-Modified conditional requests, and surfaces
`Retry-After` on rate limiting without retrying. It never checks assets,
correlates CVEs to targets, or performs automated actions.

Run the focused tests with `python3 -m unittest discover -s tests`. The GitHub
Actions workflow runs the standard-library test suite on Windows, macOS, and
Ubuntu with Python 3.10 and 3.14, and smoke-tests the matching PowerShell or
POSIX launcher on each runner.

## Local web interface and API

Start the local-only web interface and JSON API:

```sh
python3 -m garbage_intel serve --port 8000
```

Open `http://127.0.0.1:8000/`. The same server exposes `GET /api/health`,
`GET /api/investigations`, `POST /api/investigations`,
`POST /api/investigations/{id}/observations`, and
`GET /api/investigations/{id}/report`. `PATCH /api/investigations/{id}` updates
the investigation status. Printable, escaped HTML reports are available at
`/reports/{id}`. Chronological event data is available from
`GET /api/investigations/{id}/timeline` and the CLI timeline command.
The CISA cache is read-only at `GET /api/intel/cisa-kev`; an explicit
same-origin `POST /api/intel/cisa-kev/refresh` or the “Refresh CISA KEV” button
initiates a refresh. Page load and ordinary reads never contact CISA.

The development server binds only to loopback, checks Host/Origin, limits JSON
bodies to 1 MiB, and uses a restrictive content security policy. It has no
user authentication or TLS and is not suitable for remote or production
deployment. Do not expose it on a network or record information you are not
authorized to access.

## Local analysis modules

Reports include deterministic exact-value correlation when the same normalized
indicator appears in multiple observations. Correlations list every source and
do not imply attribution or maliciousness.

Hash one explicitly named, analyst-provided regular file and record its SHA-256
and filesystem metadata in an investigation:

```sh
python3 -m garbage_intel forensics hash-file \
  --investigation-id INVESTIGATION_ID \
  --path /path/to/authorized/evidence.bin
```

The command is read-only, processes one file without recursion, rejects
symbolic links and changing files, and does not store the file contents.

Inspect filesystem/document metadata without initializing the database or
reading file contents:

```sh
python3 -m garbage_intel forensics document-metadata \
  --path /path/to/authorized/document.pdf
```
