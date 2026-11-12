# Installation

## Requirements

- Python **3.10 or newer** with the standard `sqlite3` module.
- A modern browser for the interface.
- No third-party Python packages, build tools or services.

Node.js is only needed for JavaScript syntax checks and the optional development
smoke harness. It is not required to run GARBAGE.

## From source

```sh
git clone <repository-url>
cd Garbage
./scripts/run.sh doctor
./scripts/run.sh init
./scripts/run.sh serve --port 8765
```

Windows PowerShell:

```powershell
.\scripts\run.ps1 doctor
.\scripts\run.ps1 init
.\scripts\run.ps1 serve --port 8765
```

The launchers locate a Python 3 interpreter, verify the minimum version and run
from the repository root. You can bypass them:

```sh
python3 -m garbage_intel doctor
python3 -m garbage_intel init
python3 -m garbage_intel serve --port 8765
```

Open <http://127.0.0.1:8765/>.

## Optional native helpers

GARBAGE runs without native code. To build the optional C, C++ and Rust helpers:

```sh
make -C native
make -C native check
```

Requires a C11/C++17 compiler and a Rust toolchain (`cargo`). Outputs go to
`native/build/`. Set `GARBAGE_NATIVE_DIR` to load a build from another directory.
The zipapp does not bundle `.so`/`.dylib` files; use the Python fallback or set
the environment variable to an external build. See [native/README.md](../native/README.md).

## Python installation by platform

- Windows/macOS: <https://www.python.org/downloads/>
- Debian/Ubuntu/Kali: `sudo apt install python3`
- Arch: `sudo pacman -S python`
- NixOS: `nix-shell -p python3 --run "python -m garbage_intel doctor"`

## Zipapp

```sh
python3 tools/build_zipapp.py
python3 dist/garbage.pyz doctor
python3 dist/garbage.pyz init
python3 dist/garbage.pyz serve --port 8765
```

Windows: `py -3 tools\build_zipapp.py`.

The output is create-only. Use `--output PATH` for a different location or
remove the previous artifact yourself. The zipapp bundles the Python package and
web assets, not the Python interpreter.

## Data locations

- Database: `data/garbage.sqlite3` by default; override with `--database PATH`
  or `GARBAGE_DATABASE`.
- Evidence: a sibling directory managed by the application.
- CISA KEV cache: `<database>.cisa-kev-cache.json`.
- Relative paths resolve against the current working directory; the launchers
  `cd` to the repository root.

Back up the database, evidence directory and KEV cache together. JSON/SQLite
backup commands cover investigation data; the KEV cache is separate.

## First run

1. `doctor` — Python/SQLite/platform diagnostics; does not initialize data.
2. `init` — creates the database and migrations.
3. `serve` — starts the loopback API and UI.
4. Create a case and add a source before adding observations, so provenance is
   recorded from the start.

## Troubleshooting

**`GARBAGE requires Python 3.10 or newer`** — install a newer interpreter and
ensure `python3` (or `py -3`) resolves to it.

**Port already in use** — choose another port: `serve --port 8877`. The server
only binds loopback.

**Browser cannot connect** — confirm the process is running and use
`127.0.0.1`, not a LAN address. GARBAGE is not reachable from another machine by
design.

**`database is locked`** — close other processes using the same SQLite file.
Avoid running multiple writers against one database.

**CISA refresh fails** — the previous cache is retained. Check network access,
proxy settings and CISA availability; refresh is explicit and never required for
local work.

**Uploads rejected as too large** — evidence and file analysis are capped at
4 MiB decoded. Reduce or split the file; do not raise the limit casually.

## Security

Do not reverse-proxy, port-forward or bind GARBAGE to a public interface. It has
no authentication or TLS. See [SECURITY.md](SECURITY.md).
