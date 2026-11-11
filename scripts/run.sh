#!/bin/sh
set -eu

if command -v python3 >/dev/null 2>&1; then
    python=python3
elif command -v python >/dev/null 2>&1; then
    python=python
else
    printf '%s\n' "GARBAGE requires Python 3.10 or newer. Install Python and try again." >&2
    exit 127
fi

if ! "$python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    printf '%s\n' "GARBAGE requires Python 3.10 or newer; found $("$python" --version 2>&1)." >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir/.."
exec "$python" -m garbage_intel "$@"
