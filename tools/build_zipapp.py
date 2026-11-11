"""Build a dependency-free GARBAGE zipapp with its local web assets."""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "garbage.pyz",
        help="new zipapp path (default: dist/garbage.pyz)",
    )
    args = parser.parse_args(argv)
    output = args.output.resolve()

    try:
        if output.exists():
            raise FileExistsError(f"output already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="garbage-zipapp-") as temp_dir:
            staging = Path(temp_dir)
            shutil.copytree(
                ROOT / "garbage_intel",
                staging / "garbage_intel",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copytree(ROOT / "web", staging / "web")
            (staging / "__main__.py").write_text(
                "from garbage_intel.cli import main\n"
                "raise SystemExit(main())\n",
                encoding="utf-8",
            )
            zipapp.create_archive(staging, output)
    except OSError as exc:
        print(f"build_zipapp: {exc}", file=sys.stderr)
        return 2

    print(f"Built {output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
