"""Read-only, single-file forensic hashing."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def hash_file(path: str | Path) -> dict[str, Any]:
    """Hash one explicitly named regular file without following symlinks."""
    requested_path = Path(path)
    if requested_path.is_symlink():
        raise ValueError("symbolic links are not accepted")
    resolved_path = requested_path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved_path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("path must identify a regular file")

        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            digest = hashlib.sha256()
            size_bytes = 0
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)

            after = os.fstat(source.fileno())
            if (
                before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or size_bytes != after.st_size
            ):
                raise ValueError("file changed while it was being hashed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    modified_at = datetime.fromtimestamp(
        after.st_mtime, timezone.utc
    ).isoformat().replace("+00:00", "Z")
    return {
        "path": str(resolved_path),
        "file_name": resolved_path.name,
        "size_bytes": size_bytes,
        "sha256": digest.hexdigest(),
        "modified_at": modified_at,
    }
