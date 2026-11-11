"""Read-only metadata for one explicitly named document."""

from __future__ import annotations

import errno
import mimetypes
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def get_document_metadata(path: str | Path) -> dict[str, Any]:
    """Return filesystem metadata without following or reading a document."""
    requested_path = Path(path)
    flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested_path, flags)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"document does not exist: {requested_path}") from error
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise ValueError("symbolic links are not accepted") from error
        raise

    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("symbolic links are not accepted")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("path must identify a regular file")

    file_name = requested_path.name
    media_type, _ = mimetypes.guess_type(file_name, strict=False)
    modified_at = datetime.fromtimestamp(
        metadata.st_mtime, timezone.utc
    ).isoformat().replace("+00:00", "Z")
    return {
        "file_name": file_name,
        "suffix": requested_path.suffix,
        "media_type": media_type or "application/octet-stream",
        "size_bytes": metadata.st_size,
        "modified_at": modified_at,
    }
