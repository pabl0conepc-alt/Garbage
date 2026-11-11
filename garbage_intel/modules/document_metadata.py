"""Read-only metadata for one explicitly named document."""

from __future__ import annotations

import mimetypes
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .file_access import open_regular_file


def get_document_metadata(path: str | Path) -> dict[str, Any]:
    """Return filesystem metadata without following or reading a document."""
    requested_path = Path(path)
    try:
        descriptor, metadata = open_regular_file(requested_path, metadata_only=True)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"document does not exist: {requested_path}") from error
    os.close(descriptor)

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
