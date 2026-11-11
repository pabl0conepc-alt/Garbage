"""Safe opening helpers for explicitly named regular files."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path


def _is_link(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    if os.name == "nt":
        reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(getattr(metadata, "st_file_attributes", 0) & reparse_point)
    return False


def _require_regular_file(metadata: os.stat_result) -> None:
    if _is_link(metadata):
        raise ValueError(
            "symbolic links and filesystem reparse points are not accepted"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("path must identify a regular file")


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_ino != 0
        and second.st_ino != 0
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )


def open_regular_file(
    path: Path, *, metadata_only: bool = False
) -> tuple[int, os.stat_result]:
    """Open one regular file and reject links or path swaps across platforms."""
    initial = path.lstat()
    _require_regular_file(initial)

    access_flag = (
        getattr(os, "O_PATH", os.O_RDONLY) if metadata_only else os.O_RDONLY
    )
    flags = (
        access_flag
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in (
            getattr(errno, "ELOOP", None),
            getattr(errno, "EMLINK", None),
        ):
            raise ValueError(
                "symbolic links and filesystem reparse points are not accepted"
            ) from error
        raise

    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        _require_regular_file(opened)
        _require_regular_file(current)
        if not all(
            _same_file(first, second)
            for first, second in ((initial, opened), (opened, current))
        ):
            raise ValueError(
                "file changed while opening or stable identity is unavailable"
            )
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise
