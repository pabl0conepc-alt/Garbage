"""Shared input validation helpers."""

from __future__ import annotations

import re

from .errors import ValidationError


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE)
_SAFE_SCHEMES = {"http", "https", "file", "note"}


def clean_text(
    value: object,
    field: str,
    *,
    max_length: int = 20000,
    required: bool = False,
    default: str = "",
) -> str:
    if value is None:
        text = default
    elif isinstance(value, str):
        text = value
    else:
        raise ValidationError(f"{field} must be a string")
    if _CONTROL_CHARS.search(text):
        raise ValidationError(f"{field} contains unsupported control characters")
    text = text.strip()
    if required and not text:
        raise ValidationError(f"{field} must not be empty")
    if len(text) > max_length:
        raise ValidationError(f"{field} exceeds {max_length} characters")
    return text


def choice(value: object, allowed: tuple[str, ...], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(f"{field} must be one of: {', '.join(allowed)}")
    return value


def optional_choice(
    value: object, allowed: tuple[str, ...], field: str, default: str
) -> str:
    if value is None:
        return default
    return choice(value, allowed, field)


def safe_reference(
    value: object,
    field: str = "source reference",
    *,
    max_length: int = 2000,
    required: bool = False,
) -> str:
    text = clean_text(
        value, field, max_length=max_length, required=required, default=""
    )
    if not text:
        return text
    match = _SCHEME.match(text)
    if match and match.group(1).lower() not in _SAFE_SCHEMES:
        raise ValidationError(
            f"{field} must use an http, https, file or note reference"
        )
    return text


def search_pattern(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return f"%{escaped}%"


def bounded_int(
    value: object, field: str, minimum: int, maximum: int, default: int
) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}")
    return value
