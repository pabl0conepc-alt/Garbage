"""Explicit, read-only refresh of CISA's public KEV metadata feed."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FORMAT = "garbage-cisa-kev-cache"
MAX_FEED_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 10_000
REQUEST_TIMEOUT_SECONDS = 10
MIN_REFRESH_INTERVAL = timedelta(minutes=15)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_CACHE_LOCK = threading.Lock()


class CisaKevError(ValueError):
    """A safe, user-displayable connector or cache validation error."""


class _CisaRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        if (
            destination.scheme != "https"
            or destination.hostname not in {"www.cisa.gov", "cisa.gov"}
        ):
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "Refused redirect outside CISA HTTPS hosts",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CisaKevError("timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CisaKevError(f"{field} must be a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CisaKevError(f"{field} must be an ISO 8601 timestamp") from exc
    return _utc_iso(parsed)


def _text(value: object, field: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CisaKevError(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > max_length:
        raise CisaKevError(f"{field} exceeds the supported length")
    return value


def _date(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CisaKevError(f"{field} must be an ISO date")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise CisaKevError(f"{field} must be an ISO date") from exc
    return value


def _header_value(value: object, field: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > 1000
        or "\r" in value
        or "\n" in value
    ):
        raise CisaKevError(f"{field} is not a valid HTTP header value")
    return value


def _validate_item(item: object) -> dict[str, str]:
    if not isinstance(item, dict):
        raise CisaKevError("catalog contains a non-object vulnerability record")
    cve_id = _text(item.get("cveID"), "cveID", 32)
    if not _CVE_ID.fullmatch(cve_id):
        raise CisaKevError("catalog contains an invalid CVE identifier")
    ransomware_use = item.get("knownRansomwareCampaignUse", "Unknown")
    if not isinstance(ransomware_use, str) or ransomware_use not in {
        "Known",
        "Unknown",
        "Yes",
        "No",
    }:
        raise CisaKevError("catalog contains an invalid ransomware-use value")
    return {
        "cve_id": cve_id,
        "vendor_project": _text(item.get("vendorProject"), "vendorProject", 500),
        "product": _text(item.get("product"), "product", 500),
        "vulnerability_name": _text(
            item.get("vulnerabilityName"), "vulnerabilityName", 1000
        ),
        "date_added": _date(item.get("dateAdded"), "dateAdded"),
        "short_description": _text(
            item.get("shortDescription"), "shortDescription", 5000
        ),
        "required_action": _text(item.get("requiredAction"), "requiredAction", 10_000),
        "due_date": _date(item.get("dueDate"), "dueDate"),
        "ransomware_use": ransomware_use,
    }


def parse_feed(
    raw: bytes,
    *,
    fetched_at: datetime | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
) -> dict[str, Any]:
    if len(raw) > MAX_FEED_BYTES:
        raise CisaKevError("CISA KEV response exceeds the 10 MiB limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CisaKevError("CISA KEV response must be valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise CisaKevError("CISA KEV response must be a JSON object")
    if document.get("title") != "CISA Catalog of Known Exploited Vulnerabilities":
        raise CisaKevError("CISA KEV response has an unexpected catalog title")
    version = _text(document.get("catalogVersion"), "catalogVersion", 100)
    source_updated_at = _timestamp(document.get("dateReleased"), "dateReleased")
    count = document.get("count")
    items = document.get("vulnerabilities")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or count > MAX_RECORDS
        or not isinstance(items, list)
        or count != len(items)
    ):
        raise CisaKevError("CISA KEV count does not match the vulnerability records")
    validated_items = [_validate_item(item) for item in items]
    cve_ids = [item["cve_id"] for item in validated_items]
    if len(cve_ids) != len(set(cve_ids)):
        raise CisaKevError("CISA KEV catalog contains duplicate CVE identifiers")
    return {
        "format": CACHE_FORMAT,
        "source_url": FEED_URL,
        "catalog_version": version,
        "source_updated_at": source_updated_at,
        "fetched_at": _utc_iso(fetched_at or datetime.now(timezone.utc)),
        "etag": _header_value(etag, "ETag"),
        "last_modified": _header_value(last_modified, "Last-Modified"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "count": count,
        "vulnerabilities": validated_items,
    }


def cache_path(database: str | Path) -> Path:
    if str(database) == ":memory:":
        raise CisaKevError("CISA KEV cache requires a file-backed database path")
    path = Path(database)
    return path.with_name(f"{path.name}.cisa-kev-cache.json")


def _validate_cache(document: object) -> dict[str, Any]:
    fields = {
        "format",
        "source_url",
        "catalog_version",
        "source_updated_at",
        "fetched_at",
        "etag",
        "last_modified",
        "sha256",
        "count",
        "vulnerabilities",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise CisaKevError("local CISA KEV cache has an invalid schema")
    if document["format"] != CACHE_FORMAT or document["source_url"] != FEED_URL:
        raise CisaKevError("local cache is not a supported CISA KEV snapshot")
    version = _text(document["catalog_version"], "catalog_version", 100)
    source_updated_at = _timestamp(document["source_updated_at"], "source_updated_at")
    fetched_at = _timestamp(document["fetched_at"], "fetched_at")
    etag = _header_value(document["etag"], "cached ETag")
    last_modified = _header_value(
        document["last_modified"], "cached Last-Modified"
    )
    digest = document["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise CisaKevError("cached feed digest is invalid")
    items = document["vulnerabilities"]
    count = document["count"]
    if (
        not isinstance(items, list)
        or len(items) > MAX_RECORDS
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(items)
    ):
        raise CisaKevError("local CISA KEV cache has an invalid record count")
    validated_items = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "cve_id",
            "vendor_project",
            "product",
            "vulnerability_name",
            "date_added",
            "short_description",
            "required_action",
            "due_date",
            "ransomware_use",
        }:
            raise CisaKevError("local CISA KEV cache has an invalid record")
        ransomware_use = item["ransomware_use"]
        if not isinstance(ransomware_use, str) or ransomware_use not in {
            "Known",
            "Unknown",
            "Yes",
            "No",
        }:
            raise CisaKevError("local CISA KEV cache has an invalid ransomware-use value")
        validated_items.append(
            {
                "cve_id": _text(item["cve_id"], "cve_id", 32),
                "vendor_project": _text(
                    item["vendor_project"], "vendor_project", 500
                ),
                "product": _text(item["product"], "product", 500),
                "vulnerability_name": _text(
                    item["vulnerability_name"], "vulnerability_name", 1000
                ),
                "date_added": _date(item["date_added"], "date_added"),
                "short_description": _text(
                    item["short_description"], "short_description", 5000
                ),
                "required_action": _text(
                    item["required_action"], "required_action", 10_000
                ),
                "due_date": _date(item["due_date"], "due_date"),
                "ransomware_use": ransomware_use,
            }
        )
    if len({item["cve_id"] for item in validated_items}) != len(validated_items):
        raise CisaKevError("local CISA KEV cache contains duplicate CVE identifiers")
    return {
        **document,
        "catalog_version": version,
        "source_updated_at": source_updated_at,
        "fetched_at": fetched_at,
        "etag": etag,
        "last_modified": last_modified,
        "vulnerabilities": validated_items,
    }


def read_cache(database: str | Path) -> dict[str, Any] | None:
    path = cache_path(database)
    if path.is_symlink():
        raise CisaKevError("refusing to read a symlink as the CISA KEV cache")
    if not path.exists():
        return None
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_FEED_BYTES + 1)
    except OSError as exc:
        raise CisaKevError(f"could not read CISA KEV cache: {exc}") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise CisaKevError("local CISA KEV cache exceeds the 10 MiB limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CisaKevError("local CISA KEV cache is not valid UTF-8 JSON") from exc
    return _validate_cache(document)


def _write_cache(database: str | Path, snapshot: dict[str, Any]) -> None:
    path = cache_path(database)
    encoded = (json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_FEED_BYTES:
        raise CisaKevError("validated CISA KEV cache exceeds the 10 MiB limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except OSError as exc:
        raise CisaKevError(f"could not save CISA KEV cache: {exc}") from exc
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _response_header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", {})
    return headers.get(name) if headers else None


def _fetch_response(request: urllib.request.Request, opener: Any) -> Any:
    try:
        return opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        if exc.code in {304, 429}:
            return exc
        exc.close()
        raise CisaKevError(f"CISA KEV refresh failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CisaKevError("CISA KEV request failed; check connectivity and retry") from exc


def _summary(snapshot: dict[str, Any], refresh_status: str) -> dict[str, Any]:
    return {
        "source_url": snapshot["source_url"],
        "catalog_version": snapshot["catalog_version"],
        "source_updated_at": snapshot["source_updated_at"],
        "fetched_at": snapshot["fetched_at"],
        "sha256": snapshot["sha256"],
        "count": snapshot["count"],
        "refresh_status": refresh_status,
    }


def cached_status(database: str | Path) -> dict[str, Any]:
    snapshot = read_cache(database)
    if snapshot is None:
        raise CisaKevError("no CISA KEV cache; run an explicit refresh first")
    return _summary(snapshot, "cached")


def list_cached(
    database: str | Path, search: str = "", limit: int = 25
) -> dict[str, Any]:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise CisaKevError("limit must be between 1 and 100")
    snapshot = read_cache(database)
    if snapshot is None:
        raise CisaKevError("no CISA KEV cache; run an explicit refresh first")
    query = search.casefold().strip()
    matches = [
        item
        for item in snapshot["vulnerabilities"]
        if not query
        or query
        in " ".join(
            (
                item["cve_id"],
                item["vendor_project"],
                item["product"],
                item["vulnerability_name"],
                item["short_description"],
            )
        ).casefold()
    ]
    return {
        **_summary(snapshot, "cached"),
        "matched": len(matches),
        "items": matches[:limit],
    }


def refresh_cisa_kev(
    database: str | Path,
    *,
    force: bool = False,
    opener: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(force, bool):
        raise CisaKevError("force must be a boolean")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise CisaKevError("refresh time must include a timezone")
    current_time = current_time.astimezone(timezone.utc)
    with _CACHE_LOCK:
        cached = read_cache(database)
        if cached is not None and not force:
            last_fetch = datetime.fromisoformat(
                cached["fetched_at"].replace("Z", "+00:00")
            )
            age = current_time - last_fetch
            if timedelta(0) <= age < MIN_REFRESH_INTERVAL:
                return {
                    **_summary(cached, "cache_fresh"),
                    "matched": cached["count"],
                    "items": cached["vulnerabilities"][:25],
                }

        headers = {
            "Accept": "application/json",
            "User-Agent": "GARBAGE local defensive metadata connector",
        }
        if cached is not None:
            if cached["etag"]:
                headers["If-None-Match"] = cached["etag"]
            if cached["last_modified"]:
                headers["If-Modified-Since"] = cached["last_modified"]
        request = urllib.request.Request(FEED_URL, headers=headers)
        client = opener or urllib.request.build_opener(_CisaRedirectHandler())
        response = _fetch_response(request, client)
        status = getattr(response, "status", None) or response.getcode()
        if status == 304:
            if cached is None:
                response.close()
                raise CisaKevError("CISA returned not-modified without a local cache")
            cached["fetched_at"] = _utc_iso(current_time)
            cached["etag"] = _response_header(response, "ETag") or cached["etag"]
            cached["last_modified"] = (
                _response_header(response, "Last-Modified")
                or cached["last_modified"]
            )
            response.close()
            _write_cache(database, cached)
            return {
                **_summary(cached, "not_modified"),
                "matched": cached["count"],
                "items": cached["vulnerabilities"][:25],
            }
        if status == 429:
            retry_after = _response_header(response, "Retry-After")
            response.close()
            message = "CISA KEV refresh was rate-limited"
            if retry_after:
                message += f"; Retry-After: {retry_after}"
            raise CisaKevError(message)
        if status != 200:
            response.close()
            raise CisaKevError(f"CISA KEV refresh failed with HTTP {status}")
        content_length = _response_header(response, "Content-Length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                response.close()
                raise CisaKevError("CISA KEV response has invalid Content-Length") from exc
            if declared_length < 0:
                response.close()
                raise CisaKevError("CISA KEV response has invalid Content-Length")
            if declared_length > MAX_FEED_BYTES:
                response.close()
                raise CisaKevError("CISA KEV response exceeds the 10 MiB limit")
        try:
            raw = response.read(MAX_FEED_BYTES + 1)
        except OSError as exc:
            raise CisaKevError("could not read the CISA KEV response") from exc
        finally:
            response.close()
        if not isinstance(raw, bytes):
            raise CisaKevError("CISA KEV response body must be bytes")
        if len(raw) > MAX_FEED_BYTES:
            raise CisaKevError("CISA KEV response exceeds the 10 MiB limit")
        snapshot = parse_feed(
            raw,
            fetched_at=current_time,
            etag=_response_header(response, "ETag"),
            last_modified=_response_header(response, "Last-Modified"),
        )
        _write_cache(database, snapshot)
        return {
            **_summary(snapshot, "updated"),
            "matched": snapshot["count"],
            "items": snapshot["vulnerabilities"][:25],
        }
