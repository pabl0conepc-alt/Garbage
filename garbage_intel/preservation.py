"""Evidence preservation (catalogue block 5, after OpenArchive Save).

- ``capture_url`` fetches a page once and stores the exact bytes received as
  evidence, with the final URL, status, redirects, server address and
  response headers recorded at capture time. A second record holds the
  extracted text as a working copy, so the original is never altered.
- ``export_package`` writes a ZIP with every stored file of a case, a
  ``manifest.json`` (hashes, times, sources, custody events), a
  ``SHA256SUMS`` file and a standard-library ``verify.py`` so anyone can
  check the package without GARBAGE.
- ``verify_all`` re-hashes every stored file; the scheduler runs it daily and
  mismatches are logged and sent to the webhook.
"""

from __future__ import annotations

import hashlib
import html
import io
import json
import threading
import time
import zipfile
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from . import intel, net
from .db import _connection, record_activity, require_module, setting_bool, utc_now
from .errors import NotFoundError, ValidationError
from .evidence import MAX_EVIDENCE_BYTES, _read_stored_file, add_evidence, verify_evidence
from .modules.intel_web_surface import _SCRIPT_STYLE, _TAGS, visible_text_hash
from .validation import clean_text

FETCH = net.fetch

VERIFY_SCRIPT = '''#!/usr/bin/env python3
"""Check a GARBAGE evidence package: python3 verify.py (from the unzipped folder)."""
import hashlib, json, pathlib, sys

root = pathlib.Path(__file__).resolve().parent
manifest_bytes = (root / "manifest.json").read_bytes()
problems = 0
for line in (root / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    path = root / name
    if not path.is_file():
        print(f"MISSING   {name}"); problems += 1; continue
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    ok = actual == digest
    problems += not ok
    print(f"{'OK      ' if ok else 'MISMATCH'}  {name}")
manifest = json.loads(manifest_bytes)
listed = {item["file"]: item["sha256"] for item in manifest["items"] if item.get("file")}
for name, digest in listed.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        print(f"MANIFEST MISMATCH  {name}"); problems += 1
print(f"manifest.json sha256 {hashlib.sha256(manifest_bytes).hexdigest()}")
print("All files match." if not problems else f"{problems} problem(s) found.")
sys.exit(1 if problems else 0)
'''


def capture_url(database: str, investigation_id: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) - {"url", "title", "note"}:
        raise ValidationError("send {url, title?, note?}")
    url = clean_text(payload.get("url"), "url", max_length=2000, required=True)
    if urlsplit(url).scheme != "https":
        raise ValidationError("only https:// URLs are captured")
    with _connection(database) as connection:
        require_module(connection, "evidence")
        if not (setting_bool(connection, "intel.allow_network", False) and setting_bool(connection, "intel.allow_target_contact", False)):
            raise ValidationError("capturing a page contacts its server: allow network and target contact in Settings")
    captured_at = utc_now()
    try:
        page = FETCH(url, max_bytes=MAX_EVIDENCE_BYTES, timeout=20.0, keep_all_headers=True)
    except (net.NetworkError, net.NetworkPolicyError) as exc:
        raise ValidationError(f"capture failed: {exc}") from exc
    if not page.body:
        raise ValidationError(f"the server answered HTTP {page.status} with an empty body")
    host = urlsplit(page.final_url).hostname or "page"
    content_type = page.headers.get("content-type", "application/octet-stream").split(";")[0].strip()
    extension = {"text/html": "html", "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg", "application/json": "json", "text/plain": "txt"}.get(content_type, "bin")
    title = clean_text(payload.get("title", ""), "title", max_length=250) or f"Captura de {host}"
    header_lines = "\n".join(f"{key}: {value}"[:500] for key, value in sorted(page.headers.items()))
    description = "\n".join(
        [
            clean_text(payload.get("note", ""), "note", max_length=2000),
            f"Requested URL: {url}",
            f"Final URL: {page.final_url}",
            f"HTTP status: {page.status}",
            f"Redirects: {' -> '.join(page.redirects) or 'none'}",
            f"Server address: {page.address}",
            f"Captured at (UTC): {captured_at}",
            f"Response headers:\n{header_lines}",
        ]
    ).strip()
    original = add_evidence(
        database,
        investigation_id,
        title=title,
        evidence_type="url",
        description=description[:10000],
        source_reference=page.final_url,
        original_name=f"{host}.{extension}",
        data=page.body,
        acquired_at=captured_at,
    )
    working = None
    if "html" in content_type or extension == "txt":
        text_digest, words = visible_text_hash(page.body)
        text = " ".join(html.unescape(_TAGS.sub(" ", _SCRIPT_STYLE.sub(" ", page.body.decode("utf-8", errors="replace")))).split())
        if text:
            working = add_evidence(
                database,
                investigation_id,
                title=f"{title} (texto, cópia de trabalho)",
                evidence_type="document",
                description=f"Visible text extracted from evidence {original['id']} (sha256 {original['sha256']}). {words} words; text sha256 {text_digest}. Derived copy for reading and search; the original is unchanged.",
                source_reference=page.final_url,
                original_name=f"{host}.txt",
                data=text.encode("utf-8")[:MAX_EVIDENCE_BYTES],
                acquired_at=captured_at,
                analyze_image=False,
            )
    with _connection(database) as connection:
        record_activity(connection, action="capture", target_type="evidence", target_id=original["id"],
                        investigation_id=investigation_id, summary=f"Page captured: {page.final_url[:200]}")
    return {"original": original, "working_copy": working, "status": page.status, "final_url": page.final_url}


def export_package(database: str, investigation_id: str) -> tuple[bytes, str]:
    with _connection(database) as connection:
        case = connection.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if case is None:
            raise NotFoundError("investigation not found")
        rows = connection.execute("SELECT * FROM evidence WHERE investigation_id = ? ORDER BY recorded_at", (investigation_id,)).fetchall()
        custody = connection.execute(
            """SELECT target_id, action, summary, actor, created_at FROM activities
               WHERE target_type = 'evidence' AND target_id IN (SELECT id FROM evidence WHERE investigation_id = ?)
               ORDER BY created_at""",
            (investigation_id,),
        ).fetchall()
    events: dict[str, list[dict[str, Any]]] = {}
    for row in custody:
        events.setdefault(row["target_id"], []).append({key: row[key] for key in ("action", "summary", "actor", "created_at")})
    buffer = io.BytesIO()
    items = []
    sums = []
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            item = {
                key: row[key]
                for key in ("id", "title", "evidence_type", "description", "source_reference", "original_name",
                            "media_type", "size_bytes", "sha256", "acquired_at", "recorded_at", "integrity_status")
            }
            item["file"] = ""
            if row["stored_name"]:
                try:
                    data = _read_stored_file(database, row["stored_name"])
                except (NotFoundError, OSError):
                    item["export_note"] = "stored file missing at export time"
                else:
                    name = f"evidence/{row['id']}_{(row['original_name'] or 'file').replace('/', '_')[:80]}"
                    archive.writestr(name, data)
                    actual = hashlib.sha256(data).hexdigest()
                    item["file"] = name
                    item["sha256_at_export"] = actual
                    if actual != row["sha256"]:
                        item["export_note"] = "file hash differs from the hash recorded at acquisition"
                    sums.append(f"{actual}  {name}")
            item["custody"] = events.get(row["id"], [])
            items.append(item)
        manifest = {
            "format": "garbage-evidence-package/1",
            "generated_at": utc_now(),
            "investigation": {"id": case["id"], "name": case["name"]},
            "items": items,
            "notes": [
                "sha256 is the hash recorded when the evidence was acquired; sha256_at_export is the hash of the file in this package.",
                "Custody lists every logged action on each item, oldest first.",
                "Run `python3 verify.py` in the unzipped folder to check every file.",
            ],
        }
        manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
        archive.writestr("manifest.json", manifest_bytes)
        sums.append(f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json")
        archive.writestr("SHA256SUMS", "\n".join(sums) + "\n")
        archive.writestr("verify.py", VERIFY_SCRIPT)
    with _connection(database) as connection:
        record_activity(connection, action="export", target_type="investigation", target_id=investigation_id,
                        investigation_id=investigation_id, summary=f"Evidence package exported ({len(items)} items)")
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in case["name"])[:60] or "case"
    return buffer.getvalue(), f"evidencias_{safe_name}_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.zip"


def verify_all(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        ids = [row["id"] for row in connection.execute("SELECT id FROM evidence WHERE stored_name <> ''")]
    counts = {"verified": 0, "mismatch": 0, "missing": 0}
    problems = []
    for evidence_id in ids:
        result = verify_evidence(database, evidence_id)
        counts[result["integrity_status"]] = counts.get(result["integrity_status"], 0) + 1
        if result["integrity_status"] != "verified":
            problems.append({"id": evidence_id, "title": result["evidence"]["title"], "status": result["integrity_status"]})
    if problems:
        with _connection(database) as connection:
            record_activity(connection, action="integrity-alert", target_type="evidence",
                            summary=f"Integrity check: {len(problems)} item(s) failed")
        intel.post_webhook(
            database,
            "**GARBAGE evidence integrity**\n" + "\n".join(f"• {item['title'][:80]}: {item['status']}" for item in problems[:15]),
            {"problems": problems},
            "evidence",
        )
    return {"checked": len(ids), "counts": counts, "problems": problems, "checked_at": utc_now()}


_LAST_DAILY = {"at": 0.0}
_LOCK = threading.Lock()


def run_daily_verification(database: str, now: float | None = None) -> bool:
    """Called by the scheduler every minute; verifies at most once a day."""
    moment = time.monotonic() if now is None else now
    with _LOCK:
        if _LAST_DAILY["at"] and moment - _LAST_DAILY["at"] < 86400:
            return False
        _LAST_DAILY["at"] = moment
    verify_all(database)
    return True
