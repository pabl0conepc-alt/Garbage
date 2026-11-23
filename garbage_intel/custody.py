"""Chain of custody for evidence: an append-only, hash-chained event log.

Every event (recorded, verified, accessed, annotated, exported, imported,
deleted) stores the evidence digest at that moment and the hash of the
previous event, and its own hash covers all of it. Rewriting or removing an
event breaks the chain from that point, which ``chain`` reports. Events are
not deleted with the evidence: the log of a deleted item ends with its
``deleted`` event.

This proves the log was not edited after the fact by this application's
users; it is not a signature or an external timestamp.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .db import _connection, new_id, record_activity, utc_now
from .errors import NotFoundError
from .validation import clean_text

ACTIONS = ("recorded", "verified", "accessed", "annotated", "exported", "imported", "imported-history", "deleted")
GENESIS = "0" * 64
MAX_NOTE = 5000


def entry_hash(event: dict[str, Any]) -> str:
    fields = {key: event[key] for key in ("evidence_id", "sequence", "action", "actor", "detail", "sha256", "occurred_at", "previous_hash")}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def record(
    connection: Any,
    *,
    evidence_id: str,
    investigation_id: str,
    action: str,
    sha256: str = "",
    detail: str = "",
    actor: str = "analyst",
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Append one event inside the caller's transaction."""
    if action not in ACTIONS:
        raise ValueError(f"unknown custody action: {action}")
    last = connection.execute(
        "SELECT sequence, entry_hash FROM evidence_events WHERE evidence_id = ? ORDER BY sequence DESC LIMIT 1",
        (evidence_id,),
    ).fetchone()
    event = {
        "id": new_id(),
        "evidence_id": evidence_id,
        "investigation_id": investigation_id,
        "sequence": (last["sequence"] + 1) if last else 1,
        "action": action,
        "actor": actor,
        "detail": detail[:20_000],
        "sha256": sha256,
        "occurred_at": occurred_at or utc_now(),
        "previous_hash": last["entry_hash"] if last else GENESIS,
    }
    event["entry_hash"] = entry_hash(event)
    connection.execute(
        """INSERT INTO evidence_events
           (id, evidence_id, investigation_id, sequence, action, actor, detail, sha256, occurred_at, previous_hash, entry_hash)
           VALUES (:id, :evidence_id, :investigation_id, :sequence, :action, :actor, :detail, :sha256, :occurred_at, :previous_hash, :entry_hash)""",
        event,
    )
    return event


def chain(database: str, evidence_id: str) -> dict[str, Any]:
    """The event log of one evidence item and whether it is intact."""
    with _connection(database) as connection:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM evidence_events WHERE evidence_id = ? ORDER BY sequence", (evidence_id,)
        )]
        exists = connection.execute("SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)).fetchone() is not None
    if not rows and not exists:
        raise NotFoundError(f"evidence not found: {evidence_id}")
    broken_at = None
    previous = GENESIS
    for expected, event in enumerate(rows, start=1):
        if event["sequence"] != expected or event["previous_hash"] != previous or entry_hash(event) != event["entry_hash"]:
            broken_at = event["sequence"]
            break
        previous = event["entry_hash"]
    return {
        "evidence_id": evidence_id,
        "exists": exists,
        "events": rows,
        "intact": broken_at is None,
        "broken_at": broken_at,
        "head": rows[-1]["entry_hash"] if rows else GENESIS,
        "note": "Hash-chained log kept by this workstation; it shows later edits, it is not a signature or trusted timestamp.",
    }


def backfill(connection: Any) -> int:
    """Start a log for evidence recorded before custody existed."""
    rows = connection.execute(
        """SELECT e.id, e.investigation_id, e.sha256, e.recorded_at FROM evidence e
           WHERE NOT EXISTS (SELECT 1 FROM evidence_events v WHERE v.evidence_id = e.id)"""
    ).fetchall()
    for row in rows:
        record(
            connection,
            evidence_id=row["id"],
            investigation_id=row["investigation_id"],
            action="recorded",
            sha256=row["sha256"],
            detail="Recorded before the custody log existed; the log starts at the upgrade.",
            actor="system",
            occurred_at=row["recorded_at"],
        )
    return len(rows)


def add_note(database: str, evidence_id: str, body: object) -> dict[str, Any]:
    text = clean_text(body, "note", max_length=MAX_NOTE, required=True)
    with _connection(database) as connection:
        row = connection.execute("SELECT id, investigation_id, sha256, title FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"evidence not found: {evidence_id}")
        note = {"id": new_id(), "evidence_id": evidence_id, "body": text, "created_at": utc_now()}
        connection.execute(
            "INSERT INTO evidence_notes (id, evidence_id, body, created_at) VALUES (:id, :evidence_id, :body, :created_at)",
            note,
        )
        record(
            connection,
            evidence_id=evidence_id,
            investigation_id=row["investigation_id"],
            action="annotated",
            sha256=row["sha256"],
            detail=f"Note {note['id']} added (sha256 {hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}).",
        )
        record_activity(
            connection,
            action="annotate",
            target_type="evidence",
            target_id=evidence_id,
            investigation_id=row["investigation_id"],
            summary=f"Evidence note added: {row['title'][:120]}",
        )
    return note


def list_notes(database: str, evidence_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        if connection.execute("SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)).fetchone() is None:
            raise NotFoundError(f"evidence not found: {evidence_id}")
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM evidence_notes WHERE evidence_id = ? ORDER BY created_at", (evidence_id,)
        )]
    return {"items": rows, "total": len(rows)}

