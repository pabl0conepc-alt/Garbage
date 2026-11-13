"""Local storage for the operator's own API keys (plan phase 7).

Keys stay in the workspace database on this machine. The API never returns a
stored key: listings show only whether one is configured and its last four
characters. Keys are sent only to the provider they belong to, in the header
or parameter that provider documents, and are scrubbed from error messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .db import _connection, record_activity, utc_now
from .errors import NotFoundError, ValidationError


@dataclass(frozen=True)
class Provider:
    provider_id: str
    name: str
    signup_url: str
    note: str = ""


PROVIDERS: dict[str, Provider] = {
    item.provider_id: item
    for item in (
        Provider("virustotal", "VirusTotal", "https://www.virustotal.com/gui/my-apikey", "Free keys allow 4 requests per minute and 500 per day."),
        Provider("abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com/account/api", "Free keys allow 1,000 checks per day."),
        Provider("greynoise", "GreyNoise Community", "https://viz.greynoise.io/account/api-key", "Optional: lookups work without a key at a lower rate."),
        Provider("otx", "AlienVault OTX", "https://otx.alienvault.com/api", "Optional: indicator lookups work without a key."),
        Provider("shodan", "Shodan", "https://account.shodan.io/", "Optional: host lookups work without a key; with one they follow your plan's limits."),
        Provider("abusech", "abuse.ch (URLhaus, ThreatFox, MalwareBazaar)", "https://auth.abuse.ch/", "One Auth-Key serves the three abuse.ch services."),
        Provider("urlscan", "urlscan.io", "https://urlscan.io/user/profile/", "Optional: search works without a key at a lower rate."),
        Provider("nvd", "NVD (NIST)", "https://nvd.nist.gov/developers/request-an-api-key", "Optional: raises the rate limit from 5 to 50 requests per 30 s."),
        Provider("ipinfo", "IPinfo", "https://ipinfo.io/account/token", "Optional: the anonymous tier is rate limited."),
    )
}


def _provider(provider_id: str) -> Provider:
    provider = PROVIDERS.get(provider_id)
    if provider is None:
        raise NotFoundError(f"unknown key provider: {provider_id}")
    return provider


def _hint(secret: str) -> str:
    return f"…{secret[-4:]}" if len(secret) >= 8 else "…"


def list_keys(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        rows = {row["provider_id"]: row for row in connection.execute("SELECT * FROM intel_api_keys")}
    items = []
    for provider in PROVIDERS.values():
        row = rows.get(provider.provider_id)
        items.append(
            {
                "provider_id": provider.provider_id,
                "name": provider.name,
                "signup_url": provider.signup_url,
                "note": provider.note,
                "configured": row is not None,
                "hint": _hint(row["secret"]) if row else "",
                "updated_at": row["updated_at"] if row else None,
            }
        )
    return {"items": items, "total": len(items), "storage": "local workspace database; never returned by the API"}


def set_key(database: str, provider_id: str, secret: Any) -> dict[str, Any]:
    provider = _provider(provider_id)
    if not isinstance(secret, str):
        raise ValidationError("key must be a string")
    secret = secret.strip()
    # Formats change between providers and over time, so only the shape of a
    # bearer token is checked; the provider itself rejects a wrong key.
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,512}", secret):
        raise ValidationError("key must be a single token of 8 to 512 letters, digits or - _ . :")
    now = utc_now()
    with _connection(database) as connection:
        connection.execute(
            """INSERT INTO intel_api_keys (provider_id, secret, created_at, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(provider_id) DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at""",
            (provider_id, secret, now, now),
        )
        record_activity(
            connection, action="update", target_type="api-key", target_id=provider_id,
            investigation_id=None, summary=f"API key saved: {provider.name}",
        )
    return next(item for item in list_keys(database)["items"] if item["provider_id"] == provider_id)


def delete_key(database: str, provider_id: str) -> dict[str, Any]:
    provider = _provider(provider_id)
    with _connection(database) as connection:
        deleted = connection.execute("DELETE FROM intel_api_keys WHERE provider_id = ?", (provider_id,)).rowcount
        if deleted:
            record_activity(
                connection, action="delete", target_type="api-key", target_id=provider_id,
                investigation_id=None, summary=f"API key removed: {provider.name}",
            )
    return {"provider_id": provider_id, "deleted": bool(deleted)}


def get_secret(database: str, provider_id: str) -> str:
    """For connector use only; never expose the return value."""
    with _connection(database) as connection:
        row = connection.execute("SELECT secret FROM intel_api_keys WHERE provider_id = ?", (provider_id,)).fetchone()
    return row["secret"] if row else ""


def configured_providers(database: str) -> set[str]:
    with _connection(database) as connection:
        return {row["provider_id"] for row in connection.execute("SELECT provider_id FROM intel_api_keys")}
