"""Public platform account connectors: Discord and Roblox.

Only what each platform publishes about an account is read, through its own
documented API. The Discord snowflake decode is offline; the invite lookup
needs no account; the user lookup uses the operator's own bot token, which
sees the same public profile any Discord user sees. Roblox profile, counts,
groups, previous usernames and avatar come from its unauthenticated public
web APIs. Nothing is cross-referenced with breach data, message archives or
scraped server membership.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ..intel import Connector, ConnectorContext, Finding, register_connector
from . import intel_open_connectors as shared

_text = shared._text
_list = shared._list

DISCORD_API = "https://discord.com/api/v10"
DISCORD_HOSTS = ("discord.com",)
DISCORD_CDN = "https://cdn.discordapp.com"
DISCORD_EPOCH_MS = 1420070400000
ROBLOX_HOSTS = (
    "users.roblox.com",
    "friends.roblox.com",
    "groups.roblox.com",
    "thumbnails.roblox.com",
)

# Public user flags documented at discord.com/developers/docs/resources/user.
_DISCORD_FLAGS = {
    1 << 0: "Discord staff",
    1 << 1: "Partnered server owner",
    1 << 2: "HypeSquad Events",
    1 << 3: "Bug Hunter level 1",
    1 << 6: "HypeSquad Bravery",
    1 << 7: "HypeSquad Brilliance",
    1 << 8: "HypeSquad Balance",
    1 << 9: "Early supporter",
    1 << 10: "Team user",
    1 << 14: "Bug Hunter level 2",
    1 << 16: "Verified bot",
    1 << 17: "Early verified bot developer",
    1 << 18: "Moderator programs alumni",
    1 << 19: "HTTP interactions bot",
    1 << 22: "Active developer",
}


def _iso_ms(milliseconds: int) -> str:
    moment = datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def decode_snowflake(value: str) -> dict[str, Any]:
    """Split a Discord snowflake into its creation time and generator fields."""
    snowflake = int(value)
    milliseconds = (snowflake >> 22) + DISCORD_EPOCH_MS
    return {
        "created_at": _iso_ms(milliseconds),
        "unix_ms": milliseconds,
        "worker_id": (snowflake >> 17) & 0x1F,
        "process_id": (snowflake >> 12) & 0x1F,
        "increment": snowflake & 0xFFF,
    }


# ---------------------------------------------------------------------------
# Discord


def _snowflake_connector(context: ConnectorContext) -> list[Finding]:
    decoded = decode_snowflake(context.query_value)
    data = {key: value for key, value in decoded.items() if key != "created_at"}
    data["meaning"] = "when this ID was generated: account, server, channel or message creation time"
    return [Finding("created-at", decoded["created_at"], data)]


def _discord_user(context: ConnectorContext) -> list[Finding]:
    url = f"{DISCORD_API}/users/{context.query_value}"
    data, result = shared.request_json(
        url, hosts=DISCORD_HOSTS, headers={"Authorization": f"Bot {context.api_key}"}
    )
    if not isinstance(data, dict):
        return [Finding("account", "not found", {"meaning": "no Discord user has this ID, or it is not a user ID"}, url)]
    source = (result.final_url, result.sha256)
    user_id = _text(data.get("id"), 20)
    findings = [
        Finding(
            "username",
            _text(data.get("username"), 32),
            {
                "display_name": _text(data.get("global_name"), 32),
                "discriminator": _text(data.get("discriminator"), 4),
                "bot": bool(data.get("bot")),
                "system": bool(data.get("system")),
            },
            *source,
        )
    ]
    avatar = data.get("avatar")
    if avatar:
        extension = "gif" if str(avatar).startswith("a_") else "png"
        findings.append(
            Finding("avatar", f"{DISCORD_CDN}/avatars/{user_id}/{avatar}.{extension}?size=512", {"hash": _text(avatar, 64)}, *source)
        )
    banner = data.get("banner")
    if banner:
        extension = "gif" if str(banner).startswith("a_") else "png"
        findings.append(
            Finding("banner", f"{DISCORD_CDN}/banners/{user_id}/{banner}.{extension}?size=1024", {"hash": _text(banner, 64)}, *source)
        )
    if isinstance(data.get("accent_color"), int):
        findings.append(Finding("accent-color", f"#{data['accent_color']:06x}", {}, *source))
    flags = data.get("public_flags")
    if isinstance(flags, int):
        for bit, label in _DISCORD_FLAGS.items():
            if flags & bit:
                findings.append(Finding("badge", label, {"flag": bit}, *source))
    clan = data.get("clan") or data.get("primary_guild")
    if isinstance(clan, dict) and clan.get("tag"):
        findings.append(
            Finding("server-tag", _text(clan.get("tag"), 8), {"server_id": _text(clan.get("identity_guild_id"), 20)}, *source)
        )
    return findings


def _discord_invite(context: ConnectorContext) -> list[Finding]:
    code = quote(context.query_value, safe="")
    url = f"{DISCORD_API}/invites/{code}?with_counts=true&with_expiration=true"
    data, result = shared.request_json(url, hosts=DISCORD_HOSTS)
    if not isinstance(data, dict):
        return [Finding("invite", "invalid or expired", {}, url)]
    source = (result.final_url, result.sha256)
    findings: list[Finding] = []
    guild = data.get("guild") if isinstance(data.get("guild"), dict) else {}
    if guild:
        guild_id = _text(guild.get("id"), 20)
        findings.append(
            Finding(
                "server",
                _text(guild.get("name"), 100),
                {
                    "server_id": guild_id,
                    "created_at": decode_snowflake(guild_id)["created_at"] if guild_id.isdigit() else "",
                    "description": _text(guild.get("description"), 300),
                    "verification_level": guild.get("verification_level"),
                    "nsfw_level": guild.get("nsfw_level"),
                    "vanity_url_code": _text(guild.get("vanity_url_code"), 32),
                    "boosts": guild.get("premium_subscription_count"),
                },
                *source,
            )
        )
        for feature in _list(guild.get("features"), 40):
            findings.append(Finding("server-feature", _text(feature, 60), {}, *source))
        if guild.get("icon"):
            findings.append(Finding("server-icon", f"{DISCORD_CDN}/icons/{guild_id}/{guild['icon']}.png?size=512", {}, *source))
    if "approximate_member_count" in data:
        findings.append(
            Finding(
                "member-count",
                str(data.get("approximate_member_count")),
                {"online": data.get("approximate_presence_count"), "meaning": "approximate, as reported by Discord"},
                *source,
            )
        )
    channel = data.get("channel") if isinstance(data.get("channel"), dict) else {}
    if channel:
        findings.append(Finding("invite-channel", _text(channel.get("name"), 100), {"channel_id": _text(channel.get("id"), 20)}, *source))
    inviter = data.get("inviter") if isinstance(data.get("inviter"), dict) else {}
    if inviter:
        findings.append(
            Finding(
                "inviter",
                _text(inviter.get("username"), 32),
                {"user_id": _text(inviter.get("id"), 20), "display_name": _text(inviter.get("global_name"), 32)},
                *source,
            )
        )
    findings.append(Finding("invite-expires", _text(data.get("expires_at"), 40) or "never", {}, *source))
    return findings


# ---------------------------------------------------------------------------
# Roblox


def _roblox_resolve(value: str) -> tuple[str, Finding | None]:
    """Return the numeric user id; usernames are resolved through Roblox."""
    if value.isdigit():
        return value, None
    url = "https://users.roblox.com/v1/usernames/users"
    payload = json.dumps({"usernames": [value], "excludeBannedUsers": False}).encode("utf-8")
    data, result = shared.request_json(
        url, hosts=ROBLOX_HOSTS, method="POST", headers={"Content-Type": "application/json"}, body=payload
    )
    matches = _list((data or {}).get("data"), 1) if isinstance(data, dict) else []
    if not matches or not isinstance(matches[0], dict) or not matches[0].get("id"):
        return "", None
    user_id = str(matches[0]["id"])
    return user_id, Finding("user-id", user_id, {"resolved_from": value}, result.final_url, result.sha256)


def _roblox_count(path: str) -> tuple[Any, Any]:
    data, result = shared.request_json(f"https://friends.roblox.com/v1/users/{path}", hosts=ROBLOX_HOSTS)
    return (data or {}).get("count") if isinstance(data, dict) else None, result


def _roblox_user(context: ConnectorContext) -> list[Finding]:
    user_id, resolved = _roblox_resolve(context.query_value)
    if not user_id:
        return [Finding("account", "not found", {"meaning": "no Roblox user has this name"})]
    findings = [resolved] if resolved else []
    profile, result = shared.request_json(f"https://users.roblox.com/v1/users/{user_id}", hosts=ROBLOX_HOSTS)
    if not isinstance(profile, dict):
        return findings + [Finding("account", "not found", {"meaning": "no Roblox user has this ID"}, result.final_url)]
    source = (result.final_url, result.sha256)
    findings += [
        Finding(
            "username",
            _text(profile.get("name"), 20),
            {
                "user_id": user_id,
                "display_name": _text(profile.get("displayName"), 50),
                "verified_badge": bool(profile.get("hasVerifiedBadge")),
                "profile_url": f"https://www.roblox.com/users/{user_id}/profile",
            },
            *source,
        ),
        Finding("created-at", _text(profile.get("created"), 40), {}, *source),
        Finding("banned", "yes" if profile.get("isBanned") else "no", {}, *source),
    ]
    if profile.get("description"):
        findings.append(Finding("description", _text(profile.get("description"), 1000), {}, *source))

    for label, path in (("friends", "friends/count"), ("followers", "followers/count"), ("following", "followings/count")):
        count, counted = _roblox_count(f"{user_id}/{path}")
        if count is not None:
            findings.append(Finding(f"{label}-count", str(count), {}, counted.final_url, counted.sha256))

    groups, result = shared.request_json(f"https://groups.roblox.com/v2/users/{user_id}/groups/roles", hosts=ROBLOX_HOSTS)
    for item in _list((groups or {}).get("data"), 100) if isinstance(groups, dict) else []:
        group = item.get("group") or {}
        role = item.get("role") or {}
        findings.append(
            Finding(
                "group",
                _text(group.get("name"), 100),
                {
                    "group_id": group.get("id"),
                    "role": _text(role.get("name"), 100),
                    "rank": role.get("rank"),
                    "members": group.get("memberCount"),
                    "url": f"https://www.roblox.com/communities/{group.get('id')}",
                },
                result.final_url,
                result.sha256,
            )
        )

    history, result = shared.request_json(
        f"https://users.roblox.com/v1/users/{user_id}/username-history?limit=100&sortOrder=Desc", hosts=ROBLOX_HOSTS
    )
    for item in _list((history or {}).get("data"), 100) if isinstance(history, dict) else []:
        findings.append(Finding("previous-username", _text(item.get("name"), 20), {}, result.final_url, result.sha256))

    thumbs, result = shared.request_json(
        f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=420x420&format=Png&isCircular=false",
        hosts=ROBLOX_HOSTS,
    )
    for item in _list((thumbs or {}).get("data"), 1) if isinstance(thumbs, dict) else []:
        if item.get("state") == "Completed" and item.get("imageUrl"):
            findings.append(Finding("avatar", _text(item["imageUrl"], 500), {}, result.final_url, result.sha256))
    return findings


CONNECTORS = (
    Connector("discord-snowflake", "Discord ID decode",
              "Creation time and generator fields encoded in a Discord ID; nothing leaves the machine.",
              ("discord-id",), _snowflake_connector),
    Connector("discord-user", "Discord user",
              "Public profile of a Discord user by ID: username, display name, avatar, banner, badges and server tag. Needs your own bot token.",
              ("discord-id",), _discord_user, network=True, requires_key=True, key_id="discord",
              rate_per_minute=30, ttl_seconds=3600, source_url="https://discord.com/developers/docs/resources/user"),
    Connector("discord-invite", "Discord invite",
              "Server behind an invite: name, ID, creation date, description, features, approximate members and online, inviter and expiry.",
              ("discord-invite",), _discord_invite, network=True,
              rate_per_minute=20, ttl_seconds=3600, source_url="https://discord.com/developers/docs/resources/invite"),
    Connector("roblox-user", "Roblox user",
              "Public Roblox profile by ID or username: names, creation date, ban state, description, friend and follower counts, groups and roles, previous usernames and avatar.",
              ("roblox-user",), _roblox_user, network=True,
              rate_per_minute=20, ttl_seconds=3600, source_url="https://create.roblox.com/docs/cloud/legacy"),
)

for _connector in CONNECTORS:
    register_connector(_connector)
