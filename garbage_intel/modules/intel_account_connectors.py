"""Public platform account connectors: Discord, Roblox, Telegram, usernames
across public sites and Have I Been Pwned.

Only what each platform publishes about an account is read, through its own
documented API. The Discord snowflake decode is offline; the invite lookup
needs no account; the user lookup uses the operator's own bot token, which
sees the same public profile any Discord user sees. Roblox profile, counts,
groups, previous usernames and avatar come from its unauthenticated public
web APIs. Telegram facts come from the public t.me preview page. The
username check asks each site's public API or profile URL whether the name
exists. Have I Been Pwned, with the operator's own key, names the breaches an
address appeared in and never returns leaked data. Nothing is
cross-referenced with breach dumps, message archives or scraped membership.
"""

from __future__ import annotations

import base64
import html
import json
import re
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import NetworkError, NetworkPolicyError
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


# ---------------------------------------------------------------------------
# Username across public sites

# (site, URL to request, profile URL to show, how to read the answer). "status"
# means 200 = exists and 404 = free; the others read a JSON body.
USERNAME_SITES: tuple[tuple[str, str, str, str], ...] = (
    ("GitHub", "https://api.github.com/users/{}", "https://github.com/{}", "status"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={}", "https://gitlab.com/{}", "json-list"),
    ("Chess.com", "https://api.chess.com/pub/player/{}", "https://www.chess.com/member/{}", "status"),
    ("Lichess", "https://lichess.org/api/user/{}", "https://lichess.org/@/{}", "status"),
    ("Hacker News", "https://hacker-news.firebaseio.com/v0/user/{}.json", "https://news.ycombinator.com/user?id={}", "json-object"),
    ("DEV Community", "https://dev.to/api/users/by_username?url={}", "https://dev.to/{}", "status"),
    ("Docker Hub", "https://hub.docker.com/v2/users/{}/", "https://hub.docker.com/u/{}", "status"),
    ("npm", "https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1", "https://www.npmjs.com/~{}", "npm-search"),
    ("PyPI", "https://pypi.org/user/{}/", "https://pypi.org/user/{}/", "status"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "https://keybase.io/{}", "keybase"),
    ("Codeberg", "https://codeberg.org/api/v1/users/{}", "https://codeberg.org/{}", "status"),
    ("Minecraft", "https://api.mojang.com/users/profiles/minecraft/{}", "https://namemc.com/profile/{}", "status"),
    ("Steam", "https://steamcommunity.com/id/{}?xml=1", "https://steamcommunity.com/id/{}", "steam-xml"),
    ("Bluesky", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social", "https://bsky.app/profile/{}.bsky.social", "status400"),
    ("Mastodon (mastodon.social)", "https://mastodon.social/api/v1/accounts/lookup?acct={}", "https://mastodon.social/@{}", "status"),
    ("Hugging Face", "https://huggingface.co/api/users/{}/overview", "https://huggingface.co/{}", "status"),
    ("Launchpad", "https://api.launchpad.net/1.0/~{}", "https://launchpad.net/~{}", "status"),
)


def _site_answer(rule: str, status: int, body: bytes) -> bool | None:
    """True = account exists, False = no account, None = could not tell."""
    if rule == "status":
        return True if status == 200 else False if status in (404, 410) else None
    if rule == "status400":
        return True if status == 200 else False if status in (400, 404) else None
    if rule == "steam-xml":
        if status != 200:
            return False if status == 404 else None
        return b"<steamID64>" in body if b"<profile>" in body or b"<error>" in body else None
    if status != 200:
        return False if status == 404 else None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if rule == "json-list":
        return bool(data) if isinstance(data, list) else None
    if rule == "json-object":
        return isinstance(data, dict)
    if rule == "npm-search":
        return bool(data.get("total")) if isinstance(data, dict) else None
    if rule == "keybase":
        them = data.get("them") if isinstance(data, dict) else None
        return bool(them and them[0]) if isinstance(them, list) else None
    return None


def _username_connector(context: ConnectorContext) -> list[Finding]:
    name = quote(context.query_value, safe="")
    findings: list[Finding] = []
    for site, api, profile, rule in USERNAME_SITES:
        url = api.format(name)
        try:
            result = shared.FETCH(
                url,
                headers={"Accept": "application/json"},
                allowed_hosts=(url.split("/")[2],),
                max_bytes=512 * 1024,
                timeout=10.0,
            )
        except (NetworkError, NetworkPolicyError) as exc:
            findings.append(Finding("site-unknown", site, {"reason": str(exc)[:200]}, url))
            continue
        answer = _site_answer(rule, result.status, result.body)
        if answer is True:
            findings.append(Finding("account", site, {"profile_url": profile.format(name)}, result.final_url, result.sha256))
        elif answer is None:
            findings.append(Finding("site-unknown", site, {"reason": f"HTTP {result.status}"}, result.final_url))
    if not any(item.result_type == "account" for item in findings):
        findings.insert(0, Finding("account", "none found", {"sites_checked": len(USERNAME_SITES)}))
    return findings


# ---------------------------------------------------------------------------
# Telegram public preview


_TG_META = re.compile(r"<meta\s+property=\"og:(title|description|image)\"\s+content=\"([^\"]*)\"", re.IGNORECASE)
_TG_EXTRA = re.compile(r"<div class=\"tgme_page_extra\">\s*([^<]{1,200})", re.IGNORECASE)
_TG_TITLE = re.compile(r"<div class=\"tgme_page_title\"", re.IGNORECASE)
_TG_KIND = re.compile(r"tgme_action_button_new[^>]*>\s*(View in Telegram|Send Message|Join (?:Group|Channel)|View Channel|Open Bot)", re.IGNORECASE)


def _telegram_connector(context: ConnectorContext) -> list[Finding]:
    url = f"https://t.me/{context.query_value}"
    page = shared.FETCH(url, allowed_hosts=("t.me",), max_bytes=512 * 1024, timeout=15.0)
    if page.status == 404:
        return [Finding("account", "not found", {}, url)]
    if page.status >= 400:
        raise NetworkError(f"the source answered HTTP {page.status}")
    text = page.body.decode("utf-8", errors="replace")
    if not _TG_TITLE.search(text):
        return [Finding("account", "not found", {"meaning": "t.me shows no public user, bot, group or channel with this name"}, url)]
    meta = {key.lower(): html.unescape(value) for key, value in _TG_META.findall(text)}
    source = (page.final_url, page.sha256)
    extra = _TG_EXTRA.search(text)
    extra_text = html.unescape(extra.group(1)).strip() if extra else ""
    lowered = extra_text.lower()
    kind = (
        "channel" if "subscriber" in lowered
        else "group" if "member" in lowered
        else "bot" if context.query_value.endswith("bot")
        else "user"
    )
    findings = [
        Finding("telegram-name", _text(meta.get("title"), 200), {"kind": kind, "url": url}, *source),
    ]
    if meta.get("description"):
        findings.append(Finding("description", _text(meta["description"], 1000), {}, *source))
    if extra_text:
        digits = re.sub(r"[^0-9]", "", extra_text.split(",")[0])
        findings.append(
            Finding("member-count" if kind in ("channel", "group") else "handle", extra_text, {"count": int(digits) if digits else None}, *source)
        )
    if meta.get("image") and "telegram.org/img" not in meta["image"]:
        findings.append(Finding("avatar", _text(meta["image"], 500), {}, *source))
    return findings


# ---------------------------------------------------------------------------
# Have I Been Pwned


def _hibp_connector(context: ConnectorContext) -> list[Finding]:
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(context.query_value, safe='')}?truncateResponse=false"
    data, result = shared.request_json(url, hosts=("haveibeenpwned.com",), headers={"hibp-api-key": context.api_key})
    if not isinstance(data, list) or not data:
        return [Finding("breach", "none", {"meaning": "not in any breach Have I Been Pwned has loaded"}, url)]
    source = (result.final_url, result.sha256)
    findings = []
    for item in data[:200]:
        if not isinstance(item, dict):
            continue
        findings.append(
            Finding(
                "breach",
                _text(item.get("Title") or item.get("Name"), 120),
                {
                    "domain": _text(item.get("Domain"), 253),
                    "breach_date": _text(item.get("BreachDate"), 20),
                    "accounts": item.get("PwnCount"),
                    "data_exposed": ", ".join(str(kind) for kind in _list(item.get("DataClasses"), 30)),
                    "verified": bool(item.get("IsVerified")),
                    "sensitive": bool(item.get("IsSensitive")),
                },
                *source,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Username variations and analysis (offline)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
_SEPARATORS = re.compile(r"[._-]+")


def normalise_username(name: str) -> str:
    """Lowercase, undo leetspeak, drop separators and trailing digits."""
    base = _SEPARATORS.sub("", name.lower())
    base = re.sub(r"\d+$", "", base) or base
    return base.translate(_LEET)


def username_variations(name: str, limit: int = 40) -> list[tuple[str, str]]:
    """Plausible spellings of the same handle, each with the rule that made it."""
    lower = name.lower()
    parts = [part for part in _SEPARATORS.split(lower) if part]
    stem = re.sub(r"\d+$", "", lower).rstrip("._-") or lower
    found: dict[str, str] = {}

    def add(value: str, rule: str) -> None:
        if 2 <= len(value) <= 39 and value != lower and value not in found:
            found[value] = rule

    if len(parts) > 1:
        for separator in ("", ".", "_", "-"):
            add(separator.join(parts), f"separator {separator or 'none'}")
        add("".join(reversed(parts)), "parts reversed")
        add(parts[0], "first part only")
    if stem != lower:
        add(stem, "trailing digits removed")
    add(normalise_username(lower), "normalised (leetspeak and separators)")
    for prefix in ("the", "real", "its", "iam", "official"):
        add(prefix + stem, f"prefix {prefix}")
    for suffix in ("_", "official", "real", "1", "01", "123", "x", "tv", "yt", "hd"):
        add(stem + suffix, f"suffix {suffix}")
    for index, char in enumerate(stem):  # one-character typos
        if index + 1 < len(stem):
            add(stem[:index] + stem[index + 1] + stem[index] + stem[index + 2:], "adjacent letters swapped")
        add(stem[:index] + stem[index + 1:], "one letter removed")
        if char.isalpha():
            add(stem[:index] + char + stem[index:], "one letter doubled")
    return list(found.items())[:limit]


def _variations_connector(context: ConnectorContext) -> list[Finding]:
    name = context.query_value
    digits = re.search(r"(\d+)$", name)
    traits = {
        "length": len(name),
        "normalised": normalise_username(name),
        "has_separators": bool(_SEPARATORS.search(name)),
        "trailing_digits": digits.group(1) if digits else "",
        "leetspeak": bool(re.search(r"[a-z][0134578@$]|[0134578@$][a-z]", name.lower())),
    }
    if digits and len(digits.group(1)) in (2, 4):
        number = int(digits.group(1))
        if len(digits.group(1)) == 4 and 1950 <= number <= 2025 or len(digits.group(1)) == 2:
            traits["digits_may_be_year"] = True
    findings = [Finding("username-analysis", traits["normalised"], {**traits, "meaning": "structural facts only; a match on another site is not proof of the same person"})]
    findings += [Finding("variation", value, {"rule": rule, "query": f"user:{value}"}) for value, rule in username_variations(name)]
    return findings


# ---------------------------------------------------------------------------
# Minecraft and Steam public profiles


def _minecraft_connector(context: ConnectorContext) -> list[Finding]:
    hosts = ("api.mojang.com", "sessionserver.mojang.com")
    data, result = shared.request_json(f"https://api.mojang.com/users/profiles/minecraft/{quote(context.query_value, safe='')}", hosts=hosts)
    if not isinstance(data, dict) or not data.get("id"):
        return [Finding("account", "not found", {"meaning": "no Java Edition account has this name"}, result.final_url)]
    uuid = _text(data["id"], 32)
    findings = [
        Finding("username", _text(data.get("name"), 16), {"uuid": uuid, "namemc": f"https://namemc.com/profile/{uuid}", "legacy": bool(data.get("legacy")), "demo": bool(data.get("demo"))}, result.final_url, result.sha256)
    ]
    profile, result = shared.request_json(f"https://sessionserver.mojang.com/session/minecraft/profile/{uuid}", hosts=hosts)
    for prop in _list((profile or {}).get("properties"), 5) if isinstance(profile, dict) else []:
        if not isinstance(prop, dict) or prop.get("name") != "textures":
            continue
        try:
            textures = json.loads(base64.b64decode(prop.get("value", ""))).get("textures", {})
        except (ValueError, json.JSONDecodeError):
            continue
        for kind in ("SKIN", "CAPE"):
            if isinstance(textures.get(kind), dict) and textures[kind].get("url"):
                model = (textures[kind].get("metadata") or {}).get("model", "classic") if kind == "SKIN" else ""
                findings.append(Finding(kind.lower(), _text(textures[kind]["url"], 300), {"model": model} if model else {}, result.final_url, result.sha256))
    return findings


_STEAM_FIELDS = (
    ("steamID", "persona-name"),
    ("customURL", "custom-url"),
    ("memberSince", "member-since"),
    ("privacyState", "privacy"),
    ("vacBanned", "vac-banned"),
    ("tradeBanState", "trade-ban"),
    ("isLimitedAccount", "limited-account"),
    ("headline", "headline"),
    ("avatarFull", "avatar"),
)


def _steam_connector(context: ConnectorContext) -> list[Finding]:
    value = context.query_value
    path = f"profiles/{value}" if value.isdigit() and len(value) == 17 else f"id/{quote(value, safe='')}"
    url = f"https://steamcommunity.com/{path}?xml=1"
    page = shared.FETCH(url, allowed_hosts=("steamcommunity.com",), max_bytes=512 * 1024, timeout=15.0)
    if page.status >= 400:
        raise NetworkError(f"the source answered HTTP {page.status}")
    try:
        root = ElementTree.fromstring(page.body)
    except ElementTree.ParseError as exc:
        raise NetworkError("Steam returned a page that is not profile XML") from exc
    if root.tag != "profile" or root.findtext("steamID64") is None:
        return [Finding("account", "not found", {}, url)]
    source = (page.final_url, page.sha256)
    steam_id = root.findtext("steamID64", "").strip()
    findings = [Finding("steam-id64", steam_id, {"profile_url": f"https://steamcommunity.com/profiles/{steam_id}"}, *source)]
    # Real name, location and free-text summary are left out on purpose.
    for tag, result_type in _STEAM_FIELDS:
        text = (root.findtext(tag) or "").strip()
        if text and text != "None":
            findings.append(Finding(result_type, _text(text, 300), {}, *source))
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
    Connector("username-sites", "Username across sites",
              "Whether the name is taken on 17 public sites (GitHub, GitLab, Chess.com, Lichess, Hacker News, DEV, Docker Hub, npm, PyPI, Keybase, Codeberg, Minecraft, Steam, Bluesky, Mastodon, Hugging Face, Launchpad), with profile links.",
              ("username",), _username_connector, network=True, rate_per_minute=6, ttl_seconds=3600),
    Connector("username-variations", "Username variations",
              "Offline: normalised form, structural traits and plausible spellings of a handle (separators, digits, prefixes, suffixes, one-letter typos) to search next.",
              ("username",), _variations_connector),
    Connector("minecraft", "Minecraft",
              "Java Edition profile by name: UUID, skin and cape from Mojang's public API.",
              ("minecraft",), _minecraft_connector, network=True, rate_per_minute=30, ttl_seconds=3600,
              source_url="https://api.mojang.com/"),
    Connector("steam", "Steam",
              "Public Steam Community profile by custom URL or SteamID64: persona name, SteamID64, member since, privacy, VAC and trade bans, limited account and avatar.",
              ("steam",), _steam_connector, network=True, rate_per_minute=20, ttl_seconds=3600,
              source_url="https://steamcommunity.com/"),
    Connector("telegram", "Telegram",
              "Public t.me preview of a user, bot, group or channel: name, description, member or subscriber count and photo.",
              ("telegram",), _telegram_connector, network=True, rate_per_minute=20, ttl_seconds=3600,
              source_url="https://t.me/"),
    Connector("hibp", "Have I Been Pwned",
              "Breaches an email address appeared in: breach name, date, size and kinds of data exposed. Needs your own HIBP key; never returns leaked data.",
              ("email",), _hibp_connector, network=True, requires_key=True, key_id="hibp", rate_per_minute=10,
              ttl_seconds=86400, source_url="https://haveibeenpwned.com/API/v3"),
)

for _connector in CONNECTORS:
    register_connector(_connector)
