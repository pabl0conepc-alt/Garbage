"""Discord and Roblox account connectors.

Replies are built from each platform's documented response format; no live
request is made.
"""

import json
import unittest
from unittest.mock import patch

from garbage_intel.errors import ValidationError
from garbage_intel.net import FetchResult
from garbage_intel.intel import ConnectorContext, _run_one, connectors, detect_artifact
from garbage_intel.modules import intel_open_connectors as shared
from garbage_intel.modules.intel_account_connectors import decode_snowflake

from tests.test_intel_sources import Router

BY_ID = {connector.connector_id: connector for connector in connectors()}


def run(connector_id, kind, value, routes, api_key=""):
    router = Router(routes)
    with patch.object(shared, "FETCH", router):
        status, findings, error, _ = _run_one(BY_ID[connector_id], ConnectorContext("", kind, value, None, api_key))
    return status, findings, error, router.calls


def by_type(findings):
    result = {}
    for finding in findings:
        result.setdefault(finding.result_type, []).append(finding)
    return result


class DetectionTests(unittest.TestCase):
    def test_discord_id(self):
        self.assertEqual(detect_artifact("discord:175928847299117063")["type"], "discord-id")
        self.assertEqual(detect_artifact("Discord: 175928847299117063")["value"], "175928847299117063")

    def test_discord_invites(self):
        for raw in ("https://discord.gg/abcDEF", "discord.com/invite/abcDEF", "https://discordapp.com/invite/abcDEF/"):
            self.assertEqual(detect_artifact(raw), {"type": "discord-invite", "value": "abcDEF", "label": "Discord invite"})

    def test_roblox(self):
        self.assertEqual(detect_artifact("roblox:156")["value"], "156")
        self.assertEqual(detect_artifact("roblox:Builderman")["value"], "builderman")
        self.assertEqual(detect_artifact("https://www.roblox.com/users/156/profile")["value"], "156")

    def test_bare_number_is_not_an_account(self):
        with self.assertRaises(ValidationError):
            detect_artifact("175928847299117063")

    def test_existing_indicators_unchanged(self):
        self.assertEqual(detect_artifact("example.com")["type"], "domain")
        self.assertEqual(detect_artifact("https://example.com/invite/x")["type"], "url")


class DiscordTests(unittest.TestCase):
    def test_snowflake_decode(self):
        decoded = decode_snowflake("175928847299117063")
        self.assertEqual(decoded["created_at"], "2016-04-30T11:18:25.796Z")
        self.assertEqual((decoded["worker_id"], decoded["process_id"], decoded["increment"]), (1, 0, 7))

    def test_snowflake_connector_is_offline(self):
        status, findings, _, calls = run("discord-snowflake", "discord-id", "175928847299117063", {})
        self.assertEqual(status, "ok")
        self.assertEqual(calls, [])
        self.assertEqual(findings[0].value, "2016-04-30T11:18:25.796Z")

    def test_user_needs_key_and_sends_it(self):
        connector = BY_ID["discord-user"]
        self.assertTrue(connector.requires_key)
        self.assertEqual(connector.key_id, "discord")
        payload = {
            "id": "80351110224678912",
            "username": "nelly",
            "global_name": "Nelly",
            "discriminator": "0",
            "avatar": "a_8342729096ea3675442027381ff50dfe",
            "banner": None,
            "accent_color": 16711680,
            "public_flags": 64 | (1 << 22),
        }
        status, findings, _, calls = run(
            "discord-user", "discord-id", "80351110224678912", {"/users/80351110224678912": payload}, api_key="bot.token-1234"
        )
        self.assertEqual(status, "ok")
        self.assertEqual(calls[0][1]["headers"]["Authorization"], "Bot bot.token-1234")
        self.assertEqual(calls[0][1]["allowed_hosts"], ("discord.com",))
        found = by_type(findings)
        self.assertEqual(found["username"][0].value, "nelly")
        self.assertEqual(found["username"][0].data["display_name"], "Nelly")
        self.assertTrue(found["avatar"][0].value.endswith(".gif?size=512"))
        self.assertEqual(found["accent-color"][0].value, "#ff0000")
        self.assertEqual({item.value for item in found["badge"]}, {"HypeSquad Bravery", "Active developer"})

    def test_user_not_found(self):
        status, findings, _, _ = run("discord-user", "discord-id", "1", {}, api_key="bot.token-1234")
        self.assertEqual(findings[0].value, "not found")

    def test_invite(self):
        payload = {
            "code": "abcDEF",
            "expires_at": None,
            "guild": {
                "id": "175928847299117063",
                "name": "Example Server",
                "description": "A test",
                "features": ["COMMUNITY", "DISCOVERABLE"],
                "icon": "iconhash",
                "verification_level": 2,
                "nsfw_level": 0,
                "vanity_url_code": None,
                "premium_subscription_count": 3,
            },
            "channel": {"id": "1", "name": "welcome"},
            "inviter": {"id": "80351110224678912", "username": "nelly", "global_name": "Nelly"},
            "approximate_member_count": 1200,
            "approximate_presence_count": 340,
        }
        status, findings, _, calls = run("discord-invite", "discord-invite", "abcDEF", {"/invites/abcDEF": payload})
        self.assertEqual(status, "ok")
        self.assertIn("with_counts=true", calls[0][0])
        found = by_type(findings)
        self.assertEqual(found["server"][0].value, "Example Server")
        self.assertEqual(found["server"][0].data["created_at"], "2016-04-30T11:18:25.796Z")
        self.assertEqual(found["member-count"][0].value, "1200")
        self.assertEqual(found["member-count"][0].data["online"], 340)
        self.assertEqual(found["inviter"][0].value, "nelly")
        self.assertEqual(found["invite-expires"][0].value, "never")
        self.assertEqual(len(found["server-feature"]), 2)

    def test_invalid_invite(self):
        status, findings, _, _ = run("discord-invite", "discord-invite", "gone", {})
        self.assertEqual(findings[0].value, "invalid or expired")


ROBLOX_ROUTES = {
    "users.roblox.com/v1/usernames/users": {"data": [{"id": 156, "name": "builderman", "requestedUsername": "builderman"}]},
    "users.roblox.com/v1/users/156/username-history": {"data": [{"name": "OldBuilder"}]},
    "users.roblox.com/v1/users/156": {
        "id": 156,
        "name": "builderman",
        "displayName": "Builderman",
        "description": "Hello",
        "created": "2006-02-27T21:06:40.3Z",
        "isBanned": False,
        "hasVerifiedBadge": True,
    },
    "/friends/count": {"count": 12},
    "/followers/count": {"count": 9000},
    "/followings/count": {"count": 3},
    "groups.roblox.com/v2/users/156/groups/roles": {
        "data": [{"group": {"id": 7, "name": "Roblox", "memberCount": 100}, "role": {"name": "Owner", "rank": 255}}]
    },
    "thumbnails.roblox.com": {"data": [{"targetId": 156, "state": "Completed", "imageUrl": "https://tr.rbxcdn.com/x.png"}]},
}


class RobloxTests(unittest.TestCase):
    def test_by_username(self):
        status, findings, _, calls = run("roblox-user", "roblox-user", "builderman", ROBLOX_ROUTES)
        self.assertEqual(status, "ok")
        lookup = calls[0]
        self.assertEqual(lookup[1]["method"], "POST")
        self.assertEqual(json.loads(lookup[1]["body"])["usernames"], ["builderman"])
        found = by_type(findings)
        self.assertEqual(found["user-id"][0].value, "156")
        self.assertEqual(found["username"][0].data["display_name"], "Builderman")
        self.assertEqual(found["created-at"][0].value, "2006-02-27T21:06:40.3Z")
        self.assertEqual(found["banned"][0].value, "no")
        self.assertEqual(found["followers-count"][0].value, "9000")
        self.assertEqual(found["group"][0].data["role"], "Owner")
        self.assertEqual(found["previous-username"][0].value, "OldBuilder")
        self.assertEqual(found["avatar"][0].value, "https://tr.rbxcdn.com/x.png")
        for url, options in calls:
            self.assertIn(url.split("/")[2], options["allowed_hosts"])

    def test_by_id_skips_resolution(self):
        status, findings, _, calls = run("roblox-user", "roblox-user", "156", ROBLOX_ROUTES)
        self.assertNotIn("usernames", calls[0][0])
        self.assertNotIn("user-id", by_type(findings))

    def test_unknown_username(self):
        status, findings, _, _ = run("roblox-user", "roblox-user", "nobody", {"usernames/users": {"data": []}})
        self.assertEqual(findings[0].value, "not found")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Photo EXIF, usernames, Telegram, Have I Been Pwned and the run webhook

import struct
import tempfile
from pathlib import Path

from garbage_intel import intel
from garbage_intel.modules.exif import parse_exif
from garbage_intel.modules.file_intel import analyze_bytes
from garbage_intel.store import initialize
from garbage_intel.workspace import get_settings, update_settings
from tests.test_intel_sources import reply


def _rational(value):
    return struct.pack("<II", int(round(value * 100)), 100)


def jpeg_with_gps(latitude=(23, 33, 1.2), lat_ref=b"S", longitude=(46, 38, 2.5), lon_ref=b"W"):
    """Little-endian EXIF with Make, an Exif IFD (DateTimeOriginal) and GPS."""
    make, taken = b"Canon\x00", b"2024:05:01 10:20:30\x00"
    entries0 = 3
    ifd0 = 8
    ifd0_size = 2 + entries0 * 12 + 4
    make_at = ifd0 + ifd0_size
    exif_ifd = make_at + len(make)
    exif_size = 2 + 12 + 4
    taken_at = exif_ifd + exif_size
    gps_ifd = taken_at + len(taken)
    gps_entries = 4
    gps_size = 2 + gps_entries * 12 + 4
    lat_at = gps_ifd + gps_size
    lon_at = lat_at + 24

    def entry(tag, kind, count, value):
        return struct.pack("<HHI", tag, kind, count) + value

    tiff = b"II" + struct.pack("<HI", 42, ifd0)
    tiff += struct.pack("<H", entries0)
    tiff += entry(0x010F, 2, len(make), struct.pack("<I", make_at))
    tiff += entry(0x8769, 4, 1, struct.pack("<I", exif_ifd))
    tiff += entry(0x8825, 4, 1, struct.pack("<I", gps_ifd))
    tiff += b"\x00" * 4 + make
    tiff += struct.pack("<H", 1) + entry(0x9003, 2, len(taken), struct.pack("<I", taken_at)) + b"\x00" * 4 + taken
    tiff += struct.pack("<H", gps_entries)
    tiff += entry(1, 2, 2, lat_ref + b"\x00\x00\x00")
    tiff += entry(2, 5, 3, struct.pack("<I", lat_at))
    tiff += entry(3, 2, 2, lon_ref + b"\x00\x00\x00")
    tiff += entry(4, 5, 3, struct.pack("<I", lon_at))
    tiff += b"\x00" * 4
    tiff += b"".join(_rational(part) for part in latitude) + b"".join(_rational(part) for part in longitude)
    app1 = b"Exif\x00\x00" + tiff
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 10, 20, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + sof + b"\xff\xd9"


class ExifTests(unittest.TestCase):
    def test_reads_camera_time_and_gps(self):
        exif = parse_exif(jpeg_with_gps())
        self.assertEqual(exif["make"], "Canon")
        self.assertEqual(exif["captured_at"], "2024:05:01 10:20:30")
        self.assertTrue(exif["gps"]["valid"])
        self.assertAlmostEqual(exif["gps"]["latitude"], -(23 + 33 / 60 + 1.2 / 3600), places=5)
        self.assertAlmostEqual(exif["gps"]["longitude"], -(46 + 38 / 60 + 2.5 / 3600), places=5)

    def test_no_exif_and_truncated_input(self):
        self.assertIsNone(parse_exif(b"\xff\xd8\xff\xd9"))
        self.assertIsNone(parse_exif(b"not a jpeg"))
        photo = jpeg_with_gps()
        for cut in range(4, len(photo), 7):
            parse_exif(photo[:cut])  # must never raise

    def test_file_analysis_reports_position(self):
        analysis = analyze_bytes(jpeg_with_gps(), "photo.jpg")
        self.assertTrue(analysis["metadata"]["exif"]["gps"]["valid"])
        self.assertIn("exif-gps", json.dumps(analysis))


class UsernameTests(unittest.TestCase):
    def test_found_free_and_unknown(self):
        routes = {
            "api.github.com/users/alice": {"login": "alice"},
            "gitlab.com/api/v4/users": [],
            "hacker-news.firebaseio.com": [],  # stands in for the JSON null HN returns
            "registry.npmjs.org": {"total": 3},
            "keybase.io": {"them": [{"id": "x"}]},
            "lichess.org": (500, {}),
        }
        status, findings, _, calls = run("username-sites", "username", "alice", routes)
        self.assertEqual(status, "ok")
        accounts = {item.value: item.data["profile_url"] for item in findings if item.result_type == "account"}
        self.assertEqual(set(accounts), {"GitHub", "npm", "Keybase"})
        self.assertEqual(accounts["GitHub"], "https://github.com/alice")
        unknown = {item.value for item in findings if item.result_type == "site-unknown"}
        self.assertEqual(unknown, {"Lichess"})
        for url, options in calls:
            self.assertEqual(options["allowed_hosts"], (url.split("/")[2],))

    def test_none_found(self):
        _, findings, _, _ = run("username-sites", "username", "zz", {})
        self.assertEqual(findings[0].value, "none found")

    def test_detection(self):
        self.assertEqual(detect_artifact("user:@alice"), {"type": "username", "value": "alice", "label": "Username"})


TELEGRAM_PAGE = """<html><head>
<meta property="og:title" content="Example &amp; Co">
<meta property="og:image" content="https://cdn1.telesco.pe/file/abc.jpg">
<meta property="og:description" content="News about examples">
</head><body><div class="tgme_page_title" dir="auto"><span>Example &amp; Co</span></div>
<div class="tgme_page_extra">12 345 subscribers</div></body></html>"""


class TelegramTests(unittest.TestCase):
    def fetch(self, body, status=200):
        def answer(url, **options):
            self.options = options
            encoded = body.encode()
            return FetchResult(url, url, status, {}, encoded, "0" * 64, "192.0.2.1", 1, [])
        return answer

    def test_channel(self):
        with patch.object(shared, "FETCH", self.fetch(TELEGRAM_PAGE)):
            status, findings, _, _ = _run_one(BY_ID["telegram"], ConnectorContext("", "telegram", "example", None))
        self.assertEqual(status, "ok")
        found = by_type(findings)
        self.assertEqual(found["telegram-name"][0].value, "Example & Co")
        self.assertEqual(found["telegram-name"][0].data["kind"], "channel")
        self.assertEqual(found["member-count"][0].data["count"], 12345)
        self.assertEqual(self.options["allowed_hosts"], ("t.me",))

    def test_missing(self):
        with patch.object(shared, "FETCH", self.fetch("<html><meta property=\"og:title\" content=\"Telegram\"></html>")):
            _, findings, _, _ = _run_one(BY_ID["telegram"], ConnectorContext("", "telegram", "nobody", None))
        self.assertEqual(findings[0].value, "not found")

    def test_detection(self):
        for raw in ("telegram:@Example", "https://t.me/Example", "telegram.me/example/"):
            self.assertEqual(detect_artifact(raw)["value"], "example")


class HibpTests(unittest.TestCase):
    def test_breaches_and_key_header(self):
        self.assertTrue(BY_ID["hibp"].requires_key)
        payload = [{"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
                    "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}]
        status, findings, _, calls = run("hibp", "email", "a@example.com", {"breachedaccount/a%40example.com": payload}, api_key="hibp-key-1234")
        self.assertEqual(status, "ok")
        self.assertEqual(calls[0][1]["headers"]["hibp-api-key"], "hibp-key-1234")
        self.assertEqual(findings[0].value, "Adobe")
        self.assertEqual(findings[0].data["data_exposed"], "Email addresses, Passwords")

    def test_not_breached(self):
        _, findings, _, _ = run("hibp", "email", "a@example.com", {}, api_key="hibp-key-1234")
        self.assertEqual(findings[0].value, "none")
