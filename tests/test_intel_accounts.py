"""Discord and Roblox account connectors.

Replies are built from each platform's documented response format; no live
request is made.
"""

import json
import unittest
from unittest.mock import patch

from garbage_intel.errors import ValidationError
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
