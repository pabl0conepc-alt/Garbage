"""Catalogue block 2: username variations, Minecraft, Steam and more sites."""

import base64
import json
import unittest
from unittest.mock import patch

from garbage_intel.intel import ConnectorContext, _run_one, connectors, detect_artifact
from garbage_intel.modules import intel_open_connectors as shared
from garbage_intel.modules.intel_account_connectors import (
    _site_answer,
    normalise_username,
    username_variations,
)
from garbage_intel.net import FetchResult
from tests.test_intel_sources import Router

BY_ID = {connector.connector_id: connector for connector in connectors()}


def run(connector_id, kind, value, routes):
    router = Router(routes)
    with patch.object(shared, "FETCH", router):
        status, findings, error, _ = _run_one(BY_ID[connector_id], ConnectorContext("", kind, value, None))
    return status, findings, error, router.calls


def raw_fetch(body, status=200):
    def answer(url, **options):
        return FetchResult(url, url, status, {}, body, "0" * 64, "192.0.2.1", 1, [])
    return answer


class DetectionTests(unittest.TestCase):
    def test_minecraft_and_steam(self):
        self.assertEqual(detect_artifact("minecraft:Notch"), {"type": "minecraft", "value": "notch", "label": "Minecraft"})
        self.assertEqual(detect_artifact("steam:GabeLoganNewell")["value"], "gabelogannewell")
        self.assertEqual(detect_artifact("https://steamcommunity.com/profiles/76561197960287930/")["value"], "76561197960287930")
        self.assertEqual(detect_artifact("steamcommunity.com/id/gaben")["type"], "steam")


class VariationTests(unittest.TestCase):
    def test_normalise(self):
        self.assertEqual(normalise_username("john.doe1987"), "johndoe")
        self.assertEqual(normalise_username("H4x0r_99"), "haxor")

    def test_variations(self):
        found = dict(username_variations("john.doe1987"))
        self.assertEqual(found["john_doe1987"], "separator _")
        self.assertEqual(found["john.doe"], "trailing digits removed")
        self.assertIn("realjohn.doe", found)
        self.assertNotIn("john.doe1987", found)
        self.assertLessEqual(len(found), 40)
        self.assertTrue(all(2 <= len(value) <= 39 for value in found))

    def test_connector_is_offline(self):
        status, findings, _, calls = run("username-variations", "username", "gamer_2009", {})
        self.assertEqual(calls, [])
        traits = findings[0].data
        self.assertEqual(traits["trailing_digits"], "2009")
        self.assertTrue(traits["digits_may_be_year"])
        self.assertTrue(all(item.data["query"].startswith("user:") for item in findings[1:]))


class SiteRuleTests(unittest.TestCase):
    def test_rules(self):
        self.assertTrue(_site_answer("status400", 200, b""))
        self.assertFalse(_site_answer("status400", 400, b""))
        self.assertTrue(_site_answer("steam-xml", 200, b"<profile><steamID64>1</steamID64></profile>"))
        self.assertFalse(_site_answer("steam-xml", 200, b"<response><error>x</error></response>"))
        self.assertIsNone(_site_answer("steam-xml", 200, b"<html>captcha</html>"))


class MinecraftTests(unittest.TestCase):
    def test_profile_and_textures(self):
        textures = {"textures": {"SKIN": {"url": "http://textures.minecraft.net/texture/abc", "metadata": {"model": "slim"}}}}
        routes = {
            "api.mojang.com/users/profiles/minecraft/notch": {"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"},
            "sessionserver.mojang.com": {"properties": [{"name": "textures", "value": base64.b64encode(json.dumps(textures).encode()).decode()}]},
        }
        status, findings, _, _ = run("minecraft", "minecraft", "notch", routes)
        self.assertEqual(status, "ok")
        self.assertEqual(findings[0].value, "Notch")
        self.assertEqual(findings[0].data["uuid"], "069a79f444e94726a5befca90e38aaf5")
        self.assertEqual(findings[1].result_type, "skin")
        self.assertEqual(findings[1].data["model"], "slim")

    def test_missing(self):
        _, findings, _, _ = run("minecraft", "minecraft", "nobody", {})
        self.assertEqual(findings[0].value, "not found")


STEAM = b"""<?xml version="1.0"?><profile><steamID64>76561197960287930</steamID64>
<steamID><![CDATA[Rabscuttle]]></steamID><privacyState>public</privacyState><vacBanned>0</vacBanned>
<tradeBanState>None</tradeBanState><customURL><![CDATA[gabelogannewell]]></customURL>
<memberSince>September 12, 2003</memberSince><realname><![CDATA[Gabe]]></realname>
<location><![CDATA[Bellevue]]></location></profile>"""


class SteamTests(unittest.TestCase):
    def test_profile_omits_real_name_and_location(self):
        with patch.object(shared, "FETCH", raw_fetch(STEAM)):
            status, findings, _, _ = _run_one(BY_ID["steam"], ConnectorContext("", "steam", "gabelogannewell", None))
        self.assertEqual(status, "ok")
        values = {item.result_type: item.value for item in findings}
        self.assertEqual(values["steam-id64"], "76561197960287930")
        self.assertEqual(values["persona-name"], "Rabscuttle")
        self.assertEqual(values["member-since"], "September 12, 2003")
        self.assertNotIn("trade-ban", values)
        self.assertNotIn("Gabe", json.dumps([item.value for item in findings]))
        self.assertNotIn("Bellevue", json.dumps([item.value for item in findings]))

    def test_id64_path_and_missing(self):
        seen = []

        def fetch(url, **options):
            seen.append(url)
            return FetchResult(url, url, 200, {}, b"<response><error>not found</error></response>", "0" * 64, "", 1, [])

        with patch.object(shared, "FETCH", fetch):
            _, findings, _, _ = _run_one(BY_ID["steam"], ConnectorContext("", "steam", "76561197960287930", None))
        self.assertIn("/profiles/76561197960287930?xml=1", seen[0])
        self.assertEqual(findings[0].value, "not found")


if __name__ == "__main__":
    unittest.main()
