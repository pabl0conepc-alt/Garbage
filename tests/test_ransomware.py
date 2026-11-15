"""Ransomware leak-site posts (ransomware.live) for domains and companies."""

import unittest
from unittest.mock import patch

from garbage_intel.dossier import build
from garbage_intel.intel import ConnectorContext
from garbage_intel.modules import intel_br_connectors as br
from garbage_intel.modules import intel_ransomware_connectors as ransomware

from tests.test_intel_connectors import FakeWeb

VICTIMS = [
    {"victim": "NOVADATA", "domain": "novadata.com.ar", "group": "thegentlemen", "attackdate": "2026-10-30T11:39:33+00:00", "country": "AR",
     "activity": "Technology", "description": "IT integrator", "url": "https://www.ransomware.live/id/abc"},
    {"victim": "Other Corp", "domain": "other.example", "group": "akira", "attackdate": "2026-09-01T00:00:00+00:00", "country": "BR",
     "description": "Clients include Novadata and others", "url": "https://www.ransomware.live/id/def"},
]


def context(kind, value):
    return ConnectorContext("", kind, value, None)


class RansomwareTests(unittest.TestCase):
    def test_domain_match_is_direct_and_mentions_are_apart(self):
        web = FakeWeb([(lambda url: "searchvictims/novadata" in url, VICTIMS)])
        with patch.object(ransomware, "FETCH", web):
            found = ransomware._ransomware(context("domain", "novadata.com.ar"))
        kinds = [(item.result_type, item.value, item.data["match"]) for item in found if item.result_type != "ransomware-check"]
        self.assertEqual(kinds, [("ransomware-victim", "NOVADATA", "mesmo domínio"), ("ransomware-mention", "Other Corp", "citado na descrição de outra vítima")])
        self.assertEqual(web.calls[0]["allowed_hosts"], ("api.ransomware.live",))

    def test_company_searched_by_its_names_but_not_an_individuals(self):
        company = {"nome_fantasia": "NOVADATA", "razao_social": "NOVADATA SA", "email": "contato@novadata.com.ar"}
        web = FakeWeb([(lambda url: "brasilapi" in url, company), (lambda url: "searchvictims" in url, VICTIMS[:1])])
        with patch.object(ransomware, "FETCH", web), patch.object(br, "FETCH", web):
            found = ransomware._ransomware(context("cnpj", "00000000000191"))
        self.assertEqual(found[0].data["match"], "mesmo domínio")
        person = FakeWeb([(lambda url: "brasilapi" in url, {"razao_social": "FULANO DE TAL 52998224725"})])
        with patch.object(ransomware, "FETCH", person), patch.object(br, "FETCH", person):
            self.assertEqual(ransomware._ransomware(context("cnpj", "00000000000191")), [])
        self.assertFalse(any("searchvictims" in url for url in person.urls))

    def test_dossier_flag_and_section(self):
        web = FakeWeb([(lambda url: "searchvictims" in url, VICTIMS)])
        with patch.object(ransomware, "FETCH", web):
            found = ransomware._ransomware(context("domain", "novadata.com.ar"))
        results = [{"connector_id": "ransomware-live", "result_type": item.result_type, "value": item.value, "data": item.data, "status": "ok"} for item in found]
        dossier = build({"query_type": "domain", "query_value": "novadata.com.ar", "sources": [], "results": results})
        self.assertIn("thegentlemen", dossier["flags"][0]["text"])
        section = next(item for item in dossier["sections"] if item["id"] == "ransomware")
        self.assertEqual(section["list"]["items"][0]["meta"], "thegentlemen · 30/10/2026 · AR · mesmo domínio")


if __name__ == "__main__":
    unittest.main()
