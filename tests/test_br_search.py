"""CNPJ, CPF, phone numbers and places in the multi-source search.

``brasilapi-cnpj-00000000000191.json.gz`` is BrasilAPI's answer for Banco do
Brasil (a public company), recorded on 2026-11-14 with every partner's name,
document, age band and joining date replaced, so the fixture holds no
personal data.
"""

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import geoint, intel, plugins
from garbage_intel.errors import ValidationError
from garbage_intel.intel import Connector, ConnectorContext, detect_artifact, register_connector, run_query
from garbage_intel.modules import intel_br_connectors as br
from garbage_intel.store import initialize
from garbage_intel.workspace import update_settings

from tests.test_intel_connectors import FakeWeb, result

COMPANY = json.loads(gzip.decompress((Path(__file__).parent / "fixtures" / "brasilapi-cnpj-00000000000191.json.gz").read_bytes()))
PLACE = {
    "lat": "-23.5614980", "lon": "-46.6559640", "category": "tourism", "type": "museum", "osm_type": "way", "osm_id": 1,
    "display_name": "Museu de Arte de São Paulo, 1578, Avenida Paulista, Bela Vista, São Paulo",
    "address": {"city": "São Paulo", "state": "São Paulo", "country": "Brasil", "postcode": "01310-200"},
}


def registry():
    return {connector.connector_id: connector for connector in intel.connectors()}


def run(connector_id, query_type, value):
    return registry()[connector_id].run(ConnectorContext("", query_type, value, None))


class DetectionTests(unittest.TestCase):
    def detect(self, value):
        found = detect_artifact(value)
        return found["type"], found["value"]

    def test_documents_phones_and_places(self):
        cases = {
            "529.982.247-25": ("cpf", "52998224725"),
            "52998224725": ("cpf", "52998224725"),
            "33.000.167/0001-01": ("cnpj", "33000167000101"),
            "00000000000191": ("cnpj", "00000000000191"),
            "+55 11 98765-4321": ("phone", "+5511987654321"),
            "(11) 3456-7890": ("phone", "+551134567890"),
            "11987654321": ("phone", "+5511987654321"),  # check digits fail as a CPF
            "+44 20 7946 0958": ("phone", "+442079460958"),
            "-23.5505, -46.6333": ("location", "-23.550500,-46.633300"),
            "Avenida Paulista, 1578, São Paulo": ("location", "Avenida Paulista, 1578, São Paulo"),
            "local: Paris": ("location", "Paris"),
            "tel: 21987654321": ("phone", "+5521987654321"),
        }
        for value, expected in cases.items():
            self.assertEqual(self.detect(value), expected, value)

    def test_existing_types_win(self):
        # 192.168.1.100 has ten digits, like a landline; it must stay an IP.
        self.assertEqual(self.detect("192.168.1.100"), ("ipv4", "192.168.1.100"))
        self.assertEqual(self.detect("AS13335"), ("asn", "AS13335"))
        self.assertEqual(self.detect("example.com"), ("domain", "example.com"))
        for value in ("13335", "cnpj: 123", "cpf: 1", "tel: 52998224725"):
            with self.assertRaises(ValidationError):
                detect_artifact(value)

    def test_check_digits(self):
        self.assertTrue(br.cpf_valid("52998224725"))
        self.assertFalse(br.cpf_valid("52998224724"))
        self.assertFalse(br.cpf_valid("11111111111"))
        self.assertTrue(br.cnpj_valid("33000167000101"))
        self.assertFalse(br.cnpj_valid("33000167000102"))
        self.assertFalse(br.cnpj_valid("00000000000000"))

    def test_phone_parsing(self):
        mobile = br.parse_phone("+55 (21) 99876-5432")
        self.assertEqual((mobile["ddd"], mobile["state"], mobile["line_type"]), ("21", "RJ", "celular"))
        self.assertEqual(br.parse_phone("(48) 3222-1100")["line_type"], "fixo")
        self.assertEqual(br.parse_phone("0800 123 4567")["line_type"], "não geográfico")
        self.assertEqual(br.parse_phone("+351 21 123 4567")["country"], "Portugal")
        self.assertIsNone(br.parse_phone("(20) 98765-4321"))  # DDD 20 does not exist
        self.assertIsNone(br.parse_phone("(11) 88765-4321"))  # nine digits must start with 9


class ConnectorTests(unittest.TestCase):
    def test_offline_facts_never_name_an_owner(self):
        cpf = {finding.result_type: finding.value for finding in run("br-documents", "cpf", "52998224725")}
        self.assertEqual(cpf, {"validity": "válido", "fiscal-region": "ES e RJ"})
        cnpj = {finding.result_type: finding.value for finding in run("br-documents", "cnpj", "00000000000191")}
        self.assertEqual(cnpj["establishment"], "matriz")
        self.assertEqual(cnpj["formatted"], "00.000.000/0001-91")
        phone = {finding.result_type: finding.value for finding in run("br-documents", "phone", "+5511987654321")}
        self.assertEqual(phone["line-type"], "celular")
        self.assertIn("DDD 11", phone["phone-region"])

    def test_company_record_without_partner_names(self):
        web = FakeWeb([(lambda url: url.endswith("/00000000000191"), COMPANY)])
        with patch.object(br, "FETCH", web):
            findings = run("brasilapi-cnpj", "cnpj", "00000000000191")
            missing = run("brasilapi-cnpj", "cnpj", "00000000000272")
        values = {finding.result_type: finding.value for finding in findings}
        self.assertEqual(values["organization"], "BANCO DO BRASIL SA")
        self.assertEqual(values["registration-status"], "ATIVA")
        self.assertEqual(values["share-capital"], "R$ 120.000.000.000,00")
        self.assertTrue(values["partners"].startswith("41 sócio(s): 33 Diretor"))
        self.assertNotIn("REDACTED", json.dumps([finding.__dict__ for finding in findings], ensure_ascii=False))
        self.assertTrue(all(call["allowed_hosts"] == ("brasilapi.com.br",) for call in web.calls))
        self.assertIn("User-Agent", web.calls[0]["headers"])
        self.assertEqual(missing, [])  # FakeWeb answers other paths with an empty record

    def test_places_forward_and_reverse(self):
        web = FakeWeb([
            (lambda url: "/search?" in url, [PLACE]),
            (lambda url: "/reverse?" in url, PLACE),
        ])
        with patch.object(br, "FETCH", web):
            forward = run("nominatim", "location", "Avenida Paulista, 1578, São Paulo")
            reverse = run("nominatim", "location", "-23.561498,-46.655964")
        self.assertEqual([finding.result_type for finding in forward], ["geolocation", "coordinates"])
        self.assertEqual(forward[0].data["coordinates"], "-23.561498,-46.655964")
        self.assertEqual(forward[0].data["kind"], "place")
        self.assertEqual(reverse[1].value, "-23.561498,-46.655964")
        self.assertIn("lat=-23.561498", web.urls[1])

    def test_personal_types_stay_offline(self):
        with self.assertRaises(ValueError):
            register_connector(Connector("people-finder", "x", "x", ("cpf",), lambda context: [], network=True))
        self.assertNotIn("people-finder", registry())
        for connector in registry().values():
            if connector.network:
                self.assertFalse({"cpf", "phone"} & set(connector.accepts), connector.connector_id)
        with self.assertRaises(ValidationError):
            plugins.validate_manifest({"id": "phone-owner", "name": "x", "version": "1", "description": "x", "accepts": ["phone"]})


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "br.sqlite3")
        initialize(self.database)
        update_settings(self.database, {"intel.allow_network": "true"})
        intel.RATE_LIMITER.reset()

    def test_address_query_lands_on_the_map(self):
        with patch.object(br, "FETCH", FakeWeb([(lambda url: "/search?" in url, [PLACE])])):
            outcome = run_query(self.database, value="Avenida Paulista, 1578, São Paulo")
        self.assertEqual(outcome["query_type"], "location")
        sources = {item["connector_id"]: item["status"] for item in outcome["sources"]}
        self.assertEqual(sources["nominatim"], "ok")
        points = geoint.geo_points(self.database)
        self.assertEqual(points["counts"]["place"], 1)
        place = points["points"][0]
        self.assertEqual((place["kind"], place["precision"]), ("place", "geocoded"))
        self.assertAlmostEqual(place["latitude"], -23.561498)

    def test_cnpj_query_uses_both_mirrors(self):
        web = FakeWeb([(lambda url: url.endswith("00000000000191"), COMPANY)])
        with patch.object(br, "FETCH", web):
            outcome = run_query(self.database, value="00.000.000/0001-91")
        sources = {item["connector_id"]: item["status"] for item in outcome["sources"]}
        self.assertEqual({key: sources[key] for key in ("br-documents", "brasilapi-cnpj", "minhareceita-cnpj")}, {"br-documents": "ok", "brasilapi-cnpj": "ok", "minhareceita-cnpj": "ok"})
        self.assertEqual(sorted({url.split("/")[2] for url in web.urls}), ["brasilapi.com.br", "minhareceita.org"])


if __name__ == "__main__":
    unittest.main()
