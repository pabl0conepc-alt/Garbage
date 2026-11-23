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
        old = br.parse_phone("(21) 8251-6781")
        self.assertEqual((old["line_type"], old["suggestion"]), ("celular sem o 9 (formato antigo)", "+55 (21) 98251-6781"))
        self.assertTrue(mobile["capital"])
        self.assertEqual(mobile["state_ddds"], ["22", "24"])
        self.assertIn(("E.164 (sistemas e apps)", "+5521998765432"), mobile["formats"])
        self.assertEqual(br.parse_phone("4004 1234")["formatted"], "4004-1234")
        self.assertEqual(br.cpf_check_digits("529982247"), "25")


class ConnectorTests(unittest.TestCase):
    def test_offline_facts_never_name_an_owner(self):
        cpf = {finding.result_type: finding.value for finding in run("br-documents", "cpf", "52998224725")}
        self.assertEqual(cpf, {"formatted": "529.982.247-25", "validity": "válido", "check-digits": "25 conferem", "fiscal-region": "ES e RJ"})
        typo = {finding.result_type: finding.value for finding in run("br-documents", "cpf", "52998224724")}
        self.assertEqual(typo["check-digits"], "24 não conferem; o certo seria 25")
        self.assertNotIn("fiscal-region", typo)
        same = {finding.result_type: finding.value for finding in run("br-documents", "cpf", "11111111111")}
        self.assertEqual(same["warning"], "todos os dígitos iguais")
        cnpj = {finding.result_type: finding.value for finding in run("br-documents", "cnpj", "00000000000191")}
        self.assertEqual(cnpj["establishment"], "matriz")
        self.assertEqual(cnpj["formatted"], "00.000.000/0001-91")
        phone = {finding.result_type: finding.value for finding in run("br-documents", "phone", "+5511987654321")}
        self.assertEqual(phone["line-type"], "celular")
        self.assertIn("DDD 11", phone["phone-region"])
        self.assertEqual(phone["state"], "São Paulo (SP)")
        self.assertNotIn("owner", " ".join(phone).lower())

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

    def test_registrobr_counts_and_confirms_company_sites(self):
        company = {**COMPANY, "nome_fantasia": "BB", "email": "contato@bb.com.br"}
        registrant = lambda cnpj: {"entities": [
            {"roles": ["registrant"], "publicIds": [{"type": "cnpj", "identifier": cnpj}],
             "entities": [{"roles": ["administrative"], "vcardArray": ["vcard", [["fn", {}, "text", "Pessoa Contato"]]]}]},
        ]}
        web = FakeWeb([
            (lambda url: url.endswith("/entity/00000000000191"), {"nicbr_domainCount": 171, "nicbr_inetCount": 180, "nicbr_autnumCount": 1,
                                                                   "legalRepresentative": "Pessoa Representante",
                                                                   "events": [{"eventAction": "registration", "eventDate": "1998-02-09T12:00:00Z"}]}),
            (lambda url: url.endswith("/cnpj/v1/00000000000191"), company),
            (lambda url: url.endswith("/domain/bb.com.br"), registrant("00.000.000/0001-91")),
            (lambda url: url.endswith("/domain/bancobrasil.com.br"), registrant("00.000.000/0001-91")),
            (lambda url: url.endswith("/domain/banco.com.br"), registrant("11.111.111/0001-11")),
            (lambda url: "/domain/" in url, result("https://rdap.registro.br/domain/other", {}, status=404)),
        ])
        with patch.object(br, "FETCH", web):
            findings = run("registrobr-cnpj", "cnpj", "00000000000191")
        holder = next(item for item in findings if item.result_type == "registrobr-holder")
        self.assertEqual((holder.value, holder.data["ip_blocks"], holder.data["since"]), ("171 domínio(s) .br", 180, "1998-02-09"))
        sites = {item.value: item.data["confirmed"] for item in findings if item.result_type == "company-domain"}
        self.assertEqual(sites, {"bb.com.br": True, "bancobrasil.com.br": True})
        stored = json.dumps([item.__dict__ for item in findings], ensure_ascii=False)
        self.assertNotIn("Pessoa", stored)

    def test_mei_name_hides_the_owner_cpf_and_sanctions_are_listed(self):
        self.assertEqual(br.mask_cpf("FULANO DE TAL 52998224725"), "FULANO DE TAL 529.***.***-**")
        self.assertEqual(br.cnpj_with_check_digits("000000000001"), "00000000000191")
        sanction = {"tipoSancao": {"descricaoResumida": "Impedimento"}, "orgaoSancionador": {"nome": "Ministério X"},
                    "dataInicioSancao": "01/01/2025", "dataFimSancao": "01/01/2027", "numeroProcesso": "123", "fundamentacao": [{"descricao": "Lei 14.133"}]}
        web = FakeWeb([
            (lambda url: "/ceis?" in url, [sanction]),
            (lambda url: "api-de-dados" in url, []),
        ])
        with patch.object(br, "FETCH", web):
            found = registry()["sancoes-cgu"].run(ConnectorContext("", "cnpj", "00000000000191", None, api_key="k" * 32))
        self.assertEqual([(item.result_type, item.value) for item in found], [("sanction", "Impedimento · Ministério X")])
        self.assertEqual(web.calls[0]["headers"]["chave-api-dados"], "k" * 32)
        self.assertEqual(len(web.urls), 4)
        with patch.object(br, "FETCH", FakeWeb([(lambda url: True, [])])):
            clean = registry()["sancoes-cgu"].run(ConnectorContext("", "cnpj", "00000000000191", None, api_key="k" * 32))
        self.assertEqual(clean[0].value, "nenhuma sanção encontrada")

    def test_federal_contracts_and_largest_payments(self):
        contract = {"numero": "12/2024", "objeto": "Serviços  de limpeza", "situacaoContrato": "Ativo", "modalidadeCompra": "Pregão",
                    "dataAssinatura": "10/01/2024", "dataFimVigencia": "31/12/2030", "valorInicialCompra": 100.0, "valorFinalCompra": 150000.5,
                    "compra": {"contatoResponsavel": "Pessoa Contato"},
                    "unidadeGestora": {"nome": "UG X", "orgaoVinculado": {"nome": "Ministério A"}}}
        payment = {"data": "05/03/2026", "documentoResumido": "2026OB000001", "valor": "10.000,50", "orgao": "Ministério A", "programa": "Gestão", "autor": "Autor X"}
        web = FakeWeb([
            (lambda url: "contratos/cpf-cnpj" in url and "pagina=1" in url, [contract]),
            (lambda url: "documentos-por-favorecido" in url and "ano=2026" in url, [payment]),
            (lambda url: "api-de-dados" in url, []),
        ])
        with patch.object(br, "FETCH", web), patch.object(br, "_this_year", lambda: 2026):
            found = registry()["contratos-cgu"].run(ConnectorContext("", "cnpj", "00000000000191", None, api_key="k" * 32))
        kinds = [(item.result_type, item.value) for item in found]
        self.assertIn(("contract", "12/2024 · Serviços de limpeza"), kinds)
        self.assertIn(("contracts-summary", "1 contrato(s)"), kinds)
        self.assertIn(("payment", "R$ 10.000,50 · Ministério A"), kinds)
        self.assertIn(("payments-summary", "2025: 0 pagamento(s) listados"), kinds)
        contract_data = next(item.data for item in found if item.result_type == "contract")
        self.assertEqual((contract_data["organ"], contract_data["amount"]), ("Ministério A", 150000.5))
        stored = json.dumps([item.__dict__ for item in found], ensure_ascii=False)
        self.assertNotIn("Pessoa Contato", stored)
        self.assertNotIn("Autor X", stored)
        self.assertTrue(all(call["headers"]["chave-api-dados"] == "k" * 32 for call in web.calls))

    def test_company_address_becomes_a_map_point(self):
        web = FakeWeb([
            (lambda url: url.endswith("/cnpj/v1/00000000000191"), COMPANY),
            (lambda url: "/cep/v2/" in url, {"cep": "70040912", "street": "Quadra SAUN", "city": "Brasília", "state": "DF",
                                              "location": {"coordinates": {"latitude": "-15.79", "longitude": "-47.88"}}}),
        ])
        with patch.object(br, "FETCH", web):
            findings = run("brasilapi-cnpj", "cnpj", "00000000000191")
        point = next(item for item in findings if item.result_type == "geolocation")
        self.assertEqual((point.data["coordinates"], point.data["precision"], point.data["kind"]), ("-15.790000,-47.880000", "cep", "place"))
        from garbage_intel.dossier import build
        dossier = build({"query_type": "cnpj", "query_value": "00000000000191", "sources": [],
                         "results": [{"connector_id": "brasilapi-cnpj", "result_type": item.result_type, "value": item.value, "data": item.data, "status": "ok"} for item in findings]})
        self.assertEqual((dossier["map"]["lat"], dossier["map"]["precision"]), (-15.79, "CEP (aproximado)"))
        # Without coordinates for the CEP there is simply no point.
        with patch.object(br, "FETCH", FakeWeb([(lambda url: url.endswith("00000000000191"), COMPANY), (lambda url: "/cep/v2/" in url, {"cep": "70040912"})])):
            self.assertFalse(any(item.result_type == "geolocation" for item in run("brasilapi-cnpj", "cnpj", "00000000000191")))

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
        # Only public company registries; the sanctions lists wait for their key.
        self.assertEqual(sorted({url.split("/")[2] for url in web.urls}), ["brasilapi.com.br", "minhareceita.org", "rdap.registro.br"])
        self.assertEqual((sources["sancoes-cgu"], sources["contratos-cgu"]), ("key-missing", "key-missing"))


if __name__ == "__main__":
    unittest.main()
