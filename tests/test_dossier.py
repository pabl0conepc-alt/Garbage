"""The dossier: one answer per query, read off every source's results."""

import unittest

from garbage_intel.dossier import build


def result(connector, result_type, value, **data):
    return {"connector_id": connector, "result_type": result_type, "value": value, "data": data, "status": "ok"}


def run(query_type, value, results, sources=None):
    return {"query_type": query_type, "query_value": value, "results": results, "sources": sources or []}


def section(dossier, section_id):
    return next(item for item in dossier["sections"] if item["id"] == section_id)


def rows(dossier, section_id):
    return {row["label"]: row["value"] for row in section(dossier, section_id)["rows"]}


class DomainTests(unittest.TestCase):
    def test_subdomains_are_merged_and_limited_to_the_domain(self):
        dossier = build(run("domain", "example.org", [
            result("certspotter", "subdomain", "mail.example.org", last_seen="2026-10-01T00:00:00Z"),
            result("crtsh", "ct-name", "*.example.org"),
            result("crtsh", "ct-name", "MAIL.example.org"),
            result("crtsh", "ct-name", "vpn.example.org"),
            # Shared certificates list unrelated sites: they must not leak in.
            result("tls-certificate", "cert-san", "image.campus.theblock.co"),
            result("tls-certificate", "cert-san", "notexample.org"),
            result("tls-certificate", "cert-san", "example.org"),
        ]))
        listing = section(dossier, "subdomains")["list"]
        self.assertEqual([item["value"] for item in listing["items"]], ["mail.example.org", "vpn.example.org"])
        self.assertIn("crt.sh", listing["items"][0]["meta"])
        self.assertIn("Cert Spotter", listing["items"][0]["meta"])
        self.assertTrue(listing["pivot"])
        self.assertEqual({fact["label"]: fact["value"] for fact in dossier["facts"]}["Subdomínios"], "2")

    def test_registration_mail_and_flags(self):
        dossier = build(run("domain", "example.org", [
            result("rdap", "rdap-event", "2025-12-01T00:00:00Z", action="registration"),
            result("rdap", "rdap-event", "2027-12-01T00:00:00Z", action="expiration"),
            result("dns-doh", "dns-mx", "10 example-org.mail.protection.outlook.com"),
            result("dns-doh", "dns-txt", "v=spf1 include:spf.protection.outlook.com -all", policy="spf"),
            result("tls-certificate", "cert-validity", "x", days_remaining=5),
            result("typosquat", "typosquat", "examp1e.org", kind="replacement"),
            result("dns-doh", "dns-a", "192.0.2.10"),
        ]))
        self.assertEqual(rows(dossier, "registration")["Criado em"], "01/12/2025")
        mail = rows(dossier, "mail")
        self.assertEqual(mail["Provedor"], "Microsoft 365")
        self.assertEqual(mail["DMARC"], "não publicado")
        texts = " ".join(flag["text"] for flag in dossier["flags"])
        self.assertIn("vence em 5 dia(s)", texts)
        self.assertIn("não publica DMARC", texts)
        self.assertIn("1 domínio(s) parecido(s)", texts)
        self.assertIn("menos de um ano", texts)
        self.assertEqual(section(dossier, "hosting")["list"]["items"][0]["value"], "192.0.2.10")


class OtherTypesTests(unittest.TestCase):
    def test_ip_prefers_the_reverse_name(self):
        dossier = build(run("ipv4", "192.0.2.1", [
            result("shodan-internetdb", "hostname", "aaa.unrelated.example"),
            result("ipinfo", "hostname", "dns.example"),
            result("ipinfo", "network-owner", "AS64500 Example Net", anycast=False),
            result("ipinfo", "geolocation", "Somewhere, BR", coordinates="-23.5,-46.6"),
            result("shodan-internetdb", "open-port", "443"),
            result("shodan", "service", "53/tcp", module="dns-tcp"),
        ]))
        self.assertTrue(dossier["subtitle"].startswith("dns.example"))
        self.assertEqual([item["value"] for item in section(dossier, "services")["list"]["items"]], ["53", "443"])
        self.assertEqual(dossier["map"]["lat"], -23.5)

    def test_email_does_not_claim_missing_spf_when_txt_was_not_asked(self):
        only_mx = build(run("email", "a@example.org", [result("dns-doh", "dns-mx", "10 mx.example.org")]))
        self.assertEqual(only_mx["flags"], [])
        self.assertNotIn("SPF", rows(only_mx, "mail"))
        full = build(run("email", "a@example.org", [
            result("dns-doh", "dns-mx", "10 mx.example.org"),
            result("dns-doh", "dns-txt", "google-site-verification=x"),
        ]))
        self.assertEqual(rows(full, "mail")["SPF"], "não publicado")
        self.assertIn("não verifica se a caixa existe", full["subtitle"])

    def test_company_place_and_vulnerability(self):
        company = build(run("cnpj", "00000000000191", [
            result("brasilapi-cnpj", "organization", "BANCO DO BRASIL SA"),
            result("minhareceita-cnpj", "organization", "BANCO DO BRASIL SA"),
            result("brasilapi-cnpj", "registration-status", "BAIXADA", since="2020-01-01"),
        ]))
        self.assertEqual(company["title"], "BANCO DO BRASIL SA")
        self.assertEqual(rows(company, "company")["Razão social"], "BANCO DO BRASIL SA")
        self.assertIn("BAIXADA", company["flags"][0]["text"])
        place = build(run("location", "Avenida Paulista, 1000", [
            result("nominatim", "geolocation", "1000, Avenida Paulista, Bela Vista, São Paulo", coordinates="-23.56,-46.65", city="São Paulo"),
        ]))
        self.assertEqual(place["title"], "Avenida Paulista, 1000")
        self.assertEqual(place["map"]["precision"], "geocodificado")
        cve = build(run("cve", "CVE-2021-44228", [result("first-epss", "epss", "0.9700", percentile=0.99)]))
        self.assertIn("EPSS 97%", cve["flags"][0]["text"])

    def test_cve_reads_the_nvd_record_and_falls_back_to_osv(self):
        nvd = build(run("cve", "CVE-2021-44228", [
            result("nvd", "cve-record", "CVE-2021-44228", description="Log4j JNDI lookup", cwe=["CWE-502"], published="2021-12-10T10:15:09",
                   kev_due_date="2021-12-24", cvss={"version": "3.1", "score": 10.0, "severity": "CRITICAL"}),
        ]))
        summary = rows(nvd, "summary")
        self.assertEqual((summary["Descrição"], summary["CVSS"], summary["CISA KEV"], summary["Fraqueza (CWE)"]), ("Log4j JNDI lookup", "10.0 (CVSS 3.1)", "sim", "CWE-502"))
        self.assertIn("KEV", nvd["flags"][0]["text"])
        osv = build(run("cve", "CVE-2021-44228", [result("osv", "summary", "Remote code injection in Log4j")]))
        self.assertEqual(rows(osv, "summary")["Descrição"], "Remote code injection in Log4j")

    def test_portuguese_labels_and_owner_without_asn(self):
        domain = build(run("domain", "example.org", [
            result("rdap", "rdap-status", "client delete prohibited"),
            result("typosquat", "typosquat", "example.net", kind="tld-swap"),
        ]))
        self.assertEqual(rows(domain, "registration")["Situação"], "exclusão bloqueada")
        self.assertEqual(section(domain, "lookalikes")["list"]["items"][0]["meta"], "outro TLD")
        ip = build(run("ipv4", "192.0.2.1", [result("ipinfo", "network-owner", "AS64500 Example Net")]))
        self.assertEqual(ip["facts"][0], {"label": "Dono", "value": "Example Net"})

    def test_phone_and_cpf_say_what_the_number_tells(self):
        phone = build(run("phone", "+552182516781", [
            result("br-documents", "formatted", "+55 (21) 8251-6781"),
            result("br-documents", "line-type", "celular sem o 9 (formato antigo)"),
            result("br-documents", "phone-region", "DDD 21 · Rio de Janeiro e região metropolitana (RJ)"),
            result("br-documents", "state", "Rio de Janeiro (RJ)", meaning="DDD da capital"),
            result("br-documents", "phone-suggestion", "+55 (21) 98251-6781"),
            result("br-documents", "phone-format", "(21) 8251-6781", label="Nacional"),
        ]))
        self.assertEqual(phone["subtitle"], "Celular sem o 9 (formato antigo) · DDD 21 · Rio de Janeiro (RJ)")
        self.assertIn("98251-6781", phone["flags"][0]["text"])
        self.assertEqual(section(phone, "formats")["list"]["items"][0], {"value": "(21) 8251-6781", "meta": "Nacional"})
        self.assertIn("não são consultados", section(phone, "limits")["note"])
        cpf = build(run("cpf", "52998224724", [
            result("br-documents", "validity", "inválido"),
            result("br-documents", "check-digits", "24 não conferem; o certo seria 25"),
        ]))
        self.assertIn("o certo seria 25", cpf["flags"][0]["text"])

    def test_coverage_counts_and_failed_sources_by_name(self):
        dossier = build(run("domain", "example.org", [], sources=[
            {"connector_id": "dns-doh", "status": "ok"},
            {"connector_id": "crtsh", "status": "error"},
            {"connector_id": "virustotal", "status": "key-missing"},
            {"connector_id": "rdap", "status": "pending"},
        ]))
        self.assertEqual(dossier["coverage"], {"answered": 1, "empty": 0, "failed": ["crt.sh"], "missing_key": ["VirusTotal"], "network_off": 0, "pending": 1})


if __name__ == "__main__":
    unittest.main()
