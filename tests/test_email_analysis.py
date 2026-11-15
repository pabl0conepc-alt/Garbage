"""E-mail messages: hops, origin, authentication, sender mismatches, links, attachments.

``fixtures/phishing-sample.eml`` is a made-up phishing message on
example domains, written for these tests.
"""

import unittest
from pathlib import Path

from garbage_intel.modules import email_analysis, file_intel

SAMPLE = (Path(__file__).parent / "fixtures" / "phishing-sample.eml").read_bytes()


class EmailTests(unittest.TestCase):
    def test_detected_as_e_mail_and_analysed(self):
        analysis = file_intel.analyze_bytes(SAMPLE, "aviso.eml")
        self.assertEqual(analysis["format"], "eml")
        message = analysis["structure"]["email"]
        self.assertEqual(message["subject"], "Sua conta foi bloqueada")
        self.assertEqual(message["from"]["domain"], "banco-seguro.example.net")
        self.assertEqual(message["authentication"], {"spf": "softfail", "dkim": "none", "dmarc": "fail"})
        self.assertEqual(message["origin_ip"], "45.33.32.156")
        self.assertEqual([(hop["ip"], hop["delay_seconds"]) for hop in message["hops"]], [("45.33.32.156", None), ("10.0.0.2", 4)])
        self.assertEqual(analysis["text"]["method"], "corpo do e-mail")
        self.assertIn("45.33.32.156", [item["value"] for item in analysis["indicators"]])

    def test_inconsistencies_links_and_attachments(self):
        message = email_analysis.analyse(SAMPLE)
        codes = {flag["code"] for flag in message["flags"]}
        self.assertTrue({"spf-softfail", "dmarc-fail", "reply-to-mismatch", "display-name-spoof", "disguised-links", "risky-attachment", "dkim-domain-mismatch"} <= codes)
        link = message["links"][0]
        self.assertEqual((link["host"], link["disguised"]), ("login-banco.example.xyz", True))
        attachment = message["attachments"][0]
        self.assertEqual((attachment["name"], attachment["size"]), ("comprovante.html", 13))
        self.assertEqual(len(attachment["sha256"]), 64)

    def test_headers_only_and_plain_text_are_told_apart(self):
        headers = SAMPLE.split(b"\n\n", 1)[0] + b"\n\n"
        self.assertTrue(email_analysis.looks_like_email(headers.decode()))
        self.assertEqual(email_analysis.analyse(headers)["origin_ip"], "45.33.32.156")
        self.assertFalse(email_analysis.looks_like_email("Nota: lembrar de ligar.\nFrom: ninguém\nAssunto qualquer"))
        self.assertEqual(file_intel.analyze_bytes(b"linha um\nlinha dois\n", "nota.txt")["format"], "text")


if __name__ == "__main__":
    unittest.main()
