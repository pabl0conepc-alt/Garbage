"""Catalogue block 1: email/domain posture and offline header analysis."""

import hashlib
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from garbage_intel.intel import ConnectorContext, _run_one, connectors
from garbage_intel.modules import intel_connectors
from garbage_intel.modules.email_analysis import analyse
from garbage_intel.net import FetchResult

BY_ID = {connector.connector_id: connector for connector in connectors()}
TYPES = {"TXT": 16, "MX": 15, "CNAME": 5, "CAA": 257, "SOA": 6}


def doh(records, ad=False):
    """Fake DoH resolver answering from {(name, type): [data, ...]}."""
    calls = []

    def fetch(url, **options):
        query = parse_qs(urlsplit(url).query)
        name, kind = query["name"][0], query["type"][0]
        calls.append((name, kind))
        answers = [{"name": name, "type": TYPES[kind], "data": data} for data in records.get((name, kind), [])]
        body = json.dumps({"Status": 0, "AD": ad, "Answer": answers}).encode()
        return FetchResult(url, url, 200, {}, body, hashlib.sha256(body).hexdigest(), "192.0.2.1", 1, [])

    return fetch, calls


def checks(findings):
    return {item.data["check"]: item for item in findings if item.result_type == "posture-check"}


STRONG = {
    ("example.com", "MX"): ["10 aspmx.l.google.com."],
    ("example.com", "TXT"): ['"v=spf1 include:_spf.google.com -all"', '"google-site-verification=x"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:d@example.com"'],
    ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIIB"'],
    ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"'],
    ("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:t@example.com"'],
}


class PostureTests(unittest.TestCase):
    def run_posture(self, kind, value, records, ad=False):
        fetch, calls = doh(records, ad)
        with patch.object(intel_connectors, "FETCH", fetch):
            status, findings, error, _ = _run_one(BY_ID["email-posture"], ConnectorContext("", kind, value, None))
        self.assertEqual(status, "ok", error)
        return findings, calls

    def test_strong_domain(self):
        findings, _ = self.run_posture("domain", "example.com", STRONG, ad=True)
        found = checks(findings)
        for name in ("SPF", "DMARC", "DKIM", "DNSSEC", "CAA", "MTA-STS", "TLS-RPT"):
            self.assertEqual(found[name].data["status"], "pass", name)
        self.assertEqual(found["DKIM"].value, "google")
        self.assertTrue(findings[0].value.startswith("A (100/100)"))
        provider = [item for item in findings if item.result_type == "mail-provider"][0]
        self.assertEqual(provider.value, "Google Workspace / Gmail")

    def test_weak_domain(self):
        records = {
            ("weak.test", "MX"): ["10 mail.weak.test."],
            ("weak.test", "TXT"): ['"v=spf1 +all"'],
            ("_dmarc.weak.test", "TXT"): ['"v=DMARC1; p=none"'],
        }
        findings, _ = self.run_posture("domain", "weak.test", records)
        found = checks(findings)
        self.assertEqual(found["SPF"].data["status"], "fail")
        self.assertEqual(found["DMARC"].data["status"], "warn")
        self.assertIn("No rua=", found["DMARC"].data["why"])
        self.assertEqual(found["DKIM"].data["status"], "info")
        self.assertIn("F", findings[0].value)
        self.assertEqual(findings[0].data["failed"], ["SPF"])

    def test_spf_errors(self):
        two = {("a.test", "TXT"): ['"v=spf1 -all"', '"v=spf1 ~all"']}
        self.assertEqual(checks(self.run_posture("domain", "a.test", two)[0])["SPF"].data["status"], "fail")
        many = " ".join(f"include:s{i}.test" for i in range(11))
        lookups = {("b.test", "TXT"): [f'"v=spf1 {many} -all"']}
        spf = checks(self.run_posture("domain", "b.test", lookups)[0])["SPF"]
        self.assertEqual(spf.data["lookups"], 11)
        self.assertEqual(spf.data["status"], "fail")
        split = {("c.test", "TXT"): ['"v=spf1 include:x.test " "-all"']}
        self.assertEqual(checks(self.run_posture("domain", "c.test", split)[0])["SPF"].data["status"], "pass")

    def test_email_input_and_disposable(self):
        findings, calls = self.run_posture("email", "someone@yopmail.com", {})
        self.assertEqual(findings[1].result_type, "disposable-domain")
        self.assertIn(("yopmail.com", "MX"), calls)
        # No MX: MTA-STS and TLS-RPT are not checked.
        self.assertNotIn("MTA-STS", checks(findings))


HEADERS = """Delivered-To: victim@example.org
Received: by 2002:a05:6a10:1234 with SMTP id abc; Mon, 4 Nov 2024 10:00:09 -0800 (PST)
Received: from mail.evil.test (mail.evil.test [45.33.32.156])
        by mx.google.com with ESMTPS id x; Mon, 4 Nov 2024 10:00:05 -0800 (PST)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of bounce@evil.test does not designate 45.33.32.156) smtp.mailfrom=bounce@evil.test;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=bank.example
Return-Path: <bounce@evil.test>
From: "security@bank.example" <alerts@bank.example>
Reply-To: help@evil.test
To: victim@example.org
Subject: Urgent: verify your account
Message-ID: <123@evil.test>
Date: Mon, 4 Nov 2024 18:00:00 +0000

Click http://evil.test/login now
"""


class HeaderTests(unittest.TestCase):
    """Checks ported from the earlier header analyser into email_analysis."""

    def test_spoofed_message(self):
        result = analyse(HEADERS.encode())
        codes = {item["code"] for item in result["flags"]}
        self.assertTrue({"spf-fail", "dmarc-fail", "unaligned", "reply-to-mismatch"} <= codes)
        self.assertEqual(result["risk"], "high")
        self.assertEqual(result["origin_ip"], "45.33.32.156")
        self.assertEqual(result["smtp_mailfrom"], "evil.test")

    def test_aligned_message(self):
        good = (
            "From: News <news@shop.example>\n"
            "Authentication-Results: mx; spf=pass smtp.mailfrom=bounces.shop.example; dkim=pass header.d=shop.example; dmarc=pass\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=shop.example; s=s1; b=abc\n"
            "Subject: Hello\n\nbody\n"
        )
        result = analyse(good.encode())
        self.assertNotIn("unaligned", {item["code"] for item in result["flags"]})
        self.assertEqual(result["risk"], "low")

    def test_clock_skew(self):
        skewed = (
            "Received: by b.example; Mon, 4 Nov 2024 09:00:00 +0000\n"
            "Received: from a.example (a.example [203.0.113.9]) by b.example; Mon, 4 Nov 2024 10:00:00 +0000\n"
            "From: x@a.example\nSubject: t\n\nb\n"
        )
        self.assertIn("time-travel", {item["code"] for item in analyse(skewed.encode())["flags"]})


if __name__ == "__main__":
    unittest.main()
