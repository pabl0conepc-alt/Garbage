"""Email and domain posture (catalogue block 1).

Reads only public DNS through the same DNS-over-HTTPS resolver as the DNS
connector and grades what a mail receiver would see: SPF, DMARC, DKIM on
common selectors, DNSSEC, MTA-STS, TLS-RPT, BIMI and CAA. It also names the
mail provider from MX hosts and flags disposable-mail domains from a bundled
list. Every check says what it found and why it matters; nothing is sent to
the domain's own servers.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from ..intel import Connector, ConnectorContext, Finding, register_connector
from . import intel_connectors as dns

# Selectors published by common senders; a hit proves DKIM is set up, a miss
# proves nothing because selectors can be any name.
DKIM_SELECTORS = (
    "google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2",
    "dkim", "mail", "smtp", "mandrill", "everlytickey1", "zoho", "mxvault",
    "protonmail", "protonmail2", "fm1", "fm2", "sig1", "amazonses",
)

# Hostname suffix of MX targets -> provider.
MAIL_PROVIDERS = (
    ("google.com", "Google Workspace / Gmail"),
    ("googlemail.com", "Google Workspace / Gmail"),
    ("outlook.com", "Microsoft 365 / Outlook"),
    ("protection.outlook.com", "Microsoft 365 / Outlook"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("protonmail.ch", "Proton Mail"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("messagingengine.com", "Fastmail"),
    ("yahoodns.net", "Yahoo Mail"),
    ("icloud.com", "iCloud Mail"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "Amazon SES / WorkMail"),
    ("secureserver.net", "GoDaddy"),
    ("ovh.net", "OVHcloud"),
    ("hostinger.com", "Hostinger"),
    ("locaweb.com.br", "Locaweb"),
    ("uol.com.br", "UOL Host"),
    ("kinghost.net", "KingHost"),
    ("titan.email", "Titan"),
    ("yandex.net", "Yandex Mail"),
    ("mail.ru", "Mail.ru"),
    ("barracudanetworks.com", "Barracuda"),
)

# Well-known throwaway inbox domains. Not exhaustive: absence is not proof.
DISPOSABLE_DOMAINS = frozenset(
    """
    10minutemail.com 10minutemail.net 20minutemail.com 33mail.com anonaddy.me
    burnermail.io discard.email dispostable.com dropmail.me emailondeck.com
    fakeinbox.com getairmail.com getnada.com guerrillamail.biz guerrillamail.com
    guerrillamail.de guerrillamail.info guerrillamail.net guerrillamail.org
    guerrillamailblock.com harakirimail.com inboxbear.com inboxkitten.com
    mail.tm mail-temp.com mailcatch.com maildrop.cc mailinator.com mailinator.net
    mailnesia.com mailpoof.com mintemail.com moakt.com mohmal.com mytemp.email
    nada.email sharklasers.com spam4.me spamgourmet.com temp-mail.io
    temp-mail.org tempail.com tempmail.dev tempmail.net tempmailo.com
    tempr.email throwawaymail.com trashmail.com trashmail.de trashmail.net
    yopmail.com yopmail.fr yopmail.net emailfake.com fakemail.net
    """.split()
)


def _host(context: ConnectorContext) -> str:
    if context.query_type == "email":
        return context.query_value.rsplit("@", 1)[-1].lower()
    return context.query_value.lower()


def _txt(name: str, prefix: str) -> tuple[list[str], Any]:
    answers, result = dns.doh_query(name, "TXT")
    # A long TXT record arrives as quoted chunks: "v=spf1 ..." "...more".
    joined = ["".join(re.findall(r'"([^"]*)"', item)) or item.strip('"') for item in answers]
    return [item for item in joined if item.lower().startswith(prefix)], result


def _tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()
    return tags


def _check(name: str, status: str, value: str, why: str, result: Any = None, **extra: Any) -> Finding:
    data = {"check": name, "status": status, "why": why, **extra}
    if result is None:
        return Finding("posture-check", value, data)
    return Finding("posture-check", value, data, result.final_url, result.sha256)


def _spf(host: str) -> Finding:
    records, result = _txt(host, "v=spf1")
    if not records:
        return _check("SPF", "fail", "no SPF record", "Anyone can send mail claiming to be this domain without an SPF failure.", result)
    if len(records) > 1:
        return _check("SPF", "fail", f"{len(records)} SPF records", "More than one SPF record is a permanent error (RFC 7208 §4.5); receivers treat it as no SPF.", result)
    record = records[0]
    terms = record.lower().split()
    lookups = sum(1 for term in terms if re.match(r"[-+~?]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", term))
    ending = next((term for term in reversed(terms) if term.endswith("all")), "")
    if ending in ("+all", "all"):
        return _check("SPF", "fail", record, "+all authorises every server on the internet to send as this domain.", result, lookups=lookups)
    if lookups > 10:
        return _check("SPF", "fail", record, f"{lookups} DNS-lookup terms; more than 10 is a permanent error (RFC 7208 §4.6.4).", result, lookups=lookups)
    if ending == "-all":
        return _check("SPF", "pass", record, "Hard fail (-all) for unlisted senders.", result, lookups=lookups)
    if ending == "~all":
        return _check("SPF", "warn", record, "Soft fail (~all): unlisted senders are only marked, usually still delivered.", result, lookups=lookups)
    return _check("SPF", "warn", record, "Neutral or missing 'all' term: unlisted senders are not rejected.", result, lookups=lookups)


def _dmarc(host: str) -> Finding:
    records, result = _txt(f"_dmarc.{host}", "v=dmarc1")
    if not records:
        return _check("DMARC", "fail", "no DMARC record", "Receivers have no policy for mail that fails SPF and DKIM, and the owner gets no reports.", result)
    tags = _tags(records[0])
    policy = tags.get("p", "").lower()
    extra = {"policy": policy, "subdomain_policy": tags.get("sp", ""), "pct": tags.get("pct", "100"), "reports_to": tags.get("rua", "")}
    if policy == "reject":
        status, why = "pass", "p=reject: failing mail is refused."
    elif policy == "quarantine":
        status, why = "pass", "p=quarantine: failing mail goes to spam."
    else:
        status, why = "warn", "p=none: monitoring only; spoofed mail is still delivered."
    if status == "pass" and extra["pct"] not in ("", "100"):
        status, why = "warn", f"{why} Only {extra['pct']}% of failing mail is covered (pct)."
    if not extra["reports_to"]:
        why += " No rua= address, so the owner receives no aggregate reports."
    return _check("DMARC", status, records[0], why, result, **extra)


def _dkim(host: str) -> Finding:
    found = []
    last = None
    for selector in DKIM_SELECTORS:
        answers, last = dns.doh_query(f"{selector}._domainkey.{host}", "TXT")
        text = " ".join(answers)
        if "p=" in text.lower() or "v=dkim1" in text.lower():
            found.append(selector)
        else:
            cnames, last = dns.doh_query(f"{selector}._domainkey.{host}", "CNAME")
            if cnames:
                found.append(selector)
    if found:
        return _check("DKIM", "pass", ", ".join(found), "A DKIM key is published on these selectors.", last, selectors=found)
    return _check(
        "DKIM", "info", "no key on common selectors",
        f"None of {len(DKIM_SELECTORS)} common selectors has a key. DKIM may still exist under another selector; check a received message's DKIM-Signature s= tag.",
        last,
    )


def _dnssec(host: str) -> Finding:
    url = f"{dns.DOH_URL}?name={quote(host, safe='')}&type=SOA&do=1"
    data, result = dns._get_json(url, hosts=dns.DOH_HOSTS, headers={"Accept": "application/dns-json"})
    if isinstance(data, dict) and data.get("AD"):
        return _check("DNSSEC", "pass", "signed and validated", "Answers are signed and the resolver validated the chain.", result)
    return _check("DNSSEC", "info", "not validated", "The zone is unsigned or did not validate; DNS answers can be forged on the path.", result)


def _optional_txt(host: str, label: str, name: str, prefix: str, present: str, missing: str) -> Finding:
    records, result = _txt(name, prefix)
    if records:
        return _check(label, "pass", records[0], present, result)
    return _check(label, "info", "not published", missing, result)


def _caa(host: str) -> Finding:
    answers, result = dns.doh_query(host, "CAA")
    if answers:
        return _check("CAA", "pass", "; ".join(answers[:10]), "Only the listed certificate authorities may issue certificates for this domain.", result)
    return _check("CAA", "info", "not published", "Any certificate authority may issue certificates for this domain.", result)


def _mail_provider(host: str) -> tuple[list[Finding], bool]:
    answers, result = dns.doh_query(host, "MX")
    exchanges = [answer.split()[-1].rstrip(".").lower() for answer in answers if answer.split()]
    if not exchanges or exchanges == [""]:
        return [_check("MX", "info", "no MX", "The domain does not receive mail (or uses its A record as fallback).", result)], False
    providers = []
    for exchange in exchanges:
        for suffix, name in MAIL_PROVIDERS:
            if exchange == suffix or exchange.endswith("." + suffix):
                if name not in providers:
                    providers.append(name)
                break
    value = ", ".join(providers) if providers else "self-hosted or unrecognised"
    finding = Finding("mail-provider", value, {"mx": exchanges[:10]}, result.final_url, result.sha256)
    return [finding], True


def _posture_connector(context: ConnectorContext) -> list[Finding]:
    host = _host(context)
    if not host:
        return []
    findings: list[Finding] = []
    if host in DISPOSABLE_DOMAINS:
        findings.append(Finding("disposable-domain", host, {"meaning": "throwaway inbox service; listed in GARBAGE's bundled list"}))
    provider, receives_mail = _mail_provider(host)
    findings += provider
    checks = [_spf(host), _dmarc(host), _dkim(host), _dnssec(host), _caa(host)]
    if receives_mail:
        checks.append(_optional_txt(host, "MTA-STS", f"_mta-sts.{host}", "v=stsv1",
                                    "Senders must use verified TLS when delivering mail here.",
                                    "Mail to this domain can be downgraded to plaintext by an attacker on the path."))
        checks.append(_optional_txt(host, "TLS-RPT", f"_smtp._tls.{host}", "v=tlsrptv1",
                                    "The owner receives reports of TLS delivery failures.",
                                    "The owner gets no reports when TLS delivery fails."))
    checks.append(_optional_txt(host, "BIMI", f"default._bimi.{host}", "v=bimi1",
                                "A brand logo is published for supporting inboxes.",
                                "No brand logo published (optional)."))
    findings += checks
    weights = {"SPF": 25, "DMARC": 30, "DKIM": 15, "DNSSEC": 10, "MTA-STS": 10, "CAA": 5, "TLS-RPT": 5}
    earned = possible = 0
    for check in checks:
        weight = weights.get(check.data["check"], 0)
        possible += weight
        earned += weight if check.data["status"] == "pass" else weight // 2 if check.data["status"] == "warn" else 0
    score = round(100 * earned / possible) if possible else 0
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    findings.insert(
        0,
        Finding(
            "posture-score",
            f"{grade} ({score}/100)",
            {
                "failed": [check.data["check"] for check in checks if check.data["status"] == "fail"],
                "warnings": [check.data["check"] for check in checks if check.data["status"] == "warn"],
                "meaning": "weighted from public DNS only; not a full security assessment",
            },
        ),
    )
    return findings


register_connector(
    Connector(
        "email-posture", "Email and domain posture",
        "Grades SPF, DMARC, DKIM (common selectors), DNSSEC, MTA-STS, TLS-RPT, BIMI and CAA from public DNS, names the mail provider and flags disposable-mail domains.",
        ("domain", "email"), _posture_connector, network=True, rate_per_minute=20, ttl_seconds=3600,
        source_url=dns.DOH_URL,
    )
)
