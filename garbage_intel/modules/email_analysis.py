"""E-mail messages (.eml or pasted headers), read for phishing triage.

Everything is parsed from the message itself, offline:

* the hops of the ``Received`` chain, oldest first, with the delay between
  them and the first address outside private ranges (where the message most
  likely entered the internet);
* SPF, DKIM and DMARC verdicts the receiving server recorded;
* sender inconsistencies: Return-Path, Reply-To, DKIM signing domain or
  Message-ID domain different from the From domain, and a display name that
  carries another address;
* links (with the text shown for them, to catch disguised links) and
  attachments with their size and SHA-256. Attachments are hashed, never
  opened.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

from .document_text import html_text

KNOWN_HEADERS = ("received:", "from:", "to:", "subject:", "message-id:", "mime-version:", "return-path:", "delivered-to:", "date:", "authentication-results:", "dkim-signature:", "x-mailer:")
MAX_LINKS = 200
MAX_HOPS = 40
_IP = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39}:[0-9a-fA-F]{1,4})\]?")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def looks_like_email(text: str) -> bool:
    head = text.lstrip()[:16384].split("\n\n", 1)[0].split("\r\n\r\n", 1)[0].lower()
    lines = [line for line in head.splitlines() if line and not line[0].isspace()]
    if not lines or ":" not in lines[0]:
        return False
    found = {name for name in KNOWN_HEADERS for line in lines[:120] if line.startswith(name)}
    return len(found) >= 3 and ("from:" in found or "received:" in found)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[1].lower().strip(">. ") if "@" in address else ""


def _public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _hops(message: EmailMessage) -> list[dict[str, Any]]:
    hops = []
    for raw in reversed(message.get_all("Received") or []):
        text = " ".join(str(raw).split())
        sender = re.search(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", text, re.IGNORECASE)
        receiver = re.search(r"\bby\s+(\S+)", text, re.IGNORECASE)
        stamp = text.rsplit(";", 1)[1].strip() if ";" in text else ""
        when = None
        try:
            when = parsedate_to_datetime(stamp) if stamp else None
        except (TypeError, ValueError, IndexError):
            when = None
        origin_text = f"{sender.group(2) or ''} {sender.group(1)}" if sender else ""
        addresses = [match.group(1) for match in _IP.finditer(origin_text)]
        valid = []
        for value in addresses:
            try:
                valid.append(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        hops.append({
            "from": (sender.group(1) if sender else "")[:200],
            "by": (receiver.group(1) if receiver else "")[:200],
            "ip": valid[0] if valid else "",
            "time": when.isoformat() if when else "",
            "raw": text[:500],
        })
        if len(hops) >= MAX_HOPS:
            break
    previous: datetime | None = None
    for hop in hops:
        current = datetime.fromisoformat(hop["time"]) if hop["time"] else None
        hop["delay_seconds"] = int((current - previous).total_seconds()) if current and previous and current.tzinfo and previous.tzinfo else None
        previous = current or previous
    return hops


def _auth(message: EmailMessage) -> dict[str, str]:
    results: dict[str, str] = {}
    text = " ".join(" ".join(str(value).split()) for value in message.get_all("Authentication-Results") or [])
    for method in ("spf", "dkim", "dmarc", "arc"):
        found = re.search(rf"\b{method}=(\w+)", text, re.IGNORECASE)
        if found:
            results[method] = found.group(1).lower()
    if "spf" not in results and message.get("Received-SPF"):
        results["spf"] = str(message.get("Received-SPF")).split()[0].lower()
    return results


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href.strip(), "text": " ".join("".join(self._text).split())[:200]})
            self._href = None


def _host(url: str) -> str:
    match = re.match(r"https?://([^/:?#]+)", url.strip(), re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _body(message: EmailMessage) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    texts: list[str] = []
    links: list[dict[str, Any]] = []
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and content_type not in ("text/plain", "text/html")):
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "name": str(filename or "(sem nome)")[:200],
                "content_type": content_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("latin-1", "replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/html":
            parser = _Links()
            try:
                parser.feed(content)
            except (AssertionError, ValueError):
                pass
            for link in parser.links:
                shown = link["text"]
                href_host = _host(link["href"])
                shown_host = _host(shown if shown.lower().startswith("http") else f"http://{shown}") if re.search(r"[\w-]+\.[a-z]{2,}", shown, re.IGNORECASE) else ""
                links.append({
                    "url": link["href"][:1000],
                    "text": shown,
                    "host": href_host,
                    "disguised": bool(shown_host and href_host and shown_host != href_host and not href_host.endswith("." + shown_host)),
                })
            texts.append(html_text(content))
        else:
            texts.append(content)
            for url in _URL.findall(content):
                links.append({"url": url[:1000], "text": "", "host": _host(url), "disguised": False})
    unique: dict[str, dict[str, Any]] = {}
    for link in links:
        if link["url"].lower().startswith(("http://", "https://")):
            current = unique.setdefault(link["url"], link)
            current["disguised"] = current["disguised"] or link["disguised"]
    return "\n\n".join(text.strip() for text in texts if text.strip()), list(unique.values())[:MAX_LINKS], attachments


def _organisational(domain: str) -> str:
    """Last two labels (three for common second-level ccTLDs) for relaxed alignment."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _aligned(one: str, two: str) -> bool:
    return bool(one and two) and _organisational(one) == _organisational(two)


def analyse(raw: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    sender_name, sender = parseaddr(str(message.get("From") or ""))
    from_domain = _domain(sender)
    return_path = parseaddr(str(message.get("Return-Path") or ""))[1]
    reply_to = parseaddr(str(message.get("Reply-To") or ""))[1]
    message_id = str(message.get("Message-ID") or "").strip()
    dkim_domains = sorted({match.lower() for value in message.get_all("DKIM-Signature") or [] for match in re.findall(r"\bd=([\w.-]+)", str(value))})
    hops = _hops(message)
    origin = next((hop for hop in hops if hop["ip"] and _public(hop["ip"])), None)
    auth = _auth(message)
    body, links, attachments = _body(message)

    flags: list[dict[str, str]] = []

    def flag(level: str, code: str, text: str) -> None:
        flags.append({"level": level, "code": code, "message": text})

    for method in ("spf", "dkim", "dmarc"):
        if auth.get(method) in ("fail", "softfail", "permerror", "none") or (method == "dmarc" and auth.get(method) == "quarantine"):
            flag("warning", f"{method}-{auth[method]}", f"{method.upper()} result recorded by the receiving server: {auth[method]}.")
    if return_path and from_domain and _domain(return_path) != from_domain:
        flag("note", "return-path-mismatch", f"Return-Path domain ({_domain(return_path)}) differs from the From domain ({from_domain}).")
    if reply_to and from_domain and _domain(reply_to) != from_domain:
        flag("warning", "reply-to-mismatch", f"Replies go to another domain ({_domain(reply_to)}) than the sender's ({from_domain}).")
    if dkim_domains and from_domain and not any(from_domain == item or from_domain.endswith("." + item) for item in dkim_domains):
        flag("note", "dkim-domain-mismatch", f"The DKIM signature is from {', '.join(dkim_domains)}, not from {from_domain}.")
    shown_address = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", sender_name or "")
    if shown_address and shown_address.group(0).lower() != sender.lower():
        flag("warning", "display-name-spoof", f"The display name shows {shown_address.group(0)} but the message comes from {sender}.")
    message_domain = message_id.rsplit("@", 1)[1].strip("> ").lower() if "@" in message_id else ""
    if message_domain and from_domain and not (message_domain == from_domain or message_domain.endswith("." + from_domain) or from_domain.endswith("." + message_domain)):
        flag("note", "message-id-domain", f"Message-ID was generated by {message_domain}.")
    mailfrom = re.search(r"smtp\.mailfrom=(?:[^@;\s]*@)?([^;\s]+)", " ".join(str(value) for value in message.get_all("Authentication-Results") or []), re.IGNORECASE)
    smtp_mailfrom = mailfrom.group(1).lower() if mailfrom else ""
    spf_domain = smtp_mailfrom or _domain(return_path)
    if from_domain and (spf_domain or dkim_domains) and not _aligned(spf_domain, from_domain) and not any(_aligned(item, from_domain) for item in dkim_domains):
        flag("warning", "unaligned", "Neither the SPF domain nor any DKIM domain matches the From domain, so DMARC cannot pass.")
    if any((hop.get("delay_seconds") or 0) < -300 for hop in hops):
        flag("warning", "time-travel", "A later hop is stamped more than 5 minutes before an earlier one; clocks are wrong or a header was forged.")
    disguised = [link for link in links if link["disguised"]]
    if disguised:
        flag("warning", "disguised-links", f"{len(disguised)} link(s) show one address and lead to another.")
    risky = [item for item in attachments if re.search(r"\.(exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|lnk|iso|img|docm|xlsm|pptm|jar|msi|html?)$", item["name"], re.IGNORECASE)]
    if risky:
        flag("warning", "risky-attachment", f"Attachment type often used to deliver malware: {', '.join(item['name'] for item in risky[:5])}.")

    return {
        "subject": str(message.get("Subject") or "")[:500],
        "date": str(message.get("Date") or "")[:100],
        "from": {"name": sender_name[:200], "address": sender[:320], "domain": from_domain},
        "to_count": len(getaddresses([str(value) for value in message.get_all("To") or []])),
        "return_path": return_path[:320],
        "reply_to": reply_to[:320],
        "message_id": message_id[:400],
        "mailer": str(message.get("X-Mailer") or message.get("User-Agent") or "")[:200],
        "authentication": auth,
        "smtp_mailfrom": smtp_mailfrom,
        "dkim_domains": dkim_domains,
        "hops": hops,
        "origin_ip": origin["ip"] if origin else "",
        "links": links,
        "attachments": attachments,
        "body": body[:200_000],
        "flags": flags,
        "risk": "high" if sum(item["level"] == "warning" for item in flags) >= 2 else "medium" if any(item["level"] == "warning" for item in flags) else "low",
    }
