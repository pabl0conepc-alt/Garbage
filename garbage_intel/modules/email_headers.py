"""Offline analysis of email headers pasted by the operator (catalogue block 1).

Parses the delivery path, the receiver's authentication verdicts and the
identity fields, checks SPF/DKIM/DMARC alignment against the visible From
domain, and lists the signals that usually accompany spoofing or phishing.
Every signal is an observation about the headers, not a verdict about the
sender; nothing is fetched and no link is opened.
"""

from __future__ import annotations

import re
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

from .indicators import extract_indicators

MAX_HEADER_BYTES = 256 * 1024
_RECEIVED_FROM = re.compile(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_IP = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\]?", re.IGNORECASE)
_AUTH = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.IGNORECASE)
_DKIM_DOMAIN = re.compile(r"\bd=([^;\s]+)", re.IGNORECASE)
_DKIM_SELECTOR = re.compile(r"\bs=([^;\s]+)", re.IGNORECASE)
_HEADER_FROM = re.compile(r"header\.from=([^;\s]+)", re.IGNORECASE)
_MAILFROM = re.compile(r"smtp\.mailfrom=(?:[^@;\s]*@)?([^;\s]+)", re.IGNORECASE)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in address else ""


def _organisational(domain: str) -> str:
    """Last two labels (three for common second-level ccTLDs) for relaxed alignment."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _aligned(one: str, two: str) -> bool:
    return bool(one and two) and _organisational(one) == _organisational(two)


def _hops(received: list[str]) -> list[dict[str, Any]]:
    hops = []
    # Received headers are prepended, so the first one listed is the last hop.
    for index, raw in enumerate(reversed(received), start=1):
        text = " ".join(raw.split())
        sender = _RECEIVED_FROM.search(text)
        receiver = _RECEIVED_BY.search(text)
        addresses = [match for match in _IP.findall(sender.group(2) or "") if any(ch.isdigit() for ch in match)] if sender else []
        stamp = text.rsplit(";", 1)[-1].strip() if ";" in text else ""
        try:
            when = parsedate_to_datetime(stamp) if stamp else None
        except (TypeError, ValueError):
            when = None
        hops.append(
            {
                "hop": index,
                "from": sender.group(1) if sender else "",
                "from_ip": addresses[0] if addresses else "",
                "by": receiver.group(1).rstrip(";") if receiver else "",
                "time": when.isoformat() if when else stamp[:60],
                "_dt": when,
            }
        )
    for previous, current in zip(hops, hops[1:]):
        if previous["_dt"] and current["_dt"] and previous["_dt"].tzinfo and current["_dt"].tzinfo:
            current["delay_seconds"] = int((current["_dt"] - previous["_dt"]).total_seconds())
    for hop in hops:
        hop.pop("_dt")
    return hops


def analyze_headers(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("paste the message headers")
    if len(raw.encode("utf-8", errors="replace")) > MAX_HEADER_BYTES:
        raise ValueError("headers are larger than 256 KiB")
    # Stop at the first blank line so a pasted body is not parsed as headers.
    head = re.split(r"\r?\n\r?\n", raw.lstrip(), maxsplit=1)[0]
    message = HeaderParser(policy=policy.compat32).parsestr(head)
    if not message.keys():
        raise ValueError("no headers were recognised")

    def first(name: str) -> str:
        return " ".join(str(message.get(name, "")).split())

    from_name, from_address = parseaddr(first("From"))
    _, return_path = parseaddr(first("Return-Path"))
    _, reply_to = parseaddr(first("Reply-To"))
    from_domain = _domain(from_address)

    verdicts: dict[str, str] = {}
    mailfrom_domain = header_from = ""
    for value in message.get_all("Authentication-Results", []) + message.get_all("ARC-Authentication-Results", []):
        text = " ".join(str(value).split())
        for method, result in _AUTH.findall(text):
            verdicts.setdefault(method.lower(), result.lower())
        mailfrom_domain = mailfrom_domain or (_MAILFROM.search(text).group(1).lower() if _MAILFROM.search(text) else "")
        header_from = header_from or (_HEADER_FROM.search(text).group(1).lower() if _HEADER_FROM.search(text) else "")
    if not mailfrom_domain:
        mailfrom_domain = _domain(return_path)
    received_spf = first("Received-SPF")
    if "spf" not in verdicts and received_spf:
        verdicts["spf"] = received_spf.split()[0].lower()

    dkim = []
    for value in message.get_all("DKIM-Signature", []):
        text = " ".join(str(value).split())
        domain = _DKIM_DOMAIN.search(text)
        selector = _DKIM_SELECTOR.search(text)
        dkim.append({"domain": domain.group(1).lower() if domain else "", "selector": selector.group(1) if selector else ""})

    alignment = {
        "spf": _aligned(mailfrom_domain, from_domain),
        "dkim": any(_aligned(item["domain"], from_domain) for item in dkim),
    }

    signals: list[dict[str, str]] = []

    def signal(level: str, code: str, text: str) -> None:
        signals.append({"level": level, "code": code, "message": text})

    for method in ("spf", "dkim", "dmarc"):
        result = verdicts.get(method)
        if result in ("fail", "softfail", "permerror", "temperror"):
            signal("high" if method == "dmarc" or result == "fail" else "medium", f"{method}-{result}", f"The receiving server recorded {method.upper()}={result}.")
        elif result is None and method != "dkim":
            signal("low", f"{method}-missing", f"No {method.upper()} verdict in the headers.")
    if not dkim:
        signal("low", "no-dkim", "The message carries no DKIM signature.")
    if from_domain and not alignment["spf"] and not alignment["dkim"]:
        signal("high", "unaligned", "Neither the SPF domain nor any DKIM domain matches the From domain, so DMARC cannot pass.")
    if reply_to and _domain(reply_to) and not _aligned(_domain(reply_to), from_domain):
        signal("medium", "reply-to-mismatch", f"Replies go to {_domain(reply_to)}, not to the From domain {from_domain}.")
    if return_path and _domain(return_path) and not _aligned(_domain(return_path), from_domain):
        signal("low", "return-path-mismatch", f"Bounces go to {_domain(return_path)} (common for mailing services, also for spoofing).")
    if from_name and "@" in from_name and _domain(from_name) != from_domain:
        signal("high", "display-name-spoof", f"The display name shows another address ({from_name}).")
    message_id = first("Message-ID")
    message_id_domain = message_id.strip("<>").rsplit("@", 1)[-1].lower() if "@" in message_id else ""
    if message_id_domain and from_domain and not _aligned(message_id_domain, from_domain):
        signal("low", "message-id-domain", f"Message-ID was generated by {message_id_domain}.")

    hops = _hops([str(item) for item in message.get_all("Received", [])])
    if any(hop.get("delay_seconds", 0) < -300 for hop in hops):
        signal("medium", "time-travel", "A later hop is stamped more than 5 minutes before an earlier one; clocks are wrong or a header was forged.")

    indicators = extract_indicators([{"id": "headers", "content": head}])
    return {
        "subject": first("Subject"),
        "date": first("Date"),
        "from": {"name": from_name, "address": from_address, "domain": from_domain},
        "reply_to": reply_to,
        "return_path": return_path,
        "to": [address for _, address in getaddresses(message.get_all("To", []))][:50],
        "message_id": message_id,
        "authentication": {
            "verdicts": verdicts,
            "smtp_mailfrom_domain": mailfrom_domain,
            "header_from": header_from,
            "dkim_signatures": dkim,
            "alignment": alignment,
        },
        "hops": hops,
        "origin_ip": next((hop["from_ip"] for hop in hops if hop["from_ip"]), ""),
        "signals": signals,
        "risk": "high" if any(item["level"] == "high" for item in signals) else "medium" if any(item["level"] == "medium" for item in signals) else "low",
        "indicators": [{"type": item["type"], "value": item["value"]} for item in indicators][:200],
        "limitations": [
            "Headers can be forged before the first trusted hop; only the receiving server's Authentication-Results are reliable.",
            "No network lookups were made; reputation of IPs and domains is not checked.",
        ],
    }
