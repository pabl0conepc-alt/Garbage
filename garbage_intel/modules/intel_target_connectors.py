"""Connectors that contact the artifact's own servers (plan phase 4).

They are network connectors *and* target-contact connectors: they run only
when both ``intel.allow_network`` and ``intel.allow_target_contact`` are on.
Each performs the minimum an ordinary visitor would: one TLS handshake, or
one HTTPS GET of a page plus its favicon. No paths are guessed, no ports are
scanned and no form or script is executed.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError, NetworkPolicyError, TlsPeer
from .web_fingerprint import (
    analyse_cookies,
    analyse_headers,
    detect_technologies,
    favicon_hash,
    page_metadata,
)
from .x509 import CertificateError, hostname_matches, parse_certificate

FETCH: Callable[..., FetchResult] = net.fetch
TLS_PEER: Callable[..., TlsPeer] = net.tls_peer_certificate
MAX_PAGE_BYTES = 1024 * 1024
MAX_FAVICON_BYTES = 256 * 1024


def _host(context: ConnectorContext) -> str:
    if context.query_type in {"domain", "ipv4", "ipv6"}:
        return context.query_value
    if context.query_type == "url":
        return (urlsplit(context.query_value).hostname or "").rstrip(".")
    return ""


def _start_url(context: ConnectorContext) -> str:
    if context.query_type == "url":
        parts = urlsplit(context.query_value)
        # Only HTTPS is fetched; an http:// artifact is upgraded, not downgraded.
        return parts._replace(scheme="https", fragment="").geturl()
    host = _host(context)
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            host = f"[{host}]"
    except ValueError:
        pass
    return f"https://{host}/"


# ---------------------------------------------------------------------------
# TLS certificate


def _certificate_connector(context: ConnectorContext) -> list[Finding]:
    host = _host(context)
    if not host:
        return []
    peer = TLS_PEER(host)
    try:
        cert = parse_certificate(peer.der)
    except CertificateError as exc:
        raise NetworkError(f"certificate could not be parsed: {exc}") from exc
    source = f"tls://{peer.host}:443"
    digest = cert["sha256"]
    names = cert["san"]["dns"] or ([cert["subject_cn"]] if cert["subject_cn"] else [])
    findings = [
        Finding(
            "tls-trust",
            "trusted" if peer.verified else "not trusted",
            {
                "error": peer.verification_error,
                "protocol": peer.protocol,
                "cipher": peer.cipher,
                "address": peer.address,
                "hostname_match": hostname_matches(peer.host, names) if names else False,
            },
            source,
            digest,
        ),
        Finding("cert-subject", cert["subject"], {"cn": cert["subject_cn"]}, source, digest),
        Finding(
            "cert-issuer",
            cert["issuer"],
            {"cn": cert["issuer_cn"], "organization": cert["issuer_org"], "self_issued": cert["self_issued"]},
            source,
            digest,
        ),
        Finding(
            "cert-validity",
            f"{cert['not_before']} → {cert['not_after']}",
            {
                "days_remaining": cert["days_remaining"],
                "validity_days": cert["validity_days"],
                "expired": cert["expired"],
                "not_yet_valid": cert["not_yet_valid"],
            },
            source,
            digest,
        ),
        Finding(
            "cert-key",
            f"{cert['public_key']['algorithm']} {cert['public_key']['bits'] or ''}".strip(),
            {"curve": cert["public_key"]["curve"], "signature": cert["signature_algorithm"], "weak_signature": cert["weak_signature"]},
            source,
            digest,
        ),
        Finding("cert-sha256", cert["sha256"], {"sha1": cert["sha1"], "serial": cert["serial"]}, source, digest),
        Finding("cert-spki", cert["spki_sha256"], {"pin": "sha256 of SubjectPublicKeyInfo, base64"}, source, digest),
    ]
    for name in cert["san"]["dns"][:100]:
        findings.append(Finding("cert-san", name, {"wildcard": name.startswith("*.")}, source, digest))
    for address in cert["san"]["ip"][:20]:
        findings.append(Finding("cert-san-ip", address, {}, source, digest))
    extras = {
        "sct_embedded": cert["sct_embedded"],
        "ca": cert["ca"],
        "ocsp": ", ".join(cert["ocsp"][:3]),
        "extended_key_usage": ", ".join(cert["extended_key_usage"]),
    }
    findings.append(Finding("cert-extensions", "extensions", extras, source, digest))
    return findings


# ---------------------------------------------------------------------------
# Web fingerprint


def _web_connector(context: ConnectorContext) -> list[Finding]:
    url = _start_url(context)
    if not url:
        return []
    page = FETCH(url, max_bytes=MAX_PAGE_BYTES, timeout=15.0, keep_all_headers=True)
    source, digest = page.final_url, page.sha256
    findings: list[Finding] = [
        Finding(
            "http-response",
            str(page.status),
            {
                "final_url": page.final_url,
                "redirects": len(page.redirects),
                "content_type": page.headers.get("content-type", ""),
                "bytes": len(page.body),
                "address": page.address,
            },
            source,
            digest,
        )
    ]
    for hop in page.redirects:
        findings.append(Finding("http-redirect", hop, {}, source, digest))

    headers = analyse_headers(page.headers)
    for label, value in headers["present"].items():
        findings.append(Finding("security-header", label, {"value": value}, source, digest))
    for label in headers["missing"]:
        findings.append(Finding("missing-header", label, {}, source, digest))
    for name, value in headers["disclosure"].items():
        findings.append(Finding("disclosure-header", value, {"header": name}, source, digest))
    for cookie in analyse_cookies(page.headers.get("set-cookie", "")):
        findings.append(
            Finding("cookie", cookie["name"], {key: value for key, value in cookie.items() if key != "name"}, source, digest)
        )

    content_type = page.headers.get("content-type", "").lower()
    meta: dict[str, Any] = {"title": "", "meta": {}, "favicon_href": ""}
    if "html" in content_type or not content_type:
        meta = page_metadata(page.body)
        if meta["title"]:
            findings.append(Finding("page-title", meta["title"], {}, source, digest))
        for key, value in meta["meta"].items():
            findings.append(Finding("page-meta", value, {"name": key}, source, digest))
    for technology in detect_technologies(page.headers, page.body):
        findings.append(
            Finding(
                "technology",
                technology["name"],
                {key: value for key, value in technology.items() if key != "name"},
                source,
                digest,
            )
        )

    favicon_url = urljoin(page.final_url, meta["favicon_href"] or "/favicon.ico")
    final_host = urlsplit(page.final_url).hostname
    if urlsplit(favicon_url).scheme == "https" and urlsplit(favicon_url).hostname == final_host:
        try:
            icon = FETCH(favicon_url, max_bytes=MAX_FAVICON_BYTES, timeout=10.0)
        except (NetworkError, NetworkPolicyError):
            icon = None
        if icon is not None and icon.status == 200 and icon.body:
            findings.append(
                Finding(
                    "favicon",
                    str(favicon_hash(icon.body)),
                    {
                        "algorithm": "mmh3 (Shodan http.favicon.hash)",
                        "md5": hashlib.md5(icon.body).hexdigest(),
                        "bytes": len(icon.body),
                        "url": icon.final_url,
                    },
                    icon.final_url,
                    icon.sha256,
                )
            )
    return findings


CONNECTORS = (
    Connector(
        connector_id="tls-certificate",
        name="TLS certificate",
        description="One TLS handshake on port 443: trust result, protocol, subject, issuer, validity, SANs, key, fingerprints and SPKI pin.",
        accepts=("domain", "url", "ipv4", "ipv6"),
        run=_certificate_connector,
        network=True,
        contacts_target=True,
        rate_per_minute=30,
        ttl_seconds=3600,
    ),
    Connector(
        connector_id="web-fingerprint",
        name="Web fingerprint",
        description="One HTTPS GET of the page (and its favicon): status, redirects, security headers, cookie flags, title, generator, technology signatures and favicon hash.",
        accepts=("domain", "url", "ipv4", "ipv6"),
        run=_web_connector,
        network=True,
        contacts_target=True,
        rate_per_minute=20,
        ttl_seconds=3600,
    ),
)

for _connector in CONNECTORS:
    register_connector(_connector)
