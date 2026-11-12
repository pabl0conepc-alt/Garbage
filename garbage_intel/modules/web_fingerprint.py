"""Passive analysis of one HTTP response: headers, cookies, page metadata,
technology signatures and the favicon hash.

Everything here works on bytes already fetched; nothing is executed and no
script on the page is run. Technology matches are signatures, not proof: a
header or string can be spoofed or left over.
"""

from __future__ import annotations

import base64
import html
import re
from typing import Any

SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "COOP"),
)
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via")
MAX_BODY_SCAN = 512 * 1024

# (name, category, [("header", name, regex) | ("body", None, regex) | ("cookie", None, regex)])
# Version capture group 1 is optional.
TECH_RULES: tuple[tuple[str, str, tuple[tuple[str, str | None, str], ...]], ...] = (
    ("nginx", "web-server", (("header", "server", r"nginx(?:/([\d.]+))?"),)),
    ("Apache HTTP Server", "web-server", (("header", "server", r"apache(?:/([\d.]+))?"),)),
    ("Microsoft IIS", "web-server", (("header", "server", r"microsoft-iis(?:/([\d.]+))?"),)),
    ("LiteSpeed", "web-server", (("header", "server", r"litespeed"),)),
    ("Caddy", "web-server", (("header", "server", r"caddy"),)),
    ("OpenResty", "web-server", (("header", "server", r"openresty(?:/([\d.]+))?"),)),
    ("Envoy", "proxy", (("header", "server", r"envoy"), ("header", "x-envoy-upstream-service-time", r"."))),
    ("Cloudflare", "cdn", (("header", "cf-ray", r"."), ("header", "server", r"cloudflare"))),
    ("Amazon CloudFront", "cdn", (("header", "x-amz-cf-id", r"."), ("header", "via", r"cloudfront"))),
    ("Fastly", "cdn", (("header", "x-served-by", r"cache-"), ("header", "x-fastly-request-id", r"."))),
    ("Akamai", "cdn", (("header", "x-akamai-transformed", r"."), ("header", "server", r"akamaighost"))),
    ("Vercel", "hosting", (("header", "x-vercel-id", r"."), ("header", "server", r"vercel"))),
    ("Netlify", "hosting", (("header", "x-nf-request-id", r"."), ("header", "server", r"netlify"))),
    ("GitHub", "hosting", (("header", "server", r"^github\.com$"),)),
    ("Amazon S3", "hosting", (("header", "server", r"amazons3"),)),
    ("PHP", "language", (("header", "x-powered-by", r"php(?:/([\d.]+))?"), ("cookie", None, r"PHPSESSID"))),
    ("ASP.NET", "framework", (("header", "x-aspnet-version", r"([\d.]+)"), ("header", "x-powered-by", r"asp\.net"), ("cookie", None, r"ASP\.NET_SessionId"))),
    ("Express", "framework", (("header", "x-powered-by", r"express"),)),
    ("Next.js", "framework", (("header", "x-powered-by", r"next\.js"), ("body", None, r"__NEXT_DATA__|/_next/static/"))),
    ("Nuxt", "framework", (("body", None, r"__NUXT__|/_nuxt/"),)),
    ("Django", "framework", (("cookie", None, r"csrftoken"), ("body", None, r"csrfmiddlewaretoken"))),
    ("Ruby on Rails", "framework", (("cookie", None, r"_session_id"), ("body", None, r'name="csrf-param" content="authenticity_token"'))),
    ("Laravel", "framework", (("cookie", None, r"laravel_session"),)),
    ("Java (servlet)", "language", (("cookie", None, r"JSESSIONID"),)),
    ("WordPress", "cms", (("body", None, r"/wp-content/|/wp-includes/"), ("body", None, r'<meta name="generator" content="WordPress ?([\d.]*)'))),
    ("Drupal", "cms", (("header", "x-generator", r"drupal ?(\d+)?"), ("body", None, r"Drupal\.settings|/sites/default/files/"))),
    ("Joomla", "cms", (("body", None, r'<meta name="generator" content="Joomla'),)),
    ("Ghost", "cms", (("body", None, r'<meta name="generator" content="Ghost ?([\d.]*)'),)),
    ("Shopify", "ecommerce", (("header", "x-shopify-stage", r"."), ("body", None, r"cdn\.shopify\.com"))),
    ("Magento", "ecommerce", (("cookie", None, r"frontend=|mage-"), ("body", None, r"Mage\.Cookies|/static/frontend/"))),
    ("Wix", "site-builder", (("header", "x-wix-request-id", r"."), ("body", None, r"static\.wixstatic\.com"))),
    ("Squarespace", "site-builder", (("body", None, r"static1\.squarespace\.com"),)),
    ("React", "javascript", (("body", None, r"data-reactroot|react(?:\.production)?\.min\.js"),)),
    ("Vue.js", "javascript", (("body", None, r"/vue(?:@[\d.]+)?(?:/dist)?/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),)),
    ("Angular", "javascript", (("body", None, r'ng-version="([\d.]+)"'),)),
    ("jQuery", "javascript", (("body", None, r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"),)),
    ("Bootstrap", "ui", (("body", None, r"bootstrap(?:\.min)?\.(?:css|js)"),)),
    ("Google Analytics", "analytics", (("body", None, r"googletagmanager\.com/gtag/js|google-analytics\.com/(?:ga|analytics)\.js"),)),
    ("Google Tag Manager", "analytics", (("body", None, r"googletagmanager\.com/gtm\.js"),)),
    ("Matomo", "analytics", (("body", None, r"matomo\.js|piwik\.js"),)),
    ("reCAPTCHA", "security", (("body", None, r"google\.com/recaptcha/"),)),
    ("hCaptcha", "security", (("body", None, r"hcaptcha\.com/1/api\.js"),)),
)
_COMPILED = [
    (name, category, [(kind, field, re.compile(pattern, re.IGNORECASE)) for kind, field, pattern in checks])
    for name, category, checks in TECH_RULES
]
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META = re.compile(
    rb"<meta\s+[^>]*?(?:name|property)\s*=\s*[\"']([^\"']+)[\"'][^>]*?content\s*=\s*[\"']([^\"']*)[\"']",
    re.IGNORECASE,
)
_FAVICON_LINK = re.compile(
    rb"<link\s+[^>]*?rel\s*=\s*[\"'][^\"']*icon[^\"']*[\"'][^>]*?href\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned as a signed integer like ``mmh3.hash``."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length - (length % 4)
    for offset in range(0, rounded, 4):
        k1 = int.from_bytes(data[offset : offset + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Shodan-compatible favicon hash: MurmurHash3 of the base64 text with
    76-character line breaks (``base64.encodebytes``)."""
    return murmur3_32(base64.encodebytes(content))


def _text(raw: bytes) -> str:
    return html.unescape(re.sub(r"\s+", " ", raw.decode("utf-8", errors="replace"))).strip()


def page_metadata(body: bytes) -> dict[str, Any]:
    head = body[:MAX_BODY_SCAN]
    title_match = _TITLE.search(head)
    meta: dict[str, str] = {}
    for name, content in _META.findall(head):
        key = name.decode("ascii", errors="replace").lower()
        if key in {"generator", "description", "og:title", "og:site_name", "robots", "application-name"}:
            meta.setdefault(key, _text(content)[:300])
    favicon = _FAVICON_LINK.search(head)
    return {
        "title": _text(title_match.group(1))[:300] if title_match else "",
        "meta": meta,
        "favicon_href": favicon.group(1).decode("ascii", errors="replace") if favicon else "",
    }


def analyse_cookies(set_cookie: str) -> list[dict[str, Any]]:
    cookies = []
    for line in filter(None, (item.strip() for item in set_cookie.split("\n"))):
        parts = [part.strip() for part in line.split(";")]
        name = parts[0].split("=", 1)[0]
        attributes = {part.split("=", 1)[0].lower(): part.split("=", 1)[1] if "=" in part else True for part in parts[1:]}
        cookies.append(
            {
                "name": name[:100],
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": str(attributes.get("samesite", "")),
            }
        )
    return cookies[:50]


def analyse_headers(headers: dict[str, str]) -> dict[str, Any]:
    present = {label: headers[name][:500] for name, label in SECURITY_HEADERS if name in headers}
    missing = [label for name, label in SECURITY_HEADERS if name not in headers]
    hsts = headers.get("strict-transport-security", "")
    max_age = re.search(r"max-age=(\d+)", hsts)
    return {
        "present": present,
        "missing": missing,
        "hsts_max_age": int(max_age.group(1)) if max_age else None,
        "hsts_subdomains": "includesubdomains" in hsts.lower(),
        "disclosure": {name: headers[name][:200] for name in DISCLOSURE_HEADERS if name in headers},
    }


def detect_technologies(headers: dict[str, str], body: bytes) -> list[dict[str, str]]:
    text = body[:MAX_BODY_SCAN].decode("utf-8", errors="replace")
    cookies = headers.get("set-cookie", "")
    found = []
    for name, category, checks in _COMPILED:
        version = ""
        evidence = ""
        for kind, field, pattern in checks:
            haystack = headers.get(field or "", "") if kind == "header" else cookies if kind == "cookie" else text
            match = pattern.search(haystack) if haystack else None
            if match:
                evidence = f"{kind}:{field}" if field else kind
                if match.groups() and match.group(1):
                    version = match.group(1)[:30]
                break
        if evidence:
            found.append({"name": name, "category": category, "version": version, "evidence": evidence})
    return found
