"""Passive website surface (catalogue block 4).

A target-contact connector: it runs only with both network and target
contact allowed, and requests only what an ordinary visitor or search engine
would: the home page, /robots.txt, the sitemap it names (or /sitemap.xml) and
the web app manifest the page links. From these it reports crawler rules and
the paths they reveal, sitemap size, SEO and Open Graph metadata, canonical
and hreflang, the Content-Security-Policy and its weak points, mixed content,
and a hash of the visible text that watchlists use to notice page changes.
No path is guessed and no form or script is run.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import NetworkError, NetworkPolicyError
from . import intel_target_connectors as target

MAX_PAGE_BYTES = 1024 * 1024
MAX_SIDE_BYTES = 512 * 1024
_TAG = re.compile(r"<(meta|link)\b([^>]*)>", re.IGNORECASE)
_ATTR = re.compile(r"""([a-zA-Z_:-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""")
_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAGS = re.compile(r"<[^>]+>")
_HREF = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)""", re.IGNORECASE)
_INSECURE_SRC = re.compile(r"""\b(?:src|href)\s*=\s*["']http://[^"']+""", re.IGNORECASE)
_SITEMAP_LOC = re.compile(rb"<loc>\s*([^<]{1,2000})\s*</loc>", re.IGNORECASE)
INTERESTING_PATH = re.compile(r"admin|login|wp-|backup|staging|dev|test|api|private|internal|\.git|config|old|tmp", re.IGNORECASE)
_SEO_META = {"description", "keywords", "robots", "author", "generator", "theme-color", "viewport"}


def _attrs(raw: str) -> dict[str, str]:
    return {key.lower(): html.unescape(value.strip("\"'")) for key, value in _ATTR.findall(raw)}


def _get(url: str, max_bytes: int = MAX_SIDE_BYTES) -> Any:
    try:
        return target.FETCH(url, max_bytes=max_bytes, timeout=15.0)
    except (NetworkError, NetworkPolicyError):
        return None


def visible_text_hash(body: bytes) -> tuple[str, int]:
    text = body.decode("utf-8", errors="replace")
    text = _TAGS.sub(" ", _SCRIPT_STYLE.sub(" ", text))
    words = html.unescape(text).split()
    return hashlib.sha256(" ".join(words).encode("utf-8")).hexdigest(), len(words)


def analyse_csp(policy: str) -> list[str]:
    """Weak points a reviewer usually flags in a Content-Security-Policy."""
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    issues = []
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        issues.append("no script-src or default-src: scripts are not restricted")
    else:
        if "'unsafe-inline'" in scripts and not any(token.startswith(("'nonce-", "'sha")) for token in scripts):
            issues.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in scripts:
            issues.append("script-src allows 'unsafe-eval'")
        if "*" in scripts or "https:" in scripts or "http:" in scripts or "data:" in scripts:
            issues.append("script-src allows any host or data: URLs")
    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        issues.append("object-src is not restricted")
    if "base-uri" not in directives:
        issues.append("base-uri is not set")
    if "frame-ancestors" not in directives:
        issues.append("frame-ancestors is not set (clickjacking relies on X-Frame-Options)")
    return issues


def _robots(base: str) -> tuple[list[Finding], list[str]]:
    result = _get(urljoin(base, "/robots.txt"))
    if result is None or result.status != 200 or "html" in result.headers.get("content-type", "").lower():
        return [Finding("robots-txt", "not published", {})], []
    source = (result.final_url, result.sha256)
    text = result.body.decode("utf-8", errors="replace")
    disallow: list[str] = []
    sitemaps: list[str] = []
    agents: set[str] = set()
    for line in text.splitlines():
        key, _, value = line.split("#", 1)[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent" and value:
            agents.add(value[:80])
        elif key == "disallow" and value:
            disallow.append(value[:300])
        elif key == "sitemap" and value:
            sitemaps.append(value[:500])
    findings = [Finding("robots-txt", f"{len(disallow)} disallowed paths", {"user_agents": sorted(agents)[:30], "sitemaps": sitemaps[:10]}, *source)]
    for path in sorted(set(disallow))[:100]:
        findings.append(Finding("robots-disallow", path, {"notable": bool(INTERESTING_PATH.search(path))}, *source))
    return findings, sitemaps


def _sitemap(base: str, declared: list[str]) -> list[Finding]:
    host = urlsplit(base).hostname
    candidates = [url for url in declared if urlsplit(url).hostname == host and url.startswith("https://")]
    url = candidates[0] if candidates else urljoin(base, "/sitemap.xml")
    result = _get(url, max_bytes=4 * 1024 * 1024)
    if result is None or result.status != 200 or b"<loc>" not in result.body.lower():
        return [Finding("sitemap", "not found", {"tried": url})]
    locations = [html.unescape(item.decode("utf-8", errors="replace").strip()) for item in _SITEMAP_LOC.findall(result.body)]
    is_index = b"<sitemapindex" in result.body[:2000].lower()
    paths = sorted({urlsplit(item).path or "/" for item in locations if not is_index})
    sections = sorted({"/" + path.strip("/").split("/")[0] for path in paths if path.strip("/")})
    data = {"kind": "index" if is_index else "urlset", "entries": len(locations), "sections": sections[:50]}
    if is_index:
        data["child_sitemaps"] = locations[:20]
    findings = [Finding("sitemap", f"{len(locations)} {'sitemaps' if is_index else 'URLs'}", data, result.final_url, result.sha256)]
    for path in paths:
        if INTERESTING_PATH.search(path):
            findings.append(Finding("sitemap-notable", path[:300], {}, result.final_url, result.sha256))
            if len(findings) > 30:
                break
    return findings


def _page(page: Any, base: str) -> tuple[list[Finding], str]:
    source = (page.final_url, page.sha256)
    text = page.body[:MAX_PAGE_BYTES].decode("utf-8", errors="replace")
    findings: list[Finding] = []
    manifest = ""
    social: dict[str, str] = {}
    seo: dict[str, str] = {}
    alternates = []
    for tag, raw in _TAG.findall(text):
        attrs = _attrs(raw)
        if tag.lower() == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").lower()
            content = attrs.get("content", "")[:500]
            if key.startswith(("og:", "twitter:", "article:")) and content:
                social.setdefault(key, content)
            elif key in _SEO_META and content:
                seo.setdefault(key, content)
        else:
            rel = attrs.get("rel", "").lower()
            href = attrs.get("href", "")
            if rel == "canonical" and href:
                findings.append(Finding("canonical", urljoin(page.final_url, href)[:500], {"same_url": urljoin(page.final_url, href).rstrip("/") == page.final_url.rstrip("/")}, *source))
            elif rel == "alternate" and attrs.get("hreflang") and href:
                alternates.append({"lang": attrs["hreflang"][:20], "url": urljoin(page.final_url, href)[:500]})
            elif rel == "manifest" and href:
                manifest = urljoin(page.final_url, href)
    for key, value in seo.items():
        findings.append(Finding("seo-meta", value, {"name": key}, *source))
    for key, value in sorted(social.items())[:40]:
        findings.append(Finding("social-meta", value, {"property": key}, *source))
    missing = [name for name in ("description",) if name not in seo] + [name for name in ("og:title", "og:image") if name not in social]
    if missing:
        findings.append(Finding("seo-missing", ", ".join(missing), {"meaning": "previews and search snippets fall back to guesses"}, *source))
    for item in alternates[:40]:
        findings.append(Finding("hreflang", item["lang"], {"url": item["url"]}, *source))

    links = {urljoin(page.final_url, href) for href in _HREF.findall(text) if not href.lower().startswith(("mailto:", "tel:", "javascript:"))}
    host = urlsplit(page.final_url).hostname or ""
    internal = [link for link in links if urlsplit(link).hostname == host]
    external = sorted({urlsplit(link).hostname for link in links if urlsplit(link).hostname and urlsplit(link).hostname != host})
    findings.append(Finding("page-links", f"{len(internal)} internal, {len(external)} external hosts", {"external_hosts": external[:60]}, *source))
    insecure = _INSECURE_SRC.findall(text)
    if insecure and page.final_url.startswith("https://"):
        findings.append(Finding("mixed-content", f"{len(insecure)} http:// references", {"examples": [item[:200] for item in insecure[:5]]}, *source))

    csp = page.headers.get("content-security-policy", "")
    if csp:
        issues = analyse_csp(csp)
        findings.append(Finding("csp", "weak" if issues else "strict", {"policy": csp[:2000], "issues": issues}, *source))
    else:
        findings.append(Finding("csp", "absent", {"issues": ["no Content-Security-Policy header"]}, *source))

    digest, words = visible_text_hash(page.body)
    findings.append(Finding("page-text-hash", digest, {"words": words, "meaning": "changes when the visible text changes; used by watchlists"}, *source))
    return findings, manifest


def _manifest(url: str, base: str) -> list[Finding]:
    if not url or urlsplit(url).hostname != urlsplit(base).hostname or not url.startswith("https://"):
        return []
    result = _get(url)
    if result is None or result.status != 200:
        return []
    try:
        data = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    fields = {key: str(data.get(key))[:200] for key in ("name", "short_name", "start_url", "display", "theme_color", "scope", "id") if data.get(key)}
    return [Finding("web-manifest", fields.get("name") or fields.get("short_name") or "manifest", fields, result.final_url, result.sha256)]


def _surface_connector(context: ConnectorContext) -> list[Finding]:
    url = target._start_url(context)
    if not url:
        return []
    page = target.FETCH(url, max_bytes=MAX_PAGE_BYTES, timeout=15.0, keep_all_headers=True)
    base = f"https://{urlsplit(page.final_url).netloc}/"
    findings, manifest = _page(page, base) if page.status < 400 else ([Finding("http-response", str(page.status), {}, page.final_url)], "")
    robots, sitemaps = _robots(base)
    findings += robots + _sitemap(base, sitemaps) + _manifest(manifest, base)
    return findings


register_connector(
    Connector(
        "web-surface", "Website surface",
        "Home page, robots.txt, sitemap and web manifest: disallowed and notable paths, sitemap sections, SEO and Open Graph tags, canonical, hreflang, Content-Security-Policy weak points, mixed content, outbound hosts and a visible-text hash for change monitoring.",
        ("domain", "url"), _surface_connector, network=True, contacts_target=True, rate_per_minute=10, ttl_seconds=3600,
    )
)
