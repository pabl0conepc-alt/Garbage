"""News, encyclopaedia, research and feed connectors (catalogue block 8).

A ``topic:<terms>`` query searches GDELT (worldwide news, last three
months), Hacker News, Wikipedia and Wikidata, Crossref and OpenAlex (papers).
The ``rss-feed`` connector reads an RSS or Atom feed given as a URL; it
contacts the feed's server, so it needs target contact allowed. Results are
titles, dates, links and short descriptions; nothing is followed further.
"""

from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ElementTree
from typing import Any
from urllib.parse import quote, urlencode

from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import NetworkError
from . import intel_open_connectors as shared

_text = shared._text
_list = shared._list
_TAGS = re.compile(r"<[^>]+>")
MAX_ITEMS = 25


def _plain(value: Any, limit: int = 300) -> str:
    return _text(" ".join(html.unescape(_TAGS.sub(" ", str(value or ""))).split()), limit)


def _gdelt(context: ConnectorContext) -> list[Finding]:
    # Space-separated terms are ANDed by GDELT; quotes in the input keep phrases.
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode(
        {"query": context.query_value, "mode": "ArtList", "format": "json", "maxrecords": MAX_ITEMS, "sort": "DateDesc", "timespan": "3months"}
    )
    try:
        data, result = shared.request_json(url, hosts=("api.gdeltproject.org",))
    except NetworkError as exc:
        if "429" in str(exc):
            raise NetworkError("GDELT allows one request every 5 seconds; try again shortly") from exc
        raise
    articles = _list((data or {}).get("articles"), MAX_ITEMS) if isinstance(data, dict) else []
    return [
        Finding(
            "news-article",
            _plain(item.get("title"), 300),
            {"url": _text(item.get("url"), 1000), "domain": _text(item.get("domain"), 253), "seen": _text(item.get("seendate"), 20),
             "language": _text(item.get("language"), 30), "country": _text(item.get("sourcecountry"), 60)},
            result.final_url,
            result.sha256,
        )
        for item in articles
        if isinstance(item, dict) and item.get("title")
    ]


def _hackernews(context: ConnectorContext) -> list[Finding]:
    url = "https://hn.algolia.com/api/v1/search?" + urlencode({"query": context.query_value, "tags": "story", "hitsPerPage": MAX_ITEMS})
    data, result = shared.request_json(url, hosts=("hn.algolia.com",))
    hits = _list((data or {}).get("hits"), MAX_ITEMS) if isinstance(data, dict) else []
    return [
        Finding(
            "discussion",
            _plain(item.get("title"), 300),
            {"url": _text(item.get("url"), 1000), "thread": f"https://news.ycombinator.com/item?id={item.get('objectID')}",
             "points": item.get("points"), "comments": item.get("num_comments"), "created": _text(item.get("created_at"), 30)},
            result.final_url,
            result.sha256,
        )
        for item in hits
        if isinstance(item, dict) and item.get("title")
    ]


def _wikipedia(context: ConnectorContext) -> list[Finding]:
    hosts = ("en.wikipedia.org", "pt.wikipedia.org", "www.wikidata.org")
    findings: list[Finding] = []
    for language in ("pt", "en"):
        url = f"https://{language}.wikipedia.org/w/api.php?" + urlencode(
            {"action": "query", "list": "search", "srsearch": context.query_value, "format": "json", "srlimit": 5}
        )
        data, result = shared.request_json(url, hosts=hosts)
        for item in _list(((data or {}).get("query") or {}).get("search"), 5) if isinstance(data, dict) else []:
            title = _text(item.get("title"), 300)
            findings.append(
                Finding("encyclopedia-article", title,
                        {"language": language, "snippet": _plain(item.get("snippet"), 300),
                         "url": f"https://{language}.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"},
                        result.final_url, result.sha256)
            )
    url = "https://www.wikidata.org/w/api.php?" + urlencode(
        {"action": "wbsearchentities", "search": context.query_value, "language": "pt", "uselang": "pt", "format": "json", "limit": 5}
    )
    data, result = shared.request_json(url, hosts=hosts)
    for item in _list((data or {}).get("search"), 5) if isinstance(data, dict) else []:
        findings.append(
            Finding("wikidata-entity", f"{_text(item.get('label'), 200)} ({item.get('id')})",
                    {"description": _text(item.get("description"), 300), "url": f"https://www.wikidata.org/wiki/{item.get('id')}"},
                    result.final_url, result.sha256)
        )
    return findings


def _crossref(context: ConnectorContext) -> list[Finding]:
    url = "https://api.crossref.org/works?" + urlencode(
        {"query": context.query_value, "rows": 15, "select": "DOI,title,author,issued,container-title,type,URL", "mailto": "garbage-intel@users.noreply.github.com"}
    )
    data, result = shared.request_json(url, hosts=("api.crossref.org",))
    items = _list(((data or {}).get("message") or {}).get("items"), 15) if isinstance(data, dict) else []
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        authors = [f"{author.get('given', '')} {author.get('family', '')}".strip() for author in _list(item.get("author"), 5) if isinstance(author, dict)]
        year = ((item.get("issued") or {}).get("date-parts") or [[None]])[0][0]
        findings.append(
            Finding("publication", _plain((_list(item.get("title"), 1) or [""])[0], 300),
                    {"doi": _text(item.get("DOI"), 200), "year": year, "authors": ", ".join(authors),
                     "venue": _text((_list(item.get("container-title"), 1) or [""])[0], 200), "kind": _text(item.get("type"), 40),
                     "url": _text(item.get("URL"), 500)},
                    result.final_url, result.sha256)
        )
    return findings


def _openalex(context: ConnectorContext) -> list[Finding]:
    params = {"search": context.query_value, "per-page": 15, "select": "id,display_name,publication_year,doi,cited_by_count,authorships,primary_location"}
    if context.api_key:
        params["api_key"] = context.api_key
    url = "https://api.openalex.org/works?" + urlencode(params)
    data, result = shared.request_json(url, hosts=("api.openalex.org",))
    source_url = result.final_url.replace(f"api_key={context.api_key}", "api_key=***") if context.api_key else result.final_url
    findings = []
    for item in _list((data or {}).get("results"), 15) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        authors = [_text(((entry.get("author") or {}).get("display_name")), 80) for entry in _list(item.get("authorships"), 5) if isinstance(entry, dict)]
        venue = (((item.get("primary_location") or {}).get("source")) or {}).get("display_name")
        findings.append(
            Finding("publication", _plain(item.get("display_name"), 300),
                    {"year": item.get("publication_year"), "doi": _text(item.get("doi"), 200), "cited_by": item.get("cited_by_count"),
                     "authors": ", ".join(authors), "venue": _text(venue, 200), "url": _text(item.get("id"), 200)},
                    source_url, result.sha256)
        )
    return findings


_ATOM = "{http://www.w3.org/2005/Atom}"


def parse_feed(body: bytes) -> tuple[str, list[dict[str, str]]]:
    """Title and items of an RSS 2.0, RSS 1.0 or Atom feed; raises ValueError otherwise."""
    if b"<!DOCTYPE" in body[:1000].upper() or b"<!ENTITY" in body[:4000].upper():
        raise ValueError("feeds with a DTD are not parsed")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise ValueError("not well-formed XML") from exc
    items = []
    if root.tag == f"{_ATOM}feed":
        title = root.findtext(f"{_ATOM}title", "")
        for entry in root.findall(f"{_ATOM}entry")[:MAX_ITEMS]:
            link = entry.find(f"{_ATOM}link[@rel='alternate']")
            if link is None:
                link = entry.find(f"{_ATOM}link")
            items.append({"title": entry.findtext(f"{_ATOM}title", ""), "url": link.get("href", "") if link is not None else "",
                          "date": entry.findtext(f"{_ATOM}updated", "") or entry.findtext(f"{_ATOM}published", ""),
                          "summary": entry.findtext(f"{_ATOM}summary", "")})
        return title, items
    channel = root.find("channel")
    if root.tag in ("rss", "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF"):
        title = channel.findtext("title", "") if channel is not None else ""
        nodes = (channel.findall("item") if channel is not None else []) or root.findall("{http://purl.org/rss/1.0/}item")
        for node in nodes[:MAX_ITEMS]:
            def get(tag: str) -> str:
                return node.findtext(tag) or node.findtext(f"{{http://purl.org/rss/1.0/}}{tag}") or ""
            items.append({"title": get("title"), "url": get("link"), "date": get("pubDate") or node.findtext("{http://purl.org/dc/elements/1.1/}date", ""),
                          "summary": get("description")})
        return title or root.findtext("{http://purl.org/rss/1.0/}channel/{http://purl.org/rss/1.0/}title", ""), items
    raise ValueError("not an RSS or Atom feed")


def _feed_connector(context: ConnectorContext) -> list[Finding]:
    url = context.query_value
    if not url.startswith("https://"):
        return []
    result = shared.FETCH(url, max_bytes=2 * 1024 * 1024, timeout=15.0)
    content_type = result.headers.get("content-type", "").lower()
    if result.status >= 400 or not any(kind in content_type for kind in ("xml", "rss", "atom")) and not result.body.lstrip()[:5] in (b"<?xml", b"<rss ", b"<feed"):
        return []
    try:
        title, items = parse_feed(result.body)
    except ValueError:
        return []
    source = (result.final_url, result.sha256)
    findings = [Finding("feed", _plain(title, 200) or url, {"items": len(items)}, *source)]
    findings += [
        Finding("feed-item", _plain(item["title"], 300), {"url": _text(item["url"], 1000), "date": _text(item["date"], 60), "summary": _plain(item["summary"], 300)}, *source)
        for item in items
        if item["title"]
    ]
    return findings


CONNECTORS = (
    Connector("gdelt-news", "GDELT news", "Worldwide news articles from the last three months that mention the terms, newest first, with source domain, language and country.",
              ("topic",), _gdelt, network=True, rate_per_minute=6, ttl_seconds=1800, source_url="https://api.gdeltproject.org/"),
    Connector("hackernews", "Hacker News", "Hacker News stories matching the terms, with points, comments and thread links.",
              ("topic",), _hackernews, network=True, rate_per_minute=30, ttl_seconds=1800, source_url="https://hn.algolia.com/api"),
    Connector("wikipedia", "Wikipedia and Wikidata", "Matching Wikipedia articles (Portuguese and English) and Wikidata entities with descriptions.",
              ("topic",), _wikipedia, network=True, rate_per_minute=30, ttl_seconds=86400, source_url="https://www.wikipedia.org/"),
    Connector("crossref", "Crossref", "Scholarly works matching the terms: title, DOI, year, authors and venue.",
              ("topic",), _crossref, network=True, rate_per_minute=30, ttl_seconds=86400, source_url="https://api.crossref.org/"),
    Connector("openalex", "OpenAlex", "Research works matching the terms with year, DOI, citations, authors and venue. An optional key raises the shared daily budget.",
              ("topic",), _openalex, network=True, key_id="openalex", rate_per_minute=20, ttl_seconds=86400, source_url="https://openalex.org/"),
    Connector("rss-feed", "RSS/Atom feed", "Reads a feed given as an https URL: feed title and its latest items with links, dates and summaries. Contacts the feed's server.",
              ("url",), _feed_connector, network=True, contacts_target=True, rate_per_minute=20, ttl_seconds=900),
)

for _connector in CONNECTORS:
    register_connector(_connector)
