"""Organisation and community connectors (expansion step 3).

* **GitHub**: public metadata of an organisation or a repository named by a
  github.com URL: the organisation's site and repositories, or a
  repository's description, language, dates, homepage and licence. Personal
  accounts are not collected: for a user URL the connector only says so.
* **security.txt**: the RFC 9116 file an organisation publishes at
  ``/.well-known/security.txt`` for exactly this purpose: security contacts,
  policy, encryption key, expiry and whether it is signed. It is fetched from
  the artifact's own server, so it is a target-contact connector.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from .. import net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError

FETCH: Callable[..., FetchResult] = net.fetch
GITHUB_API = "https://api.github.com"
_GITHUB_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
# Paths on github.com that are not accounts.
_RESERVED = frozenset(
    "about apps blog collections contact customer-stories enterprise events explore features issues "
    "login marketplace new notifications orgs pricing pulls search security settings site sponsors "
    "topics trending users".split()
)
MAX_REPOSITORIES = 30
MAX_SECURITY_TXT = 64 * 1024


def _text(value: Any, limit: int = 300) -> str:
    return str(value)[:limit] if value not in (None, "") else ""


def github_target(url: str) -> tuple[str, str] | None:
    """(owner, repository or '') from a github.com URL, or None."""
    parts = urlsplit(url)
    if (parts.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return None
    segments = [segment for segment in parts.path.split("/") if segment]
    if not segments or segments[0].lower() in _RESERVED or not _GITHUB_NAME.fullmatch(segments[0]):
        return None
    repository = segments[1] if len(segments) > 1 else ""
    if repository.endswith(".git"):
        repository = repository[:-4]
    if repository and not _REPO_NAME.fullmatch(repository):
        return None
    return segments[0], repository


def _github(path: str) -> tuple[Any, FetchResult]:
    result = FETCH(
        f"{GITHUB_API}{path}",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        allowed_hosts=("api.github.com",),
        max_bytes=2 * 1024 * 1024,
        timeout=20.0,
        keep_all_headers=True,
    )
    if result.status == 404:
        return None, result
    if result.status in (403, 429) and (
        result.headers.get("x-ratelimit-remaining") == "0" or result.status == 429
    ):
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        return json.loads(result.body.decode("utf-8")), result
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


def _website(value: Any) -> str:
    text = _text(value, 500).strip()
    if not text:
        return ""
    if not re.match(r"https?://", text, re.IGNORECASE):
        text = f"https://{text}"
    parts = urlsplit(text)
    return text if parts.hostname and "." in parts.hostname else ""


def _repository_finding(repo: dict[str, Any], source: str, digest: str) -> list[Finding]:
    findings = [
        Finding(
            "repository",
            _text(repo.get("html_url"), 300),
            {
                "full_name": _text(repo.get("full_name"), 200),
                "description": _text(repo.get("description"), 300),
                "language": _text(repo.get("language"), 40),
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "created_at": _text(repo.get("created_at"), 30),
                "pushed_at": _text(repo.get("pushed_at"), 30),
                "archived": bool(repo.get("archived")),
                "fork": bool(repo.get("fork")),
                "license": _text((repo.get("license") or {}).get("spdx_id"), 40),
                "topics": [_text(topic, 50) for topic in (repo.get("topics") or [])[:10]],
            },
            source,
            digest,
        )
    ]
    homepage = _website(repo.get("homepage"))
    if homepage:
        findings.append(Finding("repo-homepage", homepage, {"repository": _text(repo.get("full_name"), 200)}, source, digest))
    return findings


def _github_connector(context: ConnectorContext) -> list[Finding]:
    target = github_target(context.query_value)
    if target is None:
        return []
    owner, repository = target
    if repository:
        repo, result = _github(f"/repos/{owner}/{repository}")
        if repo is None:
            return [Finding("notice", "repository not found", {"meaning": "missing, private or renamed"}, result.final_url)]
        findings = _repository_finding(repo, result.final_url, result.sha256)
        parent = repo.get("parent") or {}
        if parent.get("html_url"):
            findings.append(Finding("fork-of", _text(parent["html_url"], 300), {}, result.final_url, result.sha256))
        findings.append(
            Finding("owner-type", _text((repo.get("owner") or {}).get("type"), 20), {"owner": owner}, result.final_url, result.sha256)
        )
        return findings
    account, result = _github(f"/users/{owner}")
    if account is None:
        return [Finding("notice", "account not found", {}, result.final_url)]
    if account.get("type") != "Organization":
        # People are out of scope: no profile fields, no repositories.
        return [Finding("notice", "personal account; not collected", {"meaning": "GitHub data about people is not collected"}, result.final_url)]
    org, result = _github(f"/orgs/{owner}")
    org = org or account
    source, digest = result.final_url, result.sha256
    findings = [
        Finding(
            "github-org",
            _text(org.get("login"), 100),
            {
                "name": _text(org.get("name"), 200),
                "description": _text(org.get("description"), 300),
                "location": _text(org.get("location"), 120),
                "public_repos": org.get("public_repos"),
                "created_at": _text(org.get("created_at"), 30),
                "verified": bool(org.get("is_verified")),
                "email": _text(org.get("email"), 200),
            },
            source,
            digest,
        )
    ]
    website = _website(org.get("blog"))
    if website:
        findings.append(Finding("website", website, {"organization": _text(org.get("login"), 100)}, source, digest))
    repos, result = _github(f"/orgs/{owner}/repos?sort=pushed&per_page={MAX_REPOSITORIES}&type=public")
    for repo in (repos or [])[:MAX_REPOSITORIES]:
        if isinstance(repo, dict):
            findings.extend(_repository_finding(repo, result.final_url, result.sha256))
    return findings


# ---------------------------------------------------------------------------
# security.txt (RFC 9116)

_FIELDS = {
    "contact": "contact",
    "expires": "expires",
    "encryption": "encryption",
    "acknowledgments": "acknowledgments",
    "acknowledgements": "acknowledgments",
    "policy": "policy",
    "hiring": "hiring",
    "preferred-languages": "preferred-languages",
    "canonical": "canonical",
    "csaf": "csaf",
}


def parse_security_txt(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    signed = "-----BEGIN PGP SIGNED MESSAGE-----" in text
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-----") or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = _FIELDS.get(name.strip().lower())
        if key:
            fields.setdefault(key, []).append(value.strip()[:500])
    expires = (fields.get("expires") or [""])[0]
    expired = None
    if expires:
        try:
            moment = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            expired = moment < datetime.now(timezone.utc)
        except ValueError:
            expired = None
    return {"fields": fields, "signed": signed, "expires": expires, "expired": expired}


def _host(context: ConnectorContext) -> str:
    if context.query_type == "domain":
        return context.query_value
    if context.query_type == "url":
        return (urlsplit(context.query_value).hostname or "").rstrip(".")
    return ""


def _security_txt_connector(context: ConnectorContext) -> list[Finding]:
    host = _host(context)
    if not host:
        return []
    page = FETCH(f"https://{host}/.well-known/security.txt", max_bytes=MAX_SECURITY_TXT, timeout=15.0)
    source, digest = page.final_url, page.sha256
    content_type = page.headers.get("content-type", "")
    text = page.body.decode("utf-8", "replace")
    if page.status != 200 or "text/plain" not in content_type or not re.search(r"(?im)^contact:", text):
        return [Finding("security-txt", "not published", {"status": page.status, "content_type": content_type[:80]}, source, digest)]
    parsed = parse_security_txt(text)
    fields = parsed["fields"]
    findings = [
        Finding(
            "security-txt",
            "published",
            {
                "expires": parsed["expires"],
                "expired": parsed["expired"],
                "signed": parsed["signed"],
                "canonical": fields.get("canonical", []),
                "preferred_languages": ", ".join(fields.get("preferred-languages", [])),
                "missing_expires": not parsed["expires"],
            },
            source,
            digest,
        )
    ]
    for contact in fields.get("contact", [])[:10]:
        if contact.lower().startswith("mailto:"):
            findings.append(Finding("security-contact-email", contact[7:].split("?")[0], {}, source, digest))
        elif contact.lower().startswith(("https://", "http://")):
            findings.append(Finding("security-contact-url", contact, {}, source, digest))
        else:
            findings.append(Finding("security-contact", contact, {}, source, digest))
    for key, result_type in (("policy", "security-policy"), ("encryption", "security-encryption"), ("acknowledgments", "security-acknowledgments"), ("hiring", "security-hiring"), ("csaf", "security-csaf")):
        for value in fields.get(key, [])[:5]:
            findings.append(Finding(result_type, value, {}, source, digest))
    return findings


for _connector in (
    Connector(
        "github",
        "GitHub",
        "Public metadata of a GitHub organisation (site, repositories) or repository named by a github.com URL. Personal accounts are not collected.",
        ("url",),
        _github_connector,
        network=True,
        rate_per_minute=10,
        ttl_seconds=6 * 3600,
        source_url="https://github.com/",
    ),
    Connector(
        "security-txt",
        "security.txt",
        "The organisation's RFC 9116 security.txt: security contacts, policy, encryption key, expiry and signature. One HTTPS GET to the artifact's server.",
        ("domain", "url"),
        _security_txt_connector,
        network=True,
        contacts_target=True,
        rate_per_minute=20,
        ttl_seconds=24 * 3600,
    ),
):
    register_connector(_connector)
