"""Live check of a URL: where it leads, what the page asks for and loads,
and optionally a screenshot.

This contacts the site from this machine (the site sees your IP), so it runs
only when the analyst asks for it, with network sources allowed.

* Every redirect hop is requested one at a time (status, address, server,
  where it points), up to ten; meta refresh and script redirects on the
  final page are read from its HTML.
* The final page is read as text, never executed: title, forms (and where a
  password field posts to), scripts, frames and other hosts it loads,
  obfuscation markers, downloads and technology signatures.
* The screenshot comes from a headless Chromium or Firefox with a throwaway
  profile and a time limit. JavaScript is off unless the analyst turns it on
  for that check.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from .. import net
from ..db import _connection, new_id, record_activity, setting_bool, utc_now
from ..errors import ConflictError, NotFoundError, ValidationError
from ..net import FetchResult, NetworkError, NetworkPolicyError
from . import web_fingerprint

FETCH: Callable[..., FetchResult] = net.fetch
MAX_HOPS = 10
MAX_PAGE_BYTES = 4 * 1024 * 1024
SCREENSHOT_TIMEOUT_SECONDS = 45
THIN_PAGE_BYTES = 15_000
# What a visitor's browser sends: kits often hide from anything else.
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CHROMIUM_NAMES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge", "brave-browser", "brave")
DOWNLOAD_TYPES = re.compile(r"application/(x-msdownload|x-dosexec|octet-stream|zip|x-rar|x-7z|vnd\.android\.package-archive|java-archive|x-msi)|application/x-sh", re.IGNORECASE)
OBFUSCATION = (
    (re.compile(rb"eval\s*\(\s*atob\s*\(", re.IGNORECASE), "eval(atob(...))"),
    (re.compile(rb"document\.write\s*\(\s*unescape\s*\(", re.IGNORECASE), "document.write(unescape(...))"),
    (re.compile(rb"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e", re.IGNORECASE), "packer (p,a,c,k,e)"),
    (re.compile(rb"String\.fromCharCode\s*\((?:\s*\d+\s*,){20,}", re.IGNORECASE), "String.fromCharCode longo"),
    (re.compile(rb"[A-Za-z0-9+/]{2000,}={0,2}"), "bloco base64 grande"),
)
SCRIPT_REDIRECT = re.compile(rb"(?:window\.|document\.|top\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*[\"']([^\"']{4,500})", re.IGNORECASE)


class _Page(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.forms: list[dict[str, Any]] = []
        self.resources: list[dict[str, str]] = []
        self.refresh = ""
        self._form: dict[str, Any] | None = None

    def _url(self, value: str | None) -> str:
        return urljoin(self.base, (value or "").strip()) if value else ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            self._form = {"action": self._url(values.get("action")) or self.base, "method": values.get("method", "get").lower()[:10], "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            self._form["inputs"].append({"type": values.get("type", "text" if tag == "input" else tag).lower()[:20], "name": values.get("name", "")[:80]})
        elif tag == "script" and values.get("src"):
            self.resources.append({"kind": "script", "url": self._url(values["src"])})
        elif tag in ("iframe", "frame") and values.get("src"):
            self.resources.append({"kind": "frame", "url": self._url(values["src"])})
        elif tag == "link" and values.get("href") and any(word in values.get("rel", "") for word in ("stylesheet", "icon")):
            self.resources.append({"kind": "style" if "stylesheet" in values["rel"] else "icon", "url": self._url(values["href"])})
        elif tag == "img" and values.get("src") and not values["src"].startswith("data:"):
            self.resources.append({"kind": "image", "url": self._url(values["src"])})
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            target = re.search(r"url\s*=\s*['\"]?([^'\";]+)", values.get("content", ""), re.IGNORECASE)
            self.refresh = self._url(target.group(1)) if target else ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu", "co") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def redirect_chain(url: str) -> tuple[list[dict[str, Any]], FetchResult | None, str]:
    hops: list[dict[str, Any]] = []
    current = url
    final: FetchResult | None = None
    stopped = ""
    for _ in range(MAX_HOPS):
        try:
            result = FETCH(
                current,
                headers={"User-Agent": BROWSER_UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"},
                allow_http=True,
                follow_redirects=False,
                keep_all_headers=True,
                max_bytes=MAX_PAGE_BYTES,
                timeout=20.0,
            )
        except (NetworkError, NetworkPolicyError) as exc:
            hops.append({"url": current, "status": None, "error": str(exc)[:200]})
            stopped = str(exc)[:200]
            break
        location = result.headers.get("location", "")
        hops.append({
            "url": current,
            "status": result.status,
            "address": result.address,
            "server": result.headers.get("server", "")[:120],
            "content_type": result.headers.get("content-type", "")[:120],
            "location": urljoin(current, location) if location else "",
            "elapsed_ms": result.elapsed_ms,
        })
        if location and 300 <= result.status < 400:
            current = urljoin(current, location)
            continue
        final = result
        break
    else:
        stopped = f"more than {MAX_HOPS} redirects"
    return hops, final, stopped


def analyse_page(result: FetchResult) -> dict[str, Any]:
    body = result.body
    base = result.final_url or result.url
    page_host = _host(base)
    parser = _Page(base)
    is_html = "html" in result.headers.get("content-type", "").lower() or body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
    if is_html:
        try:
            parser.feed(body[: web_fingerprint.MAX_BODY_SCAN].decode("utf-8", "replace"))
        except (AssertionError, ValueError):
            pass
    metadata = web_fingerprint.page_metadata(body) if is_html else {"title": "", "meta": {}, "favicon_href": ""}
    forms = []
    for form in parser.forms[:20]:
        types = [item["type"] for item in form["inputs"]]
        action_host = _host(form["action"])
        forms.append({
            "action": form["action"][:500],
            "method": form["method"],
            "fields": len(types),
            "password": "password" in types,
            "other_site": bool(action_host and _registrable(action_host) != _registrable(page_host)),
            "insecure": form["action"].lower().startswith("http://"),
            "field_names": [item["name"] for item in form["inputs"] if item["name"]][:15],
        })
    hosts: dict[str, dict[str, Any]] = {}
    for resource in parser.resources:
        host = _host(resource["url"])
        if not host or host == page_host:
            continue
        entry = hosts.setdefault(host, {"host": host, "kinds": set(), "count": 0})
        entry["kinds"].add(resource["kind"])
        entry["count"] += 1
    script_redirects = sorted({match.group(1).decode("utf-8", "replace") for match in SCRIPT_REDIRECT.finditer(body[:MAX_PAGE_BYTES])})[:5]
    obfuscation = [label for pattern, label in OBFUSCATION if pattern.search(body[:MAX_PAGE_BYTES])]
    disposition = result.headers.get("content-disposition", "")
    download = bool("attachment" in disposition.lower() or DOWNLOAD_TYPES.search(result.headers.get("content-type", "")))
    return {
        "title": metadata["title"],
        "description": metadata["meta"].get("description", ""),
        "size": len(body),
        "sha256": result.sha256,
        "forms": forms,
        "external_hosts": sorted(({**item, "kinds": sorted(item["kinds"])} for item in hosts.values()), key=lambda item: -item["count"])[:60],
        "frames": [resource["url"][:500] for resource in parser.resources if resource["kind"] == "frame"][:10],
        "meta_refresh": parser.refresh[:500],
        "script_redirects": script_redirects,
        "obfuscation": obfuscation,
        "download": download,
        "download_name": re.search(r'filename="?([^";]+)', disposition).group(1)[:200] if "filename" in disposition else "",
        "technologies": web_fingerprint.detect_technologies(result.headers, body)[:20],
        "headers": web_fingerprint.analyse_headers(result.headers),
    }


def _flags(url: str, hops: list[dict[str, Any]], page: dict[str, Any] | None) -> list[dict[str, str]]:
    flags: list[dict[str, str]] = []
    final = hops[-1]["url"] if hops else url
    if len(hops) > 1 and _registrable(_host(final)) != _registrable(_host(url)):
        flags.append({"level": "medium", "text": f"Leva para outro site: {_host(final)}."})
    if len(hops) > 3:
        flags.append({"level": "info", "text": f"{len(hops) - 1} redirecionamentos até a página final."})
    if not page:
        return flags
    for form in page["forms"]:
        if form["password"]:
            where = "outro site" if form["other_site"] else "o próprio site"
            flags.append({"level": "high", "text": f"Formulário pede senha e envia para {where} ({_host(form['action']) or 'mesma página'})" + (" sem HTTPS." if form["insecure"] else ".")})
    # Ordinary sites set location in scripts too; only a thin page that does
    # it is a redirect page.
    if page["meta_refresh"] or (page["script_redirects"] and page["size"] < THIN_PAGE_BYTES):
        flags.append({"level": "medium", "text": "A página redireciona sozinha (meta refresh ou script)."})
    if page["obfuscation"]:
        flags.append({"level": "medium", "text": f"Código ofuscado na página: {', '.join(page['obfuscation'])}."})
    if page["download"]:
        flags.append({"level": "high", "text": f"A resposta é um download{f' ({page['download_name']})' if page['download_name'] else ''}."})
    if page["frames"]:
        flags.append({"level": "info", "text": f"{len(page['frames'])} quadro(s) embutido(s) (iframe)."})
    return flags


def browser() -> tuple[str, str] | None:
    """(kind, path) of a browser able to take headless screenshots."""
    override = os.environ.get("GARBAGE_SCREENSHOT_BROWSER")
    if override:
        return ("firefox" if "firefox" in os.path.basename(override).lower() else "chromium", override)
    for name in CHROMIUM_NAMES:
        found = shutil.which(name)
        if found:
            return "chromium", found
    found = shutil.which("firefox")
    return ("firefox", found) if found else None


def screenshot(url: str, *, javascript: bool = False) -> tuple[bytes | None, str]:
    """(PNG bytes, note) from a headless browser with a throwaway profile."""
    found = browser()
    if not found:
        return None, "nenhum Chromium ou Firefox instalado para a captura"
    kind, binary = found
    with tempfile.TemporaryDirectory(prefix="garbage-shot-") as folder:
        output = os.path.join(folder, "shot.png")
        if kind == "chromium":
            command = [
                binary, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run", "--disable-extensions",
                "--disable-background-networking", "--disable-sync", "--mute-audio", f"--user-data-dir={folder}/profile",
                "--window-size=1280,900", f"--user-agent={BROWSER_UA}", f"--screenshot={output}",
            ]
            if not javascript:
                command.append("--blink-settings=scriptEnabled=false")
            command.append(url)
        else:
            profile = os.path.join(folder, "profile")
            os.makedirs(profile)
            with open(os.path.join(profile, "user.js"), "w", encoding="utf-8") as prefs:
                prefs.write(f'user_pref("javascript.enabled", {"true" if javascript else "false"});\n')
                prefs.write('user_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
                prefs.write('user_pref("toolkit.telemetry.enabled", false);\nuser_pref("app.update.enabled", false);\n')
                prefs.write(f'user_pref("general.useragent.override", "{BROWSER_UA}");\n')
            command = [binary, "--headless", "--no-remote", "--profile", profile, "--window-size=1280,900", "--screenshot", output, url]
        try:
            subprocess.run(command, capture_output=True, timeout=SCREENSHOT_TIMEOUT_SECONDS, check=False, env={**os.environ, "MOZ_HEADLESS": "1"})
        except subprocess.TimeoutExpired:
            return None, "a captura passou do tempo limite"
        except OSError as exc:
            return None, f"o navegador não abriu: {exc}"[:200]
        if not os.path.exists(output):
            return None, "o navegador não gerou a captura"
        with open(output, "rb") as handle:
            data = handle.read()
    engine = "Chromium" if kind == "chromium" else "Firefox"
    return data, f"{engine} sem interface, {'com' if javascript else 'sem'} JavaScript"


def check(url: str, *, take_screenshot: bool = True, javascript: bool = False) -> tuple[dict[str, Any], bytes | None]:
    hops, final, stopped = redirect_chain(url)
    page = analyse_page(final) if final is not None else None
    image, note = (None, "")
    if take_screenshot:
        image, note = screenshot(hops[-1]["url"] if hops and not hops[-1].get("error") else url, javascript=javascript)
    result = {
        "url": url,
        "final_url": hops[-1]["url"] if hops else url,
        "final_status": final.status if final is not None else None,
        "hops": hops,
        "stopped": stopped,
        "page": page,
        "flags": _flags(url, hops, page),
        "screenshot": {"taken": image is not None, "note": note, "javascript": javascript} if take_screenshot else None,
    }
    return result, image


# ---------------------------------------------------------------------------
# Stored checks


def _target(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("url is required")
    text = value.strip()
    if not re.match(r"https?://", text, re.IGNORECASE):
        text = f"https://{text}"
    try:
        net.validate_url(text, allow_http=True)
    except NetworkPolicyError as exc:
        raise ValidationError(f"this address cannot be checked: {exc}") from exc
    return text


def run(database: str, *, url: object, take_screenshot: object = True, javascript: object = False, investigation_id: object = None) -> dict[str, Any]:
    target = _target(url)
    with _connection(database) as connection:
        if not setting_bool(connection, "intel.allow_network", True):
            raise ConflictError("network sources are off; turn them on to check a site live")
    case_id = investigation_id if isinstance(investigation_id, str) and investigation_id else None
    result, image = check(target, take_screenshot=take_screenshot is not False, javascript=javascript is True)
    check_id = new_id()
    now = utc_now()
    with _connection(database) as connection:
        connection.execute(
            "INSERT INTO live_checks (id, url, final_url, result_json, screenshot, investigation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (check_id, target, result["final_url"], json.dumps(result, ensure_ascii=False), image, case_id, now),
        )
        record_activity(
            connection, action="analysis", target_type="live-check", target_id=check_id, investigation_id=case_id,
            summary=f"Live check of {target}: {len(result['hops'])} hop(s), {len(result['flags'])} flag(s)",
        )
    return {**result, "id": check_id, "created_at": now}


def get(database: str, check_id: str) -> dict[str, Any]:
    with _connection(database) as connection:
        row = connection.execute("SELECT id, result_json, created_at FROM live_checks WHERE id = ?", (check_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"live check not found: {check_id}")
    return {**json.loads(row["result_json"]), "id": row["id"], "created_at": row["created_at"]}


def image(database: str, check_id: str) -> bytes:
    with _connection(database) as connection:
        row = connection.execute("SELECT screenshot FROM live_checks WHERE id = ?", (check_id,)).fetchone()
    if row is None or not row["screenshot"]:
        raise NotFoundError("this check has no screenshot")
    return bytes(row["screenshot"])


def history(database: str, url: object = None, limit: int = 20) -> dict[str, Any]:
    clauses, parameters = "", []
    if isinstance(url, str) and url.strip():
        clauses, parameters = "WHERE url = ? OR final_url = ?", [url.strip(), url.strip()]
    with _connection(database) as connection:
        rows = connection.execute(
            f"SELECT id, url, final_url, created_at, screenshot IS NOT NULL AS has_screenshot FROM live_checks {clauses} ORDER BY created_at DESC LIMIT ?",
            (*parameters, max(1, min(100, int(limit)))),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}
