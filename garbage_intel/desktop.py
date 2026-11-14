"""GARBAGE in its own window instead of a browser tab.

The interface is the same local server and HTML; only the frame changes.
`garbage app` starts the server on a free loopback port and opens one of:

- **webview**: a native window through pywebview, which uses the system's own
  web engine (WebView2 on Windows, WKWebView on macOS, WebKitGTK or Qt on
  Linux). Optional: `pip install pywebview`.
- **browser**: a Chromium-based browser (Chrome, Chromium, Edge, Brave,
  Vivaldi) in app mode, a window without tabs or address bar, using its own
  profile next to the database so it shares no cookies or history with the
  user's browsing.
- **none**: no window; the address is printed and the default browser opened.

`auto` tries them in that order. Closing the window stops the server.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any

from . import monitoring
from .api import create_server, prepare_runtime

ENGINES = ("auto", "webview", "browser", "none")
TITLE = "GARBAGE"
BROWSER_NAMES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge",
    "microsoft-edge-stable", "msedge", "brave-browser", "brave", "vivaldi",
)
# Keep the app-mode browser quiet: no sync, no background downloads, no
# first-run pages.
BROWSER_FLAGS = (
    "--no-first-run", "--no-default-browser-check", "--disable-sync", "--disable-background-networking",
    "--disable-component-update", "--disable-features=Translate,MediaRouter",
)


class DesktopError(RuntimeError):
    """No window could be opened with the requested engine."""


def _installed_browsers() -> list[Path]:
    """Usual install locations on macOS and Windows, where browsers are not on PATH."""
    if sys.platform == "darwin":
        apps = ("Google Chrome", "Chromium", "Microsoft Edge", "Brave Browser", "Vivaldi")
        return [Path(f"/Applications/{name}.app/Contents/MacOS/{name}") for name in apps]
    if os.name == "nt":
        roots = [os.environ.get(key, "") for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
        relative = (
            "Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe",
            "BraveSoftware/Brave-Browser/Application/brave.exe", "Chromium/Application/chrome.exe",
        )
        return [Path(root) / item for root in roots if root for item in relative]
    return []


def find_browser() -> str | None:
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for candidate in _installed_browsers():
        if candidate.is_file():
            return str(candidate)
    return None


def _webview() -> Any | None:
    try:
        import webview  # type: ignore[import-not-found]
    except ImportError:
        return None
    return webview


def run(database: str | Path, *, engine: str = "auto", port: int = 0, width: int = 1440, height: int = 900) -> str:
    """Serve the workstation and block until its window closes. Returns the
    engine used."""
    if engine not in ENGINES:
        raise ValueError(f"engine must be one of: {', '.join(ENGINES)}")
    webview = _webview() if engine in ("auto", "webview") else None
    browser = find_browser() if engine in ("auto", "browser") and webview is None else None
    if engine == "webview" and webview is None:
        raise DesktopError("pywebview is not installed (pip install pywebview)")
    if engine == "browser" and browser is None:
        raise DesktopError("no Chromium-based browser found (Chrome, Chromium, Edge, Brave or Vivaldi)")

    server = create_server(database, port)
    prepare_runtime(database)
    url = f"http://127.0.0.1:{server.server_port}/"
    thread = threading.Thread(target=server.serve_forever, name="garbage-server", daemon=True)
    thread.start()
    try:
        if webview is not None:
            settings = getattr(webview, "settings", None)
            if isinstance(settings, dict):
                settings["ALLOW_DOWNLOADS"] = True  # report and package exports
            webview.create_window(TITLE, url, width=width, height=height, min_size=(900, 600))
            webview.start()
            return "webview"
        if browser is not None:
            profile = Path(database).resolve().parent / ".garbage-window"
            profile.mkdir(exist_ok=True)
            process = subprocess.Popen(
                [browser, f"--app={url}", f"--user-data-dir={profile}", f"--window-size={width},{height}", *BROWSER_FLAGS]
            )
            process.wait()
            return "browser"
        print(f"GARBAGE local interface: {url}")
        print("No window engine available; opening the default browser. Press Ctrl+C to stop.")
        webbrowser.open(url)
        try:
            thread.join()
        except KeyboardInterrupt:
            pass
        return "none"
    finally:
        monitoring.SCHEDULER.stop()
        server.shutdown()
        server.server_close()
