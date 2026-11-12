"""Bounded outbound HTTP client for explicit intelligence connectors.

Every request is resolved once, every resolved address must be globally
routable, and the socket is pinned to the validated address so a second DNS
answer cannot redirect the connection (DNS rebinding). Redirects are followed
manually and each hop is validated again. Bodies are read with a hard byte
limit and the whole exchange shares one deadline.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
ALLOWED_PORTS = {"http": 80, "https": 443}
USER_AGENT = "GARBAGE-intel/0.1 (+local analyst workstation)"
_KEPT_HEADERS = (
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "retry-after",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
)
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

Resolver = Callable[[str, int], Iterable[str]]


class NetworkPolicyError(ValueError):
    """The request was refused before any byte left the machine."""


class NetworkError(ValueError):
    """The remote side failed, timed out or exceeded a limit."""


@dataclass(frozen=True)
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    sha256: str
    address: str
    elapsed_ms: int
    redirects: list[str] = field(default_factory=list)

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")


def _system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkError(f"could not resolve host: {host}") from exc
    return [str(info[4][0]) for info in infos]


def is_public_address(value: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_private
        and not address.is_unspecified
    )


def validate_url(
    url: str, *, allowed_hosts: Iterable[str] | None = None, allow_http: bool = False
) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, request_target) or raise NetworkPolicyError."""
    if not isinstance(url, str) or len(url) > 4096:
        raise NetworkPolicyError("url must be a string of at most 4096 characters")
    if any(ord(character) < 33 for character in url):
        raise NetworkPolicyError("url contains whitespace or control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_PORTS or (scheme == "http" and not allow_http):
        raise NetworkPolicyError(f"scheme is not allowed: {scheme or 'none'}")
    if parts.username or parts.password:
        raise NetworkPolicyError("credentials in the url are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise NetworkPolicyError("url has no host")
    try:
        port = parts.port or ALLOWED_PORTS[scheme]
    except ValueError as exc:
        raise NetworkPolicyError("url has an invalid port") from exc
    if port != ALLOWED_PORTS[scheme]:
        raise NetworkPolicyError(f"port is not allowed: {port}")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and not is_public_address(str(literal)):
        raise NetworkPolicyError("destination address is not publicly routable")
    if host in {"localhost"} or host.endswith((".localhost", ".local", ".internal")):
        raise NetworkPolicyError("destination host is local")
    if allowed_hosts is not None:
        allowed = {item.lower() for item in allowed_hosts}
        if host not in allowed:
            raise NetworkPolicyError(f"host is not allowed for this connector: {host}")
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return scheme, host, port, target


def _resolve_public(host: str, port: int, resolver: Resolver) -> str:
    addresses = list(dict.fromkeys(resolver(host, port)))
    if not addresses:
        raise NetworkError(f"could not resolve host: {host}")
    blocked = [address for address in addresses if not is_public_address(address)]
    if blocked:
        # One private answer is enough to refuse: a mixed answer set is the
        # usual shape of a rebinding attempt.
        raise NetworkPolicyError("destination resolves to a non-public address")
    return addresses[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


_CA_BUNDLE_CANDIDATES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
)


def tls_context() -> ssl.SSLContext:
    """Verified TLS context; finds the system CA bundle when the interpreter's
    compiled-in default path does not exist (standalone Python on NixOS)."""
    context = ssl.create_default_context()
    if context.cert_store_stats().get("x509_ca", 0) == 0:
        for candidate in _CA_BUNDLE_CANDIDATES:
            if os.path.isfile(candidate):
                context.load_verify_locations(cafile=candidate)
                break
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=tls_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


ConnectionFactory = Callable[[str, str, str, int, float], http.client.HTTPConnection]


def _default_connection(
    scheme: str, host: str, address: str, port: int, timeout: float
) -> http.client.HTTPConnection:
    if scheme == "https":
        return _PinnedHTTPSConnection(host, address, port, timeout)
    return _PinnedHTTPConnection(host, address, port, timeout)


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    allowed_hosts: Iterable[str] | None = None,
    allow_http: bool = False,
    max_redirects: int = MAX_REDIRECTS,
    resolver: Resolver | None = None,
    connection_factory: ConnectionFactory | None = None,
) -> FetchResult:
    """Perform one bounded request; raise NetworkPolicyError or NetworkError."""
    if method not in {"GET", "HEAD", "POST"}:
        raise NetworkPolicyError(f"method is not allowed: {method}")
    if max_bytes < 1 or max_bytes > 32 * 1024 * 1024:
        raise NetworkPolicyError("max_bytes must be between 1 byte and 32 MiB")
    resolver = resolver or _system_resolver
    connection_factory = connection_factory or _default_connection
    allowed = list(allowed_hosts) if allowed_hosts is not None else None
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    for key, value in (headers or {}).items():
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise NetworkPolicyError("header contains a line break")
        request_headers[key] = value

    started = time.monotonic()
    deadline = started + timeout
    current = url
    redirects: list[str] = []
    while True:
        scheme, host, port, target = validate_url(
            current, allowed_hosts=allowed, allow_http=allow_http
        )
        address = _resolve_public(host, port, resolver)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NetworkError("request exceeded its time budget")
        connection = connection_factory(scheme, host, address, port, remaining)
        try:
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            status = response.status
            kept = {
                name: value
                for name, value in (
                    (key.lower(), val) for key, val in response.getheaders()
                )
                if name in _KEPT_HEADERS or name == "location"
            }
            if status in _REDIRECT_STATUSES and "location" in kept:
                response.read(64 * 1024)
                if len(redirects) >= max_redirects:
                    raise NetworkError("too many redirects")
                next_url = urljoin(current, kept["location"])
                if urlsplit(next_url).scheme.lower() == "http" and scheme == "https":
                    raise NetworkPolicyError("refused redirect from https to http")
                redirects.append(next_url)
                current = next_url
                if status == 303:
                    method, body = "GET", None
                continue
            declared = kept.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise NetworkError(f"response exceeds the {max_bytes}-byte limit")
            payload = response.read(max_bytes + 1) if method != "HEAD" else b""
            if len(payload) > max_bytes:
                raise NetworkError(f"response exceeds the {max_bytes}-byte limit")
        except (socket.timeout, TimeoutError) as exc:
            raise NetworkError("request timed out") from exc
        except ssl.SSLError as exc:
            raise NetworkError(f"TLS verification failed for {host}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise NetworkError(f"connection to {host} failed") from exc
        finally:
            connection.close()
        kept.pop("location", None)
        return FetchResult(
            url=url,
            final_url=current,
            status=status,
            headers=kept,
            body=payload,
            sha256=hashlib.sha256(payload).hexdigest(),
            address=address,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            redirects=redirects,
        )
