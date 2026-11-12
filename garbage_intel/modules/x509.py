"""Read-only X.509 certificate parser (DER) with no third-party dependency.

It extracts what an analyst compares across certificates: names, validity,
SANs, key type and size, signature algorithm, fingerprints, the SPKI pin and
the usual extensions. It never validates a chain; trust is decided by the TLS
handshake that retrieved the certificate.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any

MAX_DER_BYTES = 64 * 1024

OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.48.1": "OCSP",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
}
WEAK_SIGNATURES = {"sha1WithRSAEncryption", "md5WithRSAEncryption"}
_KEY_USAGE = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)


class CertificateError(ValueError):
    """The bytes are not a DER certificate this parser understands."""


def _tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Return (tag, content_start, content_end, next_offset)."""
    if offset + 2 > len(data):
        raise CertificateError("truncated DER element")
    tag = data[offset]
    length = data[offset + 1]
    position = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or position + count > len(data):
            raise CertificateError("unsupported DER length")
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    end = position + length
    if end > len(data):
        raise CertificateError("DER element exceeds its container")
    return tag, position, end, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    items = []
    offset = start
    while offset < end:
        tag, content_start, content_end, offset = _tlv(data, offset)
        items.append((tag, content_start, content_end))
        if len(items) > 4096:
            raise CertificateError("too many DER elements")
    return items


def _oid(raw: bytes) -> str:
    if not raw:
        raise CertificateError("empty object identifier")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", errors="replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", errors="replace").rstrip("Z")
    try:
        if tag == 0x17:  # UTCTime, years 1950-2049 per RFC 5280
            moment = datetime.strptime(text[:12], "%y%m%d%H%M%S")
        else:
            moment = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError as exc:
        raise CertificateError("invalid certificate time") from exc
    return moment.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _name(data: bytes, start: int, end: int) -> list[tuple[str, str]]:
    parts = []
    for _, set_start, set_end in _children(data, start, end):
        for _, seq_start, seq_end in _children(data, set_start, set_end):
            items = _children(data, seq_start, seq_end)
            if len(items) < 2:
                continue
            oid = _oid(data[items[0][1] : items[0][2]])
            tag, value_start, value_end = items[1]
            parts.append((OID_NAMES.get(oid, oid), _string(tag, data[value_start:value_end])))
    return parts


def _name_text(parts: list[tuple[str, str]]) -> str:
    return ", ".join(f"{key}={value}" for key, value in parts)


def _general_names(data: bytes, start: int, end: int) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"dns": [], "ip": [], "email": [], "uri": []}
    for tag, value_start, value_end in _children(data, start, end):
        raw = data[value_start:value_end]
        if tag == 0x82:
            result["dns"].append(raw.decode("ascii", errors="replace").lower())
        elif tag == 0x87 and len(raw) in {4, 16}:
            result["ip"].append(str(ipaddress.ip_address(raw)))
        elif tag == 0x81:
            result["email"].append(raw.decode("ascii", errors="replace"))
        elif tag == 0x86:
            result["uri"].append(raw.decode("ascii", errors="replace"))
    return result


def _uris(data: bytes, start: int, end: int, depth: int = 0) -> list[str]:
    found = []
    if depth > 6:
        return found
    for tag, value_start, value_end in _children(data, start, end):
        if tag == 0x86:
            found.append(data[value_start:value_end].decode("ascii", errors="replace"))
        elif tag & 0x20:  # constructed: recurse
            found.extend(_uris(data, value_start, value_end, depth + 1))
    return found


def _public_key(data: bytes, start: int, end: int) -> dict[str, Any]:
    algorithm_seq, key_bits = _children(data, start, end)[:2]
    algorithm_items = _children(data, algorithm_seq[1], algorithm_seq[2])
    algorithm = OID_NAMES.get(_oid(data[algorithm_items[0][1] : algorithm_items[0][2]]), "unknown")
    info: dict[str, Any] = {"algorithm": algorithm, "bits": 0, "curve": ""}
    if algorithm == "EC" and len(algorithm_items) > 1 and algorithm_items[1][0] == 0x06:
        curve = _oid(data[algorithm_items[1][1] : algorithm_items[1][2]])
        info["curve"] = OID_NAMES.get(curve, curve)
        info["bits"] = {"P-256": 256, "P-384": 384, "P-521": 521}.get(info["curve"], 0)
    elif algorithm == "RSA":
        bit_string = data[key_bits[1] + 1 : key_bits[2]]  # skip unused-bits byte
        _, seq_start, seq_end, _ = _tlv(bit_string, 0)
        modulus = _children(bit_string, seq_start, seq_end)[0]
        number = int.from_bytes(bit_string[modulus[1] : modulus[2]], "big")
        info["bits"] = number.bit_length()
    elif algorithm in {"Ed25519", "Ed448"}:
        info["bits"] = 256 if algorithm == "Ed25519" else 456
    return info


def parse_certificate(der: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(der, (bytes, bytearray)) or not der:
        raise CertificateError("certificate must be non-empty DER bytes")
    if len(der) > MAX_DER_BYTES:
        raise CertificateError("certificate exceeds the 64 KiB limit")
    der = bytes(der)
    _, cert_start, cert_end, _ = _tlv(der, 0)
    top = _children(der, cert_start, cert_end)
    if len(top) != 3:
        raise CertificateError("certificate must have three top-level elements")
    tbs = _children(der, top[0][1], top[0][2])
    index = 0
    version = 1
    if tbs and tbs[0][0] == 0xA0:
        inner = _children(der, tbs[0][1], tbs[0][2])
        version = int.from_bytes(der[inner[0][1] : inner[0][2]], "big") + 1
        index = 1
    serial = der[tbs[index][1] : tbs[index][2]].hex()
    issuer = _name(der, tbs[index + 2][1], tbs[index + 2][2])
    validity = _children(der, tbs[index + 3][1], tbs[index + 3][2])
    not_before = _time(validity[0][0], der[validity[0][1] : validity[0][2]])
    not_after = _time(validity[1][0], der[validity[1][1] : validity[1][2]])
    subject = _name(der, tbs[index + 4][1], tbs[index + 4][2])
    _, spki_start, spki_end = tbs[index + 5]
    # The SPKI pin hashes the whole element, header included.
    header_offset = _header_offset(der, spki_start)
    spki_bytes = der[header_offset:spki_end]
    public_key = _public_key(der, spki_start, spki_end)
    signature_items = _children(der, top[1][1], top[1][2])
    signature = OID_NAMES.get(
        _oid(der[signature_items[0][1] : signature_items[0][2]]), "unknown"
    )

    extensions: dict[str, Any] = {
        "san": {"dns": [], "ip": [], "email": [], "uri": []},
        "ca": False,
        "key_usage": [],
        "extended_key_usage": [],
        "ocsp": [],
        "ca_issuers": [],
        "crl": [],
        "sct_embedded": False,
    }
    for tag, start, end in tbs[index + 6 :]:
        if tag != 0xA3:
            continue
        for _, ext_start, ext_end in _children(der, *_children(der, start, end)[0][1:]):
            parts = _children(der, ext_start, ext_end)
            oid = _oid(der[parts[0][1] : parts[0][2]])
            value_tag, value_start, value_end = parts[-1]
            if value_tag != 0x04:
                continue
            _, inner_start, inner_end, _ = _tlv(der, value_start)
            if oid == "2.5.29.17":
                extensions["san"] = _general_names(der, inner_start, inner_end)
            elif oid == "2.5.29.19":
                flags = _children(der, inner_start, inner_end)
                extensions["ca"] = bool(
                    flags and flags[0][0] == 0x01 and der[flags[0][1]] != 0
                )
            elif oid == "2.5.29.15":
                bits = der[value_start:value_end]
                _, bits_start, bits_end, _ = _tlv(bits, 0)
                payload = bits[bits_start + 1 : bits_end]
                number = int.from_bytes(payload or b"\x00", "big")
                width = len(payload) * 8
                extensions["key_usage"] = [
                    name for position, name in enumerate(_KEY_USAGE)
                    if position < width and number >> (width - 1 - position) & 1
                ]
            elif oid == "2.5.29.37":
                extensions["extended_key_usage"] = [
                    OID_NAMES.get(_oid(der[s:e]), _oid(der[s:e]))
                    for t, s, e in _children(der, inner_start, inner_end)
                    if t == 0x06
                ]
            elif oid == "1.3.6.1.5.5.7.1.1":
                for _, access_start, access_end in _children(der, inner_start, inner_end):
                    access = _children(der, access_start, access_end)
                    method = OID_NAMES.get(_oid(der[access[0][1] : access[0][2]]), "")
                    uris = _uris(der, access_start, access_end)
                    if method == "OCSP":
                        extensions["ocsp"].extend(uris)
                    elif method == "caIssuers":
                        extensions["ca_issuers"].extend(uris)
            elif oid == "2.5.29.31":
                extensions["crl"] = _uris(der, inner_start, inner_end)
            elif oid == "1.3.6.1.4.1.11129.2.4.2":
                extensions["sct_embedded"] = True

    moment = now or datetime.now(timezone.utc)
    expires = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    starts = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
    return {
        "version": version,
        "serial": serial,
        "subject": _name_text(subject),
        "subject_cn": next((value for key, value in subject if key == "CN"), ""),
        "issuer": _name_text(issuer),
        "issuer_cn": next((value for key, value in issuer if key == "CN"), ""),
        "issuer_org": next((value for key, value in issuer if key == "O"), ""),
        "self_issued": subject == issuer,
        "not_before": not_before,
        "not_after": not_after,
        "validity_days": (expires - starts).days,
        "days_remaining": (expires - moment).days,
        "expired": moment > expires,
        "not_yet_valid": moment < starts,
        "signature_algorithm": signature,
        "weak_signature": signature in WEAK_SIGNATURES,
        "public_key": public_key,
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "spki_sha256": base64.b64encode(hashlib.sha256(spki_bytes).digest()).decode("ascii"),
        **extensions,
    }


def _header_offset(data: bytes, content_start: int) -> int:
    """Find where the TLV whose content starts at ``content_start`` begins."""
    for header_length in range(2, 7):
        offset = content_start - header_length
        if offset < 0:
            break
        try:
            _, start, _, _ = _tlv(data, offset)
        except CertificateError:
            continue
        if start == content_start and data[offset] == 0x30:
            return offset
    raise CertificateError("could not locate the public key element")


def hostname_matches(hostname: str, names: list[str]) -> bool:
    host = hostname.lower().rstrip(".")
    for name in names:
        pattern = name.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.count(".") == pattern.count("."):
            if host.split(".", 1)[1] == pattern[2:]:
                return True
    return False
