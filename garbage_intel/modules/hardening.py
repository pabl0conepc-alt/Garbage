"""Bounded ELF/PE hardening inspection with a native fast path.

The result describes compiler and linker hardening indicators. It is not a
vulnerability verdict, a malware score or proof that an exploit is possible.
"""

from __future__ import annotations

import struct
from typing import Any

from .. import native

_MAX_PROGRAM_HEADERS = 128
_MAX_SECTION_HEADERS = 256
_MAX_DYNAMIC_ENTRIES = 4096


def _u16(data: bytes, offset: int, little: bool) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H" if little else ">H", data, offset)[0]


def _u32(data: bytes, offset: int, little: bool) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I" if little else ">I", data, offset)[0]


def _u64(data: bytes, offset: int, little: bool) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q" if little else ">Q", data, offset)[0]


def _contains(data: bytes, needle: bytes) -> bool:
    return needle in data


def _empty_flags() -> dict[str, bool]:
    return {
        "pie": False,
        "nx": False,
        "relro": False,
        "bind_now": False,
        "canary": False,
        "fortify": False,
        "aslr": False,
        "cfg": False,
        "high_entropy_va": False,
        "exec_stack": False,
        "stripped": False,
        "relocations": False,
    }


def _elf_raw(data: bytes) -> dict[str, Any] | None:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    bits = 64 if data[4] == 2 else 32
    little = data[5] == 1
    header_size = 64 if bits == 64 else 52
    if len(data) < header_size:
        return None
    e_type = _u16(data, 16, little)
    e_machine = _u16(data, 18, little)
    if bits == 64:
        phoff = _u64(data, 32, little)
        shoff = _u64(data, 40, little)
    else:
        phoff = _u32(data, 28, little)
        shoff = _u32(data, 32, little)
    phentsize = _u16(data, 54 if bits == 64 else 42, little)
    phnum = _u16(data, 56 if bits == 64 else 44, little)
    shentsize = _u16(data, 58 if bits == 64 else 46, little)
    shnum = _u16(data, 60 if bits == 64 else 48, little)
    shstrndx = _u16(data, 62 if bits == 64 else 50, little)
    if None in {e_type, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx}:
        return None

    flags = _empty_flags()
    has_interp = False
    has_stack = False
    has_relro = False
    bind_now = False
    minimum_phsize = 56 if bits == 64 else 32
    if phoff and phnum and phentsize >= minimum_phsize:
        for index in range(min(int(phnum), _MAX_PROGRAM_HEADERS)):
            base = int(phoff) + index * int(phentsize)
            if base + int(phentsize) > len(data):
                break
            p_type = _u32(data, base, little)
            p_flags = _u32(data, base + 4, little)
            if p_type is None or p_flags is None:
                break
            if p_type == 3:
                has_interp = True
            elif p_type == 0x6474E551:
                has_stack = True
                if p_flags & 1:
                    flags["exec_stack"] = True
            elif p_type == 0x6474E552:
                has_relro = True
            elif p_type == 2:
                if bits == 64:
                    offset = _u64(data, base + 8, little)
                    size = _u64(data, base + 32, little)
                else:
                    offset = _u32(data, base + 4, little)
                    size = _u32(data, base + 16, little)
                if offset is None or size is None or offset >= len(data):
                    continue
                entry_size = 16 if bits == 64 else 8
                count = min(int(size) // entry_size, _MAX_DYNAMIC_ENTRIES)
                for entry in range(count):
                    entry_base = int(offset) + entry * entry_size
                    if entry_base + entry_size > len(data):
                        break
                    tag = _u32(data, entry_base, little)
                    value = (
                        _u64(data, entry_base + 8, little)
                        if bits == 64
                        else _u32(data, entry_base + 4, little)
                    )
                    if tag is None or value is None or tag == 0:
                        break
                    if tag == 24 or (tag == 30 and value & 8) or (
                        tag == 0x6FFFFFFB and value & 1
                    ):
                        bind_now = True

    symbol_table = False
    minimum_shsize = 64 if bits == 64 else 40
    if shoff and shnum and shentsize >= minimum_shsize and shstrndx < shnum:
        string_header = int(shoff) + int(shstrndx) * int(shentsize)
        if string_header + int(shentsize) <= len(data):
            if bits == 64:
                string_offset = _u64(data, string_header + 24, little)
                string_size = _u64(data, string_header + 32, little)
            else:
                string_offset = _u32(data, string_header + 16, little)
                string_size = _u32(data, string_header + 20, little)
            if string_offset is not None and string_size:
                table = data[
                    int(string_offset) : int(string_offset) + min(int(string_size), 1_000_000)
                ]
                for index in range(min(int(shnum), _MAX_SECTION_HEADERS)):
                    base = int(shoff) + index * int(shentsize)
                    if base + int(shentsize) > len(data):
                        break
                    name_offset = _u32(data, base, little)
                    if name_offset is None or name_offset >= len(table):
                        continue
                    end = table.find(b"\x00", name_offset, name_offset + 96)
                    if end == -1:
                        end = min(len(table), name_offset + 96)
                    if table[name_offset:end] == b".symtab":
                        symbol_table = True

    raw_flags = _empty_flags()
    raw_flags["pie"] = bool(e_type == 3 and has_interp)
    if has_stack:
        raw_flags["nx"] = not flags["exec_stack"]
        raw_flags["exec_stack"] = flags["exec_stack"]
    raw_flags["relro"] = bool(has_relro)
    raw_flags["bind_now"] = bind_now
    raw_flags["canary"] = _contains(data, b"__stack_chk_fail")
    raw_flags["fortify"] = _contains(data, b"__fortify_fail") or _contains(
        data, b"__chk_fail"
    )
    raw_flags["stripped"] = not symbol_table
    return {
        "engine": "python-fallback",
        "format": "elf",
        "bits": bits,
        "flags": raw_flags,
        "relro": "full" if has_relro and bind_now else "partial" if has_relro else "none",
        "stack": "executable" if flags["exec_stack"] else "nx" if has_stack else "unknown",
        "section_count": int(shnum),
        "symbol_table": symbol_table,
        "detail": f"ELF{bits} {'little' if little else 'big'}-endian, machine {e_machine}",
    }


def _pe_raw(data: bytes) -> dict[str, Any] | None:
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    pe_offset = _u32(data, 0x3C, True)
    if pe_offset is None or pe_offset + 24 > len(data):
        return None
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    machine = _u16(data, pe_offset + 4, True)
    section_count = _u16(data, pe_offset + 6, True)
    optional_size = _u16(data, pe_offset + 20, True)
    optional_offset = pe_offset + 24
    magic = _u16(data, optional_offset, True)
    if None in {machine, section_count, optional_size, magic} or magic not in {
        0x10B,
        0x20B,
    }:
        return None
    bits = 64 if magic == 0x20B else 32
    dll_characteristics = _u16(data, optional_offset + 70, True)
    if dll_characteristics is None:
        return None
    reloc_rva = 0
    reloc_size = 0
    directory_base = optional_offset + (112 if bits == 64 else 96)
    if directory_base + 40 <= len(data):
        reloc_rva = _u32(data, directory_base + 5 * 8, True) or 0
        reloc_size = _u32(data, directory_base + 5 * 8 + 4, True) or 0
    flags = _empty_flags()
    flags["aslr"] = bool(dll_characteristics & 0x0040)
    flags["nx"] = bool(dll_characteristics & 0x0100)
    flags["cfg"] = bool(dll_characteristics & 0x0400)
    flags["high_entropy_va"] = bool(dll_characteristics & 0x0020)
    flags["relocations"] = bool(reloc_rva and reloc_size)
    flags["canary"] = _contains(data, b"__security_check_cookie") or _contains(
        data, b"__GSHandlerCheck"
    )
    return {
        "engine": "python-fallback",
        "format": "pe",
        "bits": bits,
        "flags": flags,
        "relro": "none",
        "stack": "nx" if flags["nx"] else "unknown",
        "section_count": int(section_count),
        "symbol_table": False,
        "detail": f"PE{'32+' if bits == 64 else '32'}, machine 0x{machine:04x}",
    }


def _check(key: str, label: str, status: str, detail: str) -> dict[str, str]:
    return {"key": key, "label": label, "status": status, "detail": detail}


def _neutral(flag: bool, enabled: str, missing: str) -> tuple[str, str]:
    return ("enabled", enabled) if flag else ("missing", missing)


def _checks(raw: dict[str, Any]) -> list[dict[str, str]]:
    flags = raw["flags"]
    checks: list[dict[str, str]] = []
    if raw["format"] == "elf":
        checks.append(
            _check(
                "pie",
                "PIE / position independent",
                *_neutral(
                    flags["pie"],
                    "ET_DYN with an interpreter; loaded at a randomized base when the OS supports it.",
                    "No PIE marker; a non-PIE executable may need a fixed load address.",
                ),
            )
        )
        if raw["stack"] == "executable":
            checks.append(
                _check(
                    "nx",
                    "Non-executable stack",
                    "missing",
                    "GNU_STACK requests an executable stack.",
                )
            )
        elif raw["stack"] == "nx":
            checks.append(
                _check(
                    "nx",
                    "Non-executable stack",
                    "enabled",
                    "GNU_STACK does not request execute permission.",
                )
            )
        else:
            checks.append(
                _check(
                    "nx",
                    "Non-executable stack",
                    "unknown",
                    "No GNU_STACK program header was found.",
                )
            )
        relro = raw["relro"]
        checks.append(
            _check(
                "relro",
                "RELRO",
                "enabled" if relro == "full" else "partial" if relro == "partial" else "missing",
                "Full RELRO (GNU_RELRO + immediate binding)."
                if relro == "full"
                else "Partial RELRO; the GOT may be writable before binding completes."
                if relro == "partial"
                else "No GNU_RELRO program header was found.",
            )
        )
        checks.append(
            _check(
                "bind_now",
                "Immediate symbol binding",
                *_neutral(
                    flags["bind_now"],
                    "BIND_NOW / DF_1_NOW is requested.",
                    "Lazy binding is not explicitly disabled.",
                ),
            )
        )
        checks.append(
            _check(
                "canary",
                "Stack canary symbols",
                *_neutral(
                    flags["canary"],
                    "__stack_chk_fail is referenced.",
                    "No __stack_chk_fail reference was found; this is not proof that no canary exists.",
                ),
            )
        )
        checks.append(
            _check(
                "fortify",
                "Fortify helpers",
                *_neutral(
                    flags["fortify"],
                    "A fortify failure helper is referenced.",
                    "No __fortify_fail or __chk_fail reference was found.",
                ),
            )
        )
        checks.append(
            _check(
                "symbols",
                "Symbol table",
                "enabled" if flags["stripped"] else "missing",
                "The symbol table is stripped."
                if flags["stripped"]
                else "A .symtab section is present, which can aid reverse engineering.",
            )
        )
    else:
        checks.extend(
            [
                _check(
                    "aslr",
                    "ASLR / DYNAMIC_BASE",
                    *_neutral(
                        flags["aslr"],
                        "DYNAMIC_BASE requests address randomization.",
                        "DYNAMIC_BASE is not set.",
                    ),
                ),
                _check(
                    "nx",
                    "NX compatibility",
                    *_neutral(
                        flags["nx"],
                        "NX_COMPAT is set.",
                        "NX_COMPAT is not set.",
                    ),
                ),
                _check(
                    "cfg",
                    "Control Flow Guard",
                    *_neutral(
                        flags["cfg"],
                        "GUARD_CF is set.",
                        "GUARD_CF is not set; this does not prove CFG is absent at runtime.",
                    ),
                ),
                _check(
                    "high_entropy_va",
                    "High-entropy VA",
                    *_neutral(
                        flags["high_entropy_va"],
                        "HIGH_ENTROPY_VA is set.",
                        "HIGH_ENTROPY_VA is not set.",
                    ),
                ),
                _check(
                    "relocations",
                    "Base relocations",
                    *_neutral(
                        flags["relocations"],
                        "A relocation directory is declared.",
                        "No base relocation directory was found; fixed-base images may not randomize.",
                    ),
                ),
                _check(
                    "canary",
                    "Security cookie symbols",
                    *_neutral(
                        flags["canary"],
                        "__security_check_cookie or __GSHandlerCheck is referenced.",
                        "No security cookie helper was found; this is not proof that no cookie exists.",
                    ),
                ),
            ]
        )
    return checks


def describe_hardening(kind: str, data: bytes) -> dict[str, Any] | None:
    """Return hardening facts for an ELF or PE buffer, or None for other formats."""
    if kind not in {"elf", "pe"}:
        return None
    raw = native.hardening_raw(kind, data)
    if raw is None:
        raw = _elf_raw(data) if kind == "elf" else _pe_raw(data)
    if raw is None:
        return None
    checks = _checks(raw)
    enabled = sum(1 for check in checks if check["status"] == "enabled")
    missing = sum(1 for check in checks if check["status"] == "missing")
    return {
        "engine": raw["engine"],
        "format": raw["format"],
        "bits": raw["bits"],
        "detail": raw["detail"],
        "status": "native" if raw["engine"] == "c-native" else "fallback",
        "checks": checks,
        "enabled_count": enabled,
        "missing_count": missing,
        "limitations": [
            "Hardening markers describe compiler and linker choices; they are not a vulnerability verdict.",
            "Absence of a marker is not proof that a mitigation is absent from the running process.",
        ],
    }
