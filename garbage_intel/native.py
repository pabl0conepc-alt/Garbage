"""Optional native helpers with strict loading rules and Python fallbacks.

No library is downloaded or loaded implicitly from a user-controlled file. Only
``GARBAGE_NATIVE_DIR`` or the repository's ``native/build`` directory is used.
A missing library, ABI mismatch or missing symbol simply disables that engine.
"""

from __future__ import annotations

import ctypes
import math
import os
from pathlib import Path
from typing import Any, Mapping

NATIVE_ABI_VERSION = 1
_FLAG = {
    "pie": 1 << 0,
    "nx": 1 << 1,
    "relro": 1 << 2,
    "bind_now": 1 << 3,
    "canary": 1 << 4,
    "fortify": 1 << 5,
    "aslr": 1 << 6,
    "cfg": 1 << 7,
    "high_entropy_va": 1 << 8,
    "exec_stack": 1 << 9,
    "stripped": 1 << 10,
    "relocations": 1 << 11,
}
_RELRO = {0: "none", 1: "partial", 2: "full"}
_STACK = {0: "unknown", 1: "nx", 2: "executable"}


class _Hardening(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("format", ctypes.c_uint32),
        ("bits", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("relro", ctypes.c_uint32),
        ("stack", ctypes.c_uint32),
        ("section_count", ctypes.c_uint32),
        ("symbol_table", ctypes.c_uint32),
        ("detail", ctypes.c_char * 192),
    ]


class _GraphMetrics(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("nodes", ctypes.c_uint64),
        ("edges", ctypes.c_uint64),
        ("components", ctypes.c_uint64),
        ("isolates", ctypes.c_uint64),
        ("self_loops", ctypes.c_uint64),
        ("reciprocal_edges", ctypes.c_uint64),
        ("degree_sum", ctypes.c_uint64),
        ("max_degree", ctypes.c_uint64),
        ("max_degree_node", ctypes.c_uint32),
        ("density", ctypes.c_double),
    ]


def _library_names(stem: str) -> tuple[str, ...]:
    if os.name == "nt":
        return (f"{stem}.dll",)
    return (f"lib{stem}.so", f"lib{stem}.dylib")


def _build_directories() -> list[Path]:
    configured = os.environ.get("GARBAGE_NATIVE_DIR", "").strip()
    if configured:
        return [Path(configured).expanduser()]
    return [Path(__file__).resolve().parent.parent / "native" / "build"]


def _load(stem: str) -> ctypes.CDLL | None:
    for directory in _build_directories():
        for name in _library_names(stem):
            path = directory / name
            if not path.is_file():
                continue
            try:
                library = ctypes.CDLL(str(path))
            except OSError:
                continue
            return library
    return None


def _configure_c(library: ctypes.CDLL) -> ctypes.CDLL | None:
    try:
        version = library.gi_native_abi_version
        version.restype = ctypes.c_uint32
        if version() != NATIVE_ABI_VERSION:
            return None
        library.gi_entropy.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_double),
        ]
        library.gi_entropy.restype = ctypes.c_int
        library.gi_hardening_scan.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.POINTER(_Hardening),
        ]
        library.gi_hardening_scan.restype = ctypes.c_int
    except AttributeError:
        return None
    return library


def _configure_cpp(library: ctypes.CDLL) -> ctypes.CDLL | None:
    try:
        version = library.gi_graph_abi_version
        version.restype = ctypes.c_uint32
        if version() != NATIVE_ABI_VERSION:
            return None
        library.gi_graph_metrics_calculate.argtypes = [
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_size_t,
            ctypes.POINTER(_GraphMetrics),
        ]
        library.gi_graph_metrics_calculate.restype = ctypes.c_int
    except AttributeError:
        return None
    return library


def _configure_rust(library: ctypes.CDLL) -> ctypes.CDLL | None:
    try:
        version = library.gi_rust_abi_version
        version.restype = ctypes.c_uint32
        if version() != NATIVE_ABI_VERSION:
            return None
        library.gi_domain_distance.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
        ]
        library.gi_domain_distance.restype = ctypes.c_int32
        library.gi_domain_skeleton.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        library.gi_domain_skeleton.restype = ctypes.c_int32
    except AttributeError:
        return None
    return library


def _initialize(stem: str, configure: Any) -> ctypes.CDLL | None:
    library = _load(stem)
    return configure(library) if library is not None else None


_C = _initialize("garbage_c", _configure_c)
_CPP = _initialize("garbage_cpp", _configure_cpp)
_RUST = _initialize("garbage_rust", _configure_rust)


def native_status() -> dict[str, Any]:
    """Return which native engines loaded, without implying they are required."""
    return {
        "abi_version": NATIVE_ABI_VERSION,
        "engines": {
            "c_file_intelligence": bool(_C),
            "cpp_graph_metrics": bool(_CPP),
            "rust_similarity": bool(_RUST),
        },
        "directory": str(_build_directories()[-1]),
        "fallback": "python",
    }


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("native input must be bytes")
    return bytes(data)


def entropy(data: bytes | bytearray | memoryview) -> float | None:
    """Return native Shannon entropy, or None when the C engine is absent."""
    if _C is None:
        return None
    payload = _as_bytes(data)
    out = ctypes.c_double()
    if _C.gi_entropy(payload, len(payload), ctypes.byref(out)) != 0:
        return None
    value = float(out.value)
    if not math.isfinite(value) or value < 0.0 or value > 8.0:
        return None
    return value


def hardening_raw(kind: str, data: bytes | bytearray | memoryview) -> dict[str, Any] | None:
    """Return raw native hardening flags, or None when unavailable."""
    formats = {"elf": 1, "pe": 2}
    if _C is None or kind not in formats:
        return None
    payload = _as_bytes(data)
    result = _Hardening()
    status = _C.gi_hardening_scan(
        payload, len(payload), formats[kind], ctypes.byref(result)
    )
    if status != 0 or int(result.abi_version) != NATIVE_ABI_VERSION:
        return None
    flags = int(result.flags)
    return {
        "engine": "c-native",
        "format": "elf" if result.format == 1 else "pe",
        "bits": int(result.bits),
        "flags": {name: bool(flags & bit) for name, bit in _FLAG.items()},
        "relro": _RELRO.get(int(result.relro), "unknown"),
        "stack": _STACK.get(int(result.stack), "unknown"),
        "section_count": int(result.section_count),
        "symbol_table": bool(result.symbol_table),
        "detail": result.detail.decode("ascii", errors="replace"),
    }


def graph_metrics(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute graph facts natively when possible, otherwise in Python."""
    identifiers = [str(node.get("id", "")) for node in nodes]
    index = {identifier: position for position, identifier in enumerate(identifiers)}
    sources: list[int] = []
    targets: list[int] = []
    for edge in edges:
        source = index.get(str(edge.get("source_entity_id", "")))
        target = index.get(str(edge.get("target_entity_id", "")))
        if source is None or target is None:
            continue
        sources.append(source)
        targets.append(target)

    if _CPP is not None and identifiers:
        source_array = (ctypes.c_uint32 * len(sources))(*sources)
        target_array = (ctypes.c_uint32 * len(targets))(*targets)
        metrics = _GraphMetrics()
        status = _CPP.gi_graph_metrics_calculate(
            len(identifiers),
            source_array,
            target_array,
            len(sources),
            ctypes.byref(metrics),
        )
        if status == 0 and int(metrics.abi_version) == NATIVE_ABI_VERSION:
            max_node = int(metrics.max_degree_node)
            return {
                "engine": "cpp-native",
                "nodes": int(metrics.nodes),
                "edges": int(metrics.edges),
                "components": int(metrics.components),
                "isolates": int(metrics.isolates),
                "self_loops": int(metrics.self_loops),
                "reciprocal_edges": int(metrics.reciprocal_edges),
                "degree_sum": int(metrics.degree_sum),
                "max_degree": int(metrics.max_degree),
                "max_degree_node": identifiers[max_node] if max_node < len(identifiers) else "",
                "density": float(metrics.density),
            }

    return _python_graph_metrics(identifiers, sources, targets)


def _python_graph_metrics(
    identifiers: list[str], sources: list[int], targets: list[int]
) -> dict[str, Any]:
    count = len(identifiers)
    degrees = [0] * count
    parents = list(range(count))

    def find(value: int) -> int:
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    directed = set(zip(sources, targets))
    self_loops = 0
    for source, target in zip(sources, targets):
        degrees[source] += 1
        degrees[target] += 1
        if source == target:
            self_loops += 1
        left, right = find(source), find(target)
        if left != right:
            parents[right] = left
    components = len({find(index) for index in range(count)}) if count else 0
    isolates = sum(1 for degree in degrees if degree == 0)
    max_degree = max(degrees) if degrees else 0
    max_node = degrees.index(max_degree) if degrees else 0
    reciprocal = sum(
        1 for source, target in zip(sources, targets) if (target, source) in directed
    )
    possible = count * (count - 1) if count > 1 else 1
    return {
        "engine": "python-fallback",
        "nodes": count,
        "edges": len(sources),
        "components": components,
        "isolates": isolates,
        "self_loops": self_loops,
        "reciprocal_edges": reciprocal,
        "degree_sum": sum(degrees),
        "max_degree": max_degree,
        "max_degree_node": identifiers[max_node] if identifiers else "",
        "density": min(1.0, len(sources) / possible),
    }


def domain_distance(left: str, right: str, max_distance: int = 2) -> int | None:
    """Return native bounded edit distance, or None when Rust is unavailable."""
    if _RUST is None:
        return None
    left_bytes = left.encode("utf-8", errors="ignore")[:253]
    right_bytes = right.encode("utf-8", errors="ignore")[:253]
    value = int(
        _RUST.gi_domain_distance(
            left_bytes,
            len(left_bytes),
            right_bytes,
            len(right_bytes),
            max(0, int(max_distance)),
        )
    )
    return value if value >= 0 else None


def domain_skeleton(value: str) -> str | None:
    """Return native skeleton, or None when Rust is unavailable."""
    if _RUST is None:
        return None
    payload = value.encode("utf-8", errors="ignore")[:253]
    output = ctypes.create_string_buffer(256)
    length = int(
        _RUST.gi_domain_skeleton(
            payload, len(payload), ctypes.cast(output, ctypes.c_char_p), len(output)
        )
    )
    if length < 0:
        return None
    return output.raw[:length].decode("ascii", errors="replace")


def python_domain_distance(left: str, right: str, max_distance: int = 2) -> int:
    """Reference OSA Damerau-Levenshtein implementation used as fallback."""
    left = left[:253].lower()
    right = right[:253].lower()
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    if left == right:
        return 0
    previous_previous = [0] * (len(right) + 1)
    previous = list(range(len(right) + 1))
    for row in range(1, len(left) + 1):
        current = [row] + [0] * len(right)
        for column in range(1, len(right) + 1):
            substitution = 0 if left[row - 1] == right[column - 1] else 1
            value = min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + substitution,
            )
            if (
                row > 1
                and column > 1
                and left[row - 1] == right[column - 2]
                and left[row - 2] == right[column - 1]
            ):
                value = min(value, previous_previous[column - 2] + 1)
            current[column] = value
        if min(current) > max_distance:
            return max_distance + 1
        previous_previous, previous = previous, current
    return previous[-1]


def python_domain_skeleton(value: str) -> str:
    """Reference skeleton used when the Rust engine is absent."""
    result: list[str] = []
    for raw in value[:253].lower():
        if raw == "-":
            continue
        result.append(
            {
                "0": "o",
                "1": "l",
                "3": "e",
                "4": "a",
                "5": "s",
                "7": "t",
                "9": "g",
            }.get(raw, raw)
        )
    return "".join(result)


def python_graph_components(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> int:
    """Small compatibility helper for callers that only need component count."""
    return int(graph_metrics(nodes, edges)["components"])
