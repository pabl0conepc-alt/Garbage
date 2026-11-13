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
            "cpp_graph_analytics": bool(globals().get("_CPP_ANALYTICS")),
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


# ---------------------------------------------------------------------------
# Graph analytics: centrality, communities and shortest paths.
#
# The Python implementation is the reference. The C++ engine implements the
# same algorithms with the same iteration order, so results match exactly on
# the same input (tests/test_native.py checks parity when the library loads).


def _graph_indexes(
    nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]
) -> tuple[list[str], list[int], list[int]]:
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
    return identifiers, sources, targets


def _simple_adjacency(count: int, sources: list[int], targets: list[int]) -> list[list[int]]:
    """Undirected, sorted neighbour lists without self-loops or duplicates."""
    neighbours: list[set[int]] = [set() for _ in range(count)]
    for source, target in zip(sources, targets):
        if source == target:
            continue
        neighbours[source].add(target)
        neighbours[target].add(source)
    return [sorted(items) for items in neighbours]


def python_centrality(
    count: int, sources: list[int], targets: list[int]
) -> tuple[list[float], list[float], list[float]]:
    adjacency = _simple_adjacency(count, sources, targets)
    scale = 1.0 / (count - 1) if count > 1 else 0.0
    degree = [len(items) * scale for items in adjacency]
    betweenness = [0.0] * count
    harmonic = [0.0] * count
    for start in range(count):
        # Brandes (2001), unweighted, one BFS per source.
        stack: list[int] = []
        predecessors: list[list[int]] = [[] for _ in range(count)]
        sigma = [0.0] * count
        distance = [-1] * count
        sigma[start] = 1.0
        distance[start] = 0
        queue = [start]
        head = 0
        while head < len(queue):
            current = queue[head]
            head += 1
            stack.append(current)
            for neighbour in adjacency[current]:
                if distance[neighbour] < 0:
                    distance[neighbour] = distance[current] + 1
                    queue.append(neighbour)
                if distance[neighbour] == distance[current] + 1:
                    sigma[neighbour] += sigma[current]
                    predecessors[neighbour].append(current)
        reach = 0.0
        for node in range(count):
            if distance[node] > 0:
                reach += 1.0 / distance[node]
        harmonic[start] = reach * scale
        delta = [0.0] * count
        while stack:
            node = stack.pop()
            for predecessor in predecessors[node]:
                delta[predecessor] += (sigma[predecessor] / sigma[node]) * (1.0 + delta[node])
            if node != start:
                betweenness[node] += delta[node]
    # Undirected pairs are counted twice; normalise by (n-1)(n-2).
    norm = 1.0 / ((count - 1) * (count - 2)) if count > 2 else 0.0
    return degree, [value * norm for value in betweenness], harmonic


def python_communities(
    count: int, sources: list[int], targets: list[int], max_levels: int = 16
) -> tuple[list[int], float]:
    """Deterministic Louvain (Blondel et al., 2008) on the undirected graph."""
    if count == 0:
        return [], 0.0
    # Level graph: weighted adjacency with self-loops for aggregated nodes.
    # Same simple graph as the centrality measures: one unit per entity pair.
    weights: list[dict[int, float]] = [
        {neighbour: 1.0 for neighbour in items}
        for items in _simple_adjacency(count, sources, targets)
    ]
    total = sum(sum(row.values()) for row in weights)  # = 2m
    membership = list(range(count))
    if total == 0.0:
        return membership, 0.0
    graph = weights
    for _ in range(max_levels):
        size = len(graph)
        strength = [sum(row.values()) for row in graph]
        community = list(range(size))
        totals = strength[:]
        improved = False
        for _pass in range(100):
            moved = False
            for node in range(size):
                current = community[node]
                links: dict[int, float] = {}
                for neighbour in sorted(graph[node]):
                    if neighbour == node:
                        continue
                    target_community = community[neighbour]
                    links[target_community] = links.get(target_community, 0.0) + graph[node][neighbour]
                totals[current] -= strength[node]
                best = current
                best_gain = links.get(current, 0.0) - totals[current] * strength[node] / total
                for candidate in sorted(links):
                    gain = links[candidate] - totals[candidate] * strength[node] / total
                    if gain > best_gain + 1e-12:
                        best, best_gain = candidate, gain
                totals[best] += strength[node]
                if best != current:
                    community[node] = best
                    moved = True
                    improved = True
            if not moved:
                break
        if not improved:
            break
        renumber: dict[int, int] = {}
        for node in range(size):
            renumber.setdefault(community[node], len(renumber))
        membership = [renumber[community[item]] for item in membership]
        aggregated: list[dict[int, float]] = [dict() for _ in range(len(renumber))]
        for node in range(size):
            left = renumber[community[node]]
            for neighbour, weight in graph[node].items():
                right = renumber[community[neighbour]]
                aggregated[left][right] = aggregated[left].get(right, 0.0) + weight
        if len(aggregated) == size:
            break
        graph = aggregated
    modularity = _modularity(weights, membership, total)
    return membership, modularity


def _modularity(weights: list[dict[int, float]], membership: list[int], total: float) -> float:
    inside: dict[int, float] = {}
    degrees: dict[int, float] = {}
    for node, row in enumerate(weights):
        label = membership[node]
        degrees[label] = degrees.get(label, 0.0) + sum(row.values())
        for neighbour, weight in row.items():
            if membership[neighbour] == label:
                inside[label] = inside.get(label, 0.0) + weight
    return sum(
        inside.get(label, 0.0) / total - (degrees[label] / total) ** 2 for label in degrees
    )


def python_shortest_path(
    count: int, sources: list[int], targets: list[int], start: int, goal: int
) -> list[int]:
    adjacency = _simple_adjacency(count, sources, targets)
    parent = [-1] * count
    seen = [False] * count
    seen[start] = True
    queue = [start]
    head = 0
    while head < len(queue):
        current = queue[head]
        head += 1
        if current == goal:
            break
        for neighbour in adjacency[current]:
            if not seen[neighbour]:
                seen[neighbour] = True
                parent[neighbour] = current
                queue.append(neighbour)
    if not seen[goal]:
        return []
    path = [goal]
    while path[-1] != start:
        path.append(parent[path[-1]])
    return path[::-1]


def graph_analytics(
    nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]
) -> dict[str, Any]:
    """Per-node centrality and community labels, native when available."""
    identifiers, sources, targets = _graph_indexes(nodes, edges)
    count = len(identifiers)
    engine = "python-fallback"
    result = _native_analytics(count, sources, targets) if count else None
    if result is not None:
        degree, betweenness, harmonic, labels, modularity = result
        engine = "cpp-native"
    else:
        degree, betweenness, harmonic = python_centrality(count, sources, targets)
        labels, modularity = python_communities(count, sources, targets)
    sizes: dict[int, int] = {}
    for label in labels:
        sizes[label] = sizes.get(label, 0) + 1
    return {
        "engine": engine,
        "communities": len(sizes),
        "modularity": round(modularity, 6),
        "nodes": {
            identifiers[position]: {
                "degree": round(degree[position], 6),
                "betweenness": round(betweenness[position], 6),
                "harmonic": round(harmonic[position], 6),
                "community": labels[position],
                "community_size": sizes[labels[position]],
            }
            for position in range(count)
        },
    }


def shortest_path(
    nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]], start_id: str, goal_id: str
) -> dict[str, Any]:
    identifiers, sources, targets = _graph_indexes(nodes, edges)
    index = {identifier: position for position, identifier in enumerate(identifiers)}
    if start_id not in index or goal_id not in index:
        return {"engine": "none", "path": [], "hops": None}
    start, goal = index[start_id], index[goal_id]
    path = _native_path(len(identifiers), sources, targets, start, goal)
    engine = "cpp-native"
    if path is None:
        path = python_shortest_path(len(identifiers), sources, targets, start, goal)
        engine = "python-fallback"
    return {
        "engine": engine,
        "path": [identifiers[position] for position in path],
        "hops": len(path) - 1 if path else None,
    }


def _native_analytics(
    count: int, sources: list[int], targets: list[int]
) -> tuple[list[float], list[float], list[float], list[int], float] | None:
    if _CPP_ANALYTICS is None:
        return None
    source_array = (ctypes.c_uint32 * len(sources))(*sources)
    target_array = (ctypes.c_uint32 * len(targets))(*targets)
    degree = (ctypes.c_double * count)()
    betweenness = (ctypes.c_double * count)()
    harmonic = (ctypes.c_double * count)()
    labels = (ctypes.c_uint32 * count)()
    modularity = ctypes.c_double()
    status = _CPP_ANALYTICS.gi_graph_centrality(
        count, source_array, target_array, len(sources), degree, betweenness, harmonic
    )
    if status != 0:
        return None
    status = _CPP_ANALYTICS.gi_graph_communities(
        count, source_array, target_array, len(sources), labels, ctypes.byref(modularity)
    )
    if status != 0:
        return None
    return list(degree), list(betweenness), list(harmonic), list(labels), float(modularity.value)


def _native_path(
    count: int, sources: list[int], targets: list[int], start: int, goal: int
) -> list[int] | None:
    if _CPP_ANALYTICS is None:
        return None
    source_array = (ctypes.c_uint32 * len(sources))(*sources)
    target_array = (ctypes.c_uint32 * len(targets))(*targets)
    path = (ctypes.c_uint32 * count)()
    length = ctypes.c_size_t()
    status = _CPP_ANALYTICS.gi_graph_shortest_path(
        count, source_array, target_array, len(sources), start, goal, path, count, ctypes.byref(length)
    )
    if status not in (0, 1):
        return None
    return list(path[: length.value]) if status == 0 else []


def _configure_cpp_analytics(library: ctypes.CDLL | None) -> ctypes.CDLL | None:
    """The analytics symbols are optional: an older build keeps its metrics."""
    if library is None:
        return None
    pointer_u32 = ctypes.POINTER(ctypes.c_uint32)
    pointer_double = ctypes.POINTER(ctypes.c_double)
    try:
        library.gi_graph_centrality.argtypes = [
            ctypes.c_size_t, pointer_u32, pointer_u32, ctypes.c_size_t,
            pointer_double, pointer_double, pointer_double,
        ]
        library.gi_graph_centrality.restype = ctypes.c_int
        library.gi_graph_communities.argtypes = [
            ctypes.c_size_t, pointer_u32, pointer_u32, ctypes.c_size_t,
            pointer_u32, pointer_double,
        ]
        library.gi_graph_communities.restype = ctypes.c_int
        library.gi_graph_shortest_path.argtypes = [
            ctypes.c_size_t, pointer_u32, pointer_u32, ctypes.c_size_t,
            ctypes.c_uint32, ctypes.c_uint32, pointer_u32, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        library.gi_graph_shortest_path.restype = ctypes.c_int
    except AttributeError:
        return None
    return library


_CPP_ANALYTICS = _configure_cpp_analytics(_CPP)
