"""Similarity digests: TLSH and ssdeep (context-triggered piecewise hashing).

Both are written from the published algorithm descriptions (Oliver, Cheng and
Chen, "TLSH - A Locality Sensitive Hash", 2013; Kornblum, "Identifying almost
identical files using context triggered piecewise hashing", 2006). Output is
byte-for-byte compatible with py-tlsh 4.x/5.x (``T1`` digests, 128 buckets,
1-byte checksum) and ssdeep 2.14; the test suite checks recorded reference
digests. The C engine in ``native/c/garbage_fuzzy.c`` mirrors this module and
is used when built.

A similar digest means the bytes share structure. It does not mean the files
share an author, purpose or verdict.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# ---------------------------------------------------------------------------
# TLSH

TLSH_MIN_LENGTH = 50
TLSH_BUCKETS = 128
TLSH_CODE_SIZE = 32

# Pearson permutation used by TLSH for every bucket and checksum mapping.
_PEARSON = bytes(
    (
        1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
        14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
        110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
        25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
        97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
        174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
        132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
        119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
        138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
        170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
        125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
        118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
        27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
        233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
        140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
        51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
    )
)
# (salt, offsets of the three window bytes); offset 0 is the newest byte.
_TLSH_TRIPLETS = ((2, 0, 1, 2), (3, 0, 1, 3), (5, 0, 2, 3), (7, 0, 2, 4), (11, 0, 1, 4), (13, 0, 3, 4))


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return (int.from_bytes(left, "little") ^ int.from_bytes(right, "little")).to_bytes(len(left), "little")


def _tlsh_length_code(length: int) -> int:
    if length <= 656:
        value = math.log(length) / math.log(1.5)
    elif length <= 3199:
        value = math.log(length) / math.log(1.3) - 8.72777
    else:
        value = math.log(length) / math.log(1.1) - 62.5472
    return int(math.floor(value)) & 0xFF


def _swap(value: int) -> int:
    return ((value & 0x0F) << 4) | ((value & 0xF0) >> 4)


def python_tlsh(data: bytes) -> str | None:
    """Return the TLSH digest, or None when the input is too short or too
    uniform (fewer than half of the buckets used), like ``TNULL``."""
    length = len(data)
    if length < TLSH_MIN_LENGTH:
        return None
    # Window views: column k holds the byte k positions before the newest one.
    columns = [data[4 - k : length - k] for k in range(5)]
    buckets: Counter[int] = Counter()
    for salt, first, second, third in _TLSH_TRIPLETS:
        mapped = columns[first].translate(bytes(_PEARSON[_PEARSON[salt] ^ value] for value in range(256)))
        mapped = _xor_bytes(mapped, columns[second]).translate(_PEARSON)
        mapped = _xor_bytes(mapped, columns[third]).translate(_PEARSON)
        buckets.update(mapped)
    # Checksum chain: T[T[T[T[0] ^ a0] ^ a1] ^ previous].
    pair = _xor_bytes(columns[0].translate(bytes(_PEARSON[_PEARSON[0] ^ value] for value in range(256))), columns[1]).translate(_PEARSON)
    checksum = 0
    for value in pair:
        checksum = _PEARSON[value ^ checksum]

    counts = [buckets.get(index, 0) for index in range(TLSH_BUCKETS)]
    if sum(1 for count in counts if count) <= TLSH_BUCKETS // 2:
        return None
    ordered = sorted(counts)
    q1, q2, q3 = ordered[31], ordered[63], ordered[95]
    if q3 == 0:
        return None
    body = bytearray(TLSH_CODE_SIZE)
    for index in range(TLSH_CODE_SIZE):
        value = 0
        for slot in range(4):
            count = counts[4 * index + slot]
            if q3 < count:
                value += 3 << (slot * 2)
            elif q2 < count:
                value += 2 << (slot * 2)
            elif q1 < count:
                value += 1 << (slot * 2)
        body[TLSH_CODE_SIZE - 1 - index] = value
    q_ratios = ((q1 * 100 // q3) % 16) | (((q2 * 100 // q3) % 16) << 4)
    header = bytes((_swap(checksum), _swap(_tlsh_length_code(length)), _swap(q_ratios)))
    return "T1" + (header + bytes(body)).hex().upper()


_TLSH_PATTERN = re.compile(r"^(?:T1)?[0-9A-Fa-f]{70}$")


def _tlsh_parts(digest: str) -> tuple[int, int, int, int, bytes]:
    if not isinstance(digest, str) or not _TLSH_PATTERN.match(digest):
        raise ValueError("not a TLSH digest")
    raw = bytes.fromhex(digest[-70:])
    q_ratios = _swap(raw[2])
    return _swap(raw[0]), _swap(raw[1]), q_ratios & 0x0F, q_ratios >> 4, raw[3:]


def _mod_diff(left: int, right: int, size: int) -> int:
    near = abs(left - right)
    return min(near, size - near)


def tlsh_distance(left: str, right: str) -> int:
    """TLSH distance including the length component; 0 means identical
    digests and values under roughly 50 usually indicate close variants."""
    checksum_a, length_a, q1_a, q2_a, body_a = _tlsh_parts(left)
    checksum_b, length_b, q1_b, q2_b, body_b = _tlsh_parts(right)
    distance = 0
    length_diff = _mod_diff(length_a, length_b, 256)
    distance += length_diff if length_diff <= 1 else length_diff * 12
    for one, two in ((q1_a, q1_b), (q2_a, q2_b)):
        ratio_diff = _mod_diff(one, two, 16)
        distance += ratio_diff if ratio_diff <= 1 else (ratio_diff - 1) * 12
    if checksum_a != checksum_b:
        distance += 1
    for one, two in zip(body_a, body_b):
        for shift in (0, 2, 4, 6):
            step = abs(((one >> shift) & 3) - ((two >> shift) & 3))
            distance += 6 if step == 3 else step
    return distance


# ---------------------------------------------------------------------------
# ssdeep

SPAMSUM_LENGTH = 64
MIN_BLOCKSIZE = 3
ROLLING_WINDOW = 7
_HASH_INIT = 0x27  # 0x28021967 reduced to the 6 bits that reach the digest
_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# FNV-1 step restricted to 6 bits: (h * 0x01000193 ^ c) & 63.
_SUM = [bytes(((state * 0x93) ^ value) & 0x3F for value in range(256)) for state in range(64)]


def _block_digests(data: bytes, block_size: int) -> tuple[str, str, int]:
    """One pass at ``block_size`` and twice it. Returns both partial digests
    and the final rolling hash, following ssdeep's overflow rules: once a
    digest is full, its last character keeps being replaced."""
    double = block_size * 2
    window = [0] * ROLLING_WINDOW
    h1 = h2 = h3 = 0
    position = 0
    first: list[int] = []
    second: list[int] = []
    hash_a = hash_b = _HASH_INIT
    first_last = second_last = 0
    sum_table = _SUM
    for value in data:
        h2 = h2 - h1 + ROLLING_WINDOW * value
        h1 = h1 + value - window[position]
        window[position] = value
        position = position + 1 if position < ROLLING_WINDOW - 1 else 0
        h3 = ((h3 << 5) & 0xFFFFFFFF) ^ value
        rolling = (h1 + h2 + h3) & 0xFFFFFFFF
        hash_a = sum_table[hash_a][value]
        hash_b = sum_table[hash_b][value]
        if rolling % block_size == block_size - 1:
            if len(first) < SPAMSUM_LENGTH - 1:
                first.append(_B64[hash_a])
                hash_a = _HASH_INIT
            else:
                first_last = _B64[hash_a]
            if rolling % double == double - 1:
                if len(second) < SPAMSUM_LENGTH // 2 - 1:
                    second.append(_B64[hash_b])
                    hash_b = _HASH_INIT
                else:
                    second_last = _B64[hash_b]
    rolling = (h1 + h2 + h3) & 0xFFFFFFFF
    if rolling:
        first.append(_B64[hash_a])
        second.append(_B64[hash_b])
    else:
        if first_last:
            first.append(first_last)
        if second_last:
            second.append(second_last)
    return bytes(first).decode("ascii"), bytes(second).decode("ascii"), len(first)


def python_ssdeep(data: bytes) -> str:
    block_size = MIN_BLOCKSIZE
    while block_size * SPAMSUM_LENGTH < len(data):
        block_size *= 2
    while True:
        first, second, count = _block_digests(data, block_size)
        if block_size > MIN_BLOCKSIZE and count < SPAMSUM_LENGTH // 2:
            block_size //= 2
            continue
        return f"{block_size}:{first}:{second}"


_SSDEEP_PATTERN = re.compile(r"^(\d{1,10}):([A-Za-z0-9+/]{0,64}):([A-Za-z0-9+/]{0,64})(?:,.*)?$")
_REPEATS = re.compile(r"(.)\1{3,}")


def _ssdeep_parts(digest: str) -> tuple[int, str, str]:
    match = _SSDEEP_PATTERN.match(digest or "") if isinstance(digest, str) else None
    if not match:
        raise ValueError("not an ssdeep digest")
    collapse = lambda part: _REPEATS.sub(lambda found: found.group(1) * 3, part)
    return int(match.group(1)), collapse(match.group(2)), collapse(match.group(3))


def _weighted_edit_distance(left: str, right: str) -> int:
    """Levenshtein distance with substitution cost 2 (insert/delete 1)."""
    previous = list(range(len(right) + 1))
    for row, char in enumerate(left, 1):
        current = [row]
        for column, other in enumerate(right, 1):
            current.append(
                min(previous[column] + 1, current[column - 1] + 1, previous[column - 1] + (0 if char == other else 2))
            )
        previous = current
    return previous[-1]


def _score_strings(left: str, right: str, block_size: int) -> int:
    if len(left) < ROLLING_WINDOW or len(right) < ROLLING_WINDOW:
        return 0
    windows = {left[index : index + ROLLING_WINDOW] for index in range(len(left) - ROLLING_WINDOW + 1)}
    if not any(right[index : index + ROLLING_WINDOW] in windows for index in range(len(right) - ROLLING_WINDOW + 1)):
        return 0
    score = _weighted_edit_distance(left, right) * SPAMSUM_LENGTH // (len(left) + len(right))
    score = 100 - (100 * score) // SPAMSUM_LENGTH
    if block_size >= (99 + ROLLING_WINDOW) // ROLLING_WINDOW * MIN_BLOCKSIZE:
        return score
    return min(score, block_size // MIN_BLOCKSIZE * min(len(left), len(right)))


def ssdeep_compare(left: str, right: str) -> int:
    """ssdeep match score from 0 (no meaningful similarity) to 100."""
    size_a, first_a, second_a = _ssdeep_parts(left)
    size_b, first_b, second_b = _ssdeep_parts(right)
    if size_a != size_b and size_a != size_b * 2 and size_b != size_a * 2:
        return 0
    if size_a == size_b and first_a == first_b and second_a == second_b:
        return 100
    if size_a == size_b:
        return max(_score_strings(first_a, first_b, size_a), _score_strings(second_a, second_b, size_a * 2))
    if size_a == size_b * 2:
        return _score_strings(first_a, second_b, size_a)
    return _score_strings(second_a, first_b, size_b)


# ---------------------------------------------------------------------------


PYTHON_FALLBACK_LIMIT = 1024 * 1024


def similarity_digests(data: bytes) -> dict[str, Any]:
    """Both digests, preferring the C engine. ``engine`` names what ran.

    The pure-Python fallback takes about two seconds per MiB, so above
    ``PYTHON_FALLBACK_LIMIT`` it reports the digests as unavailable instead of
    stalling the request."""
    from .. import native

    native_result = native.fuzzy_digests(data)
    if native_result is not None:
        return native_result
    if len(data) > PYTHON_FALLBACK_LIMIT:
        return {"tlsh": None, "ssdeep": None, "engine": "unavailable", "reason": "native-engine-required"}
    return {"tlsh": python_tlsh(data), "ssdeep": python_ssdeep(data), "engine": "python-fallback"}


def tlsh_compare(left: str, right: str) -> int:
    from .. import native

    value = native.fuzzy_compare("tlsh", left, right)
    return tlsh_distance(left, right) if value is None else value


def ssdeep_score(left: str, right: str) -> int:
    from .. import native

    value = native.fuzzy_compare("ssdeep", left, right)
    return ssdeep_compare(left, right) if value is None else value
