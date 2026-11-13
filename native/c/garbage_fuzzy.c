/* Similarity digests for the optional GARBAGE C engine: TLSH and ssdeep.
 *
 * Mirrors garbage_intel/modules/fuzzy_hash.py exactly; tests compare both
 * against recorded reference digests. Pure computation over a caller buffer:
 * no allocation visible to the caller, no I/O.
 */
#include "garbage_native.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char PEARSON[256] = {
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
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209};

#define TLSH_BUCKETS 128
#define TLSH_CODE 32

static unsigned char pearson4(unsigned char salt, unsigned char a, unsigned char b, unsigned char c) {
    return PEARSON[PEARSON[PEARSON[PEARSON[salt] ^ a] ^ b] ^ c];
}

static unsigned char swap_nibbles(unsigned char value) {
    return (unsigned char)(((value & 0x0F) << 4) | ((value & 0xF0) >> 4));
}

static unsigned char tlsh_length_code(size_t length) {
    double value;
    if (length <= 656) {
        value = log((double)length) / log(1.5);
    } else if (length <= 3199) {
        value = log((double)length) / log(1.3) - 8.72777;
    } else {
        value = log((double)length) / log(1.1) - 62.5472;
    }
    return (unsigned char)(((long long)floor(value)) & 0xFF);
}

static int compare_u32(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left, b = *(const uint32_t *)right;
    return (a > b) - (a < b);
}

static const char HEX[] = "0123456789ABCDEF";

int gi_tlsh(const unsigned char *data, size_t length, char *out, size_t capacity) {
    static const unsigned char salts[6] = {2, 3, 5, 7, 11, 13};
    static const int offsets[6][2] = {{1, 2}, {1, 3}, {2, 3}, {2, 4}, {1, 4}, {3, 4}};
    uint32_t buckets[256] = {0};
    uint32_t ordered[TLSH_BUCKETS];
    unsigned char raw[3 + TLSH_CODE];
    unsigned char checksum = 0;
    size_t i;
    int nonzero = 0;

    if (out == NULL || capacity < 73 || (data == NULL && length > 0)) {
        return -1;
    }
    out[0] = '\0';
    if (length < 50) {
        return 1;
    }
    for (i = 4; i < length; i++) {
        const unsigned char *w = data + i; /* w[0] newest, w[-4] oldest */
        int t;
        checksum = pearson4(0, w[0], w[-1], checksum);
        for (t = 0; t < 6; t++) {
            buckets[pearson4(salts[t], w[0], w[-offsets[t][0]], w[-offsets[t][1]])]++;
        }
    }
    for (i = 0; i < TLSH_BUCKETS; i++) {
        ordered[i] = buckets[i];
        nonzero += buckets[i] != 0;
    }
    if (nonzero <= TLSH_BUCKETS / 2) {
        return 1;
    }
    qsort(ordered, TLSH_BUCKETS, sizeof(uint32_t), compare_u32);
    {
        uint32_t q1 = ordered[31], q2 = ordered[63], q3 = ordered[95];
        unsigned q_ratios;
        if (q3 == 0) {
            return 1;
        }
        for (i = 0; i < TLSH_CODE; i++) {
            unsigned value = 0;
            int slot;
            for (slot = 0; slot < 4; slot++) {
                uint32_t count = buckets[4 * i + (size_t)slot];
                if (q3 < count) {
                    value += 3u << (slot * 2);
                } else if (q2 < count) {
                    value += 2u << (slot * 2);
                } else if (q1 < count) {
                    value += 1u << (slot * 2);
                }
            }
            raw[3 + TLSH_CODE - 1 - i] = (unsigned char)value;
        }
        q_ratios = (unsigned)((uint64_t)q1 * 100 / q3 % 16) | ((unsigned)((uint64_t)q2 * 100 / q3 % 16) << 4);
        raw[0] = swap_nibbles(checksum);
        raw[1] = swap_nibbles(tlsh_length_code(length));
        raw[2] = swap_nibbles((unsigned char)q_ratios);
    }
    out[0] = 'T';
    out[1] = '1';
    for (i = 0; i < sizeof raw; i++) {
        out[2 + 2 * i] = HEX[raw[i] >> 4];
        out[3 + 2 * i] = HEX[raw[i] & 0x0F];
    }
    out[72] = '\0';
    return 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int tlsh_parse(const char *digest, unsigned char raw[35]) {
    size_t length, i;
    if (digest == NULL) return -1;
    length = strlen(digest);
    if (length == 72 && digest[0] == 'T' && digest[1] == '1') {
        digest += 2;
    } else if (length != 70) {
        return -1;
    }
    for (i = 0; i < 35; i++) {
        int high = hex_value(digest[2 * i]), low = hex_value(digest[2 * i + 1]);
        if (high < 0 || low < 0) return -1;
        raw[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int mod_diff(int left, int right, int size) {
    int near = left > right ? left - right : right - left;
    return near < size - near ? near : size - near;
}

int gi_tlsh_distance(const char *left, const char *right) {
    unsigned char a[35], b[35];
    int distance = 0, step, i, shift;
    if (tlsh_parse(left, a) != 0 || tlsh_parse(right, b) != 0) {
        return -1;
    }
    step = mod_diff(swap_nibbles(a[1]), swap_nibbles(b[1]), 256);
    distance += step <= 1 ? step : step * 12;
    step = mod_diff(swap_nibbles(a[2]) & 0x0F, swap_nibbles(b[2]) & 0x0F, 16);
    distance += step <= 1 ? step : (step - 1) * 12;
    step = mod_diff(swap_nibbles(a[2]) >> 4, swap_nibbles(b[2]) >> 4, 16);
    distance += step <= 1 ? step : (step - 1) * 12;
    distance += a[0] != b[0];
    for (i = 3; i < 35; i++) {
        for (shift = 0; shift < 8; shift += 2) {
            int x = (a[i] >> shift) & 3, y = (b[i] >> shift) & 3;
            step = x > y ? x - y : y - x;
            distance += step == 3 ? 6 : step;
        }
    }
    return distance;
}

/* ------------------------------------------------------------------------ */
/* ssdeep                                                                    */

#define SPAMSUM_LENGTH 64
#define MIN_BLOCKSIZE 3u
#define ROLLING_WINDOW 7
#define HASH_INIT 0x27u

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned fnv6(unsigned state, unsigned char value) {
    return ((state * 0x93u) ^ value) & 0x3Fu;
}

/* One pass at block_size and 2 * block_size. Returns the first digest length. */
static size_t block_digests(const unsigned char *data, size_t length, uint64_t block_size,
                            char first[SPAMSUM_LENGTH + 1], char second[SPAMSUM_LENGTH / 2 + 1]) {
    unsigned char window[ROLLING_WINDOW] = {0};
    uint32_t h1 = 0, h2 = 0, h3 = 0, rolling;
    unsigned hash_a = HASH_INIT, hash_b = HASH_INIT;
    size_t first_len = 0, second_len = 0, i;
    char first_last = 0, second_last = 0;
    unsigned position = 0;
    uint64_t twice = block_size * 2;

    for (i = 0; i < length; i++) {
        unsigned char value = data[i];
        h2 = h2 - h1 + ROLLING_WINDOW * (uint32_t)value;
        h1 = h1 + value - window[position];
        window[position] = value;
        position = position + 1 < ROLLING_WINDOW ? position + 1 : 0;
        h3 = (h3 << 5) ^ value;
        rolling = h1 + h2 + h3;
        hash_a = fnv6(hash_a, value);
        hash_b = fnv6(hash_b, value);
        if (rolling % block_size == block_size - 1) {
            if (first_len < SPAMSUM_LENGTH - 1) {
                first[first_len++] = B64[hash_a];
                hash_a = HASH_INIT;
            } else {
                first_last = B64[hash_a];
            }
            if (rolling % twice == twice - 1) {
                if (second_len < SPAMSUM_LENGTH / 2 - 1) {
                    second[second_len++] = B64[hash_b];
                    hash_b = HASH_INIT;
                } else {
                    second_last = B64[hash_b];
                }
            }
        }
    }
    rolling = h1 + h2 + h3;
    if (rolling != 0) {
        first[first_len++] = B64[hash_a];
        second[second_len++] = B64[hash_b];
    } else {
        if (first_last) first[first_len++] = first_last;
        if (second_last) second[second_len++] = second_last;
    }
    first[first_len] = '\0';
    second[second_len] = '\0';
    return first_len;
}

int gi_ssdeep(const unsigned char *data, size_t length, char *out, size_t capacity) {
    char first[SPAMSUM_LENGTH + 1], second[SPAMSUM_LENGTH / 2 + 1];
    uint64_t block_size = MIN_BLOCKSIZE;
    size_t first_len;
    if (out == NULL || capacity < 148 || (data == NULL && length > 0)) {
        return -1;
    }
    while (block_size * SPAMSUM_LENGTH < length) {
        block_size *= 2;
    }
    for (;;) {
        first_len = block_digests(data, length, block_size, first, second);
        if (block_size > MIN_BLOCKSIZE && first_len < SPAMSUM_LENGTH / 2) {
            block_size /= 2;
            continue;
        }
        break;
    }
    {
        /* Build "<bs>:<first>:<second>" without stdio. */
        char number[24];
        size_t digits = 0, used = 0, i;
        uint64_t value = block_size;
        do {
            number[digits++] = (char)('0' + value % 10);
            value /= 10;
        } while (value);
        while (digits) out[used++] = number[--digits];
        out[used++] = ':';
        for (i = 0; first[i]; i++) out[used++] = first[i];
        out[used++] = ':';
        for (i = 0; second[i]; i++) out[used++] = second[i];
        out[used] = '\0';
    }
    return 0;
}

static int b64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

/* Parses "<bs>:<a>:<b>" and collapses runs longer than three characters. */
static int ssdeep_parse(const char *digest, uint64_t *block_size, char a[SPAMSUM_LENGTH + 1], char b[SPAMSUM_LENGTH + 1]) {
    const char *p = digest;
    char *parts[2] = {a, b};
    int part, digits = 0;
    if (p == NULL) return -1;
    *block_size = 0;
    while (*p >= '0' && *p <= '9') {
        if (++digits > 10) return -1;
        *block_size = *block_size * 10 + (uint64_t)(*p++ - '0');
    }
    if (digits == 0 || *p++ != ':') return -1;
    for (part = 0; part < 2; part++) {
        size_t used = 0;
        while (*p && *p != ':' && *p != ',') {
            if (!b64_char(*p) || used >= SPAMSUM_LENGTH) return -1;
            if (used >= 3 && parts[part][used - 1] == *p && parts[part][used - 2] == *p && parts[part][used - 3] == *p) {
                p++;
                continue;
            }
            parts[part][used++] = *p++;
        }
        parts[part][used] = '\0';
        if (part == 0) {
            if (*p++ != ':') return -1;
        } else if (*p != '\0' && *p != ',') {
            return -1;
        }
    }
    return 0;
}

static int has_common_window(const char *left, size_t left_len, const char *right, size_t right_len) {
    size_t i, j;
    for (i = 0; i + ROLLING_WINDOW <= left_len; i++) {
        for (j = 0; j + ROLLING_WINDOW <= right_len; j++) {
            if (memcmp(left + i, right + j, ROLLING_WINDOW) == 0) return 1;
        }
    }
    return 0;
}

static int weighted_edit_distance(const char *left, size_t left_len, const char *right, size_t right_len) {
    int previous[SPAMSUM_LENGTH + 1], current[SPAMSUM_LENGTH + 1];
    size_t row, column;
    for (column = 0; column <= right_len; column++) previous[column] = (int)column;
    for (row = 1; row <= left_len; row++) {
        current[0] = (int)row;
        for (column = 1; column <= right_len; column++) {
            int best = previous[column] + 1;
            int insert = current[column - 1] + 1;
            int replace = previous[column - 1] + (left[row - 1] == right[column - 1] ? 0 : 2);
            if (insert < best) best = insert;
            if (replace < best) best = replace;
            current[column] = best;
        }
        memcpy(previous, current, sizeof(int) * (right_len + 1));
    }
    return previous[right_len];
}

static int score_strings(const char *left, const char *right, uint64_t block_size) {
    size_t left_len = strlen(left), right_len = strlen(right);
    int score;
    uint64_t cap;
    if (left_len < ROLLING_WINDOW || right_len < ROLLING_WINDOW) return 0;
    if (!has_common_window(left, left_len, right, right_len)) return 0;
    score = weighted_edit_distance(left, left_len, right, right_len) * SPAMSUM_LENGTH / (int)(left_len + right_len);
    score = 100 - (100 * score) / SPAMSUM_LENGTH;
    if (block_size >= (99 + ROLLING_WINDOW) / ROLLING_WINDOW * MIN_BLOCKSIZE) return score;
    cap = block_size / MIN_BLOCKSIZE * (left_len < right_len ? left_len : right_len);
    return (uint64_t)score > cap ? (int)cap : score;
}

int gi_ssdeep_compare(const char *left, const char *right) {
    char a1[SPAMSUM_LENGTH + 1], a2[SPAMSUM_LENGTH + 1], b1[SPAMSUM_LENGTH + 1], b2[SPAMSUM_LENGTH + 1];
    uint64_t size_a, size_b;
    int one, two;
    if (ssdeep_parse(left, &size_a, a1, a2) != 0 || ssdeep_parse(right, &size_b, b1, b2) != 0) {
        return -1;
    }
    if (size_a != size_b && size_a != size_b * 2 && size_b != size_a * 2) return 0;
    if (size_a == size_b && strcmp(a1, b1) == 0 && strcmp(a2, b2) == 0) return 100;
    if (size_a == size_b) {
        one = score_strings(a1, b1, size_a);
        two = score_strings(a2, b2, size_a * 2);
        return one > two ? one : two;
    }
    if (size_a == size_b * 2) return score_strings(a1, b2, size_a);
    return score_strings(a2, b1, size_b);
}
