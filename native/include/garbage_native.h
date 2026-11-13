/* Stable C ABI for the optional GARBAGE native file-intelligence helpers.
 *
 * The library is read-only: it never opens files, allocates caller-visible
 * memory, executes input, spawns processes or touches the network. Every
 * buffer length is explicit and every read is bounds-checked.
 */
#ifndef GARBAGE_NATIVE_H
#define GARBAGE_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GI_NATIVE_ABI_VERSION 1u

enum {
    GI_FORMAT_ELF = 1,
    GI_FORMAT_PE = 2
};

enum {
    GI_HARDEN_PIE = 1u << 0,
    GI_HARDEN_NX = 1u << 1,
    GI_HARDEN_RELRO = 1u << 2,
    GI_HARDEN_BIND_NOW = 1u << 3,
    GI_HARDEN_CANARY = 1u << 4,
    GI_HARDEN_FORTIFY = 1u << 5,
    GI_HARDEN_ASLR = 1u << 6,
    GI_HARDEN_CFG = 1u << 7,
    GI_HARDEN_HIGH_ENTROPY_VA = 1u << 8,
    GI_HARDEN_EXEC_STACK = 1u << 9,
    GI_HARDEN_STRIPPED = 1u << 10,
    GI_HARDEN_RELOCATIONS = 1u << 11
};

enum {
    GI_RELRO_NONE = 0,
    GI_RELRO_PARTIAL = 1,
    GI_RELRO_FULL = 2
};

enum {
    GI_STACK_UNKNOWN = 0,
    GI_STACK_NX = 1,
    GI_STACK_EXECUTABLE = 2
};

typedef struct {
    uint32_t abi_version;
    uint32_t format;
    uint32_t bits;
    uint32_t flags;
    uint32_t relro;
    uint32_t stack;
    uint32_t section_count;
    uint32_t symbol_table;
    char detail[192];
} gi_hardening;

/* Returns GI_NATIVE_ABI_VERSION. */
uint32_t gi_native_abi_version(void);

/* Shannon entropy over the supplied bytes. Returns 0 on success, -1 on a null
 * output pointer, -2 when data is null with a non-zero length. */
int gi_entropy(const unsigned char *data, size_t length, double *out_entropy);

/* Bounded ELF/PE hardening scan. Returns 0 on success, -1 for invalid
 * arguments, -2 for an unsupported or truncated format. */
int gi_hardening_scan(const unsigned char *data, size_t length, int format,
                      gi_hardening *out);

/* Similarity digests (garbage_fuzzy.c). gi_tlsh writes "T1" + 70 hex digits
 * (capacity >= 73) and returns 0, 1 when the input is too short or too
 * uniform for a digest, or -1 for invalid arguments. gi_ssdeep writes
 * "<block size>:<digest>:<digest>" (capacity >= 148) and returns 0 or -1. */
int gi_tlsh(const unsigned char *data, size_t length, char *out, size_t capacity);
int gi_ssdeep(const unsigned char *data, size_t length, char *out, size_t capacity);

/* TLSH distance (0 = identical digests) or ssdeep score (0-100); -1 when a
 * digest cannot be parsed. */
int gi_tlsh_distance(const char *left, const char *right);
int gi_ssdeep_compare(const char *left, const char *right);

#ifdef __cplusplus
}
#endif

#endif /* GARBAGE_NATIVE_H */
