/* Optional Rust similarity ABI. */
#ifndef GARBAGE_RUST_H
#define GARBAGE_RUST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t gi_rust_abi_version(void);

/* Returns the OSA Damerau-Levenshtein distance, max_distance + 1 when the
 * distance exceeds the bound, or -1 for invalid input. */
int32_t gi_domain_distance(const uint8_t *left, size_t left_length,
                           const uint8_t *right, size_t right_length,
                           uint32_t max_distance);

/* Returns the skeleton length, -1 for invalid pointers, -2 for a short output
 * buffer. */
int32_t gi_domain_skeleton(const uint8_t *input, size_t input_length,
                           uint8_t *output, size_t output_capacity);

typedef struct {
    uint64_t offset;
    uint32_t kind;  /* ids listed in garbage_intel/modules/embedded_scan.py */
    uint32_t extra;
} gi_signature;

/* Embedded signature scan. Writes the hits sorted by offset and sets *count.
 * Returns 0, 1 when the scan stopped at 65536 hits, -1 for invalid
 * arguments, -2 when capacity < *count. */
int32_t gi_signature_scan(const uint8_t *data, size_t length,
                          gi_signature *out, size_t capacity, size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* GARBAGE_RUST_H */
