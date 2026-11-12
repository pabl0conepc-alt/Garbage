/* Optional C helpers for bounded file-intelligence scans. */
#include "garbage_native.h"

#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define GI_MAX_PHDRS 128u
#define GI_MAX_SHDRS 256u
#define GI_MAX_DYNAMIC 4096u
#define GI_MAX_NAME 96u

static int read_u16(const unsigned char *data, size_t length, size_t offset,
                    int little, uint16_t *out) {
    if (offset > length || length - offset < 2u) {
        return 0;
    }
    if (little) {
        *out = (uint16_t)data[offset] | ((uint16_t)data[offset + 1u] << 8);
    } else {
        *out = ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1u];
    }
    return 1;
}

static int read_u32(const unsigned char *data, size_t length, size_t offset,
                    int little, uint32_t *out) {
    if (offset > length || length - offset < 4u) {
        return 0;
    }
    if (little) {
        *out = (uint32_t)data[offset] |
               ((uint32_t)data[offset + 1u] << 8) |
               ((uint32_t)data[offset + 2u] << 16) |
               ((uint32_t)data[offset + 3u] << 24);
    } else {
        *out = ((uint32_t)data[offset] << 24) |
               ((uint32_t)data[offset + 1u] << 16) |
               ((uint32_t)data[offset + 2u] << 8) |
               (uint32_t)data[offset + 3u];
    }
    return 1;
}

static int read_u64(const unsigned char *data, size_t length, size_t offset,
                    int little, uint64_t *out) {
    uint32_t high = 0;
    uint32_t low = 0;
    if (offset > length) {
        return 0;
    }
    if (!read_u32(data, length, offset + (little ? 4u : 0u), little, &high) ||
        !read_u32(data, length, offset + (little ? 0u : 4u), little, &low)) {
        return 0;
    }
    *out = ((uint64_t)high << 32) | low;
    return 1;
}

static int contains_text(const unsigned char *data, size_t length,
                         const char *needle) {
    size_t needle_length = strlen(needle);
    size_t index;
    if (needle_length == 0 || needle_length > length) {
        return 0;
    }
    for (index = 0; index + needle_length <= length; index++) {
        if (memcmp(data + index, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

uint32_t gi_native_abi_version(void) {
    return GI_NATIVE_ABI_VERSION;
}

int gi_entropy(const unsigned char *data, size_t length, double *out_entropy) {
    uint64_t counts[256] = {0};
    double entropy = 0.0;
    size_t index;
    if (out_entropy == NULL) {
        return -1;
    }
    if (data == NULL && length != 0u) {
        return -2;
    }
    if (length == 0u) {
        *out_entropy = 0.0;
        return 0;
    }
    for (index = 0; index < length; index++) {
        counts[data[index]]++;
    }
    for (index = 0; index < 256u; index++) {
        if (counts[index] != 0u) {
            double probability = (double)counts[index] / (double)length;
            entropy -= probability * (log(probability) / log(2.0));
        }
    }
    *out_entropy = entropy;
    return 0;
}

static int elf_scan(const unsigned char *data, size_t length,
                    gi_hardening *out) {
    uint16_t e_type = 0;
    uint16_t e_machine = 0;
    uint16_t phentsize = 0;
    uint16_t phnum = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;
    uint16_t shstrndx = 0;
    uint64_t phoff = 0;
    uint64_t shoff = 0;
    int bits = data[4] == 2 ? 64 : 32;
    int little = data[5] == 1;
    int has_interp = 0;
    int has_stack = 0;
    int exec_stack = 0;
    int has_relro = 0;
    int bind_now = 0;
    int symbol_table = 0;
    size_t header_size = bits == 64 ? 64u : 52u;
    uint64_t shstr_offset = 0;
    uint64_t shstr_size = 0;
    unsigned index;

    if (length < header_size || memcmp(data, "\x7f" "ELF", 4) != 0) {
        return -2;
    }
    if (!read_u16(data, length, 16u, little, &e_type) ||
        !read_u16(data, length, 18u, little, &e_machine)) {
        return -2;
    }
    if (bits == 64) {
        if (!read_u64(data, length, 32u, little, &phoff) ||
            !read_u64(data, length, 40u, little, &shoff)) {
            return -2;
        }
    } else {
        uint32_t value = 0;
        if (!read_u32(data, length, 28u, little, &value)) {
            return -2;
        }
        phoff = value;
        if (!read_u32(data, length, 32u, little, &value)) {
            return -2;
        }
        shoff = value;
    }
    if (!read_u16(data, length, bits == 64 ? 54u : 42u, little, &phentsize) ||
        !read_u16(data, length, bits == 64 ? 56u : 44u, little, &phnum) ||
        !read_u16(data, length, bits == 64 ? 58u : 46u, little, &shentsize) ||
        !read_u16(data, length, bits == 64 ? 60u : 48u, little, &shnum) ||
        !read_u16(data, length, bits == 64 ? 62u : 50u, little, &shstrndx)) {
        return -2;
    }

    if (phoff > length) {
        phoff = 0;
    }
    if (shoff > length) {
        shoff = 0;
    }
    if (phoff != 0u && phnum != 0u && phentsize >= (bits == 64 ? 56u : 32u)) {
        for (index = 0; index < phnum && index < GI_MAX_PHDRS; index++) {
            size_t base = (size_t)phoff + (size_t)index * phentsize;
            uint32_t type = 0;
            uint32_t flags = 0;
            uint64_t offset = 0;
            uint64_t file_size = 0;
            if (base > length || length - base < phentsize) {
                break;
            }
            if (!read_u32(data, length, base, little, &type) ||
                !read_u32(data, length, base + 4u, little, &flags)) {
                break;
            }
            if (bits == 64) {
                if (!read_u64(data, length, base + 8u, little, &offset) ||
                    !read_u64(data, length, base + 32u, little, &file_size)) {
                    continue;
                }
            } else {
                uint32_t value = 0;
                if (!read_u32(data, length, base + 4u, little, &value)) {
                    continue;
                }
                offset = value;
                if (!read_u32(data, length, base + 16u, little, &value)) {
                    continue;
                }
                file_size = value;
            }
            if (type == 3u) {
                has_interp = 1;
            } else if (type == 0x6474e551u) {
                has_stack = 1;
                if (flags & 1u) {
                    exec_stack = 1;
                }
            } else if (type == 0x6474e552u) {
                has_relro = 1;
            } else if (type == 2u && offset < length) {
                uint64_t available = (uint64_t)length - offset;
                uint64_t size = file_size < available ? file_size : available;
                uint64_t dynamic_entries = size / (uint64_t)(bits == 64 ? 16 : 8);
                uint64_t entry;
                unsigned limit = dynamic_entries > GI_MAX_DYNAMIC
                                     ? GI_MAX_DYNAMIC
                                     : (unsigned)dynamic_entries;
                for (entry = 0; entry < limit; entry++) {
                    size_t base_entry =
                        (size_t)offset +
                        (size_t)entry * (size_t)(bits == 64 ? 16 : 8);
                    uint32_t tag = 0;
                    uint64_t value = 0;
                    if (bits == 64) {
                        if (!read_u32(data, length, base_entry, little, &tag) ||
                            !read_u64(data, length, base_entry + 8u, little,
                                      &value)) {
                            break;
                        }
                    } else {
                        uint32_t raw = 0;
                        if (!read_u32(data, length, base_entry, little, &tag) ||
                            !read_u32(data, length, base_entry + 4u, little,
                                      &raw)) {
                            break;
                        }
                        value = raw;
                    }
                    if (tag == 0u) {
                        break;
                    }
                    if (tag == 24u) {
                        bind_now = 1;
                    } else if (tag == 30u && (value & 8u) != 0u) {
                        bind_now = 1;
                    } else if (tag == 0x6ffffffbu && (value & 1u) != 0u) {
                        bind_now = 1;
                    }
                }
            }
        }
    }

    if (shoff != 0u && shnum != 0u && shentsize >= (bits == 64 ? 64u : 40u) &&
        shstrndx < shnum && shstrndx < GI_MAX_SHDRS) {
        size_t string_header =
            (size_t)shoff + (size_t)shstrndx * shentsize;
        if (string_header <= length && length - string_header >= shentsize) {
            if (bits == 64) {
                (void)read_u64(data, length, string_header + 24u, little,
                               &shstr_offset);
                (void)read_u64(data, length, string_header + 32u, little,
                               &shstr_size);
            } else {
                uint32_t value = 0;
                (void)read_u32(data, length, string_header + 16u, little,
                               &value);
                shstr_offset = value;
                (void)read_u32(data, length, string_header + 20u, little,
                               &value);
                shstr_size = value;
            }
        }
        if (shstr_offset < length && shstr_size != 0u) {
            uint64_t available = (uint64_t)length - shstr_offset;
            uint64_t table_size = shstr_size < available ? shstr_size : available;
            for (index = 0; index < shnum && index < GI_MAX_SHDRS; index++) {
                size_t base = (size_t)shoff + (size_t)index * shentsize;
                uint32_t name_offset = 0;
                if (base > length || length - base < shentsize) {
                    break;
                }
                if (!read_u32(data, length, base, little, &name_offset)) {
                    break;
                }
                if ((uint64_t)name_offset < table_size) {
                    size_t name_base = (size_t)shstr_offset + name_offset;
                    size_t remaining =
                        (size_t)table_size - (size_t)name_offset;
                    size_t name_length = 0;
                    while (name_length < remaining &&
                           name_length < GI_MAX_NAME &&
                           data[name_base + name_length] != '\0') {
                        name_length++;
                    }
                    if (name_length == 7u &&
                        memcmp(data + name_base, ".symtab", 7u) == 0) {
                        symbol_table = 1;
                    }
                }
            }
        }
    }

    out->flags = 0u;
    out->relro = GI_RELRO_NONE;
    out->stack = GI_STACK_UNKNOWN;
    out->section_count = shnum;
    out->symbol_table = (uint32_t)symbol_table;
    if (e_type == 3u && has_interp) {
        out->flags |= GI_HARDEN_PIE;
    }
    if (has_stack) {
        out->stack = exec_stack ? GI_STACK_EXECUTABLE : GI_STACK_NX;
        if (!exec_stack) {
            out->flags |= GI_HARDEN_NX;
        } else {
            out->flags |= GI_HARDEN_EXEC_STACK;
        }
    }
    if (has_relro) {
        out->relro = bind_now ? GI_RELRO_FULL : GI_RELRO_PARTIAL;
        out->flags |= GI_HARDEN_RELRO;
    }
    if (bind_now) {
        out->flags |= GI_HARDEN_BIND_NOW;
    }
    if (contains_text(data, length, "__stack_chk_fail")) {
        out->flags |= GI_HARDEN_CANARY;
    }
    if (contains_text(data, length, "__fortify_fail") ||
        contains_text(data, length, "__chk_fail")) {
        out->flags |= GI_HARDEN_FORTIFY;
    }
    if (!symbol_table) {
        out->flags |= GI_HARDEN_STRIPPED;
    }
    out->format = GI_FORMAT_ELF;
    out->bits = (uint32_t)bits;
    if (bits == 64) {
        snprintf(out->detail, sizeof(out->detail),
                 "ELF64 %s-endian, machine %u", little ? "little" : "big",
                 (unsigned)e_machine);
    } else {
        snprintf(out->detail, sizeof(out->detail),
                 "ELF32 %s-endian, machine %u", little ? "little" : "big",
                 (unsigned)e_machine);
    }
    return 0;
}

static int pe_scan(const unsigned char *data, size_t length, gi_hardening *out) {
    uint32_t pe_offset = 0;
    uint16_t machine = 0;
    uint16_t section_count = 0;
    uint16_t optional_size = 0;
    uint16_t magic = 0;
    uint16_t dll_characteristics = 0;
    uint32_t reloc_rva = 0;
    uint32_t reloc_size = 0;
    int bits;
    size_t optional_offset;
    size_t directory_base;

    if (length < 64u || data[0] != 'M' || data[1] != 'Z') {
        return -2;
    }
    if (!read_u32(data, length, 0x3cu, 1, &pe_offset) ||
        pe_offset > length || length - pe_offset < 24u ||
        memcmp(data + pe_offset, "PE\0\0", 4) != 0) {
        return -2;
    }
    if (!read_u16(data, length, pe_offset + 4u, 1, &machine) ||
        !read_u16(data, length, pe_offset + 6u, 1, &section_count) ||
        !read_u16(data, length, pe_offset + 20u, 1, &optional_size)) {
        return -2;
    }
    optional_offset = (size_t)pe_offset + 24u;
    if (optional_size < 72u || optional_offset > length ||
        length - optional_offset < 72u ||
        !read_u16(data, length, optional_offset, 1, &magic)) {
        return -2;
    }
    bits = magic == 0x20b ? 64 : 32;
    if (!read_u16(data, length, optional_offset + 70u, 1,
                  &dll_characteristics)) {
        return -2;
    }
    directory_base = optional_offset + (bits == 64 ? 112u : 96u);
    if (directory_base <= length && length - directory_base >= 40u) {
        (void)read_u32(data, length, directory_base + 5u * 8u, 1, &reloc_rva);
        (void)read_u32(data, length, directory_base + 5u * 8u + 4u, 1,
                       &reloc_size);
    }

    out->flags = 0u;
    out->relro = GI_RELRO_NONE;
    out->stack = GI_STACK_UNKNOWN;
    out->section_count = section_count;
    out->symbol_table = 0u;
    if ((dll_characteristics & 0x0040u) != 0u) {
        out->flags |= GI_HARDEN_ASLR;
    }
    if ((dll_characteristics & 0x0100u) != 0u) {
        out->flags |= GI_HARDEN_NX;
        out->stack = GI_STACK_NX;
    }
    if ((dll_characteristics & 0x0400u) != 0u) {
        out->flags |= GI_HARDEN_CFG;
    }
    if ((dll_characteristics & 0x0020u) != 0u) {
        out->flags |= GI_HARDEN_HIGH_ENTROPY_VA;
    }
    if (reloc_rva != 0u && reloc_size != 0u) {
        out->flags |= GI_HARDEN_RELOCATIONS;
    }
    if (contains_text(data, length, "__security_check_cookie") ||
        contains_text(data, length, "__GSHandlerCheck")) {
        out->flags |= GI_HARDEN_CANARY;
    }
    out->format = GI_FORMAT_PE;
    out->bits = (uint32_t)bits;
    snprintf(out->detail, sizeof(out->detail), "PE%s, machine 0x%04x",
             bits == 64 ? "32+" : "32", (unsigned)machine);
    return 0;
}

int gi_hardening_scan(const unsigned char *data, size_t length, int format,
                      gi_hardening *out) {
    if (data == NULL || out == NULL || length == 0u) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->abi_version = GI_NATIVE_ABI_VERSION;
    if (format == GI_FORMAT_ELF) {
        return elf_scan(data, length, out);
    }
    if (format == GI_FORMAT_PE) {
        return pe_scan(data, length, out);
    }
    return -2;
}
