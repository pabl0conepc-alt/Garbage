//! Typosquatting candidates for one domain label.
//!
//! Generates the spellings an attacker registers to catch mistyped or
//! misread names: omission, repetition, adjacent transposition, QWERTY
//! neighbour replacement and insertion, ASCII homoglyphs, hyphenation, vowel
//! swap, bit flips, appended characters and a dot that turns a prefix into a
//! subdomain. Only DNS letter-digit-hyphen labels are produced. Pure and
//! bounded: no DNS, files or network. `garbage_intel.modules.typosquat`
//! holds the identical Python reference.

use core::slice;
use std::collections::BTreeSet;

pub const OMISSION: u8 = 1;
pub const REPETITION: u8 = 2;
pub const TRANSPOSITION: u8 = 3;
pub const REPLACEMENT: u8 = 4;
pub const INSERTION: u8 = 5;
pub const HOMOGLYPH: u8 = 6;
pub const HYPHENATION: u8 = 7;
pub const VOWEL_SWAP: u8 = 8;
pub const BITSQUATTING: u8 = 9;
pub const ADDITION: u8 = 10;
pub const SUBDOMAIN: u8 = 11;

const MAX_LABEL: usize = 63;
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const VOWELS: &[u8] = b"aeiou";
const KEYBOARD: [&[u8]; 4] = [b"1234567890", b"qwertyuiop", b"asdfghjkl", b"zxcvbnm"];
// Single-character look-alikes and multi-character ones (rn/m, vv/w, cl/d).
const GLYPHS: [(&[u8], &[u8]); 14] = [
    (b"o", b"0"), (b"0", b"o"), (b"l", b"1"), (b"1", b"l"), (b"i", b"1"), (b"i", b"l"), (b"l", b"i"),
    (b"m", b"rn"), (b"rn", b"m"), (b"w", b"vv"), (b"vv", b"w"), (b"d", b"cl"), (b"cl", b"d"), (b"e", b"3"),
];

fn neighbours(key: u8) -> Vec<u8> {
    let mut found = Vec::new();
    for (row_index, row) in KEYBOARD.iter().enumerate() {
        if let Some(column) = row.iter().position(|&item| item == key) {
            if column > 0 {
                found.push(row[column - 1]);
            }
            if column + 1 < row.len() {
                found.push(row[column + 1]);
            }
            for other in [row_index.wrapping_sub(1), row_index + 1] {
                if let Some(next) = KEYBOARD.get(other) {
                    for offset in [column.wrapping_sub(1), column, column + 1] {
                        if let Some(&item) = next.get(offset) {
                            found.push(item);
                        }
                    }
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn valid(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label[0] != b'-'
        && label[label.len() - 1] != b'-'
        && label.iter().all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn splice(label: &[u8], start: usize, end: usize, middle: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + middle.len());
    out.extend_from_slice(&label[..start]);
    out.extend_from_slice(middle);
    out.extend_from_slice(&label[end..]);
    out
}

/// Candidates as (kind, spelling), sorted and without the original.
pub fn generate(label: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let label: Vec<u8> = label.iter().map(|byte| byte.to_ascii_lowercase()).collect();
    if !valid(&label) {
        return Vec::new();
    }
    let mut out: BTreeSet<(u8, Vec<u8>)> = BTreeSet::new();
    let mut add = |kind: u8, candidate: Vec<u8>| {
        if candidate != label && (kind == SUBDOMAIN || valid(&candidate)) {
            out.insert((kind, candidate));
        }
    };
    let length = label.len();
    for index in 0..length {
        let byte = label[index];
        add(OMISSION, splice(&label, index, index + 1, b""));
        add(REPETITION, splice(&label, index, index, &[byte]));
        if index + 1 < length && label[index + 1] != byte {
            add(TRANSPOSITION, splice(&label, index, index + 2, &[label[index + 1], byte]));
        }
        for near in neighbours(byte) {
            add(REPLACEMENT, splice(&label, index, index + 1, &[near]));
            add(INSERTION, splice(&label, index, index, &[near]));
            add(INSERTION, splice(&label, index + 1, index + 1, &[near]));
        }
        if index > 0 && byte != b'-' && label[index - 1] != b'-' {
            add(HYPHENATION, splice(&label, index, index, b"-"));
        }
        if VOWELS.contains(&byte) {
            for &vowel in VOWELS {
                if vowel != byte {
                    add(VOWEL_SWAP, splice(&label, index, index + 1, &[vowel]));
                }
            }
        }
        for bit in 0..8 {
            let flipped = byte ^ (1 << bit);
            if flipped.is_ascii_lowercase() || flipped.is_ascii_digit() || flipped == b'-' {
                add(BITSQUATTING, splice(&label, index, index + 1, &[flipped]));
            }
        }
        if index > 0 && byte != b'-' && label[index - 1] != b'-' {
            add(SUBDOMAIN, splice(&label, index, index, b"."));
        }
    }
    for (from, to) in GLYPHS {
        let mut start = 0;
        while start + from.len() <= length {
            if &label[start..start + from.len()] == from {
                add(HOMOGLYPH, splice(&label, start, start + from.len(), to));
            }
            start += 1;
        }
    }
    for &extra in ALPHABET {
        add(ADDITION, splice(&label, length, length, &[extra]));
    }
    out.into_iter().collect()
}

/// C ABI: writes "kind<TAB>candidate<LF>" records to `out`; `written`
/// receives the bytes needed. Returns 0, -1 for invalid arguments and -2
/// when `capacity` is too small.
#[no_mangle]
pub extern "C" fn gi_typosquat(
    label: *const u8,
    length: usize,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if label.is_null() || written.is_null() || length == 0 || length > MAX_LABEL || (out.is_null() && capacity > 0) {
        return -1;
    }
    // SAFETY: the caller provides `length` readable bytes for this call.
    let input = unsafe { slice::from_raw_parts(label, length) };
    let mut buffer = Vec::new();
    for (kind, candidate) in generate(input) {
        buffer.extend_from_slice(kind.to_string().as_bytes());
        buffer.push(b'\t');
        buffer.extend_from_slice(&candidate);
        buffer.push(b'\n');
    }
    // SAFETY: `written` is non-null per the check above.
    unsafe { *written = buffer.len() };
    if buffer.len() > capacity {
        return -2;
    }
    // SAFETY: `out` holds at least `capacity` >= buffer.len() bytes.
    unsafe { slice::from_raw_parts_mut(out, buffer.len()) }.copy_from_slice(&buffer);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(list: &[(u8, Vec<u8>)], kind: u8, text: &str) -> bool {
        list.iter().any(|(k, c)| *k == kind && c == text.as_bytes())
    }

    #[test]
    fn covers_each_kind() {
        let list = generate(b"google");
        assert!(has(&list, OMISSION, "gogle"));
        assert!(has(&list, REPETITION, "gooogle"));
        assert!(has(&list, TRANSPOSITION, "googel"));
        assert!(has(&list, REPLACEMENT, "goofle"));
        assert!(has(&list, HOMOGLYPH, "g0ogle"));
        assert!(has(&list, HYPHENATION, "goo-gle"));
        assert!(has(&list, VOWEL_SWAP, "gaogle"));
        assert!(has(&list, BITSQUATTING, "coogle"));
        assert!(has(&list, ADDITION, "googlea"));
        assert!(has(&list, SUBDOMAIN, "goo.gle"));
        assert!(!list.iter().any(|(_, c)| c == b"google"));
        assert!(has(&generate(b"modern"), HOMOGLYPH, "rnodern"));
    }

    #[test]
    fn rejects_invalid_labels() {
        assert!(generate(b"").is_empty());
        assert!(generate(b"-bad").is_empty());
        assert!(generate(b"has.dot").is_empty());
    }
}
