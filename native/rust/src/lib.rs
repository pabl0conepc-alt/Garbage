//! Optional Rust string-similarity helpers for domain lookalike analysis.
//!
//! The exported functions are pure and allocation-bounded. They never resolve
//! DNS, open files, touch the network or execute input.

use core::slice;

const MAX_INPUT: usize = 253;
const ABI_VERSION: u32 = 1;

#[inline]
fn fold(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + 32
    } else {
        byte
    }
}

#[inline]
fn bytes_at(pointer: *const u8, length: usize) -> Option<&'static [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if pointer.is_null() || length > MAX_INPUT {
        return None;
    }
    // SAFETY: the caller promises a readable buffer of `length` bytes. The
    // function only reads for the duration of the call and copies no pointers.
    Some(unsafe { slice::from_raw_parts(pointer, length) })
}

/// Optimal-string-alignment Damerau-Levenshtein distance over ASCII bytes.
///
/// Returns the distance, or `max_distance + 1` when it is certainly larger
/// than the requested bound. Returns -1 for invalid pointers or oversized
/// input.
#[no_mangle]
pub extern "C" fn gi_domain_distance(
    left: *const u8,
    left_length: usize,
    right: *const u8,
    right_length: usize,
    max_distance: u32,
) -> i32 {
    let left = match bytes_at(left, left_length) {
        Some(value) => value,
        None => return -1,
    };
    let right = match bytes_at(right, right_length) {
        Some(value) => value,
        None => return -1,
    };
    let max_distance = max_distance.min(MAX_INPUT as u32) as usize;
    if left.len().abs_diff(right.len()) > max_distance {
        return (max_distance + 1) as i32;
    }
    if left == right {
        return 0;
    }
    if left.is_empty() {
        return right.len() as i32;
    }
    if right.is_empty() {
        return left.len() as i32;
    }

    let width = right.len() + 1;
    let mut previous_previous = vec![0u32; width];
    let mut previous = vec![0u32; width];
    let mut current = vec![0u32; width];
    for column in 0..width {
        previous[column] = column as u32;
    }

    for row in 1..=left.len() {
        current[0] = row as u32;
        let mut row_minimum = current[0];
        for column in 1..=right.len() {
            let substitution = if fold(left[row - 1]) == fold(right[column - 1]) {
                0
            } else {
                1
            };
            let mut value = (previous[column] + 1)
                .min(current[column - 1] + 1)
                .min(previous[column - 1] + substitution);
            if row > 1
                && column > 1
                && fold(left[row - 1]) == fold(right[column - 2])
                && fold(left[row - 2]) == fold(right[column - 1])
            {
                value = value.min(previous_previous[column - 2] + 1);
            }
            current[column] = value;
            row_minimum = row_minimum.min(value);
        }
        if row_minimum as usize > max_distance {
            return (max_distance + 1) as i32;
        }
        core::mem::swap(&mut previous_previous, &mut previous);
        core::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()] as i32
}

/// Writes a bounded skeleton that folds common digit substitutions and removes
/// hyphens. This is a comparison aid, not a claim that two domains are related.
///
/// Returns the skeleton length, -1 for invalid pointers, or -2 when the output
/// buffer is too small.
#[no_mangle]
pub extern "C" fn gi_domain_skeleton(
    input: *const u8,
    input_length: usize,
    output: *mut u8,
    output_capacity: usize,
) -> i32 {
    let input = match bytes_at(input, input_length) {
        Some(value) => value,
        None => return -1,
    };
    if output.is_null() || output_capacity == 0 {
        return -1;
    }
    let mut written = 0usize;
    for &raw in input {
        let byte = fold(raw);
        if byte == b'-' {
            continue;
        }
        let folded = match byte {
            b'0' => b'o',
            b'1' => b'l',
            b'3' => b'e',
            b'4' => b'a',
            b'5' => b's',
            b'7' => b't',
            b'9' => b'g',
            other => other,
        };
        if written >= output_capacity {
            return -2;
        }
        // SAFETY: `output` is non-null and `written < output_capacity`.
        unsafe {
            *output.add(written) = folded;
        }
        written += 1;
    }
    written as i32
}

#[no_mangle]
pub extern "C" fn gi_rust_abi_version() -> u32 {
    ABI_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_handles_typos_and_transpositions() {
        assert_eq!(gi_domain_distance(b"paypal".as_ptr(), 6, b"paypa1".as_ptr(), 6, 2), 1);
        assert_eq!(gi_domain_distance(b"google".as_ptr(), 6, b"googel".as_ptr(), 6, 2), 1);
        assert_eq!(gi_domain_distance(b"example".as_ptr(), 7, b"example".as_ptr(), 7, 0), 0);
        assert_eq!(gi_domain_distance(b"a".as_ptr(), 1, b"abcdef".as_ptr(), 6, 2), 3);
    }

    #[test]
    fn skeleton_folds_digits_and_hyphens() {
        let mut output = [0u8; 32];
        let length = gi_domain_skeleton(b"pay-pa1.com".as_ptr(), 11, output.as_mut_ptr(), output.len());
        assert_eq!(&output[..length as usize], b"paypal.com");
    }
}
