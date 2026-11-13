//! Embedded signature scan (list-only, nothing is carved or extracted).
//!
//! Mirrors `garbage_intel/modules/embedded_scan.py`: same magic numbers, same
//! header checks, same kind ids and the same ordering and cap, so the Python
//! reference and this engine return identical lists.

use core::slice;

pub const SCAN_CAP: usize = 65536;
const MAX_SCAN_INPUT: usize = 64 * 1024 * 1024;
const ZIP_METHODS: [u16; 11] = [0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99];
const JPEG_MARKERS: [u8; 8] = [0xE0, 0xE1, 0xE2, 0xDB, 0xEE, 0xC0, 0xC4, 0xFE];
const LNK: [u8; 20] = [
    0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x46,
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct GiSignature {
    pub offset: u64,
    pub kind: u32,
    pub extra: u32,
}

#[inline]
fn u16le(d: &[u8], p: usize) -> u32 {
    d[p] as u32 | (d[p + 1] as u32) << 8
}

#[inline]
fn u16be(d: &[u8], p: usize) -> u32 {
    (d[p] as u32) << 8 | d[p + 1] as u32
}

#[inline]
fn u32le(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]])
}

#[inline]
fn u32be(d: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]])
}

#[inline]
fn at(d: &[u8], p: usize, magic: &[u8]) -> bool {
    d.len() >= p + magic.len() && &d[p..p + magic.len()] == magic
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Every (kind, extra) whose magic starts at `p`, in kind order.
fn check(d: &[u8], p: usize, out: &mut Vec<(usize, u32, usize, u32)>) {
    let n = d.len();
    let mut push = |kind: u32, offset: usize, extra: u32| out.push((p, kind, offset, extra));
    match d[p] {
        b'P' if at(d, p, b"PK\x03\x04") => {
            if p + 30 <= n && u16le(d, p + 4) <= 63 && ZIP_METHODS.contains(&(u16le(d, p + 8) as u16)) {
                let name = u16le(d, p + 26);
                if (1..=512).contains(&name) {
                    push(1, p, name);
                }
            }
        }
        0x1f if at(d, p, b"\x1f\x8b\x08") => {
            if p + 10 <= n && d[p + 3] & 0xE0 == 0 {
                push(2, p, 0);
            }
        }
        b'B' if at(d, p, b"BZh") => {
            if p + 10 <= n && (0x31..=0x39).contains(&d[p + 3]) && &d[p + 4..p + 10] == b"\x31\x41\x59\x26\x53\x59" {
                push(3, p, (d[p + 3] - 0x30) as u32);
            }
        }
        0xfd if at(d, p, b"\xfd7zXZ\x00") => {
            if p + 8 <= n && d[p + 6] == 0 && d[p + 7] & 0xF0 == 0 {
                push(4, p, 0);
            }
        }
        b'7' if at(d, p, b"7z\xbc\xaf\x27\x1c") => {
            if p + 8 <= n && d[p + 6] == 0 {
                push(5, p, d[p + 7] as u32);
            }
        }
        b'R' if at(d, p, b"Rar!\x1a\x07") => {
            if p + 7 <= n && (d[p + 6] == 0 || d[p + 6] == 1) {
                push(6, p, if d[p + 6] == 1 { 5 } else { 4 });
            }
        }
        0x28 if at(d, p, b"\x28\xb5\x2f\xfd") => {
            if p + 5 <= n && d[p + 4] & 0x08 == 0 {
                push(7, p, 0);
            }
        }
        b'M' if at(d, p, b"MSCF") => {
            if p + 26 <= n && &d[p + 4..p + 8] == b"\0\0\0\0" && u32le(d, p + 8) >= 36 && d[p + 24] == 3 && d[p + 25] == 1 {
                push(8, p, 0);
            }
        }
        b'M' if at(d, p, b"MZ") => {
            if p + 64 <= n {
                let header = u32le(d, p + 60) as usize;
                if (4..=0x1000).contains(&header) && p + header + 24 <= n && &d[p + header..p + header + 4] == b"PE\0\0" {
                    push(9, p, u16le(d, p + header + 4));
                }
            }
        }
        0x7f if at(d, p, b"\x7fELF") => {
            if p + 20 <= n && (d[p + 4] == 1 || d[p + 4] == 2) && (d[p + 5] == 1 || d[p + 5] == 2) && d[p + 6] == 1 {
                push(10, p, if d[p + 5] == 1 { u16le(d, p + 18) } else { u16be(d, p + 18) });
            }
        }
        0xfe | 0xce | 0xcf
            if at(d, p, b"\xfe\xed\xfa\xce")
                || at(d, p, b"\xfe\xed\xfa\xcf")
                || at(d, p, b"\xce\xfa\xed\xfe")
                || at(d, p, b"\xcf\xfa\xed\xfe") =>
        {
            if p + 8 <= n {
                let cpu = (if d[p] == 0xfe { u32be(d, p + 4) } else { u32le(d, p + 4) }) & 0xFFFFFF;
                if cpu == 7 || cpu == 12 || cpu == 18 {
                    push(11, p, cpu);
                }
            }
        }
        b'%' if at(d, p, b"%PDF-") => {
            if p + 8 <= n && d[p + 5].is_ascii_digit() && d[p + 6] == b'.' && d[p + 7].is_ascii_digit() {
                push(12, p, 0);
            }
        }
        0x89 if at(d, p, b"\x89PNG\r\n\x1a\n") => {
            if p + 20 <= n && &d[p + 12..p + 16] == b"IHDR" {
                push(13, p, u32be(d, p + 16));
            }
        }
        0xff if at(d, p, b"\xff\xd8\xff") => {
            if p + 4 <= n && JPEG_MARKERS.contains(&d[p + 3]) {
                push(14, p, 0);
            }
        }
        b'G' if at(d, p, b"GIF8") => {
            if p + 6 <= n && (&d[p + 3..p + 6] == b"87a" || &d[p + 3..p + 6] == b"89a") {
                push(15, p, 0);
            }
        }
        0xd0 if at(d, p, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") => {
            if p + 30 <= n && d[p + 28] == 0xfe && d[p + 29] == 0xff {
                push(16, p, 0);
            }
        }
        b'S' if at(d, p, b"SQLite format 3\x00") => push(17, p, 0),
        b'h' if at(d, p, b"hsqs") => {
            if p + 30 <= n && u16le(d, p + 28) == 4 {
                push(18, p, 4);
            }
        }
        b'0' if at(d, p, b"07070") => {
            if p + 14 <= n && (d[p + 5] == b'1' || d[p + 5] == b'2') && d[p + 6..p + 14].iter().all(|&b| is_hex(b)) {
                push(19, p, 0);
            }
        }
        b'u' if at(d, p, b"ustar") => {
            if p >= 257 && p + 8 <= n && (&d[p + 5..p + 8] == b"\x0000" || &d[p + 5..p + 8] == b"  \x00") {
                push(20, p - 257, 0);
            }
        }
        b'C' if at(d, p, b"CD001\x01") => {
            if p >= 0x8001 && d[p - 1] == 1 {
                push(21, p - 0x8001, 0);
            }
        }
        0x27 if at(d, p, b"\x27\x05\x19\x56") => {
            if p + 64 <= n && u32be(d, p + 12) > 0 && d[p + 28] <= 30 && d[p + 30] <= 10 {
                push(22, p, u32be(d, p + 12));
            }
        }
        b'd' if at(d, p, b"dex\n") => {
            if p + 8 <= n && d[p + 4..p + 7].iter().all(|b| b.is_ascii_digit()) && d[p + 7] == 0 {
                push(23, p, 0);
            }
        }
        0xca if at(d, p, b"\xca\xfe\xba\xbe") => {
            if p + 8 <= n {
                let major = u16be(d, p + 6);
                let count = u32be(d, p + 4);
                if (45..=70).contains(&major) {
                    push(24, p, major);
                } else if (1..=20).contains(&count) {
                    push(25, p, count);
                }
            }
        }
        b'{' if at(d, p, b"{\\rtf") => push(26, p, 0),
        0x4c if at(d, p, &LNK) => push(27, p, 0),
        b'-' if at(d, p, b"-----BEGIN ") => {
            let start = p + 11;
            let mut end = start;
            while end < n && end - start <= 40 && (d[end].is_ascii_uppercase() || d[end].is_ascii_digit() || d[end] == b' ') {
                end += 1;
            }
            let length = end - start;
            if (1..=40).contains(&length) && at(d, end, b"-----") {
                let label = &d[start..end];
                let contains = |needle: &[u8]| label.windows(needle.len()).any(|window| window == needle);
                let category = if label == b"CERTIFICATE" {
                    1
                } else if contains(b"PRIVATE KEY") {
                    2
                } else if contains(b"PUBLIC KEY") {
                    3
                } else {
                    4
                };
                push(28, p, category);
            }
        }
        0x00 if at(d, p, b"\x00asm\x01\x00\x00\x00") => push(29, p, 0),
        _ => {}
    }
}

/// Scan `data` and return hits sorted by (offset, kind, extra). The second
/// value is true when more than `SCAN_CAP` hits were found.
pub fn scan(data: &[u8]) -> (Vec<GiSignature>, bool) {
    let mut hits: Vec<(usize, u32, usize, u32)> = Vec::new();
    let mut truncated = false;
    for p in 0..data.len() {
        check(data, p, &mut hits);
        if hits.len() > SCAN_CAP {
            truncated = true;
            hits.truncate(SCAN_CAP);
            break;
        }
    }
    let mut result: Vec<GiSignature> = hits
        .into_iter()
        .map(|(_, kind, offset, extra)| GiSignature { offset: offset as u64, kind, extra })
        .collect();
    result.sort();
    (result, truncated)
}

/// C ABI: writes up to `capacity` hits to `out` and the total to `count`.
/// Returns 0, 1 when the scan stopped at `SCAN_CAP`, -1 for invalid
/// arguments and -2 when `capacity` is too small for every hit.
#[no_mangle]
pub extern "C" fn gi_signature_scan(
    data: *const u8,
    length: usize,
    out: *mut GiSignature,
    capacity: usize,
    count: *mut usize,
) -> i32 {
    if out.is_null() || count.is_null() || (data.is_null() && length > 0) || length > MAX_SCAN_INPUT {
        return -1;
    }
    let input: &[u8] = if length == 0 {
        &[]
    } else {
        // SAFETY: the caller provides `length` readable bytes for this call.
        unsafe { slice::from_raw_parts(data, length) }
    };
    let (hits, truncated) = scan(input);
    // SAFETY: `count` is non-null and writable per the contract above.
    unsafe { *count = hits.len() };
    if hits.len() > capacity {
        return -2;
    }
    // SAFETY: `out` holds at least `capacity` >= hits.len() records.
    let output = unsafe { slice::from_raw_parts_mut(out, hits.len()) };
    output.copy_from_slice(&hits);
    if truncated {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_embedded_pe_and_gzip() {
        let mut data = vec![0u8; 100];
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[60] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x44] = 0x64;
        pe[0x45] = 0x86;
        data.extend_from_slice(&pe);
        data.extend_from_slice(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03");
        let (hits, truncated) = scan(&data);
        assert!(!truncated);
        assert_eq!(hits, vec![
            GiSignature { offset: 100, kind: 9, extra: 0x8664 },
            GiSignature { offset: 228, kind: 2, extra: 0 },
        ]);
    }

    #[test]
    fn pem_labels() {
        let (hits, _) = scan(b"x-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----");
        assert_eq!(hits.iter().map(|hit| hit.extra).collect::<Vec<_>>(), vec![2, 1]);
    }
}
