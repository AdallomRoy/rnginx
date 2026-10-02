//! ngx_http_v3_encode.c: variable-length and prefixed integers, QPACK
//! field lines.
//!
//! The C functions write at p, or return the length with p == NULL; here
//! the writing functions append to a vector, the *_len ones return the
//! length. The prefixed integers take the bits of their first byte (what
//! C sets at *p before the call).

use super::NGX_HTTP_V3_VARLEN_INT_LEN;
use crate::huff_encode::huff_encode;

/// ngx_http_v3_encode_varlen_int with p == NULL
pub fn varlen_int_len(value: u64) -> usize {
    if value <= 63 {
        return 1;
    }

    if value <= 16383 {
        return 2;
    }

    if value <= 1073741823 {
        return 4;
    }

    8
}

/// ngx_http_v3_encode_varlen_int
pub fn encode_varlen_int(p: &mut Vec<u8>, value: u64) {
    if value <= 63 {
        p.push(value as u8);
        return;
    }

    if value <= 16383 {
        p.push(0x40 | (value >> 8) as u8);
        p.push(value as u8);
        return;
    }

    if value <= 1073741823 {
        p.push(0x80 | (value >> 24) as u8);
        p.push((value >> 16) as u8);
        p.push((value >> 8) as u8);
        p.push(value as u8);
        return;
    }

    p.push(0xc0 | (value >> 56) as u8);
    p.push((value >> 48) as u8);
    p.push((value >> 40) as u8);
    p.push((value >> 32) as u8);
    p.push((value >> 24) as u8);
    p.push((value >> 16) as u8);
    p.push((value >> 8) as u8);
    p.push(value as u8);
}

/// ngx_http_v3_encode_varlen_int of two values (a frame's type and
/// length) into a stack array: the bytes and their number.
pub fn varlen_ints_bytes(a: u64, b: u64) -> ([u8; 2 * NGX_HTTP_V3_VARLEN_INT_LEN], usize) {
    let mut buf = [0u8; 2 * NGX_HTTP_V3_VARLEN_INT_LEN];
    let mut n = 0;

    for value in [a, b] {
        let len = varlen_int_len(value);

        let v = match len {
            1 => value,
            2 => value | 0x4000,
            4 => value | 0x8000_0000,
            _ => value | 0xc000_0000_0000_0000,
        };

        buf[n..n + len].copy_from_slice(&v.to_be_bytes()[8 - len..]);
        n += len;
    }

    (buf, n)
}

/// The decimal digits of a value (ngx_sprintf "%O") into a stack array.
pub fn dec(buf: &mut [u8; 20], value: i64) -> &[u8] {
    use std::io::Write;

    let mut w = &mut buf[..];
    let _ = write!(w, "{}", value);
    let n = 20 - w.len();

    &buf[..n]
}

/// ngx_http_v3_encode_prefix_int with p == NULL
pub fn prefix_int_len(mut value: u64, prefix: u32) -> usize {
    let thresh = (1u64 << prefix) - 1;

    if value < thresh {
        return 1;
    }

    value -= thresh;

    let mut n = 2;

    while value >= 128 {
        value >>= 7;
        n += 1;
    }

    n
}

/// ngx_http_v3_encode_prefix_int: `first` has the bits of the first byte
/// above the prefix
pub fn encode_prefix_int(p: &mut Vec<u8>, first: u8, mut value: u64, prefix: u32) {
    let thresh = (1u64 << prefix) - 1;

    if value < thresh {
        p.push(first | value as u8);
        return;
    }

    value -= thresh;

    p.push(first | thresh as u8);

    while value >= 128 {
        p.push(0x80 | value as u8);
        value >>= 7;
    }

    p.push(value as u8);
}

/// ngx_http_v3_encode_field_section_prefix with p == NULL
pub fn field_section_prefix_len(insert_count: u64, _sign: bool, delta_base: u64) -> usize {
    prefix_int_len(insert_count, 8) + prefix_int_len(delta_base, 7)
}

/// ngx_http_v3_encode_field_section_prefix
pub fn encode_field_section_prefix(p: &mut Vec<u8>, insert_count: u64, sign: bool, delta_base: u64) {
    encode_prefix_int(p, 0, insert_count, 8);

    encode_prefix_int(p, if sign { 0x80 } else { 0 }, delta_base, 7);
}

/// ngx_http_v3_encode_field_ri with p == NULL
pub fn field_ri_len(_dynamic: bool, index: u64) -> usize {
    prefix_int_len(index, 6)
}

/// ngx_http_v3_encode_field_ri: Indexed Field Line
pub fn encode_field_ri(p: &mut Vec<u8>, dynamic: bool, index: u64) {
    encode_prefix_int(p, if dynamic { 0x80 } else { 0xc0 }, index, 6);
}

/// ngx_http_v3_encode_field_lri with p == NULL
pub fn field_lri_len(_dynamic: bool, index: u64, len: usize) -> usize {
    prefix_int_len(index, 4) + prefix_int_len(len as u64, 7) + len
}

/// ngx_http_v3_encode_field_lri: Literal Field Line With Name Reference;
/// without data, the caller appends the `len` bytes of the value
pub fn encode_field_lri(p: &mut Vec<u8>, dynamic: bool, index: u64, data: Option<&[u8]>, len: usize) {
    encode_prefix_int(p, if dynamic { 0x40 } else { 0x50 }, index, 4);

    let data = match data {
        Some(d) => d,
        None => {
            encode_prefix_int(p, 0, len as u64, 7);
            return;
        }
    };

    encode_string(p, 0, 0x80, 7, data, false);
}

/// A string literal of `prefix` bits, Huffman-coded if that is shorter
/// (`raw` / `huff` are the bits of the first byte for either), done in
/// place as C does: the length of the raw string, the Huffman coding
/// written behind it, then the length of the coding over it (moved down
/// when that length is shorter); no buffer besides `p`.
fn encode_string(p: &mut Vec<u8>, raw: u8, huff: u8, prefix: u32, data: &[u8], lower: bool) {
    let p1 = p.len();

    encode_prefix_int(p, raw, data.len() as u64, prefix);

    let p2 = p.len();

    p.resize(p2 + data.len(), 0);

    let hlen = huff_encode(data, &mut p[p2..], lower);

    if hlen != 0 {
        // the length of the coding, not longer than that of the string
        let (h, n) = prefix_int_bytes(huff, hlen as u64, prefix);

        if p1 + n != p2 {
            p.copy_within(p2..p2 + hlen, p1 + n);
        }

        p.truncate(p1 + n + hlen);
        p[p1..p1 + n].copy_from_slice(&h[..n]);

        return;
    }

    if lower {
        for (d, s) in p[p2..].iter_mut().zip(data) {
            *d = s.to_ascii_lowercase();
        }
    } else {
        p[p2..].copy_from_slice(data);
    }
}

/// ngx_http_v3_encode_prefix_int into a stack array: the bytes and their
/// number (at most 10: the first, and 9 of 7 bits for a 64-bit value).
fn prefix_int_bytes(first: u8, mut value: u64, prefix: u32) -> ([u8; 10], usize) {
    let mut b = [0u8; 10];
    let thresh = (1u64 << prefix) - 1;

    if value < thresh {
        b[0] = first | value as u8;
        return (b, 1);
    }

    value -= thresh;

    b[0] = first | thresh as u8;

    let mut n = 1;

    while value >= 128 {
        b[n] = 0x80 | value as u8;
        n += 1;
        value >>= 7;
    }

    b[n] = value as u8;

    (b, n + 1)
}

/// ngx_http_v3_encode_field_l with p == NULL
pub fn field_l_len(name: &[u8], value: &[u8]) -> usize {
    prefix_int_len(name.len() as u64, 3) + name.len() + prefix_int_len(value.len() as u64, 7) + value.len()
}

/// ngx_http_v3_encode_field_l: Literal Field Line With Literal Name
pub fn encode_field_l(p: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    encode_string(p, 0x20, 0x28, 3, name, true);

    encode_string(p, 0, 0x80, 7, value, false);
}

/// ngx_http_v3_encode_field_pbi with p == NULL
pub fn field_pbi_len(index: u64) -> usize {
    prefix_int_len(index, 4)
}

/// ngx_http_v3_encode_field_pbi: Indexed Field Line With Post-Base Index
pub fn encode_field_pbi(p: &mut Vec<u8>, index: u64) {
    encode_prefix_int(p, 0x10, index, 4);
}

/// ngx_http_v3_encode_field_lpbi with p == NULL
pub fn field_lpbi_len(index: u64, len: usize) -> usize {
    prefix_int_len(index, 3) + prefix_int_len(len as u64, 7) + len
}

/// ngx_http_v3_encode_field_lpbi: Literal Field Line With Post-Base Name
/// Reference
pub fn encode_field_lpbi(p: &mut Vec<u8>, index: u64, data: Option<&[u8]>, len: usize) {
    encode_prefix_int(p, 0, index, 3);

    match data {
        Some(data) => encode_string(p, 0, 0x80, 7, data, false),
        None => encode_prefix_int(p, 0, len as u64, 7),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_ints_as_rfc7541() {
        // RFC 7541, C.1.1 - C.1.3
        let mut p = Vec::new();
        encode_prefix_int(&mut p, 0, 10, 5);
        assert_eq!(p, [10]);

        let mut p = Vec::new();
        encode_prefix_int(&mut p, 0, 1337, 5);
        assert_eq!(p, [31, 154, 10]);
        assert_eq!(prefix_int_len(1337, 5), 3);

        let mut p = Vec::new();
        encode_prefix_int(&mut p, 0, 42, 8);
        assert_eq!(p, [42]);
    }

    /// The string literal through a buffer of its own, as before.
    fn reference_string(p: &mut Vec<u8>, raw: u8, huff: u8, prefix: u32, data: &[u8], lower: bool) {
        let mut h = vec![0u8; data.len()];

        let hlen = huff_encode(data, &mut h, lower);

        if hlen != 0 {
            encode_prefix_int(p, huff, hlen as u64, prefix);
            p.extend_from_slice(&h[..hlen]);
        } else {
            encode_prefix_int(p, raw, data.len() as u64, prefix);
            p.extend(data.iter().map(|c| if lower { c.to_ascii_lowercase() } else { *c }));
        }
    }

    #[test]
    fn strings_coded_in_place() {
        let mut cases: Vec<Vec<u8>> = vec![b"".to_vec(), b"a".to_vec(), b"{{{{{".to_vec(), b"aaaaa".to_vec(), b"X-Foo-Bar".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()];

        // lengths around the prefix limits: the coding's length prefix is
        // shorter than the string's (moved down), or not
        for len in [6usize, 7, 8, 9, 126, 127, 128, 129, 140, 160, 200, 300, 1000, 20000] {
            cases.push((0..len).map(|i| b"aeiost"[i % 6]).collect());
            cases.push((0..len).map(|i| (i * 37 % 256) as u8).collect());
        }

        for data in cases.iter() {
            // behind other data
            let mut p = b"xyz".to_vec();
            encode_field_l(&mut p, data, data);
            let mut want = b"xyz".to_vec();
            reference_string(&mut want, 0x20, 0x28, 3, data, true);
            reference_string(&mut want, 0, 0x80, 7, data, false);
            assert_eq!(p, want, "{:?}", data.len());

            let mut p = Vec::new();
            encode_field_lri(&mut p, false, 25, Some(data), data.len());
            let mut want = Vec::new();
            encode_prefix_int(&mut want, 0x50, 25, 4);
            reference_string(&mut want, 0, 0x80, 7, data, false);
            assert_eq!(p, want, "{:?}", data.len());

            // the raw length is an upper bound of what is written
            assert!(p.len() <= field_lri_len(false, 25, data.len()));
        }
    }

    #[test]
    fn varlen_ints() {
        for v in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let mut p = Vec::new();
            encode_varlen_int(&mut p, v);
            assert_eq!(p.len(), varlen_int_len(v));
        }
    }

    #[test]
    fn varlen_ints_on_the_stack() {
        let values = [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1 << 62) - 1];

        for a in values {
            for b in values {
                let mut want = Vec::new();
                encode_varlen_int(&mut want, a);
                encode_varlen_int(&mut want, b);

                let (got, n) = varlen_ints_bytes(a, b);
                assert_eq!(&got[..n], &want[..], "{} {}", a, b);
            }
        }

        for v in [1i64, 9, 10, 1024, 1 << 40, i64::MAX] {
            let mut b = [0u8; 20];
            assert_eq!(dec(&mut b, v), v.to_string().as_bytes());
        }
    }
}
