//! ngx_http_v3_encode.c: variable-length and prefixed integers, QPACK
//! field lines.
//!
//! The C functions write at p, or return the length with p == NULL; here
//! the writing functions append to a vector, the *_len ones return the
//! length. The prefixed integers take the bits of their first byte (what
//! C sets at *p before the call).

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

    encode_string(p, data, false);
}

/// A string literal, Huffman-coded if that is shorter (the value part of
/// the field lines).
fn encode_string(p: &mut Vec<u8>, data: &[u8], lower: bool) {
    let mut h = vec![0u8; data.len()];

    let hlen = huff_encode(data, &mut h, lower);

    if hlen != 0 {
        encode_prefix_int(p, 0x80, hlen as u64, 7);
        p.extend_from_slice(&h[..hlen]);
    } else {
        encode_prefix_int(p, 0, data.len() as u64, 7);
        p.extend_from_slice(data);
    }
}

/// ngx_http_v3_encode_field_l with p == NULL
pub fn field_l_len(name: &[u8], value: &[u8]) -> usize {
    prefix_int_len(name.len() as u64, 3) + name.len() + prefix_int_len(value.len() as u64, 7) + value.len()
}

/// ngx_http_v3_encode_field_l: Literal Field Line With Literal Name
pub fn encode_field_l(p: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let mut h = vec![0u8; name.len()];

    let hlen = huff_encode(name, &mut h, true);

    if hlen != 0 {
        encode_prefix_int(p, 0x28, hlen as u64, 3);
        p.extend_from_slice(&h[..hlen]);
    } else {
        encode_prefix_int(p, 0x20, name.len() as u64, 3);
        p.extend(name.iter().map(|c| c.to_ascii_lowercase()));
    }

    encode_string(p, value, false);
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
        Some(data) => encode_string(p, data, false),
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

    #[test]
    fn varlen_ints() {
        for v in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let mut p = Vec::new();
            encode_varlen_int(&mut p, v);
            assert_eq!(p.len(), varlen_int_len(v));
        }
    }
}
