//! HPACK string and integer encoding (nginx-c/src/http/v2/ngx_http_v2_encode.c)
//! and the related helpers from ngx_http_v2.h.

use crate::huff_encode::huff_encode;

pub const NGX_HTTP_V2_ENCODE_RAW: u8 = 0;
pub const NGX_HTTP_V2_ENCODE_HUFF: u8 = 0x80;

/// ngx_http_v2_prefix
pub const fn prefix(bits: u32) -> usize {
    (1 << bits) - 1
}

/// ngx_http_v2_indexed
pub const fn indexed(i: u8) -> u8 {
    128 + i
}

/// ngx_http_v2_inc_indexed
pub const fn inc_indexed(i: u8) -> u8 {
    64 + i
}

thread_local! {
    /// The tmp buffer of C's header filters: the Huffman coding of a
    /// string, before the length prefix is known. One for the worker,
    /// taken by each string_encode() and given back, grown to the longest
    /// string (never zero-filled again).
    static TMP: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

/// The Huffman coding of `src` in `tmp` (len 0 when it is not shorter):
/// huff_encode() into a buffer of the worker that holds the longest string
/// seen, so no buffer is allocated per string.
pub fn with_huff_encoded<T>(src: &[u8], lower: bool, f: impl FnOnce(&[u8]) -> T) -> T {
    let mut tmp = TMP.try_with(|t| t.take()).unwrap_or_default();

    if tmp.len() < src.len() {
        tmp.resize(src.len(), 0);
    }

    let hlen = huff_encode(src, &mut tmp[..src.len()], lower);

    let r = f(&tmp[..hlen]);

    let _ = TMP.try_with(|t| t.set(tmp));

    r
}

/// ngx_http_v2_string_encode: append `src` as an HPACK string literal,
/// Huffman-coded when that is shorter; with `lower`, lowercased.
pub fn string_encode(dst: &mut Vec<u8>, src: &[u8], lower: bool) {
    let coded = with_huff_encoded(src, lower, |h| {
        if h.is_empty() {
            return false;
        }

        write_int(dst, NGX_HTTP_V2_ENCODE_HUFF, prefix(7), h.len());
        dst.extend_from_slice(h);

        true
    });

    if coded {
        return;
    }

    write_int(dst, NGX_HTTP_V2_ENCODE_RAW, prefix(7), src.len());

    if lower {
        dst.extend(src.iter().map(|c| c.to_ascii_lowercase()));
    } else {
        dst.extend_from_slice(src);
    }
}

/// ngx_http_v2_write_name
pub fn write_name(dst: &mut Vec<u8>, src: &[u8]) {
    string_encode(dst, src, true);
}

/// ngx_http_v2_write_value
pub fn write_value(dst: &mut Vec<u8>, src: &[u8]) {
    string_encode(dst, src, false);
}

/// ngx_http_v2_write_int: append an HPACK integer with a `prefix` (2^N - 1)
/// prefix. `first` carries the flag bits of the first octet, which C stores
/// before calling and ORs the value into.
pub fn write_int(dst: &mut Vec<u8>, first: u8, prefix: usize, mut value: usize) {
    if value < prefix {
        dst.push(first | value as u8);
        return;
    }

    dst.push(first | prefix as u8);
    value -= prefix;

    while value >= 128 {
        dst.push((value % 128 + 128) as u8);
        value /= 128;
    }

    dst.push(value as u8);
}
