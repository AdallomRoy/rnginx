//! Byte-string utilities ported from ngx_string.c.
//!
//! nginx strings are arbitrary byte sequences, never assumed to be UTF-8.

pub const NGX_ESCAPE_URI: usize = 0;
pub const NGX_ESCAPE_ARGS: usize = 1;
pub const NGX_ESCAPE_URI_COMPONENT: usize = 2;
pub const NGX_ESCAPE_HTML: usize = 3;
pub const NGX_ESCAPE_REFRESH: usize = 4;
pub const NGX_ESCAPE_MEMCACHED: usize = 5;
pub const NGX_ESCAPE_MAIL_AUTH: usize = 6;
pub const NGX_ESCAPE_MAIL_XTEXT: usize = 7;

pub const NGX_UNESCAPE_URI: u32 = 1;
pub const NGX_UNESCAPE_REDIRECT: u32 = 2;

#[inline]
pub fn tolower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c | 0x20 } else { c }
}

#[inline]
pub fn toupper(c: u8) -> u8 {
    if c.is_ascii_lowercase() { c & !0x20 } else { c }
}

pub fn strlow(s: &mut [u8]) {
    for c in s.iter_mut() {
        *c = tolower(*c);
    }
}

pub fn to_lower_vec(s: &[u8]) -> Vec<u8> {
    s.iter().map(|&c| tolower(c)).collect()
}

/// Case-insensitive equality (ASCII only, as nginx does).
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| tolower(*x) == tolower(*y))
}

/// ngx_strncasecmp semantics: compare up to n bytes.
pub fn strncasecmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let c1 = a.get(i).copied().unwrap_or(0);
        let c2 = b.get(i).copied().unwrap_or(0);
        let c1 = tolower(c1);
        let c2 = tolower(c2);
        if c1 == c2 {
            if c1 != 0 {
                i += 1;
                continue;
            }
            return 0;
        }
        return c1 as i32 - c2 as i32;
    }
    0
}

pub fn strcasecmp(a: &[u8], b: &[u8]) -> i32 {
    let n = a.len().max(b.len()) + 1;
    strncasecmp(a, b, n)
}

pub fn starts_with_ignore_case(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && eq_ignore_case(&s[..prefix.len()], prefix)
}

/// Find `needle` in `haystack` case-insensitively; returns index.
pub fn strcasestr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    let first = tolower(needle[0]);
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if tolower(haystack[i]) == first && eq_ignore_case(&haystack[i..i + needle.len()], needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn strstr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    memchr::memmem::find(haystack, needle)
}

/// ngx_dns_strcmp: case-insensitive, '.' sorts lowest.
pub fn dns_strcmp(s1: &[u8], s2: &[u8]) -> i32 {
    let mut i = 0;
    loop {
        let c1 = s1.get(i).copied().unwrap_or(0);
        let c2 = s2.get(i).copied().unwrap_or(0);
        let c1 = tolower(c1);
        let c2 = tolower(c2);
        if c1 == c2 {
            if c1 != 0 {
                i += 1;
                continue;
            }
            return 0;
        }
        let c1 = if c1 == b'.' { b' ' } else { c1 };
        let c2 = if c2 == b'.' { b' ' } else { c2 };
        return c1 as i32 - c2 as i32;
    }
}

/// ngx_filename_cmp: '/' sorts lowest.
pub fn filename_cmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let c1 = s1.get(i).copied().unwrap_or(0);
        let c2 = s2.get(i).copied().unwrap_or(0);
        if c1 == c2 {
            if c1 != 0 {
                i += 1;
                continue;
            }
            return 0;
        }
        if c1 == 0 || c2 == 0 {
            return c1 as i32 - c2 as i32;
        }
        let c1 = if c1 == b'/' { 0 } else { c1 };
        let c2 = if c2 == b'/' { 0 } else { c2 };
        return c1 as i32 - c2 as i32;
    }
    0
}

pub fn strrchr(s: &[u8], c: u8) -> Option<usize> {
    memchr::memrchr(c, s)
}

pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    memchr::memchr(c, s)
}

// ---------------------------------------------------------------------------
// numeric conversions (return None on error, like NGX_ERROR)

pub fn atoi(line: &[u8]) -> Option<i64> {
    if line.is_empty() {
        return None;
    }
    let cutoff = i64::MAX / 10;
    let cutlim = i64::MAX % 10;
    let mut value: i64 = 0;
    for &c in line {
        if !c.is_ascii_digit() {
            return None;
        }
        let d = (c - b'0') as i64;
        if value >= cutoff && (value > cutoff || d > cutlim) {
            return None;
        }
        value = value * 10 + d;
    }
    Some(value)
}

/// Fixed point: parses "1.25" with `point` fractional digits into integer.
pub fn atofp(line: &[u8], mut point: usize) -> Option<i64> {
    if line.is_empty() {
        return None;
    }
    let cutoff = i64::MAX / 10;
    let cutlim = i64::MAX % 10;
    let mut dot = false;
    let mut value: i64 = 0;
    for &c in line {
        if point == 0 {
            return None;
        }
        if c == b'.' {
            if dot {
                return None;
            }
            dot = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        let d = (c - b'0') as i64;
        if value >= cutoff && (value > cutoff || d > cutlim) {
            return None;
        }
        value = value * 10 + d;
        if dot {
            point -= 1;
        }
    }
    while point > 0 {
        point -= 1;
        if value > cutoff {
            return None;
        }
        value *= 10;
    }
    Some(value)
}

pub fn atosz(line: &[u8]) -> Option<isize> {
    atoi(line).map(|v| v as isize)
}

pub fn atoof(line: &[u8]) -> Option<i64> {
    atoi(line)
}

pub fn atotm(line: &[u8]) -> Option<i64> {
    atoi(line)
}

pub fn hextoi(line: &[u8]) -> Option<i64> {
    if line.is_empty() {
        return None;
    }
    let cutoff = i64::MAX / 16;
    let mut value: i64 = 0;
    for &ch in line {
        if value > cutoff {
            return None;
        }
        if ch.is_ascii_digit() {
            value = value * 16 + (ch - b'0') as i64;
            continue;
        }
        let c = ch | 0x20;
        if (b'a'..=b'f').contains(&c) {
            value = value * 16 + (c - b'a' + 10) as i64;
            continue;
        }
        return None;
    }
    Some(value)
}

pub fn hex_dump(dst: &mut Vec<u8>, src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in src {
        dst.push(HEX[(b >> 4) as usize]);
        dst.push(HEX[(b & 0xf) as usize]);
    }
}

pub fn hex_string(src: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(src.len() * 2);
    hex_dump(&mut v, src);
    v
}

// ---------------------------------------------------------------------------
// escaping

static URI: [u32; 8] = [0xffffffff, 0xd000002d, 0x50000000, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];
static ARGS: [u32; 8] = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];
static URI_COMPONENT: [u32; 8] = [0xffffffff, 0xfc009fff, 0x78000001, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];
static HTML: [u32; 8] = [0xffffffff, 0x500000ad, 0x50000000, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];
static REFRESH: [u32; 8] = [0xffffffff, 0x50000085, 0x50000000, 0xd8000001, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];
static MEMCACHED: [u32; 8] = [0xffffffff, 0x00000021, 0, 0, 0, 0, 0, 0];
static MAIL_XTEXT: [u32; 8] = [0xffffffff, 0x20000801, 0x00000000, 0x80000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];

fn escape_map(ty: usize) -> (&'static [u32; 8], u8) {
    match ty {
        NGX_ESCAPE_URI => (&URI, b'%'),
        NGX_ESCAPE_ARGS => (&ARGS, b'%'),
        NGX_ESCAPE_URI_COMPONENT => (&URI_COMPONENT, b'%'),
        NGX_ESCAPE_HTML => (&HTML, b'%'),
        NGX_ESCAPE_REFRESH => (&REFRESH, b'%'),
        NGX_ESCAPE_MEMCACHED => (&MEMCACHED, b'%'),
        NGX_ESCAPE_MAIL_AUTH => (&MEMCACHED, b'%'),
        NGX_ESCAPE_MAIL_XTEXT => (&MAIL_XTEXT, b'+'),
        _ => (&URI, b'%'),
    }
}

/// Number of characters that would be escaped.
pub fn escape_uri_count(src: &[u8], ty: usize) -> usize {
    let (map, _) = escape_map(ty);
    src.iter().filter(|&&c| map[(c >> 5) as usize] & (1u32 << (c & 0x1f)) != 0).count()
}

pub fn escape_uri_into(dst: &mut Vec<u8>, src: &[u8], ty: usize) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let (map, prefix) = escape_map(ty);
    for &c in src {
        if map[(c >> 5) as usize] & (1u32 << (c & 0x1f)) != 0 {
            dst.push(prefix);
            dst.push(HEX[(c >> 4) as usize]);
            dst.push(HEX[(c & 0xf) as usize]);
        } else {
            dst.push(c);
        }
    }
}

pub fn escape_uri(src: &[u8], ty: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(src.len() + 2 * escape_uri_count(src, ty));
    escape_uri_into(&mut v, src, ty);
    v
}

/// Port of ngx_unescape_uri. Returns (decoded, consumed_src_len).
/// Decoding stops after a '?' for URI/REDIRECT types, as in nginx.
pub fn unescape_uri(src: &[u8], ty: u32) -> (Vec<u8>, usize) {
    let mut d = Vec::with_capacity(src.len());
    let mut state = 0u8;
    let mut decoded: u8 = 0;
    let mut i = 0;
    let n = src.len();
    while i < n {
        let ch = src[i];
        i += 1;
        match state {
            0 => {
                if ch == b'?' && (ty & (NGX_UNESCAPE_URI | NGX_UNESCAPE_REDIRECT)) != 0 {
                    d.push(ch);
                    return (d, i);
                }
                if ch == b'%' {
                    state = 1;
                    continue;
                }
                d.push(ch);
            }
            1 => {
                if ch.is_ascii_digit() {
                    decoded = ch - b'0';
                    state = 2;
                    continue;
                }
                let c = ch | 0x20;
                if (b'a'..=b'f').contains(&c) {
                    decoded = c - b'a' + 10;
                    state = 2;
                    continue;
                }
                state = 0;
                d.push(ch);
            }
            _ => {
                state = 0;
                if ch.is_ascii_digit() {
                    let ch = (decoded << 4) + (ch - b'0');
                    if ty & NGX_UNESCAPE_REDIRECT != 0 {
                        if ch > b'%' && ch < 0x7f {
                            d.push(ch);
                            continue;
                        }
                        d.push(b'%');
                        d.push(src[i - 2]);
                        d.push(src[i - 1]);
                        continue;
                    }
                    d.push(ch);
                    continue;
                }
                let c = ch | 0x20;
                if (b'a'..=b'f').contains(&c) {
                    let ch = (decoded << 4) + (c - b'a') + 10;
                    if ty & NGX_UNESCAPE_URI != 0 {
                        d.push(ch);
                        if ch == b'?' {
                            return (d, i);
                        }
                        continue;
                    }
                    if ty & NGX_UNESCAPE_REDIRECT != 0 {
                        if ch == b'?' {
                            d.push(ch);
                            return (d, i);
                        }
                        if ch > b'%' && ch < 0x7f {
                            d.push(ch);
                            continue;
                        }
                        d.push(b'%');
                        d.push(src[i - 2]);
                        d.push(src[i - 1]);
                        continue;
                    }
                    d.push(ch);
                    continue;
                }
                // invalid quoted character: dropped
            }
        }
    }
    (d, i)
}

pub fn escape_html_into(dst: &mut Vec<u8>, src: &[u8]) {
    for &ch in src {
        match ch {
            b'<' => dst.extend_from_slice(b"&lt;"),
            b'>' => dst.extend_from_slice(b"&gt;"),
            b'&' => dst.extend_from_slice(b"&amp;"),
            b'"' => dst.extend_from_slice(b"&quot;"),
            _ => dst.push(ch),
        }
    }
}

pub fn escape_html(src: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(src.len());
    escape_html_into(&mut v, src);
    v
}

pub fn escape_json_into(dst: &mut Vec<u8>, src: &[u8]) {
    for &ch in src {
        if ch > 0x1f {
            if ch == b'\\' || ch == b'"' {
                dst.push(b'\\');
            }
            dst.push(ch);
        } else {
            dst.push(b'\\');
            match ch {
                b'\n' => dst.push(b'n'),
                b'\r' => dst.push(b'r'),
                b'\t' => dst.push(b't'),
                0x08 => dst.push(b'b'),
                0x0c => dst.push(b'f'),
                _ => {
                    dst.extend_from_slice(b"u00");
                    dst.push(b'0' + (ch >> 4));
                    let c = ch & 0xf;
                    dst.push(if c < 10 { b'0' + c } else { b'A' + c - 10 });
                }
            }
        }
    }
}

pub fn escape_json(src: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(src.len());
    escape_json_into(&mut v, src);
    v
}

// ---------------------------------------------------------------------------
// UTF-8

/// Port of ngx_utf8_decode. Returns (code point or error marker, bytes consumed).
/// 0xffffffff = invalid, 0xfffffffe = incomplete.
pub fn utf8_decode(p: &[u8]) -> (u32, usize) {
    let n = p.len();
    if n == 0 {
        return (0xfffffffe, 0);
    }
    let mut u = p[0] as u32;
    let (valid, len) = if u >= 0xf8 {
        return (0xffffffff, 1);
    } else if u >= 0xf0 {
        u &= 0x07;
        (0xffffu32, 3usize)
    } else if u >= 0xe0 {
        u &= 0x0f;
        (0x7ff, 2)
    } else if u >= 0xc2 {
        u &= 0x1f;
        (0x7f, 1)
    } else {
        return (0xffffffff, 1);
    };
    if n - 1 < len {
        return (0xfffffffe, 0);
    }
    let mut consumed = 1;
    let mut remaining = len;
    while remaining > 0 {
        let i = p[consumed] as u32;
        consumed += 1;
        if i < 0x80 {
            return (0xffffffff, consumed);
        }
        u = (u << 6) | (i & 0x3f);
        remaining -= 1;
    }
    if u > valid {
        (u, consumed)
    } else {
        (0xffffffff, consumed)
    }
}

/// Number of UTF-8 characters, or byte length if invalid.
pub fn utf8_length(p: &[u8]) -> usize {
    let n = p.len();
    let mut i = 0;
    let mut len = 0;
    while i < n {
        let c = p[i];
        if c < 0x80 {
            i += 1;
            len += 1;
            continue;
        }
        let (u, consumed) = utf8_decode(&p[i..]);
        if u > 0x10ffff {
            return n;
        }
        i += consumed;
        len += 1;
    }
    len
}

/// Copy at most `n-1` characters (UTF-8 aware) from src; returns copied prefix.
/// Mirrors ngx_utf8_cpystrn used by autoindex for truncation.
pub fn utf8_cpystrn(src: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if n == 0 {
        return out;
    }
    let mut remaining = n;
    let mut i = 0;
    let mut len = src.len();
    while remaining > 1 {
        remaining -= 1;
        if i >= src.len() {
            break;
        }
        let c = src[i];
        if c < 0x80 {
            if c != 0 {
                out.push(c);
                i += 1;
                len -= 1;
                continue;
            }
            return out;
        }
        let (u, consumed) = utf8_decode(&src[i..]);
        if u > 0x10ffff {
            break;
        }
        out.extend_from_slice(&src[i..i + consumed]);
        i += consumed;
        len -= consumed;
    }
    let _ = len;
    out
}

// ---------------------------------------------------------------------------
// base64

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64_encoded_length(len: usize) -> usize {
    ((len + 2) / 3) * 4
}

pub fn base64_decoded_length(len: usize) -> usize {
    ((len + 3) / 4) * 3
}

fn encode_base64_internal(src: &[u8], basis: &[u8; 64], padding: bool) -> Vec<u8> {
    let mut d = Vec::with_capacity(base64_encoded_length(src.len()));
    let mut s = src;
    while s.len() > 2 {
        d.push(basis[((s[0] >> 2) & 0x3f) as usize]);
        d.push(basis[(((s[0] & 3) << 4) | (s[1] >> 4)) as usize]);
        d.push(basis[(((s[1] & 0x0f) << 2) | (s[2] >> 6)) as usize]);
        d.push(basis[(s[2] & 0x3f) as usize]);
        s = &s[3..];
    }
    if !s.is_empty() {
        d.push(basis[((s[0] >> 2) & 0x3f) as usize]);
        if s.len() == 1 {
            d.push(basis[((s[0] & 3) << 4) as usize]);
            if padding {
                d.push(b'=');
            }
        } else {
            d.push(basis[(((s[0] & 3) << 4) | (s[1] >> 4)) as usize]);
            d.push(basis[((s[1] & 0x0f) << 2) as usize]);
        }
        if padding {
            d.push(b'=');
        }
    }
    d
}

pub fn encode_base64(src: &[u8]) -> Vec<u8> {
    encode_base64_internal(src, BASE64, true)
}

pub fn encode_base64url(src: &[u8]) -> Vec<u8> {
    encode_base64_internal(src, BASE64URL, false)
}

static BASIS64: [u8; 256] = {
    let mut t = [77u8; 256];
    let mut i = 0;
    while i < 64 {
        t[BASE64[i] as usize] = i as u8;
        i += 1;
    }
    t
};

static BASIS64URL: [u8; 256] = {
    let mut t = [77u8; 256];
    let mut i = 0;
    while i < 64 {
        t[BASE64URL[i] as usize] = i as u8;
        i += 1;
    }
    t
};

fn decode_base64_internal(src: &[u8], basis: &[u8; 256]) -> Option<Vec<u8>> {
    let mut len = 0;
    while len < src.len() {
        if src[len] == b'=' {
            break;
        }
        if basis[src[len] as usize] == 77 {
            return None;
        }
        len += 1;
    }
    if len % 4 == 1 {
        return None;
    }
    let mut d = Vec::with_capacity(base64_decoded_length(src.len()));
    let mut s = &src[..len];
    while s.len() > 3 {
        d.push(basis[s[0] as usize] << 2 | basis[s[1] as usize] >> 4);
        d.push(basis[s[1] as usize] << 4 | basis[s[2] as usize] >> 2);
        d.push(basis[s[2] as usize] << 6 | basis[s[3] as usize]);
        s = &s[4..];
    }
    if s.len() > 1 {
        d.push(basis[s[0] as usize] << 2 | basis[s[1] as usize] >> 4);
    }
    if s.len() > 2 {
        d.push(basis[s[1] as usize] << 4 | basis[s[2] as usize] >> 2);
    }
    Some(d)
}

pub fn decode_base64(src: &[u8]) -> Option<Vec<u8>> {
    decode_base64_internal(src, &BASIS64)
}

pub fn decode_base64url(src: &[u8]) -> Option<Vec<u8>> {
    decode_base64_internal(src, &BASIS64URL)
}

// ---------------------------------------------------------------------------
// misc

/// Lossy conversion for diagnostics only.
pub fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

/// Display wrapper printing bytes as-is (lossy for non-UTF-8).
pub struct B<'a>(pub &'a [u8]);

impl<'a> std::fmt::Display for B<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fast path for valid UTF-8
        match std::str::from_utf8(self.0) {
            Ok(s) => f.write_str(s),
            Err(_) => f.write_str(&String::from_utf8_lossy(self.0)),
        }
    }
}

/// Split "key=value" style pairs on the first occurrence of `sep`.
pub fn split_once(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    memchr::memchr(sep, s).map(|i| (&s[..i], &s[i + 1..]))
}

pub fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// ngx_sort-compatible stable insertion sort is not needed; use slice sort.
/// Helper for building a `Vec<u8>` from several pieces.
pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let n: usize = parts.iter().map(|p| p.len()).sum();
    let mut v = Vec::with_capacity(n);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_uri() {
        assert_eq!(escape_uri(b"a b", NGX_ESCAPE_URI), b"a%20b".to_vec());
        assert_eq!(escape_uri(b"a&b=c", NGX_ESCAPE_ARGS), b"a%26b=c".to_vec());
        assert_eq!(escape_uri(b"a/b", NGX_ESCAPE_URI_COMPONENT), b"a%2Fb".to_vec());
        assert_eq!(escape_uri(b"a b", NGX_ESCAPE_MAIL_XTEXT), b"a+20b".to_vec());
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescape_uri(b"a%20b", 0).0, b"a b".to_vec());
        assert_eq!(unescape_uri(b"a%3Fb", NGX_UNESCAPE_URI).0, b"a?".to_vec());
        assert_eq!(unescape_uri(b"a%2fb", NGX_UNESCAPE_REDIRECT).0, b"a/b".to_vec());
        assert_eq!(unescape_uri(b"a%00b", NGX_UNESCAPE_REDIRECT).0, b"a%00b".to_vec());
        assert_eq!(unescape_uri(b"a%zzb", 0).0, b"azzb".to_vec());
    }

    #[test]
    fn test_base64() {
        assert_eq!(encode_base64(b"hello"), b"aGVsbG8=".to_vec());
        assert_eq!(decode_base64(b"aGVsbG8=").unwrap(), b"hello".to_vec());
        assert_eq!(encode_base64url(b"hello?>"), b"aGVsbG8_Pg".to_vec());
        assert!(decode_base64(b"a").is_none());
    }

    #[test]
    fn test_atoi() {
        assert_eq!(atoi(b"123"), Some(123));
        assert_eq!(atoi(b""), None);
        assert_eq!(atoi(b"12a"), None);
        assert_eq!(atofp(b"1.25", 2), Some(125));
        assert_eq!(atofp(b"1", 3), Some(1000));
        assert_eq!(atofp(b"1.2345", 2), None);
        assert_eq!(hextoi(b"ff"), Some(255));
    }

    #[test]
    fn test_utf8() {
        assert_eq!(utf8_length("héllo".as_bytes()), 5);
        assert_eq!(utf8_length(b"\xff\xfe"), 2);
    }
}
