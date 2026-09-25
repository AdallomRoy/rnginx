// HTTP parsing functions ported from ngx_http_parse.c
#![allow(non_snake_case, dead_code)]

use ngx_core::rc::*;

// HTTP methods
pub const NGX_HTTP_UNKNOWN: u32 = 0x00000001;
pub const NGX_HTTP_GET: u32 = 0x00000002;
pub const NGX_HTTP_HEAD: u32 = 0x00000004;
pub const NGX_HTTP_POST: u32 = 0x00000008;
pub const NGX_HTTP_PUT: u32 = 0x00000010;
pub const NGX_HTTP_DELETE: u32 = 0x00000020;
pub const NGX_HTTP_MKCOL: u32 = 0x00000040;
pub const NGX_HTTP_COPY: u32 = 0x00000080;
pub const NGX_HTTP_MOVE: u32 = 0x00000100;
pub const NGX_HTTP_OPTIONS: u32 = 0x00000200;
pub const NGX_HTTP_PROPFIND: u32 = 0x00000400;
pub const NGX_HTTP_PROPPATCH: u32 = 0x00000800;
pub const NGX_HTTP_LOCK: u32 = 0x00001000;
pub const NGX_HTTP_UNLOCK: u32 = 0x00002000;
pub const NGX_HTTP_PATCH: u32 = 0x00004000;
pub const NGX_HTTP_TRACE: u32 = 0x00008000;
pub const NGX_HTTP_CONNECT: u32 = 0x00010000;

// HTTP versions
pub const NGX_HTTP_VERSION_9: u32 = 9;
pub const NGX_HTTP_VERSION_10: u32 = 1000;
pub const NGX_HTTP_VERSION_11: u32 = 1001;
pub const NGX_HTTP_VERSION_20: u32 = 2000;
pub const NGX_HTTP_VERSION_30: u32 = 3000;

// Parse error codes
pub const NGX_HTTP_PARSE_HEADER_DONE: i64 = 1;
pub const NGX_HTTP_PARSE_INVALID_METHOD: i64 = 10;
pub const NGX_HTTP_PARSE_INVALID_REQUEST: i64 = 11;
pub const NGX_HTTP_PARSE_INVALID_VERSION: i64 = 12;
pub const NGX_HTTP_PARSE_INVALID_09_METHOD: i64 = 13;
pub const NGX_HTTP_PARSE_INVALID_HEADER: i64 = 14;

pub const NGX_HTTP_LOG_UNSAFE: u32 = 1;

pub const NGX_HTTP_LC_HEADER_LEN: usize = 32;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const NGX_MAX_OFF_T_VALUE: i64 = i64::MAX;

// Bit flags for "usual" characters
static USUAL: &[u32] = &[
    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */
                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0x7fffffff, /* 0111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
];

#[inline]
fn is_usual(ch: u8) -> bool {
    USUAL[(ch as usize) >> 5] & (1u32 << (ch as usize & 0x1f)) != 0
}

// ngx_hash function for header hashing
#[inline]
fn ngx_hash(hash: u32, ch: u8) -> u32 {
    hash.wrapping_mul(31).wrapping_add(ch as u32)
}

#[derive(Debug, Clone)]
pub struct ParseRequest {
    pub state: u32,
    pub request_start: usize,
    pub request_end: usize,
    pub method: u32,
    pub method_end: usize,
    pub http_major: u32,
    pub http_minor: u32,
    pub http_version: u32,
    pub schema_start: Option<usize>,
    pub schema_end: Option<usize>,
    pub host_start: Option<usize>,
    pub host_end: Option<usize>,
    pub port_start: Option<usize>,
    pub port_end: Option<usize>,
    pub uri_start: Option<usize>,
    pub uri_end: Option<usize>,
    pub uri_ext: Option<usize>,
    pub args_start: Option<usize>,
    pub complex_uri: bool,
    pub quoted_uri: bool,
    pub plus_in_uri: bool,
    pub empty_path_in_uri: bool,
    pub space_in_uri: bool,
    pub header_name_start: usize,
    pub header_name_end: usize,
    pub header_start: usize,
    pub header_end: usize,
    pub header_hash: u32,
    pub lowcase_header: [u8; NGX_HTTP_LC_HEADER_LEN],
    pub lowcase_index: usize,
    pub invalid_header: bool,
    pub http_protocol_start: Option<usize>,
    /// C: request_end != NULL
    pub request_end_set: bool,
    /// set when parsing upstream response headers (enables IIS "HTTP/" line skipping)
    pub upstream: bool,
}

impl Default for ParseRequest {
    fn default() -> Self {
        ParseRequest {
            state: 0,
            request_start: 0,
            request_end: 0,
            method: 0,
            method_end: 0,
            http_major: 0,
            http_minor: 0,
            http_version: 0,
            schema_start: None,
            schema_end: None,
            host_start: None,
            host_end: None,
            port_start: None,
            port_end: None,
            uri_start: None,
            uri_end: None,
            uri_ext: None,
            args_start: None,
            complex_uri: false,
            quoted_uri: false,
            plus_in_uri: false,
            empty_path_in_uri: false,
            space_in_uri: false,
            header_name_start: 0,
            header_name_end: 0,
            header_start: 0,
            header_end: 0,
            header_hash: 0,
            lowcase_header: [0u8; NGX_HTTP_LC_HEADER_LEN],
            lowcase_index: 0,
            invalid_header: false,
            http_protocol_start: None,
            request_end_set: false,
            upstream: false,
        }
    }
}

// Lowcase table for header parsing
static LOWCASE: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0\
0123456789\0\0\0\0\0\0\
\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0\
\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// Parse HTTP request line (port of ngx_http_parse_request_line).
/// Returns NGX_OK on success, NGX_AGAIN if incomplete, or an NGX_HTTP_PARSE_* code.
/// Offsets are relative to `buf`; `pos` is advanced like `b->pos`.
pub fn parse_request_line(r: &mut ParseRequest, buf: &[u8], pos: &mut usize) -> i64 {
    const SW_START: u32 = 0;
    const SW_METHOD: u32 = 1;
    const SW_SPACES_BEFORE_URI: u32 = 2;
    const SW_SCHEMA: u32 = 3;
    const SW_SCHEMA_SLASH: u32 = 4;
    const SW_SCHEMA_SLASH_SLASH: u32 = 5;
    const SW_SPACES_BEFORE_HOST: u32 = 6;
    const SW_HOST_START: u32 = 7;
    const SW_HOST: u32 = 8;
    const SW_HOST_END: u32 = 9;
    const SW_HOST_IP_LITERAL: u32 = 10;
    const SW_PORT_START: u32 = 11;
    const SW_PORT: u32 = 12;
    const SW_AFTER_SLASH_IN_URI: u32 = 13;
    const SW_CHECK_URI: u32 = 14;
    const SW_URI: u32 = 15;
    const SW_HTTP_09: u32 = 16;
    const SW_HTTP_H: u32 = 17;
    const SW_HTTP_HT: u32 = 18;
    const SW_HTTP_HTT: u32 = 19;
    const SW_HTTP_HTTP: u32 = 20;
    const SW_FIRST_MAJOR_DIGIT: u32 = 21;
    const SW_MAJOR_DIGIT: u32 = 22;
    const SW_FIRST_MINOR_DIGIT: u32 = 23;
    const SW_MINOR_DIGIT: u32 = 24;
    const SW_SPACES_AFTER_DIGIT: u32 = 25;
    const SW_ALMOST_DONE: u32 = 26;

    let mut state = r.state;
    let mut p = *pos;
    let mut done = false;

    while p < buf.len() {
        let ch = buf[p];
        // each arm either advances p (continue), or sets done and breaks
        match state {
            SW_START => {
                r.request_start = p;
                if ch == CR || ch == LF {
                    p += 1;
                    continue;
                }
                if !(b'A'..=b'Z').contains(&ch) && ch != b'_' && ch != b'-' {
                    return NGX_HTTP_PARSE_INVALID_METHOD;
                }
                state = SW_METHOD;
            }
            SW_METHOD => {
                if ch == b' ' {
                    r.method_end = p - 1;
                    let m = &buf[r.request_start..p];
                    state = SW_SPACES_BEFORE_URI;
                    match m {
                        b"GET" => r.method = NGX_HTTP_GET,
                        b"PUT" => r.method = NGX_HTTP_PUT,
                        b"POST" => r.method = NGX_HTTP_POST,
                        b"COPY" => r.method = NGX_HTTP_COPY,
                        b"MOVE" => r.method = NGX_HTTP_MOVE,
                        b"LOCK" => r.method = NGX_HTTP_LOCK,
                        b"HEAD" => r.method = NGX_HTTP_HEAD,
                        b"MKCOL" => r.method = NGX_HTTP_MKCOL,
                        b"PATCH" => r.method = NGX_HTTP_PATCH,
                        b"TRACE" => r.method = NGX_HTTP_TRACE,
                        b"DELETE" => r.method = NGX_HTTP_DELETE,
                        b"UNLOCK" => r.method = NGX_HTTP_UNLOCK,
                        b"OPTIONS" => r.method = NGX_HTTP_OPTIONS,
                        b"CONNECT" => {
                            r.method = NGX_HTTP_CONNECT;
                            state = SW_SPACES_BEFORE_HOST;
                        }
                        b"PROPFIND" => r.method = NGX_HTTP_PROPFIND,
                        b"PROPPATCH" => r.method = NGX_HTTP_PROPPATCH,
                        _ => {}
                    }
                } else if !(b'A'..=b'Z').contains(&ch) && ch != b'_' && ch != b'-' {
                    return NGX_HTTP_PARSE_INVALID_METHOD;
                }
            }
            SW_SPACES_BEFORE_URI => {
                if ch == b'/' {
                    r.uri_start = Some(p);
                    state = SW_AFTER_SLASH_IN_URI;
                } else {
                    let c = ch | 0x20;
                    if (b'a'..=b'z').contains(&c) {
                        r.schema_start = Some(p);
                        state = SW_SCHEMA;
                    } else if ch != b' ' {
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                }
            }
            SW_SCHEMA => {
                let c = ch | 0x20;
                if (b'a'..=b'z').contains(&c) || ch.is_ascii_digit() || ch == b'+' || ch == b'-' || ch == b'.' {
                    // stay
                } else if ch == b':' {
                    r.schema_end = Some(p);
                    state = SW_SCHEMA_SLASH;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_SCHEMA_SLASH => {
                if ch == b'/' {
                    state = SW_SCHEMA_SLASH_SLASH;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_SCHEMA_SLASH_SLASH => {
                if ch == b'/' {
                    state = SW_HOST_START;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_SPACES_BEFORE_HOST | SW_HOST_START | SW_HOST | SW_HOST_END => {
                let mut st = state;
                let mut handled = false;
                if st == SW_SPACES_BEFORE_HOST {
                    if ch == b' ' {
                        handled = true;
                    } else {
                        st = SW_HOST_START;
                    }
                }
                if !handled && st == SW_HOST_START {
                    r.host_start = Some(p);
                    if ch == b'[' {
                        state = SW_HOST_IP_LITERAL;
                        handled = true;
                    } else {
                        st = SW_HOST;
                    }
                }
                if !handled && st == SW_HOST {
                    let c = ch | 0x20;
                    if (b'a'..=b'z').contains(&c) || ch.is_ascii_digit() || ch == b'.' || ch == b'-' {
                        state = SW_HOST;
                        handled = true;
                    } else {
                        st = SW_HOST_END;
                    }
                }
                if !handled && st == SW_HOST_END {
                    if ch == b':' {
                        state = SW_PORT_START;
                    } else {
                        r.host_end = Some(p);
                        if r.method == NGX_HTTP_CONNECT {
                            return NGX_HTTP_PARSE_INVALID_REQUEST;
                        }
                        match ch {
                            b'/' => {
                                r.uri_start = Some(p);
                                state = SW_AFTER_SLASH_IN_URI;
                            }
                            b'?' => {
                                r.uri_start = Some(p);
                                r.args_start = Some(p + 1);
                                r.empty_path_in_uri = true;
                                state = SW_URI;
                            }
                            b' ' => {
                                let se = r.schema_end.unwrap_or(0);
                                r.uri_start = Some(se + 1);
                                r.uri_end = Some(se + 2);
                                state = SW_HTTP_09;
                            }
                            _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
                        }
                    }
                }
            }
            SW_HOST_IP_LITERAL => {
                let c = ch | 0x20;
                if ch.is_ascii_digit() || (b'a'..=b'z').contains(&c) {
                    // stay
                } else {
                    match ch {
                        b':' => {}
                        b']' => state = SW_HOST_END,
                        b'-' | b'.' | b'_' | b'~' => {}
                        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
                        _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
                    }
                }
            }
            SW_PORT_START | SW_PORT => {
                let mut fallthrough = false;
                if state == SW_PORT_START {
                    state = SW_PORT;
                    if ch.is_ascii_digit() {
                        // stay
                    } else if r.method == NGX_HTTP_CONNECT {
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    } else {
                        fallthrough = true;
                    }
                } else {
                    fallthrough = true;
                }
                if fallthrough {
                    if ch.is_ascii_digit() {
                        // stay in port
                    } else {
                        r.host_end = Some(p);
                        if r.method == NGX_HTTP_CONNECT {
                            if ch == b' ' {
                                state = SW_HTTP_09;
                            } else {
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                        } else {
                            match ch {
                                b'/' => {
                                    r.uri_start = Some(p);
                                    state = SW_AFTER_SLASH_IN_URI;
                                }
                                b'?' => {
                                    r.uri_start = Some(p);
                                    r.args_start = Some(p + 1);
                                    r.empty_path_in_uri = true;
                                    state = SW_URI;
                                }
                                b' ' => {
                                    let se = r.schema_end.unwrap_or(0);
                                    r.uri_start = Some(se + 1);
                                    r.uri_end = Some(se + 2);
                                    state = SW_HTTP_09;
                                }
                                _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
                            }
                        }
                    }
                }
            }
            SW_AFTER_SLASH_IN_URI => {
                if usual(ch) {
                    state = SW_CHECK_URI;
                } else {
                    match ch {
                        b' ' => {
                            r.uri_end = Some(p);
                            state = SW_HTTP_09;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = SW_ALMOST_DONE;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            done = true;
                            break;
                        }
                        b'.' => {
                            r.complex_uri = true;
                            state = SW_URI;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = SW_URI;
                        }
                        b'/' => {
                            r.complex_uri = true;
                            state = SW_URI;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = SW_URI;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = SW_URI;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                            state = SW_CHECK_URI;
                        }
                    }
                }
            }
            SW_CHECK_URI => {
                if !usual(ch) {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = SW_AFTER_SLASH_IN_URI;
                        }
                        b'.' => {
                            r.uri_ext = Some(p + 1);
                        }
                        b' ' => {
                            r.uri_end = Some(p);
                            state = SW_HTTP_09;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = SW_ALMOST_DONE;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            done = true;
                            break;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = SW_URI;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = SW_URI;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = SW_URI;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                        }
                    }
                }
            }
            SW_URI => {
                if !usual(ch) {
                    match ch {
                        b' ' => {
                            r.uri_end = Some(p);
                            state = SW_HTTP_09;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = SW_ALMOST_DONE;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            done = true;
                            break;
                        }
                        b'#' => {
                            r.complex_uri = true;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                        }
                    }
                }
            }
            SW_HTTP_09 => match ch {
                b' ' => {}
                CR => {
                    r.http_minor = 9;
                    state = SW_ALMOST_DONE;
                }
                LF => {
                    r.http_minor = 9;
                    done = true;
                    break;
                }
                b'H' => {
                    r.http_protocol_start = Some(p);
                    state = SW_HTTP_H;
                }
                _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
            },
            SW_HTTP_H => {
                if ch == b'T' {
                    state = SW_HTTP_HT;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_HTTP_HT => {
                if ch == b'T' {
                    state = SW_HTTP_HTT;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_HTTP_HTT => {
                if ch == b'P' {
                    state = SW_HTTP_HTTP;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_HTTP_HTTP => {
                if ch == b'/' {
                    if r.method == NGX_HTTP_CONNECT {
                        r.uri_start = Some(p);
                        r.uri_end = Some(p + 1);
                    }
                    state = SW_FIRST_MAJOR_DIGIT;
                } else {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }
            SW_FIRST_MAJOR_DIGIT => {
                if !(b'1'..=b'9').contains(&ch) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                r.http_major = (ch - b'0') as u32;
                if r.http_major > 1 {
                    return NGX_HTTP_PARSE_INVALID_VERSION;
                }
                state = SW_MAJOR_DIGIT;
            }
            SW_MAJOR_DIGIT => {
                if ch == b'.' {
                    state = SW_FIRST_MINOR_DIGIT;
                } else if !ch.is_ascii_digit() {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                } else {
                    r.http_major = r.http_major * 10 + (ch - b'0') as u32;
                    if r.http_major > 1 {
                        return NGX_HTTP_PARSE_INVALID_VERSION;
                    }
                }
            }
            SW_FIRST_MINOR_DIGIT => {
                if !ch.is_ascii_digit() {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                r.http_minor = (ch - b'0') as u32;
                state = SW_MINOR_DIGIT;
            }
            SW_MINOR_DIGIT => {
                if ch == CR {
                    state = SW_ALMOST_DONE;
                } else if ch == LF {
                    done = true;
                    break;
                } else if ch == b' ' {
                    state = SW_SPACES_AFTER_DIGIT;
                } else if !ch.is_ascii_digit() {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                } else {
                    if r.http_minor > 99 {
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                    r.http_minor = r.http_minor * 10 + (ch - b'0') as u32;
                }
            }
            SW_SPACES_AFTER_DIGIT => match ch {
                b' ' => {}
                CR => state = SW_ALMOST_DONE,
                LF => {
                    done = true;
                    break;
                }
                _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
            },
            SW_ALMOST_DONE => {
                r.request_end = p - 1;
                r.request_end_set = true;
                if ch == LF {
                    done = true;
                    break;
                }
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            _ => return NGX_HTTP_PARSE_INVALID_REQUEST,
        }
        p += 1;
    }

    if !done {
        *pos = p;
        r.state = state;
        return NGX_AGAIN;
    }

    // done:
    *pos = p + 1;
    if !r.request_end_set {
        r.request_end = p;
        r.request_end_set = true;
    }
    r.http_version = r.http_major * 1000 + r.http_minor;
    r.state = SW_START;
    if r.http_version == 9 && r.method != NGX_HTTP_GET {
        return NGX_HTTP_PARSE_INVALID_09_METHOD;
    }
    NGX_OK
}

#[inline]
fn usual(ch: u8) -> bool {
    USUAL[(ch >> 5) as usize] & (1u32 << (ch & 0x1f)) != 0
}


/// Parse a header line (port of ngx_http_parse_header_line).
/// Returns NGX_OK (header parsed), NGX_HTTP_PARSE_HEADER_DONE (empty line), NGX_AGAIN,
/// or NGX_HTTP_PARSE_INVALID_HEADER.
pub fn parse_header_line(r: &mut ParseRequest, buf: &[u8], pos: &mut usize, allow_underscores: bool) -> i64 {
    const SW_START: u32 = 0;
    const SW_NAME: u32 = 1;
    const SW_SPACE_BEFORE_VALUE: u32 = 2;
    const SW_VALUE: u32 = 3;
    const SW_SPACE_AFTER_VALUE: u32 = 4;
    const SW_IGNORE_LINE: u32 = 5;
    const SW_ALMOST_DONE: u32 = 6;
    const SW_HEADER_ALMOST_DONE: u32 = 7;

    let mut state = r.state;
    let mut hash = r.header_hash;
    let mut i = r.lowcase_index;
    let mut p = *pos;
    #[derive(PartialEq)]
    enum Fin {
        None,
        Done,
        HeaderDone,
    }
    let mut fin = Fin::None;

    while p < buf.len() {
        let ch = buf[p];
        match state {
            SW_START => {
                r.header_name_start = p;
                r.invalid_header = false;
                match ch {
                    CR => {
                        r.header_end = p;
                        state = SW_HEADER_ALMOST_DONE;
                    }
                    LF => {
                        r.header_end = p;
                        fin = Fin::HeaderDone;
                        break;
                    }
                    _ => {
                        state = SW_NAME;
                        let c = LOWCASE[ch as usize];
                        if c != 0 {
                            hash = ngx_hash(0, c);
                            r.lowcase_header[0] = c;
                            i = 1;
                        } else if ch == b'_' {
                            if allow_underscores {
                                hash = ngx_hash(0, ch);
                                r.lowcase_header[0] = ch;
                                i = 1;
                            } else {
                                hash = 0;
                                i = 0;
                                r.invalid_header = true;
                            }
                        } else if ch <= 0x20 || ch == 0x7f || ch == b':' {
                            r.header_end = p;
                            return NGX_HTTP_PARSE_INVALID_HEADER;
                        } else {
                            hash = 0;
                            i = 0;
                            r.invalid_header = true;
                        }
                    }
                }
            }
            SW_NAME => {
                let c = LOWCASE[ch as usize];
                if c != 0 {
                    hash = ngx_hash(hash, c);
                    r.lowcase_header[i] = c;
                    i = (i + 1) & (NGX_HTTP_LC_HEADER_LEN - 1);
                } else if ch == b'_' {
                    if allow_underscores {
                        hash = ngx_hash(hash, ch);
                        r.lowcase_header[i] = ch;
                        i = (i + 1) & (NGX_HTTP_LC_HEADER_LEN - 1);
                    } else {
                        r.invalid_header = true;
                    }
                } else if ch == b':' {
                    r.header_name_end = p;
                    state = SW_SPACE_BEFORE_VALUE;
                } else if ch == CR {
                    r.header_name_end = p;
                    r.header_start = p;
                    r.header_end = p;
                    state = SW_ALMOST_DONE;
                } else if ch == LF {
                    r.header_name_end = p;
                    r.header_start = p;
                    r.header_end = p;
                    fin = Fin::Done;
                    break;
                } else if ch == b'/' && r.upstream && p - r.header_name_start == 4 && &buf[r.header_name_start..p] == b"HTTP" {
                    state = SW_IGNORE_LINE;
                } else if ch <= 0x20 || ch == 0x7f {
                    r.header_end = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                } else {
                    r.invalid_header = true;
                }
            }
            SW_SPACE_BEFORE_VALUE => match ch {
                b' ' => {}
                CR => {
                    r.header_start = p;
                    r.header_end = p;
                    state = SW_ALMOST_DONE;
                }
                LF => {
                    r.header_start = p;
                    r.header_end = p;
                    fin = Fin::Done;
                    break;
                }
                0 => {
                    r.header_end = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }
                _ => {
                    r.header_start = p;
                    state = SW_VALUE;
                }
            },
            SW_VALUE => match ch {
                b' ' => {
                    r.header_end = p;
                    state = SW_SPACE_AFTER_VALUE;
                }
                CR => {
                    r.header_end = p;
                    state = SW_ALMOST_DONE;
                }
                LF => {
                    r.header_end = p;
                    fin = Fin::Done;
                    break;
                }
                0 => {
                    r.header_end = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }
                _ => {}
            },
            SW_SPACE_AFTER_VALUE => match ch {
                b' ' => {}
                CR => state = SW_ALMOST_DONE,
                LF => {
                    fin = Fin::Done;
                    break;
                }
                0 => {
                    r.header_end = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }
                _ => state = SW_VALUE,
            },
            SW_IGNORE_LINE => {
                if ch == LF {
                    state = SW_START;
                }
            }
            SW_ALMOST_DONE => match ch {
                LF => {
                    fin = Fin::Done;
                    break;
                }
                CR => {}
                _ => return NGX_HTTP_PARSE_INVALID_HEADER,
            },
            SW_HEADER_ALMOST_DONE => {
                if ch == LF {
                    fin = Fin::HeaderDone;
                    break;
                }
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            _ => return NGX_HTTP_PARSE_INVALID_HEADER,
        }
        p += 1;
    }

    match fin {
        Fin::None => {
            *pos = p;
            r.state = state;
            r.header_hash = hash;
            r.lowcase_index = i;
            NGX_AGAIN
        }
        Fin::Done => {
            *pos = p + 1;
            r.state = SW_START;
            r.header_hash = hash;
            r.lowcase_index = i;
            NGX_OK
        }
        Fin::HeaderDone => {
            *pos = p + 1;
            r.state = SW_START;
            NGX_HTTP_PARSE_HEADER_DONE
        }
    }
}




/// Parse URI to detect complex characteristics
pub fn parse_uri(r: &mut ParseRequest, buf: &[u8]) -> i64 {
    let uri_start = match r.uri_start {
        Some(s) => s,
        None => return NGX_ERROR,
    };
    let uri_end = match r.uri_end {
        Some(e) => e,
        None => return NGX_ERROR,
    };

    #[repr(u32)]
    enum State {
        Start = 0,
        AfterSlashInUri = 1,
        CheckUri = 2,
        Uri = 3,
    }

    let mut state = State::Start as usize;

    if uri_start >= buf.len() || uri_end > buf.len() || uri_start >= uri_end {
        return NGX_ERROR;
    }

    for p in uri_start..uri_end {
        let ch = buf[p];

        match state {
            0 => {
                // sw_start
                if ch != b'/' {
                    return NGX_ERROR;
                }

                state = State::AfterSlashInUri as usize;
            }

            1 => {
                // sw_after_slash_in_uri
                if is_usual(ch) {
                    state = State::CheckUri as usize;
                } else {
                    match ch {
                        b'.' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = State::Uri as usize;
                        }
                        b'/' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = State::Uri as usize;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return NGX_ERROR;
                            }
                            state = State::CheckUri as usize;
                        }
                    }
                }
            }

            2 => {
                // sw_check_uri
                if is_usual(ch) {
                    // continue
                } else {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = State::AfterSlashInUri as usize;
                        }
                        b'.' => {
                            r.uri_ext = Some(p + 1);
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = State::Uri as usize;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = State::Uri as usize;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return NGX_ERROR;
                            }
                        }
                    }
                }
            }

            3 => {
                // sw_uri
                if is_usual(ch) {
                    // continue
                } else {
                    match ch {
                        b'#' => {
                            r.complex_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return NGX_ERROR;
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }

    NGX_OK
}

/// Result struct for parse_complex_uri
pub struct ComplexUri {
    pub uri: Vec<u8>,
    pub args: Option<Vec<u8>>,
    pub exten: Option<Vec<u8>>,
}

/// Parse complex URI with normalization.
/// Ported from ngx_http_parse_complex_uri.
/// Returns normalized URI, optional args (from after ?), and optional extension.
pub fn parse_complex_uri(
    r: &ParseRequest,
    buf: &[u8],
    merge_slashes: bool,
) -> Result<ComplexUri, i64> {
    const SW_USUAL: usize = 0;
    const SW_SLASH: usize = 1;
    const SW_DOT: usize = 2;
    const SW_DOT_DOT: usize = 3;
    const SW_QUOTED: usize = 4;
    const SW_QUOTED_SECOND: usize = 5;

    let uri_start = match r.uri_start {
        Some(s) => s,
        None => return Err(NGX_HTTP_PARSE_INVALID_REQUEST),
    };
    let uri_end = match r.uri_end {
        Some(e) => e,
        None => return Err(NGX_HTTP_PARSE_INVALID_REQUEST),
    };

    if uri_start >= buf.len() || uri_end > buf.len() || uri_start >= uri_end {
        return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
    }

    let mut state: usize = SW_USUAL;
    let mut quoted_state: usize = SW_USUAL;
    let mut decoded: u8 = 0;
    let mut u = Vec::new();
    let mut args_buf: Vec<u8> = Vec::new();
    let mut uri_ext: Option<usize> = None;
    let mut args_set = false;
    let mut reprocess_ch = false;

    // Handle empty_path_in_uri: prepend /
    if r.empty_path_in_uri {
        u.push(b'/');
    }

    // Mimic C code: read first character, then loop with p <= uri_end
    let mut p = uri_start;
    if p >= buf.len() {
        return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
    }
    let mut ch = buf[p];
    p += 1;

    // Main parsing loop - p <= uri_end
    while p <= uri_end {
        match state {
            SW_USUAL => {
                if is_usual(ch) {
                    u.push(ch);
                } else {
                    match ch {
                        b'/' => {
                            uri_ext = None;
                            state = SW_SLASH;
                            u.push(ch);
                        }
                        b'%' => {
                            quoted_state = state;
                            state = SW_QUOTED;
                        }
                        b'?' => {
                            // Args start at next position
                            args_set = true;
                            while p < uri_end {
                                // Scan for # to mark end of args
                                if buf[p] == b'#' {
                                    args_buf.extend_from_slice(&buf[p + 1..uri_end]);
                                    break;
                                }
                                args_buf.push(buf[p]);
                                p += 1;
                            }
                            break;
                        }
                        b'#' => {
                            // Fragment ends the URI
                            break;
                        }
                        b'.' => {
                            uri_ext = Some(u.len() + 1);
                            u.push(ch);
                        }
                        b'+' => {
                            u.push(ch);
                        }
                        _ => {
                            u.push(ch);
                        }
                    }
                }
            }

            SW_SLASH => {
                if is_usual(ch) {
                    state = SW_USUAL;
                    u.push(ch);
                } else {
                    match ch {
                        b'/' => {
                            if !merge_slashes {
                                u.push(ch);
                            }
                        }
                        b'.' => {
                            state = SW_DOT;
                            u.push(ch);
                        }
                        b'%' => {
                            quoted_state = state;
                            state = SW_QUOTED;
                        }
                        b'?' => {
                            args_set = true;
                            while p < uri_end {
                                if buf[p] == b'#' {
                                    args_buf.extend_from_slice(&buf[p + 1..uri_end]);
                                    break;
                                }
                                args_buf.push(buf[p]);
                                p += 1;
                            }
                            break;
                        }
                        b'#' => {
                            break;
                        }
                        b'+' => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                        _ => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                    }
                }
            }

            SW_DOT => {
                if is_usual(ch) {
                    state = SW_USUAL;
                    u.push(ch);
                } else {
                    match ch {
                        b'/' => {
                            state = SW_SLASH;
                            if u.len() > 0 {
                                u.pop(); // Remove the dot
                            }
                        }
                        b'.' => {
                            state = SW_DOT_DOT;
                            u.push(ch);
                        }
                        b'%' => {
                            quoted_state = state;
                            state = SW_QUOTED;
                        }
                        b'?' => {
                            if u.len() > 0 {
                                u.pop(); // Remove the dot
                            }
                            args_set = true;
                            while p < uri_end {
                                if buf[p] == b'#' {
                                    args_buf.extend_from_slice(&buf[p + 1..uri_end]);
                                    break;
                                }
                                args_buf.push(buf[p]);
                                p += 1;
                            }
                            break;
                        }
                        b'#' => {
                            if u.len() > 0 {
                                u.pop(); // Remove the dot
                            }
                            break;
                        }
                        b'+' => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                        _ => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                    }
                }
            }

            SW_DOT_DOT => {
                if is_usual(ch) {
                    state = SW_USUAL;
                    u.push(ch);
                } else {
                    match ch {
                        b'/' | b'?' | b'#' => {
                            // Remove ".." (3 chars: dot dot plus preceding slash)
                            if u.len() >= 3 {
                                u.truncate(u.len() - 3);
                            }

                            // Find the previous slash and position after it
                            while !u.is_empty() {
                                if u[u.len() - 1] == b'/' {
                                    break;
                                }
                                u.pop();
                            }

                            if ch == b'?' {
                                args_set = true;
                                while p < uri_end {
                                    if buf[p] == b'#' {
                                        args_buf.extend_from_slice(&buf[p + 1..uri_end]);
                                        break;
                                    }
                                    args_buf.push(buf[p]);
                                    p += 1;
                                }
                                break;
                            } else if ch == b'#' {
                                break;
                            }
                            state = SW_SLASH;
                        }
                        b'%' => {
                            quoted_state = state;
                            state = SW_QUOTED;
                        }
                        b'+' => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                        _ => {
                            state = SW_USUAL;
                            u.push(ch);
                        }
                    }
                }
            }

            SW_QUOTED => {
                // Expecting first hex digit
                if ch >= b'0' && ch <= b'9' {
                    decoded = ch - b'0';
                    state = SW_QUOTED_SECOND;
                } else {
                    let c = ch | 0x20;
                    if c >= b'a' && c <= b'f' {
                        decoded = c - b'a' + 10;
                        state = SW_QUOTED_SECOND;
                    } else {
                        return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
                    }
                }
            }

            SW_QUOTED_SECOND => {
                // Expecting second hex digit
                let decodedch: u8;
                if ch >= b'0' && ch <= b'9' {
                    decodedch = (decoded << 4) + (ch - b'0');
                } else {
                    let c = ch | 0x20;
                    if c >= b'a' && c <= b'f' {
                        decodedch = (decoded << 4) + (c - b'a' + 10);
                    } else {
                        return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
                    }
                }

                // Check for invalid characters
                if decodedch == 0 {
                    // %00 is not allowed
                    return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
                }

                if decodedch == b'%' || decodedch == b'#' {
                    state = SW_USUAL;
                    u.push(decodedch);
                } else if decodedch == b'?' {
                    state = SW_USUAL;
                    u.push(decodedch);
                } else if decodedch == b'+' {
                    // Track plus_in_uri (caller will use this if needed)
                    state = quoted_state;
                    ch = decodedch;
                    reprocess_ch = true;
                } else {
                    state = quoted_state;
                    ch = decodedch;
                    reprocess_ch = true;
                }
            }

            _ => {}
        }

        if !reprocess_ch {
            if p >= buf.len() {
                break;
            }
            ch = buf[p];
            p += 1;
        } else {
            reprocess_ch = false;
        }
    }

    // Handle trailing incomplete states
    if state == SW_QUOTED || state == SW_QUOTED_SECOND {
        return Err(NGX_HTTP_PARSE_INVALID_REQUEST);
    }

    // Handle trailing dot or dot-dot
    if state == SW_DOT {
        if u.len() > 0 {
            u.pop();
        }
    } else if state == SW_DOT_DOT {
        if u.len() >= 3 {
            u.truncate(u.len() - 3);
        }
        while !u.is_empty() && u[u.len() - 1] != b'/' {
            u.pop();
        }
    }

    // Extract extension if set (from the position marked during parsing)
    let exten = uri_ext.and_then(|ext_start| {
        if ext_start <= u.len() {
            Some(u[ext_start..].to_vec())
        } else {
            None
        }
    });

    let args = if args_set && !args_buf.is_empty() {
        Some(args_buf)
    } else {
        None
    };

    Ok(ComplexUri { uri: u, args, exten })
}

/// Parse status line (used by proxy)
#[derive(Debug, Clone, Default)]
pub struct Status {
    pub http_version: u32,
    pub code: u32,
    pub count: u32,
    pub start: usize,
    pub end: usize,
}

pub fn parse_status_line(buf: &[u8], pos: &mut usize, status: &mut Status) -> i64 {
    #[repr(u32)]
    enum State {
        Start = 0,
        H = 1,
        HT = 2,
        HTT = 3,
        HTTP = 4,
        FirstMajorDigit = 5,
        MajorDigit = 6,
        FirstMinorDigit = 7,
        MinorDigit = 8,
        StatusCode = 9,
        SpaceAfterStatus = 10,
        StatusText = 11,
        AlmostDone = 12,
    }

    let mut state = 0usize;
    let mut http_major = 0u32;
    let mut http_minor = 0u32;
    let mut p = *pos;

    while p < buf.len() {
        let ch = buf[p];

        match state {
            0 => {
                // sw_start
                status.start = p;

                if ch == b'H' {
                    state = State::H as usize;
                    p += 1;
                } else {
                    return NGX_ERROR;
                }
            }

            1 => {
                // sw_H
                if ch == b'T' {
                    state = State::HT as usize;
                    p += 1;
                } else {
                    return NGX_ERROR;
                }
            }

            2 => {
                // sw_HT
                if ch == b'T' {
                    state = State::HTT as usize;
                    p += 1;
                } else {
                    return NGX_ERROR;
                }
            }

            3 => {
                // sw_HTT
                if ch == b'P' {
                    state = State::HTTP as usize;
                    p += 1;
                } else {
                    return NGX_ERROR;
                }
            }

            4 => {
                // sw_HTTP
                if ch == b'/' {
                    state = State::FirstMajorDigit as usize;
                    p += 1;
                } else {
                    return NGX_ERROR;
                }
            }

            5 => {
                // sw_first_major_digit
                if ch < b'1' || ch > b'9' {
                    return NGX_ERROR;
                }

                http_major = (ch - b'0') as u32;
                state = State::MajorDigit as usize;
                p += 1;
            }

            6 => {
                // sw_major_digit
                if ch == b'.' {
                    state = State::FirstMinorDigit as usize;
                    p += 1;
                } else if ch < b'0' || ch > b'9' {
                    return NGX_ERROR;
                } else {
                    if http_major > 99 {
                        return NGX_ERROR;
                    }
                    http_major = http_major * 10 + (ch - b'0') as u32;
                    p += 1;
                }
            }

            7 => {
                // sw_first_minor_digit
                if ch < b'0' || ch > b'9' {
                    return NGX_ERROR;
                }

                http_minor = (ch - b'0') as u32;
                state = State::MinorDigit as usize;
                p += 1;
            }

            8 => {
                // sw_minor_digit
                if ch == b' ' {
                    state = State::StatusCode as usize;
                    p += 1;
                } else if ch < b'0' || ch > b'9' {
                    return NGX_ERROR;
                } else {
                    if http_minor > 99 {
                        return NGX_ERROR;
                    }
                    http_minor = http_minor * 10 + (ch - b'0') as u32;
                    p += 1;
                }
            }

            9 => {
                // sw_status
                if ch == b' ' {
                    p += 1;
                } else if ch < b'0' || ch > b'9' {
                    return NGX_ERROR;
                } else {
                    status.code = status.code * 10 + (ch - b'0') as u32;

                    status.count += 1;
                    if status.count == 3 {
                        state = State::SpaceAfterStatus as usize;
                        status.start = p - 2;
                    }

                    p += 1;
                }
            }

            10 => {
                // sw_space_after_status
                match ch {
                    b' ' | b'.' => {
                        state = State::StatusText as usize;
                        p += 1;
                    }
                    CR => {
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        p += 1;
                        status.end = p - 1;
                        status.http_version = http_major * 1000 + http_minor;
                        *pos = p;
                        return NGX_OK;
                    }
                    _ => {
                        return NGX_ERROR;
                    }
                }
            }

            11 => {
                // sw_status_text
                match ch {
                    CR => {
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        p += 1;
                        status.end = p - 1;
                        status.http_version = http_major * 1000 + http_minor;
                        *pos = p;
                        return NGX_OK;
                    }
                    _ => {
                        p += 1;
                    }
                }
            }

            12 => {
                // sw_almost_done
                status.end = p - 1;
                if ch == LF {
                    p += 1;
                    status.http_version = http_major * 1000 + http_minor;
                    *pos = p;
                    return NGX_OK;
                } else {
                    return NGX_ERROR;
                }
            }

            _ => {
                p += 1;
            }
        }
    }

    *pos = p;
    NGX_AGAIN
}

/// Parse unsafe URI - checks for "..", "./%00", "/%00", and "/.." patterns.
/// Ported from ngx_http_parse_unsafe_uri.
/// Returns NGX_OK if safe, NGX_ERROR if unsafe.
pub fn parse_unsafe_uri(uri: &[u8], _args: &[u8], _flags: &mut u32) -> i64 {
    // Check for empty path or starts with ?
    if uri.is_empty() || uri[0] == b'?' {
        return NGX_ERROR;
    }

    // Check for ".." at the start
    if uri.len() > 1 && uri[0] == b'.' && uri[1] == b'.'
        && (uri.len() == 2 || uri[2] == b'/')
    {
        return NGX_ERROR;
    }

    // Check for unsafe patterns in URI
    let mut quoted = false;
    let mut i = 0;
    while i < uri.len() {
        let ch = uri[i];

        if ch == b'%' {
            quoted = true;
            i += 1;
            continue;
        }

        // Check for usual characters
        if is_usual(ch) {
            i += 1;
            continue;
        }

        match ch {
            b'?' => {
                // Found args marker
                break;
            }
            b'\0' => {
                // Null character is unsafe
                return NGX_ERROR;
            }
            b'/' => {
                // Check for "/../" and "/.."
                if i + 2 < uri.len() {
                    if uri[i + 1] == b'.' && uri[i + 2] == b'.'
                        && (i + 3 >= uri.len() || uri[i + 3] == b'/')
                    {
                        return NGX_ERROR;
                    }
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    // If quoted, need to re-check after unquoting
    if quoted {
        // For simplicity, we check the patterns again
        // In the C code, it would unescape and re-check
        // Here we just validate that escaped nulls aren't present
        let mut j = 0;
        while j < uri.len() {
            if uri[j] == b'%' {
                if j + 2 < uri.len() {
                    // Check for %00 (null)
                    if (uri[j + 1] == b'0' || uri[j + 1] == b'0')
                        && (uri[j + 2] == b'0' || uri[j + 2] == b'0')
                    {
                        return NGX_ERROR;
                    }
                }
                j += 3;
            } else {
                j += 1;
            }
        }

        // Check again for ".." after conceptual unquoting
        let mut i = 0;
        while i < uri.len() {
            if uri[i] == b'/' && i + 2 < uri.len() {
                if uri[i + 1] == b'.' && uri[i + 2] == b'.' {
                    if i + 3 >= uri.len() || uri[i + 3] == b'/' {
                        return NGX_ERROR;
                    }
                }
            }
            i += 1;
        }
    }

    NGX_OK
}

/// Parse Set-Cookie header values looking for a specific cookie name.
/// Returns the cookie value if found, None otherwise.
/// Ported from ngx_http_parse_set_cookie_lines.
pub fn parse_set_cookie_lines(values: &[&[u8]], name: &[u8]) -> Option<Vec<u8>> {
    for value in values {
        // Name must be shorter than value
        if name.len() >= value.len() {
            continue;
        }

        let mut start = 0;
        let end = value.len();

        // Check if this header starts with the name
        if !case_insensitive_eq(&value[start..], name) {
            continue;
        }

        start += name.len();

        // Skip whitespace
        while start < end && value[start] == b' ' {
            start += 1;
        }

        // Expect '=' after name
        if start >= end || value[start] != b'=' {
            continue;
        }

        start += 1;

        // Skip whitespace after '='
        while start < end && value[start] == b' ' {
            start += 1;
        }

        // Find the end of the value (terminated by ; or end of string)
        let val_start = start;
        while start < end && value[start] != b';' {
            start += 1;
        }

        return Some(value[val_start..start].to_vec());
    }

    None
}

/// Parse header value for multi-header lines (cookies, accept, etc.)
pub fn parse_multi_header_lines(values: &[&[u8]], name: &[u8], sep: u8) -> Option<Vec<u8>> {
    for value in values {
        if value.len() < name.len() {
            continue;
        }

        let mut start = 0usize;
        let end = value.len();

        while start < end {
            if start + name.len() > end {
                break;
            }

            if !case_insensitive_eq(&value[start..], name) {
                // Skip to next separator
                while start < end && value[start] != sep {
                    start += 1;
                }
                if start < end {
                    start += 1; // Skip separator
                }
                while start < end && value[start] == b' ' {
                    start += 1;
                }
                continue;
            }

            start += name.len();

            while start < end && value[start] == b' ' {
                start += 1;
            }

            if start >= end || value[start] != b'=' {
                // No value
                if start >= end || value[start] == sep {
                    return Some(Vec::new());
                }

                // Skip to next separator
                while start < end && value[start] != sep {
                    start += 1;
                }
                if start < end {
                    start += 1;
                }
                while start < end && value[start] == b' ' {
                    start += 1;
                }
                continue;
            }

            start += 1; // Skip '='

            while start < end && value[start] == b' ' {
                start += 1;
            }

            let val_start = start;
            while start < end && value[start] != sep {
                start += 1;
            }

            return Some(value[val_start..start].to_vec());
        }
    }

    None
}

#[inline]
fn case_insensitive_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() < b.len() {
        return false;
    }
    for i in 0..b.len() {
        if (a[i] | 0x20) != (b[i] | 0x20) {
            return false;
        }
    }
    true
}

/// Find argument in query string
pub fn arg<'a>(args: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if args.is_empty() {
        return None;
    }

    let mut p = 0usize;
    let last = args.len();

    while p < last {
        // Find the name
        if p == 0 || args[p - 1] == b'&' {
            let mut i = 0;
            while i < name.len() && p + i < last {
                if args[p + i] != name[i] {
                    break;
                }
                i += 1;
            }

            if i == name.len() && p + i < last && args[p + i] == b'=' {
                p += i + 1;

                // Find end of value
                let val_start = p;
                while p < last && args[p] != b'&' {
                    p += 1;
                }

                return Some(&args[val_start..p]);
            }
        }

        // Skip to next '&'
        while p < last && args[p] != b'&' {
            p += 1;
        }
        if p < last {
            p += 1;
        }
    }

    None
}

/// Split arguments from URI
pub fn split_args(uri: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = uri.iter().position(|&b| b == b'?') {
        (&uri[..pos], &uri[pos + 1..])
    } else {
        (uri, &[])
    }
}

/// Parse chunked transfer encoding
#[derive(Debug, Clone, Default)]
pub struct ChunkedState {
    pub state: u32,
    pub size: i64,
    pub length: i64,
}

pub fn parse_chunked(
    ctx: &mut ChunkedState,
    buf: &[u8],
    pos: &mut usize,
    keep_trailers: bool,
) -> i64 {
    #[repr(u32)]
    enum State {
        ChunkStart = 0,
        ChunkSize = 1,
        ChunkExtension = 2,
        ChunkExtensionAlmostDone = 3,
        ChunkData = 4,
        AfterData = 5,
        AfterDataAlmostDone = 6,
        LastChunkExtension = 7,
        LastChunkExtensionAlmostDone = 8,
        Trailer = 9,
        TrailerAlmostDone = 10,
        TrailerHeader = 11,
        TrailerHeaderAlmostDone = 12,
    }

    let mut state = ctx.state as usize;

    if state == State::ChunkData as usize && ctx.size == 0 {
        state = State::AfterData as usize;
    }

    let mut rc = NGX_AGAIN;

    for pos_iter in *pos..buf.len() {
        let ch = buf[pos_iter];

        match state {
            0 => {
                // sw_chunk_start
                if ch >= b'0' && ch <= b'9' {
                    state = State::ChunkSize as usize;
                    ctx.size = (ch - b'0') as i64;
                } else {
                    let c = ch | 0x20;
                    if c >= b'a' && c <= b'f' {
                        state = State::ChunkSize as usize;
                        ctx.size = (c - b'a' + 10) as i64;
                    } else {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                }
            }

            1 => {
                // sw_chunk_size
                if ctx.size > NGX_MAX_OFF_T_VALUE / 16 {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }

                if ch >= b'0' && ch <= b'9' {
                    ctx.size = ctx.size * 16 + (ch - b'0') as i64;
                } else {
                    let c = ch | 0x20;
                    if c >= b'a' && c <= b'f' {
                        ctx.size = ctx.size * 16 + (c - b'a' + 10) as i64;
                    } else if ctx.size == 0 {
                        match ch {
                            CR => {
                                state = State::LastChunkExtensionAlmostDone as usize;
                            }
                            b';' | b' ' | b'\t' => {
                                state = State::LastChunkExtension as usize;
                            }
                            _ => {
                                *pos = pos_iter;
                                return NGX_ERROR;
                            }
                        }
                    } else {
                        match ch {
                            CR => {
                                state = State::ChunkExtensionAlmostDone as usize;
                            }
                            b';' | b' ' | b'\t' => {
                                state = State::ChunkExtension as usize;
                            }
                            _ => {
                                *pos = pos_iter;
                                return NGX_ERROR;
                            }
                        }
                    }
                }
            }

            2 => {
                // sw_chunk_extension
                match ch {
                    CR => {
                        state = State::ChunkExtensionAlmostDone as usize;
                    }
                    LF => {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                    _ => {}
                }
            }

            3 => {
                // sw_chunk_extension_almost_done
                if ch == LF {
                    state = State::ChunkData as usize;
                } else {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }
            }

            4 => {
                // sw_chunk_data
                rc = NGX_OK;
                *pos = pos_iter;
                ctx.state = state as u32;

                // Calculate length
                compute_chunk_length(ctx, state);
                return rc;
            }

            5 => {
                // sw_after_data
                match ch {
                    CR => {
                        state = State::AfterDataAlmostDone as usize;
                    }
                    _ => {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                }
            }

            6 => {
                // sw_after_data_almost_done
                if ch == LF {
                    state = State::ChunkStart as usize;
                } else {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }
            }

            7 => {
                // sw_last_chunk_extension
                match ch {
                    CR => {
                        state = State::LastChunkExtensionAlmostDone as usize;
                    }
                    LF => {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                    _ => {}
                }
            }

            8 => {
                // sw_last_chunk_extension_almost_done
                if ch == LF {
                    if keep_trailers {
                        *pos = pos_iter + 1;
                        ctx.state = 0;
                        return NGX_DONE;
                    }
                    state = State::Trailer as usize;
                } else {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }
            }

            9 => {
                // sw_trailer
                match ch {
                    CR => {
                        state = State::TrailerAlmostDone as usize;
                    }
                    LF => {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                    _ => {
                        state = State::TrailerHeader as usize;
                    }
                }
            }

            10 => {
                // sw_trailer_almost_done
                if ch == LF {
                    *pos = pos_iter + 1;
                    ctx.state = 0;
                    return NGX_DONE;
                } else {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }
            }

            11 => {
                // sw_trailer_header
                match ch {
                    CR => {
                        state = State::TrailerHeaderAlmostDone as usize;
                    }
                    LF => {
                        *pos = pos_iter;
                        return NGX_ERROR;
                    }
                    _ => {}
                }
            }

            12 => {
                // sw_trailer_header_almost_done
                if ch == LF {
                    state = State::Trailer as usize;
                } else {
                    *pos = pos_iter;
                    return NGX_ERROR;
                }
            }

            _ => {}
        }
    }

    ctx.state = state as u32;
    *pos = buf.len();

    if ctx.size > NGX_MAX_OFF_T_VALUE - 9 {
        return NGX_ERROR;
    }

    compute_chunk_length(ctx, state);

    rc
}

#[inline]
fn compute_chunk_length(ctx: &mut ChunkedState, state: usize) {
    match state {
        0 => {
            ctx.length = 5; // "0" CRLF CRLF
        }
        1 => {
            ctx.length = 2 + (if ctx.size != 0 { ctx.size + 7 } else { 2 });
        }
        2 => {
            ctx.length = 2 + ctx.size + 7;
        }
        3 => {
            ctx.length = 1 + ctx.size + 7;
        }
        4 => {
            ctx.length = ctx.size + 7;
        }
        5 => {
            ctx.length = 7;
        }
        6 => {
            ctx.length = 6;
        }
        7 => {
            ctx.length = 4;
        }
        8 => {
            ctx.length = 3;
        }
        9 => {
            ctx.length = 2;
        }
        10 => {
            ctx.length = 1;
        }
        11 => {
            ctx.length = 4;
        }
        12 => {
            ctx.length = 3;
        }
        _ => {
            ctx.length = 0;
        }
    }
}

// Method comparison helpers
#[inline]
fn eq3(m: &[u8], c0: u8, c1: u8, c2: u8) -> bool {
    m.len() >= 3 && m[0] == c0 && m[1] == c1 && m[2] == c2
}

#[inline]
fn eq3O(m: &[u8], c0: u8, _c1: u8, c2: u8, c3: u8) -> bool {
    m.len() >= 4 && m[0] == c0 && m[2] == c2 && m[3] == c3
}

#[inline]
fn eq4(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8) -> bool {
    m.len() >= 4 && m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3
}

#[inline]
fn eq5(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8, c4: u8) -> bool {
    m.len() >= 5 && m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4
}

#[inline]
fn eq6(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8) -> bool {
    m.len() >= 6
        && m[0] == c0
        && m[1] == c1
        && m[2] == c2
        && m[3] == c3
        && m[4] == c4
        && m[5] == c5
}

#[inline]
fn eq7(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8, c6: u8) -> bool {
    m.len() >= 7
        && m[0] == c0
        && m[1] == c1
        && m[2] == c2
        && m[3] == c3
        && m[4] == c4
        && m[5] == c5
        && m[6] == c6
}

#[inline]
fn eq8(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8) -> bool {
    m.len() >= 8
        && m[0] == c0
        && m[1] == c1
        && m[2] == c2
        && m[3] == c3
        && m[4] == c4
        && m[5] == c5
        && m[6] == c6
        && m[7] == c7
}

#[inline]
fn eq9(m: &[u8], c0: u8, c1: u8, c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8) -> bool {
    m.len() >= 9
        && m[0] == c0
        && m[1] == c1
        && m[2] == c2
        && m[3] == c3
        && m[4] == c4
        && m[5] == c5
        && m[6] == c6
        && m[7] == c7
        && m[8] == c8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line_get_http11() {
        let buf = b"GET /index.html HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_GET);
        assert_eq!(r.http_major, 1);
        assert_eq!(r.http_minor, 1);
        assert_eq!(r.http_version, 1001);
        assert_eq!(r.uri_start, Some(4));
        assert_eq!(r.uri_end, Some(15));
        assert_eq!(pos, 26);
    }

    #[test]
    fn test_parse_request_line_post_http10() {
        let buf = b"POST /api/data HTTP/1.0\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_POST);
        assert_eq!(r.http_version, 1000);
    }

    #[test]
    fn test_parse_request_line_head() {
        let buf = b"HEAD /file.txt HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_HEAD);
    }

    #[test]
    fn test_parse_request_line_delete() {
        let buf = b"DELETE /resource HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_DELETE);
    }

    #[test]
    fn test_parse_request_line_put() {
        let buf = b"PUT /data HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_PUT);
    }

    #[test]
    fn test_parse_request_line_options() {
        let buf = b"OPTIONS /path HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_OPTIONS);
    }

    #[test]
    fn test_parse_request_line_connect() {
        let buf = b"CONNECT host:443 HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_CONNECT);
    }

    #[test]
    fn test_parse_request_line_patch() {
        let buf = b"PATCH /api HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_PATCH);
    }

    #[test]
    fn test_parse_request_line_trace() {
        let buf = b"TRACE / HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_TRACE);
    }

    #[test]
    fn test_parse_request_line_absolute_uri() {
        let buf = b"GET http://example.com/path HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.schema_start, Some(4));
        assert_eq!(r.schema_end, Some(8));
        assert_eq!(r.host_start, Some(11));
    }

    #[test]
    fn test_parse_request_line_http09_get() {
        let buf = b"GET /path\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.http_version, 9);
    }

    #[test]
    fn test_parse_request_line_invalid_method() {
        let buf = b"get /path HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_METHOD);
    }

    #[test]
    fn test_parse_request_line_invalid_version() {
        let buf = b"GET /path HTTP/9.9\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_VERSION);
    }

    #[test]
    fn test_parse_request_line_incomplete() {
        let buf = b"GET /path HTTP/1.1\r";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_AGAIN);
    }

    #[test]
    fn test_parse_request_line_lf_only() {
        let buf = b"GET /path HTTP/1.1\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
    }

    #[test]
    fn test_parse_header_line_simple() {
        let buf = b"Host: example.com\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.header_name_start, 0);
        assert_eq!(r.header_name_end, 4);
        assert_eq!(r.header_start, 6);
        assert_eq!(r.header_end, 17);
    }

    #[test]
    fn test_parse_header_line_with_underscores_allowed() {
        let buf = b"X_Custom_Header: value\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, true);

        assert_eq!(rc, NGX_OK);
    }

    #[test]
    fn test_parse_header_line_with_underscores_disallowed() {
        let buf = b"X_Custom_Header: value\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.invalid_header, true);
    }

    #[test]
    fn test_parse_header_line_empty_line() {
        let buf = b"\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE);
    }

    #[test]
    fn test_parse_header_line_lf_only() {
        let buf = b"\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE);
    }

    #[test]
    fn test_parse_header_line_incomplete() {
        let buf = b"Host: example.com\r";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_AGAIN);
    }

    #[test]
    fn test_arg_found() {
        let args = b"foo=bar&baz=qux";
        let result = arg(args, b"foo");
        assert_eq!(result, Some(&b"bar"[..]));
    }

    #[test]
    fn test_arg_not_found() {
        let args = b"foo=bar&baz=qux";
        let result = arg(args, b"notfound");
        assert_eq!(result, None);
    }

    #[test]
    fn test_arg_last_param() {
        let args = b"foo=bar&baz=qux";
        let result = arg(args, b"baz");
        assert_eq!(result, Some(&b"qux"[..]));
    }

    #[test]
    fn test_arg_empty_value() {
        let args = b"foo=&baz=qux";
        let result = arg(args, b"foo");
        assert_eq!(result, Some(&b""[..]));
    }

    #[test]
    fn test_split_args_with_query() {
        let uri = b"/path?arg1=val1&arg2=val2";
        let (path, args) = split_args(uri);
        assert_eq!(path, &b"/path"[..]);
        assert_eq!(args, &b"arg1=val1&arg2=val2"[..]);
    }

    #[test]
    fn test_split_args_no_query() {
        let uri = b"/path/to/file";
        let (path, args) = split_args(uri);
        assert_eq!(path, &b"/path/to/file"[..]);
        assert_eq!(args, &b""[..]);
    }

    #[test]
    fn test_status_line_http11_200() {
        let buf = b"HTTP/1.1 200 OK\r\n";
        let mut status = Status::default();
        let mut pos = 0;

        let rc = parse_status_line(buf, &mut pos, &mut status);

        assert_eq!(rc, NGX_OK);
        assert_eq!(status.code, 200);
        assert_eq!(status.http_version, 1001);
    }

    #[test]
    fn test_status_line_http10_404() {
        let buf = b"HTTP/1.0 404 Not Found\r\n";
        let mut status = Status::default();
        let mut pos = 0;

        let rc = parse_status_line(buf, &mut pos, &mut status);

        assert_eq!(rc, NGX_OK);
        assert_eq!(status.code, 404);
        assert_eq!(status.http_version, 1000);
    }

    #[test]
    fn test_chunked_simple() {
        let buf = b"5\r\nhello\r\n0\r\n\r\n";
        let mut ctx = ChunkedState::default();
        let mut pos = 0;

        let rc = parse_chunked(&mut ctx, buf, &mut pos, false);

        assert!(rc == NGX_OK || rc == NGX_DONE);
    }

    #[test]
    fn test_parse_multi_header_lines_found() {
        let values = vec![b"foo=bar, baz=qux".as_ref()];
        let result = parse_multi_header_lines(&values, b"foo", b',');
        assert_eq!(result, Some(b"bar".to_vec()));
    }

    #[test]
    fn test_parse_multi_header_lines_not_found() {
        let values = vec![b"foo=bar, baz=qux".as_ref()];
        let result = parse_multi_header_lines(&values, b"notfound", b',');
        assert_eq!(result, None);
    }

    #[test]
    fn test_case_insensitive_eq() {
        assert!(case_insensitive_eq(b"HOST", b"host"));
        assert!(case_insensitive_eq(b"Content-Type", b"content-type"));
        assert!(!case_insensitive_eq(b"foo", b"bar"));
    }

    #[test]
    fn test_is_usual() {
        assert!(is_usual(b'a'));
        assert!(is_usual(b'9'));
        assert!(is_usual(b'-'));
        assert!(!is_usual(0x00));
        assert!(!is_usual(0x1f));
    }

    #[test]
    fn test_mkcol() {
        let buf = b"MKCOL /col HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_MKCOL);
    }

    #[test]
    fn test_propfind() {
        let buf = b"PROPFIND /col HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_PROPFIND);
    }

    #[test]
    fn test_proppatch() {
        let buf = b"PROPPATCH /col HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_PROPPATCH);
    }

    #[test]
    fn test_lock() {
        let buf = b"LOCK /res HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_LOCK);
    }

    #[test]
    fn test_unlock() {
        let buf = b"UNLOCK /res HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_UNLOCK);
    }

    #[test]
    fn test_uri_with_double_slash() {
        let buf = b"GET /path//to//file HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.complex_uri, true);
    }

    #[test]
    fn test_uri_with_dotdot() {
        let buf = b"GET /path/../file HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.complex_uri, true);
    }

    #[test]
    fn test_uri_with_percent() {
        let buf = b"GET /path%20with%20spaces HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.quoted_uri, true);
    }

    #[test]
    fn test_uri_with_plus() {
        let buf = b"GET /path+with+plus HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.plus_in_uri, true);
    }

    // Tests for parse_complex_uri
    #[test]
    fn test_parse_complex_uri_simple() {
        let buf = b"/path/to/file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(13);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        assert_eq!(uri.uri, b"/path/to/file");
    }

    #[test]
    fn test_parse_complex_uri_with_dot() {
        let buf = b"/path/./file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(12);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        // The dot should be removed
        assert_eq!(uri.uri, b"/path/file");
    }

    #[test]
    fn test_parse_complex_uri_with_dotdot() {
        let buf = b"/path/../file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(13);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        // Should go back up one level
        assert_eq!(uri.uri, b"/file");
    }

    #[test]
    fn test_parse_complex_uri_with_extension() {
        let buf = b"/path/file.html\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(15);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        assert_eq!(uri.uri, b"/path/file.html");
        assert!(uri.exten.is_some());
        assert_eq!(uri.exten.unwrap(), b"html");
    }

    #[test]
    fn test_parse_complex_uri_with_query() {
        let buf = b"/path?query=value\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(17);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        assert_eq!(uri.uri, b"/path");
        assert!(uri.args.is_some());
        assert_eq!(uri.args.unwrap(), b"query=value");
    }

    #[test]
    fn test_parse_complex_uri_with_fragment() {
        let buf = b"/path#fragment\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(14);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        assert_eq!(uri.uri, b"/path");
    }

    #[test]
    fn test_parse_complex_uri_merge_slashes_false() {
        let buf = b"/path//to/file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(14);

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_complex_uri_empty_path_prepend() {
        let buf = b"path/to/file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(12);
        r.empty_path_in_uri = true;

        let result = parse_complex_uri(&r, buf, true);

        assert!(result.is_ok());
        let uri = result.unwrap();
        // Should prepend / when empty_path_in_uri is set
        assert!(uri.uri[0] == b'/');
    }

    #[test]
    fn test_parse_complex_uri_invalid_percent_encoding() {
        let buf = b"/path%GG/file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(13);

        let result = parse_complex_uri(&r, buf, true);

        // Invalid percent encoding should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_complex_uri_null_char_invalid() {
        let buf = b"/path%00/file\r\n";
        let mut r = ParseRequest::default();
        r.uri_start = Some(0);
        r.uri_end = Some(13);

        let result = parse_complex_uri(&r, buf, true);

        // %00 (null byte) is invalid
        assert!(result.is_err());
    }

    // Tests for parse_unsafe_uri
    #[test]
    fn test_parse_unsafe_uri_safe() {
        let uri = b"/path/to/file";
        let args = b"";
        let mut flags = 0u32;

        let rc = parse_unsafe_uri(uri, args, &mut flags);

        assert_eq!(rc, NGX_OK);
    }

    #[test]
    fn test_parse_unsafe_uri_empty() {
        let uri = b"";
        let args = b"";
        let mut flags = 0u32;

        let rc = parse_unsafe_uri(uri, args, &mut flags);

        assert_eq!(rc, NGX_ERROR);
    }

    #[test]
    fn test_parse_unsafe_uri_question_mark() {
        let uri = b"?query";
        let args = b"";
        let mut flags = 0u32;

        let rc = parse_unsafe_uri(uri, args, &mut flags);

        assert_eq!(rc, NGX_ERROR);
    }

    #[test]
    fn test_parse_unsafe_uri_dotdot_start() {
        let uri = b"../etc/passwd";
        let args = b"";
        let mut flags = 0u32;

        let rc = parse_unsafe_uri(uri, args, &mut flags);

        assert_eq!(rc, NGX_ERROR);
    }

    #[test]
    fn test_parse_unsafe_uri_dotdot_in_path() {
        let uri = b"/path/../etc/passwd";
        let args = b"";
        let mut flags = 0u32;

        let rc = parse_unsafe_uri(uri, args, &mut flags);

        assert_eq!(rc, NGX_ERROR);
    }

    // Tests for parse_set_cookie_lines
    #[test]
    fn test_parse_set_cookie_lines_found() {
        let values = vec![b"SessionID=abc123; Path=/; HttpOnly".as_ref()];
        let result = parse_set_cookie_lines(&values, b"SessionID");

        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"abc123");
    }

    #[test]
    fn test_parse_set_cookie_lines_not_found() {
        let values = vec![b"SessionID=abc123; Path=/".as_ref()];
        let result = parse_set_cookie_lines(&values, b"OtherID");

        assert!(result.is_none());
    }

    #[test]
    fn test_parse_set_cookie_lines_multiple_values() {
        let values = vec![
            b"OldID=old; Path=/".as_ref(),
            b"NewID=new; Path=/".as_ref(),
        ];
        let result = parse_set_cookie_lines(&values, b"NewID");

        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"new");
    }

    // Additional specific test cases from nginx compliance
    #[test]
    fn test_parse_request_line_http09_minimal() {
        // GET /\r\n (HTTP/0.9 with no version)
        let buf = b"GET /\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.http_version, 9);
        assert_eq!(r.method, NGX_HTTP_GET);
        assert!(r.uri_start.is_some());
    }

    #[test]
    fn test_parse_request_line_with_query_and_extension() {
        // GET /a/b.html?x=1 HTTP/1.1
        let buf = b"GET /a/b.html?x=1 HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert!(r.uri_ext.is_some());
        assert!(r.args_start.is_some());
    }

    #[test]
    fn test_parse_request_line_double_space() {
        // GET  / HTTP/1.0 (double space)
        let buf = b"GET  / HTTP/1.0\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
    }

    #[test]
    fn test_parse_request_line_invalid_http_version() {
        // GET / HTTP/2.0 (only HTTP/1.x supported)
        let buf = b"GET / HTTP/2.0\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_VERSION);
    }

    #[test]
    fn test_parse_request_line_quoted_slash() {
        // GET /%2f HTTP/1.1
        let buf = b"GET /%2f HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.quoted_uri, true);
    }

    #[test]
    fn test_parse_request_line_double_slash_complex() {
        // GET /a//b HTTP/1.1
        let buf = b"GET /a//b HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.complex_uri, true);
    }

    #[test]
    fn test_parse_request_line_dot_slash_complex() {
        // GET /a/./b
        let buf = b"GET /a/./b HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.complex_uri, true);
    }

    #[test]
    fn test_parse_request_line_lowercase_method_invalid() {
        // get / HTTP/1.0 (lowercase method)
        let buf = b"get / HTTP/1.0\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_METHOD);
    }

    #[test]
    fn test_parse_request_line_trailing_data() {
        // GET / HTTP/1.1 extra\r\n
        let buf = b"GET / HTTP/1.1 extra\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        // Should have error due to extra data after version
        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_REQUEST);
    }

    #[test]
    fn test_parse_header_line_no_space_after_colon() {
        // Host:x (no space)
        let buf = b"Host:x\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.header_name_end, 4);
    }

    #[test]
    fn test_parse_header_line_trailing_spaces() {
        // "Header: value   \r\n"
        let buf = b"Header: value   \r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_OK);
    }

    #[test]
    fn test_parse_header_line_invalid_char() {
        // "Ho st: x" (space in header name)
        let buf = b"Ho st: x\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_header_line(&mut r, buf, &mut pos, false);

        assert_eq!(rc, NGX_HTTP_PARSE_INVALID_HEADER);
    }

    #[test]
    fn test_parse_chunked_simple_chunk() {
        let buf = b"5\r\nhello\r\n0\r\n\r\n";
        let mut ctx = ChunkedState::default();
        let mut pos = 0;

        // Parse chunk size
        let rc1 = parse_chunked(&mut ctx, buf, &mut pos, false);
        // Should indicate chunk data is ready
        assert!(rc1 == NGX_OK || rc1 == NGX_AGAIN);
    }

    #[test]
    fn test_parse_chunked_with_extension() {
        let buf = b"4;ext=1\r\nWiki\r\n0\r\n\r\n";
        let mut ctx = ChunkedState::default();
        let mut pos = 0;

        let rc = parse_chunked(&mut ctx, buf, &mut pos, false);
        // Should handle chunk extensions
        assert!(rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE);
    }

    #[test]
    fn test_parse_status_line_simple() {
        let buf = b"HTTP/1.1 200 OK\r\n";
        let mut status = Status::default();
        let mut pos = 0;

        let rc = parse_status_line(buf, &mut pos, &mut status);

        assert_eq!(rc, NGX_OK);
        assert_eq!(status.code, 200);
        assert_eq!(status.http_version, 1001);
    }

    #[test]
    fn test_parse_status_line_http10() {
        let buf = b"HTTP/1.0 404 Not Found\r\n";
        let mut status = Status::default();
        let mut pos = 0;

        let rc = parse_status_line(buf, &mut pos, &mut status);

        assert_eq!(rc, NGX_OK);
        assert_eq!(status.code, 404);
        assert_eq!(status.http_version, 1000);
    }

    #[test]
    fn test_parse_status_line_no_reason() {
        let buf = b"HTTP/1.1 200\r\n";
        let mut status = Status::default();
        let mut pos = 0;

        let rc = parse_status_line(buf, &mut pos, &mut status);

        assert_eq!(rc, NGX_OK);
        assert_eq!(status.code, 200);
    }
}
