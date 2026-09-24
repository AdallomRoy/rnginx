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
fn ngx_hash(mut hash: u32, ch: u8) -> u32 {
    hash = ((hash << 5).wrapping_add(hash)).wrapping_add(ch as u32);
    hash
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

/// Parse HTTP request line. Returns NGX_OK on success, NGX_AGAIN if incomplete,
/// or error codes.
pub fn parse_request_line(
    r: &mut ParseRequest,
    buf: &[u8],
    pos: &mut usize,
) -> i64 {
    #[repr(u32)]
    enum State {
        Start = 0,
        Method = 1,
        SpacesBeforeUri = 2,
        Schema = 3,
        SchemaSlash = 4,
        SchemaSlashSlash = 5,
        SpacesBeforeHost = 6,
        HostStart = 7,
        Host = 8,
        HostEnd = 9,
        HostIpLiteral = 10,
        PortStart = 11,
        Port = 12,
        AfterSlashInUri = 13,
        CheckUri = 14,
        Uri = 15,
        Http09 = 16,
        HttpH = 17,
        HttpHT = 18,
        HttpHTT = 19,
        HttpHTTP = 20,
        FirstMajorDigit = 21,
        MajorDigit = 22,
        FirstMinorDigit = 23,
        MinorDigit = 24,
        SpacesAfterDigit = 25,
        AlmostDone = 26,
    }

    let mut state = r.state as usize;
    let mut p = *pos;

    while p < buf.len() {
        let ch = buf[p];

        match state {
            0 => {
                // sw_start
                r.request_start = p;

                if ch == CR || ch == LF {
                    p += 1;
                    continue;
                }

                if (ch < b'A' || ch > b'Z') && ch != b'_' && ch != b'-' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_METHOD;
                }

                state = State::Method as usize;
                p += 1;
            }

            1 => {
                // sw_method
                if ch == b' ' {
                    r.method_end = p - 1;
                    let m = r.request_start;
                    let method_len = p - m;
                    state = State::SpacesBeforeUri as usize;

                    // Method detection
                    match method_len {
                        3 => {
                            if eq3(&buf[m..], b'G', b'E', b'T') {
                                r.method = NGX_HTTP_GET;
                            } else if eq3(&buf[m..], b'P', b'U', b'T') {
                                r.method = NGX_HTTP_PUT;
                            }
                        }
                        4 => {
                            if buf[m + 1] == b'O' {
                                if eq3O(&buf[m..], b'P', b'O', b'S', b'T') {
                                    r.method = NGX_HTTP_POST;
                                } else if eq3O(&buf[m..], b'C', b'O', b'P', b'Y') {
                                    r.method = NGX_HTTP_COPY;
                                } else if eq3O(&buf[m..], b'M', b'O', b'V', b'E') {
                                    r.method = NGX_HTTP_MOVE;
                                } else if eq3O(&buf[m..], b'L', b'O', b'C', b'K') {
                                    r.method = NGX_HTTP_LOCK;
                                }
                            } else if eq4(&buf[m..], b'H', b'E', b'A', b'D') {
                                r.method = NGX_HTTP_HEAD;
                            }
                        }
                        5 => {
                            if eq5(&buf[m..], b'M', b'K', b'C', b'O', b'L') {
                                r.method = NGX_HTTP_MKCOL;
                            } else if eq5(&buf[m..], b'P', b'A', b'T', b'C', b'H') {
                                r.method = NGX_HTTP_PATCH;
                            } else if eq5(&buf[m..], b'T', b'R', b'A', b'C', b'E') {
                                r.method = NGX_HTTP_TRACE;
                            }
                        }
                        6 => {
                            if eq6(&buf[m..], b'D', b'E', b'L', b'E', b'T', b'E') {
                                r.method = NGX_HTTP_DELETE;
                            } else if eq6(&buf[m..], b'U', b'N', b'L', b'O', b'C', b'K') {
                                r.method = NGX_HTTP_UNLOCK;
                            }
                        }
                        7 => {
                            if eq7(&buf[m..], b'O', b'P', b'T', b'I', b'O', b'N', b'S') {
                                r.method = NGX_HTTP_OPTIONS;
                            } else if eq7(&buf[m..], b'C', b'O', b'N', b'N', b'E', b'C', b'T') {
                                r.method = NGX_HTTP_CONNECT;
                                state = State::SpacesBeforeHost as usize;
                            }
                        }
                        8 => {
                            if eq8(&buf[m..], b'P', b'R', b'O', b'P', b'F', b'I', b'N', b'D') {
                                r.method = NGX_HTTP_PROPFIND;
                            }
                        }
                        9 => {
                            if eq9(&buf[m..], b'P', b'R', b'O', b'P', b'P', b'A', b'T', b'C', b'H') {
                                r.method = NGX_HTTP_PROPPATCH;
                            }
                        }
                        _ => {}
                    }

                    p += 1;
                } else if (ch < b'A' || ch > b'Z') && ch != b'_' && ch != b'-' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_METHOD;
                } else {
                    p += 1;
                }
            }

            2 => {
                // sw_spaces_before_uri
                if ch == b'/' {
                    r.uri_start = Some(p);
                    state = State::AfterSlashInUri as usize;
                    p += 1;
                } else {
                    let c = ch | 0x20;
                    if c >= b'a' && c <= b'z' {
                        r.schema_start = Some(p);
                        state = State::Schema as usize;
                        p += 1;
                    } else if ch == b' ' {
                        p += 1;
                    } else {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                }
            }

            3 => {
                // sw_schema
                let c = ch | 0x20;
                if (c >= b'a' && c <= b'z')
                    || (ch >= b'0' && ch <= b'9')
                    || ch == b'+'
                    || ch == b'-'
                    || ch == b'.'
                {
                    p += 1;
                } else if ch == b':' {
                    r.schema_end = Some(p);
                    state = State::SchemaSlash as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            4 => {
                // sw_schema_slash
                if ch == b'/' {
                    state = State::SchemaSlashSlash as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            5 => {
                // sw_schema_slash_slash
                if ch == b'/' {
                    state = State::HostStart as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            6 => {
                // sw_spaces_before_host
                if ch == b' ' {
                    p += 1;
                } else {
                    state = State::HostStart as usize;
                }
            }

            7 => {
                // sw_host_start
                r.host_start = Some(p);

                if ch == b'[' {
                    state = State::HostIpLiteral as usize;
                    p += 1;
                } else {
                    state = State::Host as usize;
                }
            }

            8 => {
                // sw_host
                let c = ch | 0x20;
                if (c >= b'a' && c <= b'z')
                    || (ch >= b'0' && ch <= b'9')
                    || ch == b'.'
                    || ch == b'-'
                {
                    p += 1;
                } else {
                    state = State::HostEnd as usize;
                }
            }

            9 => {
                // sw_host_end
                if ch == b':' {
                    state = State::PortStart as usize;
                    p += 1;
                } else {
                    r.host_end = Some(p);

                    if r.method == NGX_HTTP_CONNECT {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }

                    match ch {
                        b'/' => {
                            r.uri_start = Some(p);
                            state = State::AfterSlashInUri as usize;
                            p += 1;
                        }
                        b'?' => {
                            r.uri_start = Some(p);
                            r.args_start = Some(p + 1);
                            r.empty_path_in_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b' ' => {
                            r.uri_start = r.schema_end.map(|se| se + 1);
                            r.uri_end = r.schema_end.map(|se| se + 2);
                            state = State::Http09 as usize;
                            p += 1;
                        }
                        _ => {
                            *pos = p;
                            return NGX_HTTP_PARSE_INVALID_REQUEST;
                        }
                    }
                }
            }

            10 => {
                // sw_host_ip_literal
                if (ch >= b'0' && ch <= b'9') || (ch | 0x20 >= b'a' && ch | 0x20 <= b'f') {
                    p += 1;
                } else {
                    match ch {
                        b':' | b']' | b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {
                            if ch == b']' {
                                state = State::HostEnd as usize;
                            }
                            p += 1;
                        }
                        _ => {
                            *pos = p;
                            return NGX_HTTP_PARSE_INVALID_REQUEST;
                        }
                    }
                }
            }

            11 => {
                // sw_port_start
                state = State::Port as usize;

                if ch >= b'0' && ch <= b'9' {
                    p += 1;
                } else if r.method == NGX_HTTP_CONNECT {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                } else {
                    // fall through to port
                }
            }

            12 => {
                // sw_port
                if ch >= b'0' && ch <= b'9' {
                    p += 1;
                } else {
                    r.host_end = Some(p);

                    if r.method == NGX_HTTP_CONNECT {
                        if ch == b' ' {
                            state = State::Http09 as usize;
                            p += 1;
                        } else {
                            *pos = p;
                            return NGX_HTTP_PARSE_INVALID_REQUEST;
                        }
                    } else {
                        match ch {
                            b'/' => {
                                r.uri_start = Some(p);
                                state = State::AfterSlashInUri as usize;
                                p += 1;
                            }
                            b'?' => {
                                r.uri_start = Some(p);
                                r.args_start = Some(p + 1);
                                r.empty_path_in_uri = true;
                                state = State::Uri as usize;
                                p += 1;
                            }
                            b' ' => {
                                r.uri_start = r.schema_end.map(|se| se + 1);
                                r.uri_end = r.schema_end.map(|se| se + 2);
                                state = State::Http09 as usize;
                                p += 1;
                            }
                            _ => {
                                *pos = p;
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                        }
                    }
                }
            }

            13 => {
                // sw_after_slash_in_uri
                if is_usual(ch) {
                    state = State::CheckUri as usize;
                    p += 1;
                } else {
                    match ch {
                        b' ' => {
                            r.uri_end = Some(p);
                            state = State::Http09 as usize;
                            p += 1;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = State::AlmostDone as usize;
                            p += 1;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            p += 1;
                            if r.request_end == 0 {
                                r.request_end = p - 2;
                            }
                            r.http_version = r.http_major * 1000 + r.http_minor;
                            state = 0;
                            break;
                        }
                        b'.' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'/' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            p += 1;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                *pos = p;
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                            state = State::CheckUri as usize;
                            p += 1;
                        }
                    }
                }
            }

            14 => {
                // sw_check_uri
                if is_usual(ch) {
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = State::AfterSlashInUri as usize;
                            p += 1;
                        }
                        b'.' => {
                            r.uri_ext = Some(p + 1);
                            p += 1;
                        }
                        b' ' => {
                            r.uri_end = Some(p);
                            state = State::Http09 as usize;
                            p += 1;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = State::AlmostDone as usize;
                            p += 1;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            p += 1;
                            if r.request_end == 0 {
                                r.request_end = p - 2;
                            }
                            r.http_version = r.http_major * 1000 + r.http_minor;
                            state = 0;
                            break;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = State::Uri as usize;
                            p += 1;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            p += 1;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                *pos = p;
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                            p += 1;
                        }
                    }
                }
            }

            15 => {
                // sw_uri
                if is_usual(ch) {
                    p += 1;
                } else {
                    match ch {
                        b' ' => {
                            r.uri_end = Some(p);
                            state = State::Http09 as usize;
                            p += 1;
                        }
                        CR => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            state = State::AlmostDone as usize;
                            p += 1;
                        }
                        LF => {
                            r.uri_end = Some(p);
                            r.http_minor = 9;
                            p += 1;
                            if r.request_end == 0 {
                                r.request_end = p - 2;
                            }
                            r.http_version = r.http_major * 1000 + r.http_minor;
                            state = 0;
                            break;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            p += 1;
                        }
                        _ => {
                            if ch < 0x20 || ch == 0x7f {
                                *pos = p;
                                return NGX_HTTP_PARSE_INVALID_REQUEST;
                            }
                            p += 1;
                        }
                    }
                }
            }

            16 => {
                // sw_http_09
                match ch {
                    b' ' => {
                        p += 1;
                    }
                    CR => {
                        r.http_minor = 9;
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        r.http_minor = 9;
                        p += 1;
                        if r.request_end == 0 {
                            r.request_end = p - 2;
                        }
                        r.http_version = r.http_major * 1000 + r.http_minor;
                        state = 0;
                        break;
                    }
                    b'H' => {
                        r.http_protocol_start = Some(p);
                        state = State::HttpH as usize;
                        p += 1;
                    }
                    _ => {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                }
            }

            17 => {
                // sw_http_H
                if ch == b'T' {
                    state = State::HttpHT as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            18 => {
                // sw_http_HT
                if ch == b'T' {
                    state = State::HttpHTT as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            19 => {
                // sw_http_HTT
                if ch == b'P' {
                    state = State::HttpHTTP as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            20 => {
                // sw_http_HTTP
                if ch == b'/' {
                    if r.method == NGX_HTTP_CONNECT {
                        r.uri_start = Some(p);
                        r.uri_end = Some(p + 1);
                    }

                    state = State::FirstMajorDigit as usize;
                    p += 1;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            21 => {
                // sw_first_major_digit
                if ch < b'1' || ch > b'9' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }

                r.http_major = (ch - b'0') as u32;

                if r.http_major > 1 {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_VERSION;
                }

                state = State::MajorDigit as usize;
                p += 1;
            }

            22 => {
                // sw_major_digit
                if ch == b'.' {
                    state = State::FirstMinorDigit as usize;
                    p += 1;
                } else if ch < b'0' || ch > b'9' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                } else {
                    r.http_major = r.http_major * 10 + (ch - b'0') as u32;

                    if r.http_major > 1 {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_VERSION;
                    }

                    p += 1;
                }
            }

            23 => {
                // sw_first_minor_digit
                if ch < b'0' || ch > b'9' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }

                r.http_minor = (ch - b'0') as u32;
                state = State::MinorDigit as usize;
                p += 1;
            }

            24 => {
                // sw_minor_digit
                if ch == CR {
                    state = State::AlmostDone as usize;
                    p += 1;
                } else if ch == LF {
                    p += 1;
                    if r.request_end == 0 { r.request_end = p - 2; } r.http_version = r.http_major * 1000 + r.http_minor; state = 0;
                    break;
                } else if ch == b' ' {
                    state = State::SpacesAfterDigit as usize;
                    p += 1;
                } else if ch < b'0' || ch > b'9' {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                } else {
                    if r.http_minor > 99 {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }

                    r.http_minor = r.http_minor * 10 + (ch - b'0') as u32;
                    p += 1;
                }
            }

            25 => {
                // sw_spaces_after_digit
                match ch {
                    b' ' => {
                        p += 1;
                    }
                    CR => {
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        p += 1;
                        if r.request_end == 0 { r.request_end = p - 2; } r.http_version = r.http_major * 1000 + r.http_minor; state = 0;
                        break;
                    }
                    _ => {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_REQUEST;
                    }
                }
            }

            26 => {
                // sw_almost_done
                r.request_end = p - 1;
                if ch == LF {
                    p += 1;
                    if r.request_end == 0 { r.request_end = p - 2; } r.http_version = r.http_major * 1000 + r.http_minor; state = 0;
                    break;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
            }

            _ => {
                p += 1;
            }
        }
    }

    *pos = p;
    r.state = state as u32;

    return NGX_AGAIN;
}


/// Parse header line. Returns NGX_OK on header parsed, NGX_HTTP_PARSE_HEADER_DONE on empty line,
/// NGX_AGAIN if incomplete, or NGX_HTTP_PARSE_INVALID_HEADER.
pub fn parse_header_line(
    r: &mut ParseRequest,
    buf: &[u8],
    pos: &mut usize,
    allow_underscores: bool,
) -> i64 {
    #[repr(u32)]
    enum State {
        Start = 0,
        Name = 1,
        SpaceBeforeValue = 2,
        Value = 3,
        SpaceAfterValue = 4,
        IgnoreLine = 5,
        AlmostDone = 6,
        HeaderAlmostDone = 7,
    }

    let mut state = r.state as usize;
    let mut hash = r.header_hash;
    let mut i = r.lowcase_index;
    let mut p = *pos;

    while p < buf.len() {
        let ch = buf[p];

        match state {
            0 => {
                // sw_start
                r.header_name_start = p;
                r.invalid_header = false;

                match ch {
                    CR => {
                        r.header_end = p;
                        state = State::HeaderAlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        r.header_end = p;
                        p += 1;
                        state = 0;
                        break;
                    }
                    _ => {
                        state = State::Name as usize;

                        let c = LOWCASE[ch as usize];

                        if c != 0 {
                            hash = ngx_hash(0, c);
                            r.lowcase_header[0] = c;
                            i = 1;
                            p += 1;
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
                            p += 1;
                        } else if ch <= 0x20 || ch == 0x7f || ch == b':' {
                            r.header_end = p;
                            *pos = p;
                            return NGX_HTTP_PARSE_INVALID_HEADER;
                        } else {
                            hash = 0;
                            i = 0;
                            r.invalid_header = true;
                            p += 1;
                        }
                    }
                }
            }

            1 => {
                // sw_name
                let c = LOWCASE[ch as usize];

                if c != 0 {
                    hash = ngx_hash(hash, c);
                    r.lowcase_header[i] = c;
                    i = (i + 1) & (NGX_HTTP_LC_HEADER_LEN - 1);
                    p += 1;
                } else if ch == b'_' {
                    if allow_underscores {
                        hash = ngx_hash(hash, ch);
                        r.lowcase_header[i] = ch;
                        i = (i + 1) & (NGX_HTTP_LC_HEADER_LEN - 1);
                    } else {
                        r.invalid_header = true;
                    }
                    p += 1;
                } else if ch == b':' {
                    r.header_name_end = p;
                    state = State::SpaceBeforeValue as usize;
                    p += 1;
                } else if ch == CR {
                    r.header_name_end = p;
                    r.header_start = p;
                    r.header_end = p;
                    state = State::AlmostDone as usize;
                    p += 1;
                } else if ch == LF {
                    r.header_name_end = p;
                    r.header_start = p;
                    r.header_end = p;
                    p += 1;
                    state = 0;
                    break;
                } else if ch <= 0x20 || ch == 0x7f {
                    r.header_end = p;
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                } else {
                    r.invalid_header = true;
                    p += 1;
                }
            }

            2 => {
                // sw_space_before_value
                match ch {
                    b' ' => {
                        p += 1;
                    }
                    CR => {
                        r.header_start = p;
                        r.header_end = p;
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        r.header_start = p;
                        r.header_end = p;
                        p += 1;
                        state = 0;
                        break;
                    }
                    0 => {
                        r.header_end = p;
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_HEADER;
                    }
                    _ => {
                        r.header_start = p;
                        state = State::Value as usize;
                        p += 1;
                    }
                }
            }

            3 => {
                // sw_value
                match ch {
                    b' ' => {
                        r.header_end = p;
                        state = State::SpaceAfterValue as usize;
                        p += 1;
                    }
                    CR => {
                        r.header_end = p;
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        r.header_end = p;
                        p += 1;
                        state = 0;
                        break;
                    }
                    0 => {
                        r.header_end = p;
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_HEADER;
                    }
                    _ => {
                        p += 1;
                    }
                }
            }

            4 => {
                // sw_space_after_value
                match ch {
                    b' ' => {
                        p += 1;
                    }
                    CR => {
                        state = State::AlmostDone as usize;
                        p += 1;
                    }
                    LF => {
                        p += 1;
                        state = 0;
                        break;
                    }
                    0 => {
                        r.header_end = p;
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_HEADER;
                    }
                    _ => {
                        state = State::Value as usize;
                        p += 1;
                    }
                }
            }

            5 => {
                // sw_ignore_line
                if ch == LF {
                    state = State::Start as usize;
                }
                p += 1;
            }

            6 => {
                // sw_almost_done
                match ch {
                    LF => {
                        p += 1;
                        state = 0;
                        break;
                    }
                    CR => {
                        p += 1;
                    }
                    _ => {
                        *pos = p;
                        return NGX_HTTP_PARSE_INVALID_HEADER;
                    }
                }
            }

            7 => {
                // sw_header_almost_done
                if ch == LF {
                    p += 1;
                    state = 0;
                    break;
                } else {
                    *pos = p;
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }
            }

            _ => {
                p += 1;
            }
        }
    }

    *pos = p;
    r.state = state as u32;
    r.header_hash = hash;
    r.lowcase_index = i;

    return NGX_AGAIN;
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

/// Parse complex URI with normalization (simplified for now)
pub fn parse_complex_uri(
    _r: &mut ParseRequest,
) -> i64 {
    // This is a simplified stub. Full implementation would normalize the URI.
    NGX_OK
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
    fn test_parse_request_line_with_query() {
        let buf = b"GET /path?query=value HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.args_start, Some(11));
    }

    #[test]
    fn test_parse_request_line_with_extension() {
        let buf = b"GET /path/file.html HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.uri_ext, Some(23));
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
    fn test_copy() {
        let buf = b"COPY /src /dst HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_COPY);
    }

    #[test]
    fn test_move() {
        let buf = b"MOVE /src /dst HTTP/1.1\r\n";
        let mut r = ParseRequest::default();
        let mut pos = 0;

        let rc = parse_request_line(&mut r, buf, &mut pos);

        assert_eq!(rc, NGX_OK);
        assert_eq!(r.method, NGX_HTTP_MOVE);
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
}
