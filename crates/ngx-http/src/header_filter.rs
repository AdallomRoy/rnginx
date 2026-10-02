//! ngx_http_header_filter_module

use std::rc::Rc;

use ngx_core::buf::Buf;
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::core::*;
use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_header_filter_module");

pub fn header_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_header_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    set_top_header_filter(Rc::new(header_filter));
    set_top_early_hints_filter(Rc::new(early_hints_filter));
    Ok(())
}

/// ngx_http_early_hints_filter: "103 Early Hints" with the headers of
/// r->headers_out, flushed
pub fn early_hints_filter(r: R) -> Step {
    if !r.is_main() {
        return Step::Ready(NGX_OK);
    }

    if r.http_version.get() < NGX_HTTP_VERSION_11 {
        return Step::Ready(NGX_OK);
    }

    // ngx_http_early_hints_status_line
    const STATUS_LINE: &[u8] = b"HTTP/1.1 103 Early Hints\r\n";

    let out = {
        let ho = r.headers_out.borrow();

        let len: usize = ho.headers.iter().filter(|h| h.hash.get() != 0).map(|h| h.key.len() + 2 + h.value.borrow().len() + 2).sum();

        if len == 0 {
            return Step::Ready(NGX_OK);
        }

        let mut out = Vec::with_capacity(STATUS_LINE.len() + len + 2);

        out.extend_from_slice(STATUS_LINE);

        for h in ho.headers.iter() {
            if h.hash.get() == 0 {
                continue;
            }

            out.extend_from_slice(&h.key);
            out.extend_from_slice(b": ");
            out.extend_from_slice(&h.value.borrow());
            out.extend_from_slice(b"\r\n");
        }

        out
    };

    let mut out = out;

    http_debug!(r, "{}", B(&out));

    // the end of HTTP early hints
    out.extend_from_slice(b"\r\n");

    r.header_size.set(out.len());

    let mut b = Buf::from_vec(out);
    b.flush = true;

    let mut chain = alloc_chain();
    chain.push_back(b);

    crate::write_filter::write_filter(r, chain)
}

pub const SERVER_STRING: &[u8] = b"Server: nginx\r\n";
pub const SERVER_FULL_STRING: &[u8] = b"Server: nginx/1.31.7\r\n";
pub const SERVER_BUILD_STRING: &[u8] = b"Server: nginx/1.31.7\r\n";

/// ngx_http_status_lines: the statuses without a line there are written as
/// their number
static STATUS_LINES: &[(i64, &str)] = &[
    (200, "200 OK"),
    (201, "201 Created"),
    (202, "202 Accepted"),
    (204, "204 No Content"),
    (206, "206 Partial Content"),
    (301, "301 Moved Permanently"),
    (302, "302 Moved Temporarily"),
    (303, "303 See Other"),
    (304, "304 Not Modified"),
    (307, "307 Temporary Redirect"),
    (308, "308 Permanent Redirect"),
    (400, "400 Bad Request"),
    (401, "401 Unauthorized"),
    (402, "402 Payment Required"),
    (403, "403 Forbidden"),
    (404, "404 Not Found"),
    (405, "405 Not Allowed"),
    (406, "406 Not Acceptable"),
    (407, "407 Proxy Authentication Required"),
    (408, "408 Request Time-out"),
    (409, "409 Conflict"),
    (410, "410 Gone"),
    (411, "411 Length Required"),
    (412, "412 Precondition Failed"),
    (413, "413 Request Entity Too Large"),
    (414, "414 Request-URI Too Large"),
    (415, "415 Unsupported Media Type"),
    (416, "416 Requested Range Not Satisfiable"),
    (421, "421 Misdirected Request"),
    (429, "429 Too Many Requests"),
    (500, "500 Internal Server Error"),
    (501, "501 Not Implemented"),
    (502, "502 Bad Gateway"),
    (503, "503 Service Temporarily Unavailable"),
    (504, "504 Gateway Time-out"),
    (505, "505 HTTP Version Not Supported"),
    (507, "507 Insufficient Storage"),
];

pub fn status_line(status: i64) -> Option<&'static str> {
    STATUS_LINES.iter().find(|(s, _)| *s == status).map(|(_, l)| *l)
}

/// NGX_INT_T_LEN, NGX_OFF_T_LEN, NGX_TIME_T_LEN: the longest 64-bit
/// decimal ("-9223372036854775808")
const NGX_INT64_LEN: usize = 20;

/// The length of "Mon, 28 Sep 1970 06:00:00 GMT"
const HTTP_TIME_LEN: usize = 29;

/// ngx_http_header_filter: the response header in one buffer, its size
/// counted before it is written, as C allocates it
pub fn header_filter(r: R) -> Step {
    if r.header_sent.get() {
        return Step::Ready(NGX_OK);
    }
    r.header_sent.set(true);
    if !r.is_main() {
        return Step::Ready(NGX_OK);
    }
    if r.http_version.get() < NGX_HTTP_VERSION_10 {
        return Step::Ready(NGX_OK);
    }
    if r.method.get() == NGX_HTTP_HEAD {
        r.header_only.set(true);
    }
    let out = build_header(&r);
    http_debug!(r, "{}", B(&out).to_string().trim_end_matches("\r\n").replace("\r\n", "\n"));
    r.header_size.set(out.len());
    let mut b = Buf::from_vec(out);
    b.tag = HEADER_BUF_TAG;
    b.last_buf = r.header_only.get();
    b.flush = r.header_only.get();
    let mut chain = alloc_chain();
    chain.push_back(b);
    // Header bytes go directly to the write filter (they bypass body filters like range/gzip/sub).
    crate::write_filter::write_filter(r, chain)
}

/// The header of ngx_http_header_filter, in a buffer of the size counted
/// first
fn build_header(r: &R) -> Vec<u8> {
    let clcf = r.clcf();
    let cl = clcf.borrow();
    let mut ho = r.headers_out.borrow_mut();

    // r->headers_out.last_modified = NULL: a header of the list stays
    if ho.last_modified_time != -1 && ho.status != NGX_HTTP_OK && ho.status != NGX_HTTP_PARTIAL_CONTENT && ho.status != NGX_HTTP_NOT_MODIFIED {
        ho.last_modified_time = -1;
        ho.last_modified = None;
    }
    if ho.status == NGX_HTTP_NO_CONTENT {
        r.header_only.set(true);
        ho.content_type_len = 0;
        ho.content_type.clear();
        ho.content_length_n = -1;
        if let Some(cl) = ho.content_length.take() {
            cl.hash.set(0);
        }
        ho.last_modified = None;
        ho.last_modified_time = -1;
    }
    if ho.status == NGX_HTTP_NOT_MODIFIED {
        r.header_only.set(true);
    }

    let status = ho.status;
    let known_line = if ho.status_line.is_empty() { status_line(status) } else { None };

    // Suppress keep-alive during graceful shutdown so this response
    // signals to the client that no further requests should follow —
    // matches C's ngx_http_header_filter check of ngx_terminate /
    // ngx_exiting.
    let terminating = ngx_core::process::SIG_TERMINATE.load(std::sync::atomic::Ordering::SeqCst) || ngx_core::event::is_exiting();

    // Location: a relative one made absolute (absolute_redirect), its
    // header not written again from the list; any other stays in the list
    let location = match &ho.location {
        Some(loc) if *cl.absolute_redirect && loc.value.borrow().first() == Some(&b'/') => Some(loc.clone()),
        _ => None,
    };
    let cscf;
    let hin;
    // server_name_in_redirect on: the server name; else the client's
    // Host; else the local address
    let host: std::borrow::Cow<[u8]> = if location.is_none() {
        std::borrow::Cow::Borrowed(&[])
    } else if *cl.server_name_in_redirect {
        cscf = r.cscf();
        std::borrow::Cow::Owned(cscf.borrow().server_name.clone())
    } else if {
        hin = r.headers_in.borrow();
        !hin.server.is_empty()
    } {
        std::borrow::Cow::Borrowed(&hin.server[..])
    } else if let Some(local) = r.connection.local_sockaddr() {
        std::borrow::Cow::Owned(match local {
            ngx_core::inet::SockAddr::V4(a) => a.ip().to_string().into_bytes(),
            ngx_core::inet::SockAddr::V6(a) => a.ip().to_string().into_bytes(),
            ngx_core::inet::SockAddr::Unix(_) => Vec::new(),
        })
    } else {
        std::borrow::Cow::Owned(r.cscf().borrow().server_name.clone())
    };
    let ssl = location.is_some() && r.connection.ssl.borrow().is_some();
    let port = match &location {
        Some(_) if *cl.port_in_redirect => match r.connection.local_sockaddr() {
            Some(local) if local.port() != 0 && local.port() != if ssl { 443 } else { 80 } => local.port(),
            _ => 0,
        },
        _ => 0,
    };

    // NGX_HTTP_GZIP
    if r.gzip_vary.get() && !*cl.gzip_vary {
        r.gzip_vary.set(false);
    }

    let charset = !ho.content_type.is_empty() && ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty();

    let mut len = "HTTP/1.x ".len() + 2 /* the end of the header */ + 2;

    len += if !ho.status_line.is_empty() {
        ho.status_line.len()
    } else if let Some(l) = known_line {
        l.len()
    } else {
        NGX_INT64_LEN + 1
    };

    if ho.server.is_none() {
        len += match *cl.server_tokens {
            NGX_HTTP_SERVER_TOKENS_ON => SERVER_FULL_STRING.len(),
            NGX_HTTP_SERVER_TOKENS_BUILD => SERVER_BUILD_STRING.len(),
            _ => SERVER_STRING.len(),
        };
    }
    if ho.date.is_none() {
        len += "Date: ".len() + HTTP_TIME_LEN + 2;
    }
    if !ho.content_type.is_empty() {
        len += "Content-Type: ".len() + ho.content_type.len() + 2;
        if charset {
            len += "; charset=".len() + ho.charset.len();
        }
    }
    if ho.content_length.is_none() && ho.content_length_n >= 0 {
        len += "Content-Length: ".len() + NGX_INT64_LEN + 2;
    }
    if ho.last_modified.is_none() && ho.last_modified_time != -1 {
        len += "Last-Modified: ".len() + HTTP_TIME_LEN + 2;
    }
    if let Some(loc) = &location {
        len += "Location: https://".len() + host.len() + loc.value.borrow().len() + 2;
        if port != 0 {
            len += ":65535".len();
        }
    }
    if r.chunked.get() {
        len += "Transfer-Encoding: chunked\r\n".len();
    }
    if status == NGX_HTTP_SWITCHING_PROTOCOLS {
        len += "Connection: upgrade\r\n".len();
    } else if r.keepalive.get() && !terminating {
        len += "Connection: keep-alive\r\n".len();
        if *cl.keepalive_header > 0 {
            len += "Keep-Alive: timeout=".len() + NGX_INT64_LEN + 2;
        }
    } else {
        len += "Connection: close\r\n".len();
    }
    if r.gzip_vary.get() {
        len += "Vary: Accept-Encoding\r\n".len();
    }
    for h in ho.headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }
        if location.as_ref().is_some_and(|loc| Rc::ptr_eq(loc, h)) {
            // the Location made absolute: its hash is cleared below
            continue;
        }
        len += h.key.len() + 2 + h.value.borrow().len() + 2;
    }

    let mut out = take_header_buf(len);

    out.extend_from_slice(b"HTTP/1.1 ");
    if !ho.status_line.is_empty() {
        out.extend_from_slice(&ho.status_line);
    } else if let Some(l) = known_line {
        out.extend_from_slice(l.as_bytes());
    } else {
        // "%03ui " (as "{:03}" formats a number)
        let mut digits = 1;
        let mut v = status.unsigned_abs();
        while v >= 10 {
            v /= 10;
            digits += 1;
        }
        if status < 0 {
            out.push(b'-');
            digits += 1;
        }
        for _ in digits..3 {
            out.push(b'0');
        }
        write_dec(&mut out, status.unsigned_abs());
        out.push(b' ');
    }
    out.extend_from_slice(b"\r\n");

    // ngx_http_header_filter: "Server", "Date", "Content-Length" and
    // "Last-Modified" are written here only from the fields when there is
    // no header for them; the headers of r->headers_out.headers (typed
    // slots included) follow in their order after "Connection"
    if ho.server.is_none() {
        match *cl.server_tokens {
            NGX_HTTP_SERVER_TOKENS_ON => out.extend_from_slice(SERVER_FULL_STRING),
            NGX_HTTP_SERVER_TOKENS_BUILD => out.extend_from_slice(SERVER_BUILD_STRING),
            _ => out.extend_from_slice(SERVER_STRING),
        }
    }
    if ho.date.is_none() {
        out.extend_from_slice(b"Date: ");
        ngx_core::times::with_cached(|t| out.extend_from_slice(t.http_time.as_bytes()));
        out.extend_from_slice(b"\r\n");
    }
    if !ho.content_type.is_empty() {
        out.extend_from_slice(b"Content-Type: ");
        let p = out.len();
        out.extend_from_slice(&ho.content_type);
        if charset {
            out.extend_from_slice(b"; charset=");
            out.extend_from_slice(&ho.charset);
            // update r->headers_out.content_type for possible logging
            ho.content_type = out[p..].to_vec();
        }
        out.extend_from_slice(b"\r\n");
    }
    if ho.content_length.is_none() && ho.content_length_n >= 0 {
        out.extend_from_slice(b"Content-Length: ");
        write_int(&mut out, ho.content_length_n);
        out.extend_from_slice(b"\r\n");
    }
    if ho.last_modified.is_none() && ho.last_modified_time != -1 {
        out.extend_from_slice(b"Last-Modified: ");
        write_http_time(&mut out, ho.last_modified_time);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(loc) = &location {
        loc.hash.set(0);
        let p = out.len() + b"Location: ".len();
        out.extend_from_slice(if ssl { b"Location: https://" } else { b"Location: http://" });
        out.extend_from_slice(&host);
        if port != 0 {
            out.push(b':');
            write_int(&mut out, port as i64);
        }
        out.extend_from_slice(&loc.value.borrow());
        // update r->headers_out.location->value for possible logging
        *loc.value.borrow_mut() = out[p..].to_vec();
        out.extend_from_slice(b"\r\n");
    }
    if r.chunked.get() {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    if status == NGX_HTTP_SWITCHING_PROTOCOLS {
        out.extend_from_slice(b"Connection: upgrade\r\n");
    } else if r.keepalive.get() && !terminating {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
        if *cl.keepalive_header > 0 {
            out.extend_from_slice(b"Keep-Alive: timeout=");
            write_int(&mut out, *cl.keepalive_header);
            out.extend_from_slice(b"\r\n");
        }
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    if r.gzip_vary.get() {
        out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
    }
    for h in ho.headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }
        out.extend_from_slice(&h.key);
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value.borrow());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    debug_assert!(out.len() <= len, "header {} of {}", out.len(), len);
    out
}

/// buf->tag of the header buffers: their memory is kept once they are sent
pub const HEADER_BUF_TAG: usize = 0x6e67_785f_6864_7273;

/// The free header buffers kept, and the largest one kept
const FREE_HEADER_BUFS: usize = 16;
const FREE_HEADER_BUF_SIZE: usize = 4096;

thread_local! {
    /// The memory of the response headers sent, for the next ones (C
    /// allocates them from the request's pool)
    static FREE_HEADERS: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// An empty header buffer of at least `len` bytes: a free one, or a new one
pub fn take_header_buf(len: usize) -> Vec<u8> {
    let free = FREE_HEADERS.with(|f| {
        let mut f = f.borrow_mut();
        let i = f.iter().rposition(|v| v.capacity() >= len)?;
        Some(f.swap_remove(i))
    });

    match free {
        Some(mut v) => {
            v.clear();
            v
        }
        None => Vec::with_capacity(len),
    }
}

/// The memory of a header buffer sent, kept for the next header
pub fn free_header_buf(v: Vec<u8>) {
    if v.capacity() > FREE_HEADER_BUF_SIZE {
        return;
    }

    FREE_HEADERS.with(|f| {
        let mut f = f.borrow_mut();
        if f.len() < FREE_HEADER_BUFS {
            f.push(v);
        }
    });
}

/// `v` in decimal ("%d" of ngx_sprintf)
pub fn write_int(out: &mut Vec<u8>, v: i64) {
    if v < 0 {
        out.push(b'-');
    }
    write_dec(out, v.unsigned_abs());
}

/// `v` in decimal ("%ud")
pub fn write_dec(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(dec_digits(v, &mut [0u8; 20]));
}

/// The decimal digits of `v`, in `buf`
pub fn dec_digits(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// `v` in lowercase hexadecimal ("%xd"), a negative value as its two's
/// complement
pub fn write_hex(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(hex_digits(v, &mut [0u8; 16]));
}

/// The lowercase hexadecimal digits of `v` (a negative value as its
/// two's complement), in `buf`
pub fn hex_digits(v: i64, buf: &mut [u8; 16]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut v = v as u64;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// A short value written on the stack (a header value the header list
/// copies)
pub struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuf<N> {
    pub fn new() -> StackBuf<N> {
        StackBuf { buf: [0u8; N], len: 0 }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> Default for StackBuf<N> {
    fn default() -> StackBuf<N> {
        StackBuf::new()
    }
}

/// `v` in decimal ("%d")
pub fn int_digits(v: i64, buf: &mut [u8; 21]) -> &[u8] {
    let mut digits = [0u8; 20];
    let d = dec_digits(v.unsigned_abs(), &mut digits);
    let mut n = 0;
    if v < 0 {
        buf[0] = b'-';
        n = 1;
    }
    buf[n..n + d.len()].copy_from_slice(d);
    &buf[..n + d.len()]
}

/// ngx_http_time: "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn write_http_time(out: &mut Vec<u8>, t: i64) {
    let tm = ngx_core::times::gmtime(t);
    let two = |out: &mut Vec<u8>, v: u32| {
        if v < 10 {
            out.push(b'0');
        }
        write_dec(out, v as u64);
    };
    out.extend_from_slice(ngx_core::times::WEEK[tm.wday as usize].as_bytes());
    out.extend_from_slice(b", ");
    two(out, tm.mday);
    out.push(b' ');
    out.extend_from_slice(ngx_core::times::MONTHS[(tm.mon - 1) as usize].as_bytes());
    out.push(b' ');
    // "%4d"
    for d in [1000, 100, 10] {
        if tm.year < d {
            out.push(b' ');
        }
    }
    write_dec(out, tm.year as u64);
    out.push(b' ');
    two(out, tm.hour);
    out.push(b':');
    two(out, tm.min);
    out.push(b':');
    two(out, tm.sec);
    out.extend_from_slice(b" GMT");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writers() {
        for v in [0i64, 7, 10, 99, 100, 12345, -1, -12345, i64::MAX, i64::MIN] {
            let mut out = Vec::new();
            write_int(&mut out, v);
            assert_eq!(out, v.to_string().into_bytes());

            let mut out = Vec::new();
            write_hex(&mut out, v);
            assert_eq!(out, format!("{:x}", v).into_bytes());
        }

        for t in [0i64, 1, 59, 86399, 86400, 784111777, 1_000_000_000, 1_790_000_000, 2_147_483_647, 4_102_444_800, 253_402_300_799, 300_000_000_000] {
            let mut out = Vec::new();
            write_http_time(&mut out, t);
            assert_eq!(out, ngx_core::times::http_time(t).into_bytes(), "{}", t);
        }
    }
}
