//! ngx_http_proxy_module - HTTP proxy with upstream framework

use std::any::Any;
use std::rc::Rc;
use std::io::Write;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;
use ngx_core::conf::{NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_TAKE3, NGX_CONF_TAKE4, NGX_CONF_TAKE12, NGX_CONF_TAKE123, NGX_CONF_TAKE1234, NGX_CONF_1MORE, NGX_CONF_2MORE};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::cell::RefCell;

use crate::core::*;
use crate::request::*;
use crate::upstream::*;
use crate::variables::VarDef;
use crate::get_loc_conf;
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_SRV_CONF, NGX_HTTP_LOC_CONF, NGX_HTTP_LIF_CONF, NGX_HTTP_LMT_CONF, NGX_HTTP_BAD_GATEWAY, NGX_HTTP_OK, NGX_HTTP_HEAD, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_proxy_module");

/// Proxy location configuration
pub struct NgxHttpProxyLocConf {
    pub upstream_uri: Option<Vec<u8>>,  // proxy_pass URL
}

impl Default for NgxHttpProxyLocConf {
    fn default() -> Self {
        NgxHttpProxyLocConf {
            upstream_uri: None,
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpProxyLocConf::default())
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpProxyLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpProxyLocConf>(conf).borrow_mut();
    if c.upstream_uri.is_none() {
        c.upstream_uri = p.upstream_uri.clone();
    }
    Ok(())
}

fn proxy_pass_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no proxy_pass URI specified"));
    }

    if let Some(c) = conf {
        let conf = conf_rc::<NgxHttpProxyLocConf>(&c);
        conf.borrow_mut().upstream_uri = Some(cf.args[1].clone());
    }

    // Set the location handler to our proxy_handler and mark auto_redirect for `/xxx/` locs.
    let loc_conf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
    let mut lc = loc_conf.borrow_mut();
    lc.handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));
    if lc.name.last() == Some(&b'/') {
        lc.auto_redirect = true;
    }

    Ok(())
}

fn proxy_redirect_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_buffering_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_request_buffering_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_bind_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_connect_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_send_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_read_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_set_header_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_host_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return proxy_host (hostname being proxied to)
    v.not_found = true; NGX_OK
}

fn proxy_port_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return proxy_port (port being proxied to)
    v.not_found = true; NGX_OK
}

fn proxy_add_x_forwarded_for_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return whether to add X-Forwarded-For header
    v.not_found = true; NGX_OK
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef {
            name: "proxy_host",
            get: Some(proxy_host_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "proxy_port",
            get: Some(proxy_port_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "proxy_add_x_forwarded_for",
            get: Some(proxy_add_x_forwarded_for_variable),
            set: None,
            data: 0,
            flags: 0,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // Register proxy handler in content phase
    crate::core::add_phase_handler(cf, crate::NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(proxy_handler(r))));

    Ok(())
}

async fn proxy_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();

    // Read the client request body first (or discard if none) — nginx does this before
    // opening the upstream connection so we can either forward it or drop it cleanly.
    drop(conf_borrowed);
    let has_body = r.headers_in.borrow().content_length_n > 0 || r.headers_in.borrow().chunked;
    if has_body {
        let rc = crate::request_body::read_client_request_body(&r).await;
        if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
            return rc;
        }
    } else {
        let rc = crate::request_body::discard_request_body(&r).await;
        if rc != NGX_OK { return rc; }
    }
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();

    // Check if this location has proxy_pass configured
    let upstream_uri = match &conf_borrowed.upstream_uri {
        Some(uri) => uri.clone(),
        None => {
            return NGX_DECLINED;
        }
    };

    // Parse upstream URI
    let upstream_uri_str = match std::str::from_utf8(&upstream_uri) {
        Ok(s) => s,
        Err(_) => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    let (host, port, upstream_path) = match parse_upstream_uri(upstream_uri_str) {
        Some(p) => p,
        None => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };
    // If proxy_pass URL includes a URI (e.g. "http://backend/local/"), rewrite:
    //   forwarded = upstream_path + (request_uri - location_prefix)
    // Else forward the request URI as-is.
    let clcf = r.clcf();
    let loc_name = clcf.borrow().name.clone();
    let request_uri = r.uri.borrow().clone();
    let forwarded_uri: Vec<u8> = if upstream_path != "/" || upstream_uri_str.ends_with('/') || upstream_uri_str.contains("//") && upstream_uri_str[7..].contains('/') {
        let mut u = upstream_path.as_bytes().to_vec();
        // Strip trailing slash if adding suffix that starts with /
        let tail = if request_uri.starts_with(loc_name.as_slice()) {
            &request_uri[loc_name.len()..]
        } else {
            &request_uri[..]
        };
        if u.last() == Some(&b'/') && tail.first() == Some(&b'/') {
            u.pop();
        }
        u.extend_from_slice(tail);
        u
    } else {
        request_uri.clone()
    };
    // For byte-preservation in the request line below.
    let request_uri_bytes = forwarded_uri;

    // Try to connect to upstream
    let addr = format!("{}:{}", host, port);
    let mut upstream = match TcpStream::connect(&addr).await {
        Ok(s) => {
            s
        }
        Err(e) => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    // Build request line
    let method_name = r.method_name.borrow();
    let method = std::str::from_utf8(&method_name).unwrap_or("GET");

    let uri_path = std::str::from_utf8(&request_uri_bytes).unwrap_or("/").to_string();
    // Include query string if present
    let args = r.args.borrow();
    let uri_with_args = if !args.is_empty() {
        format!("{}?{}", uri_path, std::str::from_utf8(&args).unwrap_or(""))
    } else {
        uri_path
    };

    // Collect request body (if any) into a Vec.
    let body_bytes: Vec<u8> = {
        let rb = r.request_body.borrow();
        let mut out = Vec::new();
        if let Some(body) = rb.as_ref() {
            let bod = body.borrow();
            for b in bod.bufs.iter() {
                if let ngx_core::buf::BufData::Memory(m) = &b.data {
                    let end = b.last.min(m.len());
                    if b.pos < end { out.extend_from_slice(&m[b.pos..end]); }
                }
                if b.in_file {
                    if let ngx_core::buf::BufData::File(f) = &b.data {
                        let sz = (b.file_last - b.file_pos) as usize;
                        let mut buf = vec![0u8; sz];
                        let mut off = 0usize;
                        while off < sz {
                            let n = unsafe { libc::pread(f.fd, buf[off..].as_mut_ptr() as *mut _, sz - off, b.file_pos + off as i64) };
                            if n <= 0 { break; }
                            off += n as usize;
                        }
                        out.extend_from_slice(&buf[..off]);
                    }
                }
            }
        }
        out
    };
    let content_length_hdr = if !body_bytes.is_empty() {
        format!("Content-Length: {}\r\n", body_bytes.len())
    } else if r.headers_in.borrow().content_length_n > 0 || r.headers_in.borrow().chunked {
        format!("Content-Length: 0\r\n")
    } else {
        String::new()
    };
    let content_type_hdr = {
        let hin = r.headers_in.borrow();
        if let Some(ct) = hin.content_type.first() {
            format!("Content-Type: {}\r\n", std::str::from_utf8(&ct.value.borrow()).unwrap_or(""))
        } else { String::new() }
    };
    // Forward client request headers that aren't the ones we synthesize ourselves.
    // C proxies most client headers by default; the exact list is governed by
    // proxy_set_header, hide_headers, etc.  We don't implement those yet, so this
    // is a subset: pass everything except headers that would conflict with the
    // synthesized request line, hop-by-hop headers, and things upstream shouldn't
    // trust from the client.
    let forward_headers: String = {
        let hin = r.headers_in.borrow();
        let mut s = String::new();
        for h in hin.headers.iter() {
            if h.hash.get() == 0 { continue; }
            let lc = &h.lowcase_key;
            if matches!(lc.as_slice(),
                b"host" | b"connection" | b"keep-alive" |
                b"transfer-encoding" | b"te" | b"upgrade" |
                b"content-length" | b"content-type" |
                b"expect" | b"proxy-connection")
            {
                continue;
            }
            let key = match std::str::from_utf8(&h.key) { Ok(s) => s, Err(_) => continue };
            let val = h.value.borrow();
            let val = match std::str::from_utf8(&val) { Ok(s) => s, Err(_) => continue };
            s.push_str(key);
            s.push_str(": ");
            s.push_str(val);
            s.push_str("\r\n");
        }
        s
    };

    let request = format!(
        "{} {} HTTP/1.0\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         {}{}{}\r\n",
        method, uri_with_args, host, content_length_hdr, content_type_hdr, forward_headers
    );

    // Send request to upstream
    if let Err(_) = upstream.write_all(request.as_bytes()).await {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }
    if !body_bytes.is_empty() {
        if let Err(_) = upstream.write_all(&body_bytes).await {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    }

    // Read entire response
    let mut response = Vec::new();
    if let Err(_) = upstream.read_to_end(&mut response).await {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }

    if response.is_empty() {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }

    // Parse status line
    // Pick the earliest header/body separator. \r\n\r\n and \n\n can both occur;
    // if the upstream uses \n line endings but the body is chunked, a stray
    // "0\r\n\r\n" later in the response fools a pure \r\n\r\n search into
    // treating the trailer as the header terminator.
    let sep_crlf = response.windows(4).position(|w| w == b"\r\n\r\n");
    let sep_lf = response.windows(2).position(|w| w == b"\n\n");
    let (status_line_end, body_start) = match (sep_crlf, sep_lf) {
        (Some(a), Some(b)) if a <= b => (a, a + 4),
        (Some(_), Some(b)) => (b, b + 2),
        (Some(a), None) => (a, a + 4),
        (None, Some(b)) => (b, b + 2),
        (None, None) => return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await,
    };

    let headers_section = &response[..status_line_end];

    // Parse status line
    let status_line_end_nl = match headers_section.iter().position(|&b| b == b'\n') {
        Some(pos) => pos,
        None => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    let status_line = &headers_section[..status_line_end_nl];
    let status_line_str = std::str::from_utf8(status_line).unwrap_or("HTTP/1.0 500 Internal Server Error");

    // Parse "HTTP/1.x NNN Reason"
    let parts: Vec<&str> = status_line_str.split_whitespace().collect();
    let status: i64 = if parts.len() >= 2 {
        parts[1].parse().unwrap_or(502)
    } else {
        502
    };

    // Set status in response headers and copy upstream headers
    let mut upstream_chunked = false;
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        // Parse and copy headers from headers_section
        let mut pos = status_line_end_nl + 1;
        while pos < headers_section.len() {
            let line_end = headers_section[pos..].iter().position(|&b| b == b'\n').map(|i| pos + i).unwrap_or(headers_section.len());
            let line = &headers_section[pos..line_end];
            let line = if line.last() == Some(&b'\r') { &line[..line.len()-1] } else { line };
            if line.is_empty() { break; }
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = &line[..colon];
                let mut vstart = colon + 1;
                while vstart < line.len() && (line[vstart] == b' ' || line[vstart] == b'\t') { vstart += 1; }
                let value = &line[vstart..];
                // Stash into upstream_headers_in so $upstream_http_* can read them.
                r.upstream_headers_in.borrow_mut().push(crate::request::TableElt::new(name, value));
                let lc = name.to_ascii_lowercase();
                // Handle a few well-known headers specially so header_filter renders them.
                match lc.as_slice() {
                    b"content-length" => {
                        if let Ok(s) = std::str::from_utf8(value) {
                            if let Ok(n) = s.trim().parse::<i64>() { ho.content_length_n = n; }
                        }
                        let h = crate::request::TableElt::new(name, value);
                        ho.content_length = Some(h);
                    }
                    b"content-type" => {
                        ho.content_type = value.to_vec();
                        ho.content_type_len = value.len();
                    }
                    b"transfer-encoding" => {
                        // Track chunked so we can decode the body; header itself
                        // is not forwarded (we handle framing ourselves).
                        if value.eq_ignore_ascii_case(b"chunked") {
                            upstream_chunked = true;
                        }
                    }
                    b"connection" | b"keep-alive" | b"server" | b"date" => {
                        // suppress: our header_filter emits its own
                    }
                    b"location" => {
                        let h = crate::request::TableElt::new(name, value);
                        ho.location = Some(h);
                    }
                    b"last-modified" => {
                        let h = crate::request::TableElt::new(name, value);
                        ho.last_modified = Some(h);
                        // best-effort time parse skipped; header_filter emits from .last_modified
                    }
                    b"etag" => {
                        let h = crate::request::TableElt::new(name, value);
                        ho.etag = Some(h);
                    }
                    _ => {
                        ho.add(name, value);
                    }
                }
            }
            pos = line_end + 1;
        }
    }

    // Snapshot upstream Content-Length before send_header runs — filters like
    // addition_filter / sub_filter / gzip clear ho.content_length_n during
    // their header pass.
    let upstream_content_length = r.headers_out.borrow().content_length_n;

    // Send status and headers to client
    let send_hdr_rc = crate::core_rt::send_header(&r).await;
    if send_hdr_rc != NGX_OK {
        return NGX_ERROR;
    }

    // Forward response body. Respect HEAD (no body) and Content-Length (truncate
    // any extra bytes upstream sent past the declared length — matches C which
    // reads exactly content_length_n bytes and logs "upstream sent more data
    // than specified in Content-Length"). We captured upstream_content_length
    // above BEFORE send_header, because some filters (e.g. addition_filter,
    // sub_filter, gzip) clear r.headers_out.content_length_n.
    let head_only = r.method.get() == NGX_HTTP_HEAD || r.header_only.get();
    if head_only {
        return NGX_OK;
    }
    if body_start < response.len() {
        let body_owned: Vec<u8>;
        let body: &[u8] = if upstream_chunked {
            body_owned = decode_chunked(&response[body_start..]);
            &body_owned
        } else {
            let end = if upstream_content_length >= 0 {
                (body_start + upstream_content_length as usize).min(response.len())
            } else {
                response.len()
            };
            &response[body_start..end]
        };

        // Create a buffer chain for the body
        use ngx_core::buf::{Buf, BufData, Chain};
        use std::collections::VecDeque;

        let mut chain: Chain = VecDeque::new();

        let buf = Buf {
            pos: 0,
            last: body.len(),
            file_pos: 0,
            file_last: 0,
            tag: 0,
            num: 0,
            data: BufData::Memory(body.to_vec()),
            temporary: true,
            memory: false,
            mmap: false,
            recycled: false,
            in_file: false,
            flush: false,
            sync: false,
            last_buf: true,
            last_in_chain: true,
            temp_file: false,
        };

        chain.push_back(buf);

        if crate::core_rt::output_filter(&r, chain).await != NGX_OK {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

async fn return_error(r: &R, status: i64) -> i64 {
    let mut ho = r.headers_out.borrow_mut();
    ho.status = status;
    drop(ho);

    if crate::core_rt::send_header(r).await != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// Parse upstream URL of form "http://host:port/path" or "http://host/path" (assumes port 80)
/// Decode HTTP/1.1 chunked transfer encoding. Malformed input truncates the
/// output at the first bad chunk rather than erroring — mirrors what a
/// buffering proxy tends to do when the upstream is misbehaving.
fn decode_chunked(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        // Find end of chunk size line
        let line_end = match input[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => break,
        };
        let mut size_end = line_end;
        // Strip trailing \r
        if size_end > i && input[size_end - 1] == b'\r' {
            size_end -= 1;
        }
        // Chunk size stops at ';' (chunk extension) or whitespace
        let hex_end = input[i..size_end]
            .iter()
            .position(|&b| b == b';' || b == b' ' || b == b'\t')
            .map(|p| i + p)
            .unwrap_or(size_end);
        let hex_str = match std::str::from_utf8(&input[i..hex_end]) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        let size = match usize::from_str_radix(hex_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        i = line_end + 1; // move past \n
        if size == 0 {
            break;
        }
        if i + size > input.len() {
            out.extend_from_slice(&input[i..]);
            break;
        }
        out.extend_from_slice(&input[i..i + size]);
        i += size;
        // Skip trailing \r\n after chunk data
        if i < input.len() && input[i] == b'\r' { i += 1; }
        if i < input.len() && input[i] == b'\n' { i += 1; }
    }
    out
}

fn parse_upstream_uri(uri: &str) -> Option<(String, u16, String)> {
    if !uri.starts_with("http://") {
        return None;
    }

    let rest = &uri[7..];

    // Find host:port or just host
    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else {
        (rest, "/".to_string())
    };

    // Parse host and port
    let (host, port) = if let Some(pos) = host_port.find(':') {
        let h = &host_port[..pos];
        let p: u16 = host_port[pos+1..].parse().ok()?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };

    Some((host, port, path))
}

pub fn proxy_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("proxy_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_pass_handler),
        cmd_fn!("proxy_redirect", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, proxy_redirect_handler),
        cmd_fn!("proxy_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_buffering_handler),
        cmd_fn!("proxy_request_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_request_buffering_handler),
        cmd_fn!("proxy_bind", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_bind_handler),
        cmd_fn!("proxy_connect_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_connect_timeout_handler),
        cmd_fn!("proxy_send_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_send_timeout_handler),
        cmd_fn!("proxy_read_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_read_timeout_handler),
        cmd_fn!("proxy_set_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, proxy_set_header_handler),
        // Additional proxy directives that tests need
        cmd_fn!("proxy_temp_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_busy_buffers_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_max_temp_file_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_request_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_method", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_http_version", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_socket_keepalive", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_set_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_hide_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ignore_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_intercept_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ignore_client_abort", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_store", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_store_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_limit_rate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_force_ranges", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_headers_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_headers_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_valid", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_bypass", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_use_stale", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_lock", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_lock_age", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_lock_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_min_uses", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_revalidate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_max_range_offset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_methods", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_purge", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_convert_head", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_background_update", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_no_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_certificate_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_password_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_ciphers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_protocols", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_server_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_verify", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_verify_depth", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_trusted_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_crl", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_conf_command", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_session_reuse", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ssl_key_log", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_proxy_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proxy_conf() {
        let mut cf = Conf::default();
        let _slot = create_loc_conf(&mut cf);
    }
}
