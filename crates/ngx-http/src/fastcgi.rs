//! ngx_http_fastcgi_module
//!
//! Like proxy.rs, not a port of ngx_http_upstream.c: the handler reads the
//! client body, connects, sends the request as ngx_http_fastcgi_create_request
//! builds it (BEGIN_REQUEST, PARAMS and STDIN records), and reads the
//! response records up to END_REQUEST before it sends the response. The
//! records are parsed as ngx_http_fastcgi_process_record,
//! ngx_http_fastcgi_process_header and ngx_http_fastcgi_input_filter do.

use std::any::Any;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::regex::Regex;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::parse::{self, ParseRequest, NGX_HTTP_PARSE_HEADER_DONE};
use crate::proxy::{UpstreamSock, FT_ERROR, FT_HTTP_403, FT_HTTP_404, FT_HTTP_429, FT_HTTP_500, FT_HTTP_502, FT_HTTP_503, FT_HTTP_504, FT_INVALID_HEADER, FT_NON_IDEMPOTENT, FT_OFF, FT_TIMEOUT};
use crate::request::*;
use crate::script::ComplexValue;
use crate::variables::VarDef;
use crate::*;

crate::http_module_index!("ngx_http_fastcgi_module");

const NGX_HTTP_FASTCGI_RESPONDER: u8 = 1;

const NGX_HTTP_FASTCGI_KEEP_CONN: u8 = 1;

const NGX_HTTP_FASTCGI_BEGIN_REQUEST: u8 = 1;
const NGX_HTTP_FASTCGI_END_REQUEST: u8 = 3;
const NGX_HTTP_FASTCGI_PARAMS: u8 = 4;
const NGX_HTTP_FASTCGI_STDIN: u8 = 5;
const NGX_HTTP_FASTCGI_STDOUT: u8 = 6;
const NGX_HTTP_FASTCGI_STDERR: u8 = 7;

/// sizeof(ngx_http_fastcgi_header_t)
const HEADER_SIZE: usize = 8;

/// ngx_http_fastcgi_hide_headers
const FASTCGI_HIDE_HEADERS: &[&[u8]] = &[
    b"status",
    b"x-accel-expires",
    b"x-accel-redirect",
    b"x-accel-limit-rate",
    b"x-accel-buffering",
    b"x-accel-charset",
];

/// A fastcgi_param: the name, the value, and "if_not_empty".
pub struct Param {
    pub key: Vec<u8>,
    pub value: ComplexValue,
    pub skip_empty: bool,
}

pub struct NgxHttpFastcgiLocConf {
    /// fastcgi_pass without variables, and with them.
    pub pass: Option<Vec<u8>>,
    pub pass_cv: Option<ComplexValue>,
    /// fastcgi_param (params_source): inherited as a whole.
    pub params: Option<Rc<Vec<Param>>>,
    pub index: Val<Vec<u8>>,
    pub split_regex: Option<Rc<Regex>>,
    pub split_name: Vec<u8>,
    pub request_buffering: Val<bool>,
    pub pass_request_headers: Val<bool>,
    pub pass_request_body: Val<bool>,
    pub intercept_errors: Val<bool>,
    pub keep_conn: Val<bool>,
    pub catch_stderr: Option<Vec<Vec<u8>>>,
    pub hide_headers: Option<Vec<Vec<u8>>>,
    pub pass_headers: Option<Vec<Vec<u8>>>,
    pub next_upstream: Val<u32>,
    pub next_upstream_tries: Val<i64>,
    pub connect_timeout: Val<u64>,
    pub send_timeout: Val<u64>,
    pub read_timeout: Val<u64>,
}

impl Default for NgxHttpFastcgiLocConf {
    fn default() -> Self {
        NgxHttpFastcgiLocConf {
            pass: None,
            pass_cv: None,
            params: None,
            index: Val::unset(),
            split_regex: None,
            split_name: Vec::new(),
            request_buffering: Val::unset(),
            pass_request_headers: Val::unset(),
            pass_request_body: Val::unset(),
            intercept_errors: Val::unset(),
            keep_conn: Val::unset(),
            catch_stderr: None,
            hide_headers: None,
            pass_headers: None,
            next_upstream: Val::unset(),
            next_upstream_tries: Val::unset(),
            connect_timeout: Val::unset(),
            send_timeout: Val::unset(),
            read_timeout: Val::unset(),
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpFastcgiLocConf::default())
}

/// ngx_http_fastcgi_merge_loc_conf
fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpFastcgiLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpFastcgiLocConf>(conf).borrow_mut();

    if c.pass.is_none() && c.pass_cv.is_none() {
        c.pass = p.pass.clone();
        c.pass_cv = p.pass_cv.clone();
    }
    if c.params.is_none() {
        c.params = p.params.clone();
    }
    c.index.merge(&p.index, Vec::new());
    if c.split_regex.is_none() {
        c.split_regex = p.split_regex.clone();
        c.split_name = p.split_name.clone();
    }
    c.request_buffering.merge(&p.request_buffering, true);
    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);
    c.intercept_errors.merge(&p.intercept_errors, false);
    c.keep_conn.merge(&p.keep_conn, false);
    if c.catch_stderr.is_none() {
        c.catch_stderr = p.catch_stderr.clone();
    }
    if c.hide_headers.is_none() {
        c.hide_headers = p.hide_headers.clone();
    }
    if c.pass_headers.is_none() {
        c.pass_headers = p.pass_headers.clone();
    }
    c.next_upstream.merge(&p.next_upstream, FT_ERROR | FT_TIMEOUT);
    if *c.next_upstream.get() & FT_OFF != 0 {
        c.next_upstream = Val::set(FT_OFF);
    }
    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);
    c.connect_timeout.merge(&p.connect_timeout, 60000);
    c.send_timeout.merge(&p.send_timeout, 60000);
    c.read_timeout.merge(&p.read_timeout, 60000);
    Ok(())
}

/// ngx_http_fastcgi_pass
fn fastcgi_pass_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());

    if cell.borrow().pass.is_some() || cell.borrow().pass_cv.is_some() {
        return Err(msg("is duplicate"));
    }

    let url = cf.args[1].clone();

    if url.contains(&b'$') {
        let cv = crate::script::compile_complex_value(cf, &url, 0)?;
        cell.borrow_mut().pass_cv = Some(cv);
    } else {
        cell.borrow_mut().pass = Some(url);
    }

    let loc_conf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
    let mut lc = loc_conf.borrow_mut();
    lc.handler = Some(Rc::new(|r| Box::pin(fastcgi_handler(r))));
    if lc.name.last() == Some(&b'/') {
        lc.auto_redirect = true;
    }

    Ok(())
}

/// ngx_http_upstream_param_set_slot
fn fastcgi_param_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());

    let args = cf.args.clone();

    let skip_empty = if args.len() == 4 {
        if args[3] != b"if_not_empty" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&args[3]))));
        }
        true
    } else {
        false
    };

    let value = crate::script::compile_complex_value(cf, &args[2], 0)?;

    let mut c = cell.borrow_mut();
    let mut params: Vec<Param> = match c.params.take() {
        Some(p) => match Rc::try_unwrap(p) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };
    params.push(Param { key: args[1].clone(), value, skip_empty });
    c.params = Some(Rc::new(params));

    Ok(())
}

/// ngx_http_fastcgi_split_path_info
fn fastcgi_split_path_info_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());

    let pattern = cf.args[1].clone();

    let re = ngx_core::regex::Regex::compile(&pattern, 0).map_err(|e| cf.emerg(format_args!("{}", e)))?;

    if re.captures != 2 {
        return Err(cf.emerg(format_args!("pattern \"{}\" must have 2 captures", B(&pattern))));
    }

    let mut c = cell.borrow_mut();
    c.split_name = pattern;
    c.split_regex = Some(re);

    Ok(())
}

fn fastcgi_catch_stderr_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
    let v = cf.args[1].clone();
    cell.borrow_mut().catch_stderr.get_or_insert_with(Vec::new).push(v);
    Ok(())
}

fn fastcgi_hide_header_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
    let v = cf.args[1].to_ascii_lowercase();
    cell.borrow_mut().hide_headers.get_or_insert_with(Vec::new).push(v);
    Ok(())
}

fn fastcgi_pass_header_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
    let v = cf.args[1].to_ascii_lowercase();
    cell.borrow_mut().pass_headers.get_or_insert_with(Vec::new).push(v);
    Ok(())
}

/// ngx_conf_set_bitmask_slot with ngx_http_fastcgi_next_upstream_masks
fn fastcgi_next_upstream_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
    let mut mask = 0u32;
    for arg in cf.args.iter().skip(1) {
        let bit = match arg.as_slice() {
            b"off" => FT_OFF,
            b"error" => FT_ERROR,
            b"timeout" => FT_TIMEOUT,
            b"invalid_header" => FT_INVALID_HEADER,
            b"http_500" => FT_HTTP_500,
            b"http_503" => FT_HTTP_503,
            b"http_403" => FT_HTTP_403,
            b"http_404" => FT_HTTP_404,
            b"http_429" => FT_HTTP_429,
            b"updating" => crate::proxy::FT_UPDATING,
            b"non_idempotent" => FT_NON_IDEMPOTENT,
            _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(arg)))),
        };
        mask |= bit;
    }
    cell.borrow_mut().next_upstream = Val::set(mask);
    Ok(())
}

/// ngx_http_fastcgi_split: the script name and path info of the URI.
fn split(r: &R) -> (Vec<u8>, Vec<u8>) {
    let flcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());
    let re = flcf.borrow().split_regex.clone();
    let uri = r.uri.borrow().clone();

    let re = match re {
        Some(re) => re,
        None => return (uri, Vec::new()),
    };

    match re.exec(&uri) {
        Some(caps) => {
            let (s1, e1) = caps[1];
            let (s2, e2) = caps[2];
            let script = if s1 >= 0 { uri[s1 as usize..e1 as usize].to_vec() } else { Vec::new() };
            let info = if s2 >= 0 { uri[s2 as usize..e2 as usize].to_vec() } else { Vec::new() };
            (script, info)
        }
        None => (uri, Vec::new()),
    }
}

/// ngx_http_fastcgi_script_name_variable
fn script_name_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let (mut script, _) = split(r);

    if script.last() == Some(&b'/') {
        let flcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());
        script.extend_from_slice(flcf.borrow().index.get());
    }

    v.data = script;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

/// ngx_http_fastcgi_path_info_variable
fn path_info_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let (_, info) = split(r);

    v.data = info;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef { name: "fastcgi_script_name", get: Some(script_name_variable), set: None, data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH },
        VarDef { name: "fastcgi_path_info", get: Some(path_info_variable), set: None, data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH },
    ];
    crate::variables::add_variables(cf, &vars)
}

/// A FastCGI record header (ngx_http_fastcgi_header_t) for request id 1.
fn record_header(out: &mut Vec<u8>, kind: u8, len: usize, padding: usize) {
    out.extend_from_slice(&[1, kind, 0, 1, (len >> 8) as u8, len as u8, padding as u8, 0]);
}

/// A name-value pair length: one byte, or four with the high bit set.
fn nv_len(out: &mut Vec<u8>, len: usize) {
    if len > 127 {
        out.push(((len >> 24) & 0x7f) as u8 | 0x80);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(len as u8);
    }
}

/// STDIN records for `data`, of up to 32K each, padded to 8 bytes.
fn stdin_records(out: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(32 * 1024) {
        let padding = (8 - chunk.len() % 8) % 8;
        record_header(out, NGX_HTTP_FASTCGI_STDIN, chunk.len(), padding);
        out.extend_from_slice(chunk);
        out.extend(std::iter::repeat(0).take(padding));
    }
}

fn buf_data(b: &Buf) -> &[u8] {
    match &b.data {
        BufData::Memory(m) => {
            let end = b.last.min(m.len());
            if b.pos < end { &m[b.pos..end] } else { &[] }
        }
        _ => &[],
    }
}

/// ngx_http_fastcgi_body_output_filter: body buffers as STDIN records, and
/// the empty STDIN record after the last buffer, in the same write.
fn body_output_filter(out: &mut Vec<u8>, bufs: &Chain) {
    let mut last = false;

    for b in bufs.iter() {
        if b.last_buf {
            last = true;
        }
        stdin_records(out, buf_data(b));
    }

    if last {
        record_header(out, NGX_HTTP_FASTCGI_STDIN, 0, 0);
    }
}

/// ngx_http_fastcgi_create_request: BEGIN_REQUEST, the PARAMS record (the
/// fastcgi_param values, then the request headers as HTTP_* unless a
/// fastcgi_param of that name exists), the empty PARAMS record, and for a
/// buffered body its STDIN records and the empty one.
fn create_request(r: &R, flcf: &NgxHttpFastcgiLocConf) -> Result<Vec<u8>, i64> {
    let mut params_data = Vec::new();

    // the params hash: names after "HTTP_" hide the request headers
    let mut header_names: Vec<Vec<u8>> = Vec::new();

    if let Some(params) = &flcf.params {
        for p in params.iter() {
            if p.key.len() > 5 && p.key.starts_with(b"HTTP_") {
                header_names.push(p.key[5..].to_ascii_lowercase());

                if p.value.value.is_empty() {
                    continue;
                }
            }

            let value = crate::script::complex_value(r, &p.value).map_err(|_| NGX_ERROR)?;

            if p.skip_empty && value.is_empty() {
                continue;
            }

            nv_len(&mut params_data, p.key.len());
            nv_len(&mut params_data, value.len());
            params_data.extend_from_slice(&p.key);
            params_data.extend_from_slice(&value);

            http_debug!(r, "fastcgi param: \"{}: {}\"", B(&p.key), B(&value));
        }
    }

    if *flcf.pass_request_headers.get() {
        // ngx_http_link_multi_headers: later headers of a name join the first
        let headers = r.headers_in.borrow().headers.clone();
        let mut linked = vec![false; headers.len()];

        for i in 0..headers.len() {
            if linked[i] {
                continue;
            }

            let h = &headers[i];

            if !header_names.is_empty() {
                let lc: Vec<u8> = h
                    .key
                    .iter()
                    .map(|&ch| if ch.is_ascii_uppercase() { ch | 0x20 } else if ch == b'-' { b'_' } else { ch })
                    .collect();

                if header_names.contains(&lc) {
                    continue;
                }
            }

            let mut value = h.value.borrow().clone();

            let sep = if h.key.eq_ignore_ascii_case(b"Cookie") { b';' } else { b',' };

            for j in i + 1..headers.len() {
                if !linked[j] && headers[j].key.eq_ignore_ascii_case(&h.key) {
                    linked[j] = true;
                    value.push(sep);
                    value.push(b' ');
                    value.extend_from_slice(&headers[j].value.borrow());
                }
            }

            let mut key = b"HTTP_".to_vec();
            key.extend(h.key.iter().map(|&ch| if ch.is_ascii_lowercase() { ch & !0x20 } else if ch == b'-' { b'_' } else { ch }));

            nv_len(&mut params_data, key.len());
            nv_len(&mut params_data, value.len());
            params_data.extend_from_slice(&key);
            params_data.extend_from_slice(&value);

            http_debug!(r, "fastcgi param: \"{}: {}\"", B(&key), B(&value));
        }
    }

    let len = params_data.len();

    if len > 65535 {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "fastcgi request record is too big: {}", len);
        return Err(NGX_ERROR);
    }

    let padding = (8 - len % 8) % 8;

    let mut out = Vec::with_capacity(3 * HEADER_SIZE + 8 + len + padding);

    // ngx_http_fastcgi_request_start
    record_header(&mut out, NGX_HTTP_FASTCGI_BEGIN_REQUEST, 8, 0);
    let flags = if *flcf.keep_conn.get() { NGX_HTTP_FASTCGI_KEEP_CONN } else { 0 };
    out.extend_from_slice(&[0, NGX_HTTP_FASTCGI_RESPONDER, flags, 0, 0, 0, 0, 0]);

    record_header(&mut out, NGX_HTTP_FASTCGI_PARAMS, len, padding);
    out.extend_from_slice(&params_data);
    out.extend(std::iter::repeat(0).take(padding));

    record_header(&mut out, NGX_HTTP_FASTCGI_PARAMS, 0, 0);

    if r.request_body_no_buffering.get() {
        // the body follows through body_output_filter
        return Ok(out);
    }

    if *flcf.pass_request_body.get() {
        if let Some(rb) = r.request_body.borrow().as_ref() {
            let rb = rb.borrow();
            for b in rb.bufs.iter() {
                if b.in_file {
                    if let BufData::File(f) = &b.data {
                        let data = read_file_range(f.fd, b.file_pos, b.file_last);
                        stdin_records(&mut out, &data);
                    }
                    continue;
                }
                stdin_records(&mut out, buf_data(b));
            }
        }
    }

    record_header(&mut out, NGX_HTTP_FASTCGI_STDIN, 0, 0);

    Ok(out)
}

fn read_file_range(fd: i32, from: i64, to: i64) -> Vec<u8> {
    let size = (to - from).max(0) as usize;
    let mut buf = vec![0u8; size];
    let mut off = 0usize;
    while off < size {
        let n = unsafe { libc::pread(fd, buf[off..].as_mut_ptr() as *mut _, size - off, from + off as i64) };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
    buf.truncate(off);
    buf
}

/// The upstream to connect to: an upstream{} block, a unix socket, or an
/// address (ngx_http_fastcgi_pass / ngx_http_fastcgi_eval).
enum Target {
    Named(Vec<u8>),
    Addr(String, u16),
}

fn parse_target(r: &R, url: &[u8]) -> Option<Target> {
    let url = std::str::from_utf8(url).ok()?;

    if crate::upstream::get_upstream_by_name(r, url.as_bytes()).is_some() {
        return Some(Target::Named(url.as_bytes().to_vec()));
    }

    if url.starts_with("unix:") {
        return Some(Target::Addr(url.to_string(), 0));
    }

    if let Some(rest) = url.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = rest[end + 1..].strip_prefix(':')?.parse().ok()?;
        return Some(Target::Addr(rest[..end].to_string(), port));
    }

    let (host, port) = url.rsplit_once(':')?;
    Some(Target::Addr(host.to_string(), port.parse().ok()?))
}

fn addr_string(host: &str, port: u16) -> String {
    if host.starts_with("unix:") {
        format!("{}:{}", host, port)
    } else if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// What reading the response needs of the location, taken before awaiting.
struct ReadConf {
    read_timeout: u64,
    keep_conn: bool,
    catch_stderr: Option<Vec<Vec<u8>>>,
    /// A HEAD request: the body is not read (ngx_http_upstream_send_response
    /// finalizes after the header), so the connection is not kept.
    header_only: bool,
}

/// The FastCGI record parser state (ngx_http_fastcgi_ctx_t).
#[derive(Default)]
struct Records {
    /// STDOUT data of the response.
    stdout: Vec<u8>,
    /// An empty STDOUT record was seen (the application closed stdout).
    stdout_closed: bool,
    /// END_REQUEST was seen.
    end_request: bool,
    /// Bytes consumed from the input.
    pos: usize,
}

/// Why reading the response failed.
enum ReadError {
    /// NGX_HTTP_UPSTREAM_INVALID_HEADER (502), logged.
    Invalid,
    /// The upstream closed the connection (ngx_http_upstream_next FT_ERROR).
    Closed,
    /// The upstream timed out (FT_TIMEOUT).
    Timeout,
}

/// ngx_http_fastcgi_process_record and the record handling of
/// ngx_http_fastcgi_process_header / ngx_http_fastcgi_input_filter: parse
/// the complete records in `buf[st.pos..]`, collecting STDOUT data and
/// logging STDERR (C logs each piece of stderr as it arrives; here a record
/// is logged once it is complete). `header_done` tells whether the response
/// header was complete before this data.
fn process_records(r: &R, conf: &ReadConf, buf: &[u8], st: &mut Records) -> Result<(), ReadError> {
    loop {
        let p = &buf[st.pos..];

        if p.len() < HEADER_SIZE {
            return Ok(());
        }

        if p[0] != 1 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unsupported FastCGI protocol version: {}", p[0]);
            return Err(ReadError::Invalid);
        }

        let kind = p[1];

        match kind {
            NGX_HTTP_FASTCGI_STDOUT | NGX_HTTP_FASTCGI_STDERR | NGX_HTTP_FASTCGI_END_REQUEST => {}
            _ => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid FastCGI record type: {}", kind);
                return Err(ReadError::Invalid);
            }
        }

        if p[2] != 0 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected FastCGI request id high byte: {}", p[2]);
            return Err(ReadError::Invalid);
        }

        if p[3] != 1 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected FastCGI request id low byte: {}", p[3]);
            return Err(ReadError::Invalid);
        }

        let length = ((p[4] as usize) << 8) | p[5] as usize;
        let padding = p[6] as usize;

        if p.len() < HEADER_SIZE + length + padding {
            return Ok(());
        }

        let content = &p[HEADER_SIZE..HEADER_SIZE + length];

        http_debug!(r, "http fastcgi record length: {}", length);

        let header_done = header_end(&st.stdout).is_some();

        match kind {
            NGX_HTTP_FASTCGI_STDERR => {
                if length > 0 {
                    let mut end = content.len();
                    while end > 0 && matches!(content[end - 1], b'\n' | b'\r' | b'.' | b' ') {
                        end -= 1;
                    }
                    let msg = &content[..end];

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "FastCGI sent in stderr: \"{}\"", B(msg));

                    if !header_done {
                        if let Some(patterns) = &conf.catch_stderr {
                            if patterns.iter().any(|pat| msg.windows(pat.len().max(1)).any(|w| w == pat.as_slice())) {
                                return Err(ReadError::Invalid);
                            }
                        }
                    }
                }
            }
            NGX_HTTP_FASTCGI_STDOUT => {
                if length == 0 {
                    if !header_done {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");
                        return Err(ReadError::Invalid);
                    }
                    http_debug!(r, "http fastcgi closed stdout");
                    st.stdout_closed = true;
                } else {
                    st.stdout.extend_from_slice(content);
                }
            }
            _ => {
                if !header_done {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected FastCGI record: {}", kind);
                    return Err(ReadError::Invalid);
                }
                http_debug!(r, "http fastcgi sent end request");
                st.end_request = true;
            }
        }

        st.pos += HEADER_SIZE + length + padding;

        if st.end_request {
            return Ok(());
        }
    }
}

/// The end of the response header in the STDOUT data, if it is complete.
fn header_end(stdout: &[u8]) -> Option<usize> {
    match header_state(stdout) {
        HeaderState::Done(pos) => Some(pos),
        _ => None,
    }
}

enum HeaderState {
    Done(usize),
    Again,
    Invalid,
}

fn header_state(stdout: &[u8]) -> HeaderState {
    let mut pr = ParseRequest::default();
    let mut pos = 0;
    loop {
        match parse::parse_header_line(&mut pr, stdout, &mut pos, true) {
            NGX_OK => continue,
            NGX_HTTP_PARSE_HEADER_DONE => return HeaderState::Done(pos),
            NGX_AGAIN => return HeaderState::Again,
            _ => return HeaderState::Invalid,
        }
    }
}

/// Read the response records up to END_REQUEST, or the end of the
/// connection (which ends a response without keep_conn,
/// ngx_http_fastcgi_input_filter_init's p->length = -1).
async fn read_response(r: &R, conf: &ReadConf, upstream: &mut UpstreamSock, received: &mut i64) -> Result<Records, ReadError> {
    let timeout = conf.read_timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut st = Records::default();
    let mut chunk = vec![0u8; 16384];

    loop {
        let n = match tokio::time::timeout(Duration::from_millis(timeout), upstream.read(&mut chunk)).await {
            Err(_) => {
                let during = if header_end(&st.stdout).is_some() { "reading upstream" } else { "reading response header from upstream" };
                let action = r.connection.log.action();
                r.connection.log.set_action(Some(during));
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                r.connection.log.set_action(action);
                if header_end(&st.stdout).is_some() {
                    return Ok(st);
                }
                return Err(ReadError::Timeout);
            }
            Ok(Err(_)) => 0,
            Ok(Ok(n)) => n,
        };

        if n == 0 {
            if header_end(&st.stdout).is_some() {
                if conf.keep_conn && !st.end_request {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection while reading upstream");
                }
                return Ok(st);
            }
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection while reading response header from upstream");
            return Err(ReadError::Closed);
        }

        *received += n as i64;
        buf.extend_from_slice(&chunk[..n]);

        process_records(r, conf, &buf, &mut st)?;

        if st.end_request || conf.header_only && header_end(&st.stdout).is_some() {
            return Ok(st);
        }

        // ngx_http_fastcgi_process_header rejects an invalid header at once
        if let HeaderState::Invalid = header_state(&st.stdout) {
            return Ok(st);
        }
    }
}

/// ngx_http_fastcgi_handler, with the upstream steps it drives.
async fn fastcgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());

    {
        let c = lcf.borrow();
        if !*c.request_buffering.get() && *c.pass_request_body.get() {
            r.request_body_no_buffering.set(true);
        }
    }

    let rc = crate::request_body::read_client_request_body(&r).await;
    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    // ngx_http_fastcgi_eval
    let url = {
        let c = lcf.borrow();
        match (&c.pass, &c.pass_cv) {
            (Some(u), _) => u.clone(),
            (None, Some(cv)) => {
                let cv = cv.clone();
                drop(c);
                match crate::script::complex_value(&r, &cv) {
                    Ok(v) => v,
                    Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
                }
            }
            (None, None) => return NGX_DECLINED,
        }
    };

    let target = match parse_target(&r, &url) {
        Some(t) => t,
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid upstream \"{}\"", B(&url));
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    };

    let request = {
        let c = lcf.borrow();
        match create_request(&r, &c) {
            Ok(v) => v,
            Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        }
    };

    // the body read so far goes out with the request
    let initial_body = if r.request_body_no_buffering.get() {
        let bufs = match r.request_body.borrow().as_ref() {
            Some(rb) => std::mem::take(&mut rb.borrow_mut().bufs),
            None => Chain::new(),
        };
        let mut out = Vec::new();
        body_output_filter(&mut out, &bufs);
        out
    } else {
        Vec::new()
    };

    let (named, mut host, mut port) = match target {
        Target::Named(name) => match crate::upstream::first_server_for(&r, &name) {
            Some((h, p)) => (Some(name), h, p),
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no live upstreams while connecting to upstream");
                r.upstream_states.borrow_mut().push(UpstreamState { status: 502, peer: name.clone(), ..Default::default() });
                return NGX_HTTP_BAD_GATEWAY;
            }
        },
        Target::Addr(h, p) => (None, h, p),
    };

    let (next_upstream, next_tries, connect_timeout, keep_conn) = {
        let c = lcf.borrow();
        (*c.next_upstream.get(), *c.next_upstream_tries.get() as u32, *c.connect_timeout.get(), *c.keep_conn.get())
    };
    let peer_limit = named.as_ref().map(|n| crate::upstream::peer_count_for(&r, n) as u32).unwrap_or(0);
    let mut attempts: u32 = if named.is_some() { 1 } else { 0 };

    let want_keepalive = keep_conn
        && named.as_ref().and_then(|n| crate::upstream_keepalive::limits_for(n)).map(|l| l.max_cached > 0).unwrap_or(false);

    let can_retry = |attempts: u32| {
        named.is_some() && attempts < peer_limit && (next_tries == 0 || attempts < next_tries) && !r.request_body_no_buffering.get()
    };

    let idempotent = matches!(r.method.get(), NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_PUT | NGX_HTTP_DELETE);

    loop {
        let started = ngx_core::times::current_msec();
        let addr = addr_string(&host, port);

        let pooled = if want_keepalive && !addr.starts_with("unix:") {
            named.as_ref().and_then(|n| crate::upstream_keepalive::pool_take(n, &addr))
        } else {
            None
        };

        let mut upstream = match pooled {
            Some(s) => UpstreamSock::Tcp(s),
            None => match crate::proxy::connect_upstream(&r, &addr, None, None, connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    let (status, ft) = match e {
                        crate::proxy::ConnectError::Error => (NGX_HTTP_BAD_GATEWAY, FT_ERROR),
                        crate::proxy::ConnectError::Timeout => (NGX_HTTP_GATEWAY_TIME_OUT, FT_TIMEOUT),
                        crate::proxy::ConnectError::Internal => return NGX_HTTP_INTERNAL_SERVER_ERROR,
                    };
                    r.upstream_states.borrow_mut().push(UpstreamState {
                        status,
                        peer: addr.clone().into_bytes(),
                        connect_time: ngx_core::times::current_msec().saturating_sub(started),
                        header_time: u64::MAX,
                        response_time: u64::MAX,
                        ..Default::default()
                    });
                    if let Some(name) = &named {
                        crate::upstream::mark_bad_server(&r, name, &host, port);
                        if next_upstream & ft != 0 && can_retry(attempts) {
                            if let Some((h, p)) = crate::upstream::next_server_for(&r, name) {
                                host = h;
                                port = p;
                                attempts += 1;
                                continue;
                            }
                        }
                    }
                    return status;
                }
            },
        };

        let connect_time = ngx_core::times::current_msec().saturating_sub(started);

        let mut wire = request.clone();
        wire.extend_from_slice(&initial_body);

        let mut sent = wire.len() as i64;

        let send_timeout = *lcf.borrow().send_timeout.get();
        let written = tokio::time::timeout(Duration::from_millis(send_timeout), upstream.write_all(&wire)).await;

        let mut failure: Option<(i64, u32)> = match written {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some((NGX_HTTP_BAD_GATEWAY, FT_ERROR)),
            Err(_) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out while sending request to upstream");
                Some((NGX_HTTP_GATEWAY_TIME_OUT, FT_TIMEOUT))
            }
        };

        if failure.is_none() && r.reading_body.get() {
            match crate::proxy::send_request_body(&r, &mut upstream, &body_output_filter).await {
                Ok(n) => sent += n,
                Err(rc) => {
                    drop(upstream);
                    r.upstream_states.borrow_mut().push(UpstreamState {
                        status: rc,
                        peer: addr.clone().into_bytes(),
                        connect_time,
                        header_time: u64::MAX,
                        response_time: ngx_core::times::current_msec().saturating_sub(started),
                        bytes_sent: sent,
                        ..Default::default()
                    });
                    return rc;
                }
            }
        }

        let mut received = 0i64;

        let records = if failure.is_none() {
            let conf = {
                let c = lcf.borrow();
                ReadConf {
                    read_timeout: *c.read_timeout.get(),
                    keep_conn: *c.keep_conn.get(),
                    catch_stderr: c.catch_stderr.clone(),
                    header_only: r.method.get() == NGX_HTTP_HEAD,
                }
            };
            match read_response(&r, &conf, &mut upstream, &mut received).await {
                Ok(st) => Some(st),
                Err(ReadError::Invalid) => {
                    failure = Some((NGX_HTTP_BAD_GATEWAY, FT_INVALID_HEADER));
                    None
                }
                Err(ReadError::Closed) => {
                    failure = Some((NGX_HTTP_BAD_GATEWAY, FT_ERROR));
                    None
                }
                Err(ReadError::Timeout) => {
                    failure = Some((NGX_HTTP_GATEWAY_TIME_OUT, FT_TIMEOUT));
                    None
                }
            }
        } else {
            None
        };

        let response_time = ngx_core::times::current_msec().saturating_sub(started);

        if let Some((status, ft)) = failure {
            r.upstream_states.borrow_mut().push(UpstreamState {
                status,
                peer: addr.clone().into_bytes(),
                connect_time,
                header_time: u64::MAX,
                response_time,
                bytes_sent: sent,
                bytes_received: received,
                ..Default::default()
            });
            if let Some(name) = &named {
                crate::upstream::mark_bad_server(&r, name, &host, port);
                if next_upstream & ft != 0 && (idempotent || next_upstream & FT_NON_IDEMPOTENT != 0) && can_retry(attempts) {
                    if let Some((h, p)) = crate::upstream::next_server_for(&r, name) {
                        host = h;
                        port = p;
                        attempts += 1;
                        continue;
                    }
                }
            }
            return status;
        }

        let records = records.unwrap();

        let hend = header_end(&records.stdout).unwrap_or(records.stdout.len());

        let (status, status_line, headers) = match process_header(&r, &records.stdout[..hend]) {
            Ok(v) => v,
            Err(()) => {
                r.upstream_states.borrow_mut().push(UpstreamState {
                    status: 502,
                    peer: addr.clone().into_bytes(),
                    connect_time,
                    header_time: response_time,
                    response_time,
                    bytes_sent: sent,
                    bytes_received: received,
                    ..Default::default()
                });
                return NGX_HTTP_BAD_GATEWAY;
            }
        };

        // ngx_http_upstream_test_next for the status
        let ft = match status {
            500 => FT_HTTP_500,
            502 => FT_HTTP_502,
            503 => FT_HTTP_503,
            504 => FT_HTTP_504,
            403 => FT_HTTP_403,
            404 => FT_HTTP_404,
            429 => FT_HTTP_429,
            _ => 0,
        };

        r.upstream_states.borrow_mut().push(UpstreamState {
            status,
            peer: addr.clone().into_bytes(),
            connect_time,
            header_time: response_time,
            response_time,
            bytes_sent: sent,
            bytes_received: received,
            response_length: (records.stdout.len() - hend) as i64,
            ..Default::default()
        });

        if ft != 0 && next_upstream & ft != 0 && (idempotent || next_upstream & FT_NON_IDEMPOTENT != 0) {
            if let Some(name) = &named {
                if !matches!(status, 403 | 404) {
                    crate::upstream::mark_bad_server(&r, name, &host, port);
                }
                if can_retry(attempts) {
                    if let Some((h, p)) = crate::upstream::next_server_for(&r, name) {
                        host = h;
                        port = p;
                        attempts += 1;
                        continue;
                    }
                }
            }
        }

        // the connection can be kept only after END_REQUEST, with the
        // request body sent in full
        if want_keepalive && records.end_request && !r.reading_body.get() {
            if let (Some(name), UpstreamSock::Tcp(s)) = (&named, upstream) {
                crate::upstream_keepalive::pool_put(name, &addr, s);
            }
        }

        return send_response(&r, &lcf, status, status_line, headers, &records.stdout[hend..]).await;
    }
}

/// The header part of ngx_http_fastcgi_process_header: the status from
/// "Status" (or 302 with "Location", else 200) and the header lines.
fn process_header(r: &R, data: &[u8]) -> Result<(i64, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), ()> {
    let mut pr = ParseRequest::default();
    let mut pos = 0;
    let mut headers = Vec::new();

    loop {
        let rc = parse::parse_header_line(&mut pr, data, &mut pos, true);

        http_debug!(r, "http fastcgi parser: {}", rc);

        if rc == NGX_OK {
            let name = data[pr.header_name_start..pr.header_name_end].to_vec();
            let value = data[pr.header_start..pr.header_end].to_vec();
            http_debug!(r, "http fastcgi header: \"{}: {}\"", B(&name), B(&value));
            headers.push((name, value));
            continue;
        }

        if rc == NGX_HTTP_PARSE_HEADER_DONE {
            http_debug!(r, "http fastcgi header done");
            break;
        }

        if rc == NGX_AGAIN {
            // the application ended stdout within the header
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");
            return Err(());
        }

        let end = pr.header_end.min(data.len());
        let from = pr.header_name_start.min(end);
        let ch = data.get(end).copied().unwrap_or(0);
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header: \"{}\\x{:02X}...\"", B(&data[from..end]), ch);
        return Err(());
    }

    let status_value = headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(b"Status")).map(|(_, v)| v.clone());

    let (status, status_line) = if let Some(v) = status_value {
        let status = match ngx_core::string::atoi(&v[..v.len().min(3)]) {
            Some(s) if v.len() >= 3 => s,
            _ => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid status \"{}\"", B(&v));
                return Err(());
            }
        };
        (status, if v.len() > 3 { v } else { Vec::new() })
    } else if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(b"Location")) {
        (302, b"302 Moved Temporarily".to_vec())
    } else {
        (200, b"200 OK".to_vec())
    };

    Ok((status, status_line, headers))
}

/// ngx_http_upstream_process_headers and ngx_http_upstream_send_response
/// for the buffered response.
async fn send_response(
    r: &R,
    lcf: &Rc<std::cell::RefCell<NgxHttpFastcgiLocConf>>,
    status: i64,
    status_line: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: &[u8],
) -> i64 {
    // ngx_http_upstream_intercept_errors
    let intercept = *lcf.borrow().intercept_errors.get();
    if intercept && status >= NGX_HTTP_SPECIAL_RESPONSE {
        let clcf = r.clcf();
        let has_page = clcf.borrow().error_pages.as_ref().map(|pages| pages.iter().any(|p| p.status == status)).unwrap_or(false);
        if has_page {
            return status;
        }
    }

    let hide: Vec<Vec<u8>> = {
        let c = lcf.borrow();
        let mut set: Vec<Vec<u8>> = FASTCGI_HIDE_HEADERS.iter().map(|s| s.to_vec()).collect();
        if let Some(h) = &c.hide_headers {
            for x in h {
                if !set.contains(x) {
                    set.push(x.clone());
                }
            }
        }
        if let Some(pass) = &c.pass_headers {
            set.retain(|h| !pass.contains(h));
        }
        set
    };

    r.upstream_headers_in.borrow_mut().clear();

    let mut copied = crate::upstream::CopiedHeaders::default();

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        if !status_line.is_empty() {
            ho.status_line = status_line;
        }

        for (name, value) in &headers {
            r.upstream_headers_in.borrow_mut().push(TableElt::new(name, value));

            if hide.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                continue;
            }

            crate::upstream::copy_header(&mut ho, &mut copied, status, name, value);
        }
    }

    if copied.invalid {
        return NGX_HTTP_BAD_GATEWAY;
    }

    let content_length = r.headers_out.borrow().content_length_n;

    let rc = crate::core_rt::send_header(r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() || r.method.get() == NGX_HTTP_HEAD {
        return rc;
    }

    // ngx_http_fastcgi_input_filter_init / input_filter: the Content-Length
    // limits the body
    let mut body = body;
    if matches!(status, NGX_HTTP_NO_CONTENT | NGX_HTTP_NOT_MODIFIED) {
        body = &[];
    } else if content_length >= 0 && body.len() as i64 > content_length {
        ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
        body = &body[..content_length as usize];
    }

    // ngx_http_fastcgi_input_filter: stdout closed or END_REQUEST with
    // f->rest > 0 is an upstream error, the response stays incomplete
    let short = content_length >= 0 && (body.len() as i64) < content_length;
    if short {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");
        r.upstream_response_incomplete.set(true);
    }

    let mut chain = Chain::new();

    if !body.is_empty() {
        let mut b = Buf::from_vec(body.to_vec());
        b.temporary = true;
        b.flush = short;
        chain.push_back(b);
    }

    if !short {
        let mut last = Buf::special();
        last.last_buf = true;
        chain.push_back(last);
    }

    let rc = crate::core_rt::output_filter(r, chain).await;

    if short {
        r.connection.error.set(true);
        return NGX_ERROR;
    }

    rc
}

pub fn fastcgi_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
        Ok(())
    }

    let commands = vec![
        cmd_fn!("fastcgi_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_pass_handler),
        ngx_core::cmd!("fastcgi_index", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, index, set_str),
        cmd_fn!("fastcgi_split_path_info", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_split_path_info_handler),
        Command::new("fastcgi_store", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_store_access", F | NGX_CONF_TAKE123, ConfLevel::None, accept),
        Command::new("fastcgi_buffering", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        ngx_core::cmd!("fastcgi_request_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, request_buffering, set_flag),
        Command::new("fastcgi_ignore_client_abort", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_bind", F | NGX_CONF_TAKE12, ConfLevel::None, accept),
        Command::new("fastcgi_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        ngx_core::cmd!("fastcgi_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, connect_timeout, set_msec),
        ngx_core::cmd!("fastcgi_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, send_timeout, set_msec),
        Command::new("fastcgi_send_lowat", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        ngx_core::cmd!("fastcgi_pass_request_headers", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, pass_request_headers, set_flag),
        ngx_core::cmd!("fastcgi_pass_request_body", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, pass_request_body, set_flag),
        ngx_core::cmd!("fastcgi_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, intercept_errors, set_flag),
        ngx_core::cmd!("fastcgi_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, read_timeout, set_msec),
        Command::new("fastcgi_buffers", F | NGX_CONF_TAKE2, ConfLevel::None, accept),
        Command::new("fastcgi_busy_buffers_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_force_ranges", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_limit_rate", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_key", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::None, accept),
        Command::new("fastcgi_cache_bypass", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        Command::new("fastcgi_no_cache", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        Command::new("fastcgi_cache_valid", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        Command::new("fastcgi_cache_min_uses", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_max_range_offset", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_use_stale", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        Command::new("fastcgi_cache_methods", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        Command::new("fastcgi_cache_lock", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_cache_lock_timeout", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_lock_age", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_cache_revalidate", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_cache_background_update", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_temp_path", F | NGX_CONF_TAKE1234, ConfLevel::None, accept),
        Command::new("fastcgi_max_temp_file_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_temp_file_write_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        cmd_fn!("fastcgi_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, fastcgi_next_upstream_handler),
        ngx_core::cmd!("fastcgi_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, next_upstream_tries, set_num),
        Command::new("fastcgi_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        cmd_fn!("fastcgi_param", F | NGX_CONF_TAKE23, ConfLevel::Loc, fastcgi_param_handler),
        cmd_fn!("fastcgi_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_pass_header_handler),
        cmd_fn!("fastcgi_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_hide_header_handler),
        Command::new("fastcgi_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::None, accept),
        cmd_fn!("fastcgi_catch_stderr", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_catch_stderr_handler),
        ngx_core::cmd!("fastcgi_keep_conn", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, keep_conn, set_flag),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_fastcgi_module", def, commands)
}
