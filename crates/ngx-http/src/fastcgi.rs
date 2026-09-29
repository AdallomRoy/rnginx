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
    /// the upstream of fastcgi_pass without variables (ngx_http_upstream_add)
    pub upstream: Option<Rc<crate::upstream::UpstreamSrvConf>>,
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
    /// flcf->params and flcf->params_cache: the params of fastcgi_param
    /// with the defaults of ngx_http_fastcgi_headers and
    /// ngx_http_fastcgi_cache_headers (ngx_http_fastcgi_init_params)
    pub params_built: Option<Rc<Vec<Param>>>,
    pub params_cache: Option<Rc<Vec<Param>>>,
    /// The cache fields of flcf->upstream (fastcgi_cache,
    /// fastcgi_cache_*, fastcgi_no_cache, fastcgi_ignore_headers) and
    /// flcf->cache_key.
    pub cache: crate::upstream_cache::UpstreamCacheConf,
    /// fastcgi_buffer_size (upstream.buffer_size)
    pub buffer_size: Val<usize>,
    /// fastcgi_temp_path (upstream.temp_path)
    pub temp_path: Val<Rc<PathConf>>,
}

impl crate::upstream_cache::UpstreamCacheLocConf for NgxHttpFastcgiLocConf {
    fn upstream_cache(&mut self) -> &mut crate::upstream_cache::UpstreamCacheConf {
        &mut self.cache
    }
}

impl Default for NgxHttpFastcgiLocConf {
    fn default() -> Self {
        NgxHttpFastcgiLocConf {
            pass: None,
            pass_cv: None,
            upstream: None,
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
            params_built: None,
            params_cache: None,
            cache: crate::upstream_cache::UpstreamCacheConf::default(),
            buffer_size: Val::unset(),
            temp_path: Val::unset(),
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpFastcgiLocConf::default())
}

/// ngx_http_fastcgi_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpFastcgiLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpFastcgiLocConf>(conf).borrow_mut();

    if c.params.is_none() {
        c.params = p.params.clone();
        c.params_built = p.params_built.clone();
        c.params_cache = p.params_cache.clone();
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

    // the fastcgi_pass of the enclosing location is inherited by the "if"
    // and "limit_except" blocks only (conf->upstream.upstream and
    // fastcgi_lengths/values), not by nested locations
    let clcf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());

    if clcf.borrow().noname && c.upstream.is_none() && c.pass_cv.is_none() {
        c.upstream = p.upstream.clone();
        c.pass = p.pass.clone();
        c.pass_cv = p.pass_cv.clone();
    }

    let lmt_excpt_no_handler = {
        let l = clcf.borrow();
        l.lmt_excpt && l.handler.is_none()
    };

    if lmt_excpt_no_handler && (c.upstream.is_some() || c.pass_cv.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(fastcgi_handler(r))));
    }

    c.next_upstream.merge(&p.next_upstream, FT_ERROR | FT_TIMEOUT);
    if *c.next_upstream.get() & FT_OFF != 0 {
        c.next_upstream = Val::set(FT_OFF);
    }
    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);
    c.connect_timeout.merge(&p.connect_timeout, 60000);
    c.send_timeout.merge(&p.send_timeout, 60000);
    c.read_timeout.merge(&p.read_timeout, 60000);

    c.buffer_size.merge(&p.buffer_size, ngx_core::os::pagesize());

    {
        let mut slot = std::mem::take(&mut c.temp_path);
        merge_path_value(cf, &mut slot, &p.temp_path, ngx_core::NGX_HTTP_FASTCGI_TEMP_PATH, [1, 2, 0])?;
        c.temp_path = slot;
    }

    c.cache.merge(cf, &p.cache, "fastcgi", false)?;

    // ngx_http_fastcgi_init_params: flcf->params, and flcf->params_cache
    // with a cache
    if c.params_built.is_none() {
        let params = init_params(cf, c.params.as_ref(), FASTCGI_HEADERS)?;
        c.params_built = Some(params);
    }

    if c.cache.enabled() && c.params_cache.is_none() {
        let params = init_params(cf, c.params.as_ref(), FASTCGI_CACHE_HEADERS)?;
        c.params_cache = Some(params);
    }

    Ok(())
}

/// ngx_http_fastcgi_headers
const FASTCGI_HEADERS: &[(&[u8], &[u8])] = &[(b"HTTP_HOST", b"$host$is_request_port$request_port")];

/// ngx_http_fastcgi_cache_headers
const FASTCGI_CACHE_HEADERS: &[(&[u8], &[u8])] = &[
    (b"HTTP_HOST", b"$host$is_request_port$request_port"),
    (b"HTTP_IF_MODIFIED_SINCE", b"$upstream_cache_last_modified"),
    (b"HTTP_IF_UNMODIFIED_SINCE", b""),
    (b"HTTP_IF_NONE_MATCH", b"$upstream_cache_etag"),
    (b"HTTP_IF_MATCH", b""),
    (b"HTTP_RANGE", b""),
    (b"HTTP_IF_RANGE", b""),
];

/// ngx_http_fastcgi_init_params: the params of fastcgi_param, then those of
/// `defaults` not set by them (skipped when empty).
fn init_params(cf: &mut Conf, source: Option<&Rc<Vec<Param>>>, defaults: &[(&[u8], &[u8])]) -> Result<Rc<Vec<Param>>, ConfError> {
    let mut merged: Vec<Param> = Vec::new();

    if let Some(src) = source {
        for p in src.iter() {
            merged.push(Param { key: p.key.clone(), value: p.value.clone(), skip_empty: p.skip_empty });
        }
    }

    for (key, value) in defaults {
        if merged.iter().any(|p| p.key.eq_ignore_ascii_case(key)) {
            continue;
        }

        let value = crate::script::compile_complex_value(cf, value, 0)?;

        merged.push(Param { key: key.to_vec(), value, skip_empty: true });
    }

    Ok(Rc::new(merged))
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
        let mut u = ngx_core::inet::Url::new(&url);
        u.no_resolve = true;
        let uscf = crate::upstream::upstream_add(cf, &mut u, 0)?;
        cell.borrow_mut().upstream = Some(uscf);
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

/// ngx_http_fastcgi_next_upstream_masks
const FASTCGI_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
    ("error", FT_ERROR),
    ("timeout", FT_TIMEOUT),
    ("invalid_header", FT_INVALID_HEADER),
    ("non_idempotent", FT_NON_IDEMPOTENT),
    ("http_500", FT_HTTP_500),
    ("http_503", FT_HTTP_503),
    ("http_403", FT_HTTP_403),
    ("http_404", FT_HTTP_404),
    ("http_429", FT_HTTP_429),
    ("updating", crate::proxy::FT_UPDATING),
    ("off", FT_OFF),
];

/// ngx_http_fastcgi_cache: "fastcgi_cache zone | off" (fastcgi_store,
/// which it is incompatible with, is not ported)
fn fastcgi_cache_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_fastcgi_module");
    cell.borrow_mut().cache = ucf;
    rc
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
fn create_request(r: &R, flcf: &NgxHttpFastcgiLocConf, cacheable: bool) -> Result<Vec<u8>, i64> {
    let mut params_data = Vec::new();

    // the params hash: names after "HTTP_" hide the request headers
    let mut header_names: Vec<Vec<u8>> = Vec::new();

    // params = u->cacheable ? &flcf->params_cache : &flcf->params
    let params = if cacheable { &flcf.params_cache } else { &flcf.params_built };

    if let Some(params) = params {
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
    /// The response as read (u->buffer and what followed), and where the
    /// STDOUT data of each record is in it: (offset in raw, offset in
    /// stdout, length).
    raw: Vec<u8>,
    stdout_map: Vec<(usize, usize, usize)>,
    /// The response ended with an error or a timeout after the header
    /// (p->upstream_error).
    upstream_error: bool,
}

impl Records {
    /// u->buffer.pos - u->buffer.start after ngx_http_fastcgi_process_header:
    /// where the response header ends in the response as read, for the
    /// end of the header at `hend` of the STDOUT data.
    fn raw_header_end(&self, hend: usize) -> usize {
        for &(raw_start, out_start, len) in &self.stdout_map {
            if hend > out_start && hend <= out_start + len {
                return raw_start + (hend - out_start);
            }
        }

        self.raw.len()
    }

    /// The response header as u->buffer has it once
    /// ngx_http_fastcgi_process_header is done, for the cache file: the
    /// records read up to the end of the header; or, when stderr before the
    /// header did not fit into the buffer (`room`), its tail in a dummy STDERR
    /// record, as f->large_stderr leaves it, then the STDOUT records of the
    /// header. None if the header does not fit.
    fn cache_header(&self, hend: usize, room: usize) -> Option<Vec<u8>> {
        let raw_hend = self.raw_header_end(hend);

        if raw_hend <= room {
            return Some(self.raw[..raw_hend].to_vec());
        }

        let stdout_start = self.stdout_map.first()?.0 - HEADER_SIZE;
        let stdout_part = raw_hend - stdout_start;

        if stdout_part + HEADER_SIZE > room {
            return None;
        }

        let tail = (room - stdout_part - HEADER_SIZE).min(stdout_start).min(0xffff);

        let mut out = Vec::with_capacity(HEADER_SIZE + tail + stdout_part);

        if tail > 0 {
            record_header(&mut out, NGX_HTTP_FASTCGI_STDERR, tail, 0);
            out.extend_from_slice(&self.raw[stdout_start - tail..stdout_start]);
        }

        out.extend_from_slice(&self.raw[stdout_start..raw_hend]);

        Some(out)
    }
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
                    st.stdout_map.push((st.pos + HEADER_SIZE, st.stdout.len(), content.len()));
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
                    st.raw = buf;
                    st.upstream_error = true;
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
                    st.upstream_error = true;
                }
                st.raw = buf;
                return Ok(st);
            }
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection while reading response header from upstream");
            return Err(ReadError::Closed);
        }

        *received += n as i64;
        buf.extend_from_slice(&chunk[..n]);

        process_records(r, conf, &buf, &mut st)?;

        if st.end_request || conf.header_only && header_end(&st.stdout).is_some() {
            st.raw = buf;
            return Ok(st);
        }

        // ngx_http_fastcgi_process_header rejects an invalid header at once
        if let HeaderState::Invalid = header_state(&st.stdout) {
            st.raw = buf;
            return Ok(st);
        }
    }
}

/// ngx_http_fastcgi_handler, with the upstream steps it drives.
async fn fastcgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());

    // ngx_http_upstream_create; u->conf (the cache fields) and u->caches
    // of the main configuration
    {
        let c = lcf.borrow();
        let fmcf = r.main_conf::<crate::upstream_cache::UpstreamCacheMainConf>(ctx_index());
        let caches = Rc::new(fmcf.borrow().caches.clone());
        crate::upstream_cache::upstream_create(&r, c.cache.clone(), caches, "fastcgi", c.buffer_size.get_or(ngx_core::os::pagesize()));
    }

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
            (None, None) => {
                // ngx_http_upstream_init_request: no u->conf->upstream
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "no upstream configuration");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    };

    // ngx_http_upstream_init_request: ngx_http_upstream_cache, then
    // ngx_http_upstream_cache_send for a response from the cache

    let ucache = match crate::upstream_cache::upstream_of(&r) {
        Some(uc) => uc,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    if ucache.conf.enabled() {
        let mut rc = crate::upstream_cache::upstream_cache_wait(&r, &ucache, &create_key).await;

        if rc == NGX_ERROR {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if rc == NGX_OK {
            rc = cache_send(&r, &lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_DECLINED;
                r.cached.set(false);
                ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_MISS);
            }
        }

        if rc != NGX_DECLINED {
            return rc;
        }
    }

    // the cache is freed when the upstream is done (finalize_request)
    let _cache_guard = crate::upstream_cache::CacheGuard::new(&r);

    // u->cacheable
    let cacheable = ucache.cacheable.get();

    let request = {
        let c = lcf.borrow();
        match create_request(&r, &c, cacheable) {
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

    let (next_upstream, next_tries, next_timeout, connect_timeout, keep_conn, static_upstream) = {
        let c = lcf.borrow();
        (
            *c.next_upstream.get(),
            *c.next_upstream_tries.get() as u32,
            0u64,
            *c.connect_timeout.get(),
            *c.keep_conn.get(),
            c.upstream.clone(),
        )
    };

    let tag = Rc::as_ptr(&lcf) as *const () as usize;

    // ngx_http_upstream_init_request
    let peer = match static_upstream {
        Some(uscf) => crate::upstream::UpstreamPeer::init(&r, &uscf, next_upstream, next_tries, next_timeout, tag),
        None => {
            // ngx_http_fastcgi_eval
            let mut u = ngx_core::inet::Url::new(&url);
            u.no_resolve = true;
            if ngx_core::inet::parse_url(&mut u).is_err() {
                if let Some(err) = u.err {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "{} in upstream \"{}\"", err, B(&url));
                }
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            crate::upstream::UpstreamPeer::resolve(&r, &u, next_upstream, next_tries, next_timeout, tag).await
        }
    };

    let peer = match peer {
        Ok(p) => p,
        Err(rc) => return rc,
    };

    let mut g = crate::upstream::PeerGuard::new(&r, peer);

    loop {
        // ngx_http_upstream_connect
        let rc = g.u.connect(&r);

        if rc == NGX_ERROR {
            return crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if rc == NGX_BUSY {
            match g.u.next(&r, crate::upstream::NGX_HTTP_UPSTREAM_FT_NOLIVE) {
                Ok(()) => continue,
                Err(st) => return next_failed(&r, &lcf, crate::upstream::NGX_HTTP_UPSTREAM_FT_NOLIVE, st).await,
            }
        }

        let started = g.u.start_time;

        let (mut upstream, requests, start_time) = if rc == NGX_DONE {
            let c = g.u.pc.connection.take().unwrap();
            (c.sock, c.requests, c.start_time)
        } else {
            let sockaddr = match g.u.pc.sockaddr.clone() {
                Some(sa) => sa,
                None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            };
            match crate::proxy::connect_upstream(&r, &sockaddr, None, None, None, connect_timeout).await {
                Ok(s) => (s, 0, ngx_core::times::current_msec()),
                Err(e) => {
                    let ft = match e {
                        crate::proxy::ConnectError::Error => FT_ERROR,
                        crate::proxy::ConnectError::Timeout => FT_TIMEOUT,
                        crate::proxy::ConnectError::Internal => return NGX_HTTP_INTERNAL_SERVER_ERROR,
                    };
                    match g.u.next(&r, ft) {
                        Ok(()) => continue,
                        Err(st) => return next_failed(&r, &lcf, ft, st).await,
                    }
                }
            }
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.connect_time = ngx_core::times::current_msec().saturating_sub(started);
        }

        let mut wire = request.clone();
        wire.extend_from_slice(&initial_body);

        let mut sent = wire.len() as i64;

        g.u.request_sent = true;

        let send_timeout = *lcf.borrow().send_timeout.get();
        let written = tokio::time::timeout(Duration::from_millis(send_timeout), upstream.write_all(&wire)).await;

        let failure: Option<u32> = match written {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some(FT_ERROR),
            Err(_) => {
                let action = r.connection.log.action();
                r.connection.log.set_action(Some("sending request to upstream"));
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                r.connection.log.set_action(action);
                Some(FT_TIMEOUT)
            }
        };

        if let Some(ft) = failure {
            match g.u.next(&r, ft) {
                Ok(()) => continue,
                Err(st) => return next_failed(&r, &lcf, ft, st).await,
            }
        }

        if r.reading_body.get() {
            match crate::proxy::send_request_body(&r, &mut upstream, &body_output_filter).await {
                Ok(n) => sent += n,
                Err(rc) => {
                    drop(upstream);
                    if rc == NGX_HTTP_BAD_GATEWAY {
                        // the upstream write failed
                        match g.u.next(&r, FT_ERROR) {
                            Ok(()) => continue,
                            Err(st) => return next_failed(&r, &lcf, FT_ERROR, st).await,
                        }
                    }
                    return rc;
                }
            }
        }

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_sent = sent;
        }

        let mut received = 0i64;

        let conf = {
            let c = lcf.borrow();
            ReadConf {
                read_timeout: *c.read_timeout.get(),
                keep_conn: *c.keep_conn.get(),
                catch_stderr: c.catch_stderr.clone(),
                // a cacheable response is read in full (u->pipe->downstream_error)
                header_only: r.method.get() == NGX_HTTP_HEAD && !cacheable,
            }
        };

        let records = match read_response(&r, &conf, &mut upstream, &mut received).await {
            Ok(st) => st,
            Err(e) => {
                let ft = match e {
                    ReadError::Invalid => FT_INVALID_HEADER,
                    ReadError::Closed => FT_ERROR,
                    ReadError::Timeout => FT_TIMEOUT,
                };
                if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
                    st.bytes_received = received;
                }
                match g.u.next(&r, ft) {
                    Ok(()) => continue,
                    Err(st) => return next_failed(&r, &lcf, ft, st).await,
                }
            }
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.header_time = ngx_core::times::current_msec().saturating_sub(started);
            st.bytes_received = received;
        }
        g.u.notify(&r, crate::upstream::NGX_HTTP_UPSTREAM_NOTIFY_HEADER);

        let hend = header_end(&records.stdout).unwrap_or(records.stdout.len());

        let mut hin = crate::upstream_cache::CacheHeadersIn::new();

        let (status, status_line, headers) = match process_header(&r, &records.stdout[..hend], &mut hin) {
            Ok(v) => v,
            Err(()) => match g.u.next(&r, FT_INVALID_HEADER) {
                Ok(()) => continue,
                Err(st) => return next_failed(&r, &lcf, FT_INVALID_HEADER, st).await,
            },
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            if st.status == 0 {
                st.status = status;
            }
            st.response_length = (records.stdout.len() - hend) as i64;
        }

        // ngx_http_upstream_test_next
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

        if ft != 0 {
            let mut mask = ft;
            if g.u.request_sent && matches!(r.method.get(), NGX_HTTP_POST | NGX_HTTP_LOCK | NGX_HTTP_PATCH) {
                mask |= FT_NON_IDEMPOTENT;
            }
            if g.u.pc.tries > 1 && next_upstream & mask == mask && !(g.u.request_sent && r.request_body_no_buffering.get()) {
                drop(upstream);
                match g.u.next(&r, ft) {
                    Ok(()) => continue,
                    Err(st) => return next_failed(&r, &lcf, ft, st).await,
                }
            }
        }

        // u->keepalive: END_REQUEST was read on a kept connection
        if keep_conn && records.end_request {
            g.conn = Some(crate::upstream::UpstreamConn { sock: upstream, requests: requests + 1, start_time });
            g.keepalive = true;
        }

        // u->buffer after the cache header: the room for the response header
        let room = match (crate::file_cache::cache_of(&r), crate::upstream_cache::upstream_of(&r)) {
            (Some(c), Some(u)) => u.buffer_size.saturating_sub(c.borrow().header_start),
            _ => usize::MAX,
        };

        let cache_header = records.cache_header(hend, room);

        return send_response(&r, &lcf, status, status_line, headers, &hin, cache_header.as_deref(), &records.stdout[hend..], records.upstream_error).await;
    }
}

/// The header part of ngx_http_fastcgi_process_header: the status from
/// "Status" (or 302 with "Location", else 200) and the header lines, with
/// the cache handlers of ngx_http_upstream_headers_in[] (a duplicate of a
/// header processed once is not processed).
fn process_header(r: &R, data: &[u8], hin: &mut crate::upstream_cache::CacheHeadersIn) -> Result<(i64, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), ()> {
    let mut pr = ParseRequest::default();
    let mut pos = 0;
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    loop {
        let rc = parse::parse_header_line(&mut pr, data, &mut pos, true);

        http_debug!(r, "http fastcgi parser: {}", rc);

        if rc == NGX_OK {
            let name = data[pr.header_name_start..pr.header_name_end].to_vec();
            let value = data[pr.header_start..pr.header_end].to_vec();

            let lowcase = if name.len() == pr.lowcase_index { pr.lowcase_header[..name.len()].to_vec() } else { name.to_ascii_lowercase() };

            match lowcase.as_slice() {
                b"expires" | b"x-accel-expires" | b"last-modified" | b"etag" => {
                    if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
                        crate::upstream_cache::process_header_line(r, hin, &lowcase, &value);
                    }
                }
                b"set-cookie" | b"cache-control" | b"vary" => {
                    crate::upstream_cache::process_header_line(r, hin, &lowcase, &value);
                }
                _ => {}
            }

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

/// ngx_http_fastcgi_create_key: fastcgi_cache_key.
fn create_key(r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());

    let cv = lcf.borrow().cache.cache_key.clone();

    let key = match cv {
        Some(cv) => match crate::script::complex_value(r, &cv) {
            Ok(k) => k,
            Err(_) => return NGX_ERROR,
        },
        None => Vec::new(),
    };

    keys.push(key);

    NGX_OK
}

/// u->process_header on the response header of a cache file: the records
/// from header_start, as ngx_http_fastcgi_process_header parses them (the
/// last STDOUT record goes on in the body of the file), and their STDOUT
/// data.
fn cached_stdout(r: &R, catch_stderr: &Option<Vec<Vec<u8>>>, buf: &[u8]) -> Result<Vec<u8>, i64> {
    let mut stdout = Vec::new();
    let mut pos = 0;

    while buf.len() - pos >= HEADER_SIZE {
        let p = &buf[pos..];

        if p[0] != 1 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unsupported FastCGI protocol version: {}", p[0]);
            return Err(crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER);
        }

        let kind = p[1];

        if kind != NGX_HTTP_FASTCGI_STDOUT && kind != NGX_HTTP_FASTCGI_STDERR {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected FastCGI record: {}", kind);
            return Err(crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER);
        }

        let length = ((p[4] as usize) << 8) | p[5] as usize;
        let padding = p[6] as usize;

        let avail = (p.len() - HEADER_SIZE).min(length);
        let content = &p[HEADER_SIZE..HEADER_SIZE + avail];

        if kind == NGX_HTTP_FASTCGI_STDOUT {
            if length == 0 {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");
                return Err(crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER);
            }

            stdout.extend_from_slice(content);

            if header_end(&stdout).is_some() {
                break;
            }
        } else if length > 0 {
            let mut end = content.len();
            while end > 0 && matches!(content[end - 1], b'\n' | b'\r' | b'.' | b' ') {
                end -= 1;
            }
            let msg = &content[..end];

            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "FastCGI sent in stderr: \"{}\"", B(msg));

            if let Some(patterns) = catch_stderr {
                if patterns.iter().any(|pat| msg.windows(pat.len().max(1)).any(|w| w == pat.as_slice())) {
                    return Err(crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER);
                }
            }
        }

        if avail < length {
            break;
        }

        pos += HEADER_SIZE + length + padding.min(p.len() - HEADER_SIZE - length);
    }

    Ok(stdout)
}

/// ngx_http_upstream_cache_send with ngx_http_fastcgi_process_header and
/// ngx_http_upstream_process_headers: the response from the cache.
async fn cache_send(r: &R, lcf: &Rc<std::cell::RefCell<NgxHttpFastcgiLocConf>>) -> i64 {
    crate::upstream_cache::upstream_cache_send(r, |buf| async move {
        let catch_stderr = lcf.borrow().catch_stderr.clone();

        let stdout = match cached_stdout(r, &catch_stderr, &buf) {
            Ok(s) => s,
            Err(rc) => return rc,
        };

        let hend = match header_state(&stdout) {
            HeaderState::Done(p) => p,
            HeaderState::Again => return NGX_AGAIN,
            HeaderState::Invalid => stdout.len(),
        };

        let mut hin = crate::upstream_cache::CacheHeadersIn::new();

        let (status, status_line, headers) = match process_header(r, &stdout[..hend], &mut hin) {
            Ok(v) => v,
            Err(()) => return crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER,
        };

        match process_headers(r, lcf, status, status_line, headers, &hin) {
            Ok(()) => NGX_OK,
            Err(rc) => {
                crate::upstream_cache::finalize(r, rc, None);
                rc
            }
        }
    })
    .await
}

/// The stale response of ngx_http_upstream_next, when there is no next
/// upstream to try, or the error status the request is finalized with.
async fn next_failed(r: &R, lcf: &Rc<std::cell::RefCell<NgxHttpFastcgiLocConf>>, ft_type: u32, status: i64) -> i64 {
    if crate::upstream_cache::next_stale(r, ft_type) {
        // u->reinit_request(r)

        if let Some(u) = crate::upstream_cache::upstream_of(r) {
            u.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);
        }

        let mut rc = cache_send(r, lcf).await;

        if rc == NGX_DONE {
            return NGX_DONE;
        }

        if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        crate::upstream_cache::finalize(r, rc, None);

        return rc;
    }

    // ngx_http_upstream_finalize_request: a 502 or 504 is cached for its
    // fastcgi_cache_valid time
    crate::upstream_cache::finalize(r, status, None);

    status
}

/// ngx_http_upstream_process_headers: the headers not hidden go to
/// headers_out.
fn process_headers(
    r: &R,
    lcf: &Rc<std::cell::RefCell<NgxHttpFastcgiLocConf>>,
    status: i64,
    status_line: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    hin: &crate::upstream_cache::CacheHeadersIn,
) -> Result<(), i64> {
    // u->headers_in.no_cache || u->headers_in.expired
    crate::upstream_cache::process_headers_cacheable(r, hin);

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

    let cacheable = crate::upstream_cache::cacheable(r);

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

            // ngx_http_upstream_copy_allow_ranges
            if name.eq_ignore_ascii_case(b"Accept-Ranges") {
                if r.cached.get() {
                    r.allow_ranges.set(true);
                    continue;
                }

                if cacheable {
                    r.allow_ranges.set(true);
                    r.single_range.set(true);
                    continue;
                }
            }

            crate::upstream::copy_header(&mut ho, &mut copied, status, name, value);
        }
    }

    if copied.invalid {
        return Err(NGX_HTTP_BAD_GATEWAY);
    }

    r.disable_not_modified.set(!cacheable);

    Ok(())
}

/// ngx_http_upstream_test_next and ngx_http_upstream_intercept_errors for a
/// status of the upstream, then ngx_http_upstream_process_headers and
/// ngx_http_upstream_send_response for the buffered response: the header,
/// the cache file (the response header as read, then the body) and the body.
#[allow(clippy::too_many_arguments)]
async fn send_response(
    r: &R,
    lcf: &Rc<std::cell::RefCell<NgxHttpFastcgiLocConf>>,
    status: i64,
    status_line: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    hin: &crate::upstream_cache::CacheHeadersIn,
    raw_header: Option<&[u8]>,
    body: &[u8],
    upstream_error: bool,
) -> i64 {
    if status >= NGX_HTTP_SPECIAL_RESPONSE {
        // ngx_http_upstream_test_next: the stale response instead of the
        // status fastcgi_cache_use_stale names

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

        if ft != 0 && crate::upstream_cache::test_next_stale(r, ft) {
            if let Some(u) = crate::upstream_cache::upstream_of(r) {
                u.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);
            }

            let mut rc = cache_send(r, lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            crate::upstream_cache::finalize(r, rc, None);

            return rc;
        }

        // the expired response was revalidated

        if crate::upstream_cache::test_next_not_modified(r, status) {
            let saved = crate::upstream_cache::not_modified_start(r);

            let mut rc = cache_send(r, lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            let cached_status = r.headers_out.borrow().status;

            crate::upstream_cache::not_modified_finish(r, saved, cached_status);

            crate::upstream_cache::finalize(r, rc, None);

            return rc;
        }

        // ngx_http_upstream_intercept_errors
        let intercept = *lcf.borrow().intercept_errors.get();
        if intercept {
            let clcf = r.clcf();
            let has_page = clcf.borrow().error_pages.as_ref().map(|pages| pages.iter().any(|p| p.status == status)).unwrap_or(false);
            if has_page {
                crate::upstream_cache::intercept_errors(r, status, hin);
                return status;
            }
        }
    }

    if let Err(rc) = process_headers(r, lcf, status, status_line, headers, hin) {
        crate::upstream_cache::finalize(r, rc, None);
        return rc;
    }

    let content_length = r.headers_out.borrow().content_length_n;

    let rc = crate::core_rt::send_header(r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.post_action.get() {
        crate::upstream_cache::finalize(r, rc, None);
        return rc;
    }

    let header_only = r.header_only.get() || r.method.get() == NGX_HTTP_HEAD;

    if header_only && !crate::upstream_cache::cacheable(r) {
        crate::upstream_cache::finalize(r, rc, None);
        return rc;
    }

    // the cache: fastcgi_no_cache, the valid time, the header of the cache
    // file; p->temp_file with it (p->buf_to_file)

    let mut writer: Option<crate::upstream_cache::CacheWriter> = None;

    // a response header which does not fit into u->buffer after the cache
    // header is not cached ("upstream sent too big header" in C)
    let raw_header: &[u8] = match raw_header {
        Some(h) => h,
        None => {
            if let Some(u) = crate::upstream_cache::upstream_of(r) {
                u.cacheable.set(false);
            }
            &[]
        }
    };

    match crate::upstream_cache::send_response(r, status, hin, raw_header.len()) {
        Err(()) => {
            crate::upstream_cache::finalize(r, NGX_ERROR, None);
            return NGX_ERROR;
        }

        Ok(Some(header)) => {
            let temp_path = lcf.borrow().temp_path.as_option().cloned();

            writer = crate::upstream_cache::CacheWriter::new(r, temp_path.as_deref(), &header, raw_header);

            if writer.is_none() {
                crate::upstream_cache::finalize(r, NGX_ERROR, None);
                return NGX_ERROR;
            }
        }

        Ok(None) => {}
    }

    if header_only && !crate::upstream_cache::cacheable(r) {
        crate::upstream_cache::finalize(r, 0, None);
        return 0;
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

    // ngx_http_upstream_process_request: the cache file
    if let Some(mut w) = writer {
        w.write(r, body);
        w.finish(r, !short && !upstream_error, false, content_length);
    }

    if header_only {
        crate::upstream_cache::finalize(r, rc, None);
        return rc;
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
    } else {
        // ngx_http_upstream_finalize_request with the header sent and an
        // error: ngx_http_send_special(r, NGX_HTTP_FLUSH), the response
        // header goes out even without a body
        let mut flush = Buf::special();
        flush.flush = true;
        chain.push_back(flush);
    }

    let rc = crate::core_rt::output_filter(r, chain).await;

    crate::upstream_cache::finalize(r, rc, None);

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
        ngx_core::cmd!("fastcgi_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, buffer_size, set_size),
        ngx_core::cmd!("fastcgi_pass_request_headers", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, pass_request_headers, set_flag),
        ngx_core::cmd!("fastcgi_pass_request_body", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, pass_request_body, set_flag),
        ngx_core::cmd!("fastcgi_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, intercept_errors, set_flag),
        ngx_core::cmd!("fastcgi_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, read_timeout, set_msec),
        Command::new("fastcgi_buffers", F | NGX_CONF_TAKE2, ConfLevel::None, accept),
        Command::new("fastcgi_busy_buffers_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_force_ranges", F | NGX_CONF_FLAG, ConfLevel::None, accept),
        Command::new("fastcgi_limit_rate", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        cmd_fn!("fastcgi_cache", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_cache_handler),
        cmd_fn!("fastcgi_cache_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_key_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, |cf, cmd, conf| crate::upstream_cache::cache_path_slot(cf, cmd, conf, "ngx_http_fastcgi_module")),
        cmd_fn!("fastcgi_cache_bypass", F | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_bypass_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_no_cache", F | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::no_cache_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_valid", F | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_valid_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_min_uses", F | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_min_uses_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_max_range_offset", F | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_max_range_offset_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_use_stale", F | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
            let mut c = cell.borrow_mut();
            crate::upstream_cache::cache_use_stale_slot(cf, cmd, &mut c.cache, FASTCGI_NEXT_UPSTREAM_MASKS)
        }),
        cmd_fn!("fastcgi_cache_methods", F | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_methods_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_lock", F | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_lock_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_lock_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_lock_timeout_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_lock_age", F | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_lock_age_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_revalidate", F | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_revalidate_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_cache_background_update", F | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_background_update_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_temp_path", F | NGX_CONF_TAKE1234, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().unwrap());
            let mut slot = std::mem::take(&mut cell.borrow_mut().temp_path);
            let rc = set_path(cf, cmd, &mut slot);
            cell.borrow_mut().temp_path = slot;
            rc
        }),
        Command::new("fastcgi_max_temp_file_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("fastcgi_temp_file_write_size", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        cmd_fn!("fastcgi_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, fastcgi_next_upstream_handler),
        ngx_core::cmd!("fastcgi_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpFastcgiLocConf, next_upstream_tries, set_num),
        Command::new("fastcgi_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::None, accept),
        cmd_fn!("fastcgi_param", F | NGX_CONF_TAKE23, ConfLevel::Loc, fastcgi_param_handler),
        cmd_fn!("fastcgi_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_pass_header_handler),
        cmd_fn!("fastcgi_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_hide_header_handler),
        cmd_fn!("fastcgi_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::ignore_headers_slot::<NgxHttpFastcgiLocConf>),
        cmd_fn!("fastcgi_catch_stderr", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_catch_stderr_handler),
        ngx_core::cmd!("fastcgi_keep_conn", F | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpFastcgiLocConf, keep_conn, set_flag),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_main_conf: Some(crate::upstream_cache::create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_fastcgi_module", def, commands)
}
