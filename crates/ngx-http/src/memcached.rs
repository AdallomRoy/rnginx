//! ngx_http_memcached_module
//!
//! The request is "get <$memcached_key escaped>" (ngx_http_memcached_create_request),
//! the response "VALUE <key> <flags> <length>" and the data with the
//! "CRLF END CRLF" trailer (ngx_http_memcached_process_header and
//! ngx_http_memcached_filter), or "END" for a key not found (404). The
//! response is not buffered; the request lifecycle is that of
//! crate::upstream_rt.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::inet::Url;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::event_pipe::EventPipe;
use crate::request::*;
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, NGX_CONF_BITMASK_SET, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_rt::{Upstream, UpstreamConf, UpstreamLocal, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_memcached_module");

/// ngx_http_memcached_next_upstream_masks
const MEMCACHED_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
    ("error", NGX_HTTP_UPSTREAM_FT_ERROR),
    ("timeout", NGX_HTTP_UPSTREAM_FT_TIMEOUT),
    ("invalid_response", NGX_HTTP_UPSTREAM_FT_INVALID_HEADER),
    ("not_found", NGX_HTTP_UPSTREAM_FT_HTTP_404),
    ("off", NGX_HTTP_UPSTREAM_FT_OFF),
];

/// ngx_http_memcached_end
const MEMCACHED_END: &[u8] = b"\r\nEND\r\n";

/// NGX_HTTP_MEMCACHED_END
const NGX_HTTP_MEMCACHED_END: i64 = MEMCACHED_END.len() as i64;

/// ngx_http_memcached_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module sets.
pub struct NgxHttpMemcachedLocConf {
    /// upstream.upstream: the upstream of memcached_pass
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    /// upstream.local: unset, NULL ("off") or the address
    pub local: Val<Option<Rc<UpstreamLocal>>>,
    pub socket_keepalive: Val<bool>,
    pub next_upstream_tries: Val<i64>,
    pub connect_timeout: Val<u64>,
    pub send_timeout: Val<u64>,
    pub read_timeout: Val<u64>,
    pub next_upstream_timeout: Val<u64>,
    pub buffer_size: Val<usize>,

    /// upstream.next_upstream: a bitmask, 0 when not set
    pub next_upstream: u32,

    /// the index of $memcached_key (NGX_CONF_UNSET: none)
    pub index: Option<usize>,
    pub gzip_flag: Val<i64>,

    /// mlcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

/// ngx_http_memcached_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(new_loc_conf())
}

fn new_loc_conf() -> NgxHttpMemcachedLocConf {
    // set by ngx_pcalloc(): bufs.num = 0, next_upstream = 0, temp_path = NULL
    NgxHttpMemcachedLocConf {
        upstream: None,
        local: Val::unset(),
        socket_keepalive: Val::unset(),
        next_upstream_tries: Val::unset(),
        connect_timeout: Val::unset(),
        send_timeout: Val::unset(),
        read_timeout: Val::unset(),
        next_upstream_timeout: Val::unset(),
        buffer_size: Val::unset(),
        next_upstream: 0,
        index: None,
        gzip_flag: Val::unset(),
        upstream_conf: None,
    }
}

/// ngx_http_memcached_merge_loc_conf
fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpMemcachedLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpMemcachedLocConf>(conf).borrow_mut();

    crate::upstream_ssl::merge_ptr(&mut c.local, &p.local);

    c.socket_keepalive.merge(&p.socket_keepalive, false);

    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);

    c.connect_timeout.merge(&p.connect_timeout, 60000);

    c.send_timeout.merge(&p.send_timeout, 60000);

    c.read_timeout.merge(&p.read_timeout, 60000);

    c.next_upstream_timeout.merge(&p.next_upstream_timeout, 0);

    c.buffer_size.merge(&p.buffer_size, ngx_core::os::pagesize());

    if c.next_upstream == 0 {
        c.next_upstream = if p.next_upstream == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT } else { p.next_upstream };
    }

    if c.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF != 0 {
        c.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if c.upstream.is_none() {
        c.upstream = p.upstream.clone();
    }

    if c.index.is_none() {
        c.index = p.index;
    }

    c.gzip_flag.merge(&p.gzip_flag, 0);

    c.upstream_conf = Some(Rc::new(upstream_conf(&c)));

    Ok(())
}

/// mlcf->upstream, with the hardcoded values of
/// ngx_http_memcached_create_loc_conf
fn upstream_conf(c: &NgxHttpMemcachedLocConf) -> UpstreamConf {
    UpstreamConf {
        upstream: c.upstream.clone(),
        connect_timeout: *c.connect_timeout,
        send_timeout: *c.send_timeout,
        read_timeout: *c.read_timeout,
        next_upstream_timeout: *c.next_upstream_timeout,
        send_lowat: 0,
        buffer_size: *c.buffer_size,
        limit_rate: None,
        busy_buffers_size: 0,
        max_temp_file_size: 0,
        temp_file_write_size: 0,
        bufs: Bufs::default(),
        next_upstream: c.next_upstream,
        store_access: 0,
        next_upstream_tries: *c.next_upstream_tries as u32,
        buffering: false,
        request_buffering: true,
        pass_request_headers: false,
        pass_request_body: false,
        pass_trailers: false,
        pass_early_hints: false,
        ignore_client_abort: false,
        intercept_errors: true,
        cyclic_temp_file: false,
        force_ranges: true,
        temp_path: None,
        hide_headers_hash: None,
        local: c.local.as_option().cloned().flatten(),
        socket_keepalive: *c.socket_keepalive,
        socket_rcvbuf: 0,
        socket_sndbuf: 0,
        cache: UpstreamCacheConf::default(),
        store: false,
        store_values: None,
        intercept_404: true,
        change_buffering: false,
        preserve_output: false,
        ignore_input: false,
        ssl: UpstreamSslConf::default(),
        module: "",
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// ngx_http_memcached_ctx_t: the key sent, and what is left of the trailer
struct MemcachedModule {
    lcf: Rc<RefCell<NgxHttpMemcachedLocConf>>,
    /// ctx->rest
    rest: i64,
    /// ctx->key: the key as sent (escaped)
    key: Vec<u8>,
}

/// ngx_http_memcached_handler
async fn memcached_handler(r: R) -> i64 {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }

    let rc = crate::request_body::discard_request_body(&r).await;

    if rc != NGX_OK {
        return rc;
    }

    if crate::core_rt::set_content_type(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let lcf = r.loc_conf::<NgxHttpMemcachedLocConf>(ctx_index());

    let conf = match lcf.borrow().upstream_conf.clone() {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // ngx_http_upstream_create; u->schema = "memcached://"
    let u = Upstream::create(&r, conf, Rc::new(Vec::new()), b"memcached://");

    let mut m = MemcachedModule { lcf, rest: 0, key: Vec::new() };

    // r->main->count++; ngx_http_upstream_init(r)
    crate::upstream_rt::init(r, u, &mut m).await
}

impl UpstreamModule for MemcachedModule {
    fn create_key(&self, _r: &R, _keys: &mut Vec<Vec<u8>>) -> i64 {
        NGX_OK
    }

    /// ngx_http_memcached_create_request: "get <key>" CRLF
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let index = self.lcf.borrow().index;

        let vv = index.and_then(|i| get_indexed_variable(r, i));

        let value = match vv {
            Some(v) if !v.not_found && !v.data.is_empty() => v.data,
            _ => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the \"$memcached_key\" variable is not set");
                return NGX_ERROR;
            }
        };

        let mut b = b"get ".to_vec();

        self.key = ngx_core::string::escape_uri(&value, ngx_core::string::NGX_ESCAPE_MEMCACHED);

        b.extend_from_slice(&self.key);

        http_debug!(r, "http memcached request: \"{}\"", B(&self.key));

        b.extend_from_slice(b"\r\n");

        let mut bufs = Chain::new();
        bufs.push_back(Buf::from_vec(b));

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_memcached_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        NGX_OK
    }

    /// ngx_http_memcached_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let buf = &u.resp.buf;

        let lf = match buf.iter().position(|&c| c == b'\n') {
            Some(p) => p,
            None => return NGX_AGAIN,
        };

        // found:

        if lf == 0 || buf[lf - 1] != b'\r' {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid response: \"{}\"", B(&buf[..lf]));
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        // the line without the CR; "*p = '\0'" at the LF
        let line = buf[..lf - 1].to_vec();

        http_debug!(r, "memcached: \"{}\"", B(&line));

        let no_valid = |r: &R| {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid response: \"{}\"", B(&line));
            NGX_HTTP_UPSTREAM_INVALID_HEADER
        };

        // the line and its CR, as the C string up to the LF
        let s = &buf[..lf];

        if let Some(rest) = s.strip_prefix(b"VALUE ") {
            if !rest.starts_with(&self.key) {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid key in response \"{}\" for key \"{}\"", B(&line), B(&self.key));
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            let mut p = "VALUE ".len() + self.key.len();

            if s.get(p) != Some(&b' ') {
                return no_valid(r);
            }

            p += 1;

            // flags

            let start = p;

            let space = match s[p..].iter().position(|&c| c == b' ') {
                Some(n) => p + n,
                None => return no_valid(r),
            };

            p = space + 1;

            let gzip_flag = *self.lcf.borrow().gzip_flag;

            if gzip_flag != 0 {
                // flags:

                let flags = match ngx_core::string::atoi(&s[start..space]) {
                    Some(f) => f,
                    None => {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid flags in response \"{}\" for key \"{}\"", B(&line), B(&self.key));
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }
                };

                if flags & gzip_flag != 0 {
                    let h = TableElt::new(b"Content-Encoding", b"gzip");

                    let mut ho = r.headers_out.borrow_mut();

                    ho.headers.push(h.clone());
                    ho.content_encoding = Some(h);
                }
            }

            // length:

            let length = &line[p.min(line.len())..];

            let n = atoof(length);

            if n == NGX_ERROR || n > i64::MAX - NGX_HTTP_MEMCACHED_END {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid length in response \"{}\" for key \"{}\"", B(&line), B(&self.key));
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            u.resp.content_length_n = n;
            u.resp.status_n = 200;

            if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                state.status = 200;
            }

            u.resp.pos = lf + 1;

            return NGX_OK;
        }

        if s == b"END\r" {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "key: \"{}\" was not found by memcached", B(&self.key));

            u.resp.content_length_n = 0;
            u.resp.status_n = 404;

            if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                state.status = 404;
            }

            u.resp.pos = lf + 1;
            u.keepalive = true;

            return NGX_OK;
        }

        no_valid(r)
    }

    /// ngx_http_memcached_filter_init
    fn input_filter_init(&mut self, _r: &R, u: &mut Upstream, _p: Option<&mut EventPipe>) -> i64 {
        if u.resp.status_n != 404 {
            u.length = u.resp.content_length_n + NGX_HTTP_MEMCACHED_END;
            self.rest = NGX_HTTP_MEMCACHED_END;
        } else {
            u.length = 0;
        }

        NGX_OK
    }

    /// ngx_http_memcached_filter: the data up to the trailer, which is
    /// checked
    fn input_filter(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        let bytes = data.len() as i64;

        if u.length == self.rest {
            let end = (NGX_HTTP_MEMCACHED_END - self.rest) as usize;

            if bytes > u.length || data != &MEMCACHED_END[end..end + data.len()] {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid trailer");

                u.length = 0;
                self.rest = 0;

                return NGX_OK;
            }

            u.length -= bytes;
            self.rest -= bytes;

            if u.length == 0 {
                u.keepalive = true;
            }

            return NGX_OK;
        }

        http_debug!(r, "memcached filter bytes:{} size:{} length:{} rest:{}", bytes, bytes, u.length, self.rest);

        if bytes <= u.length - NGX_HTTP_MEMCACHED_END {
            u.length -= bytes;

            push_buf(u, data);

            return NGX_OK;
        }

        let last = (u.length - NGX_HTTP_MEMCACHED_END) as usize;

        if bytes > u.length || data[last..] != MEMCACHED_END[..data.len() - last] {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "memcached sent invalid trailer");

            push_buf(u, &data[..last]);

            u.length = 0;
            self.rest = 0;

            return NGX_OK;
        }

        self.rest -= (data.len() - last) as i64;

        push_buf(u, &data[..last]);

        u.length = self.rest;

        if u.length == 0 {
            u.keepalive = true;
        }

        NGX_OK
    }

    /// ngx_http_memcached_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize http memcached request");
    }
}

/// A buffer of the data to u->out_bufs (flush, memory)
fn push_buf(u: &mut Upstream, data: &[u8]) {
    let mut b = Buf::from_vec(data.to_vec());
    b.flush = true;
    b.memory = true;
    b.temporary = false;

    u.out_bufs.push_back(b);
}

/// ngx_atoof: a non-negative decimal number, NGX_ERROR otherwise
fn atoof(v: &[u8]) -> i64 {
    if v.is_empty() {
        return NGX_ERROR;
    }

    let mut n: i64 = 0;

    for &c in v {
        if !c.is_ascii_digit() {
            return NGX_ERROR;
        }

        let d = (c - b'0') as i64;

        if n > (i64::MAX - d) / 10 {
            return NGX_ERROR;
        }

        n = n * 10 + d;
    }

    n
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn mlcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpMemcachedLocConf>> {
    conf_rc::<NgxHttpMemcachedLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_memcached_pass
fn memcached_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = mlcf_of(&conf);

    if cell.borrow().upstream.is_some() {
        return Err(msg("is duplicate"));
    }

    let mut u = Url::new(&cf.args[1]);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    cell.borrow_mut().upstream = Some(uscf);

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    {
        let mut lc = clcf.borrow_mut();

        lc.handler = Some(Rc::new(|r| Box::pin(memcached_handler(r))));

        if lc.name.last() == Some(&b'/') {
            lc.auto_redirect = true;
        }
    }

    let index = get_variable_index(cf, b"memcached_key")?;

    cell.borrow_mut().index = Some(index);

    Ok(())
}

/// memcached_bind: ngx_http_upstream_bind_set_slot
fn memcached_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = mlcf_of(&conf);
    let mut local = std::mem::take(&mut cell.borrow_mut().local);
    let rc = crate::upstream_rt::bind_set_slot(cf, &mut local);
    cell.borrow_mut().local = local;
    rc
}

/// memcached_next_upstream: ngx_conf_set_bitmask_slot
fn memcached_next_upstream(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = mlcf_of(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.next_upstream, MEMCACHED_NEXT_UPSTREAM_MASKS)
}

pub fn memcached_module() -> ModuleDef {
    use ngx_core::cmd;

    type C = NgxHttpMemcachedLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("memcached_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, memcached_pass),
        cmd_fn!("memcached_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, memcached_bind),
        cmd!("memcached_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("memcached_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("memcached_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd!("memcached_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("memcached_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd_fn!("memcached_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, memcached_next_upstream),
        cmd!("memcached_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("memcached_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
        cmd!("memcached_gzip_flag", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, gzip_flag, set_num),
    ];

    let def = HttpModuleDef { create_loc_conf: Some(create_loc_conf), merge_loc_conf: Some(merge_loc_conf), ..Default::default() };

    http_module_def("ngx_http_memcached_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atoof() {
        assert_eq!(atoof(b"5"), 5);
        assert_eq!(atoof(b""), NGX_ERROR);
        assert_eq!(atoof(b"5 "), NGX_ERROR);
    }

    #[test]
    fn test_new_loc_conf_unset() {
        let c = new_loc_conf();
        assert!(!c.gzip_flag.is_set());
        assert!(c.index.is_none());
        assert_eq!(c.next_upstream, 0);
    }
}
