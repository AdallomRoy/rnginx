//! ngx_http_tunnel_module
//!
//! The CONNECT method: tunnel_pass connects to the address the request
//! names ("$host:$request_port" by default) or to the upstream it names,
//! and the response is "200 OK" as soon as the connection is there, with
//! nothing read from the upstream first (u->conf->ignore_input). Then the
//! connection is an upgraded one (ngx_http_upstream_upgrade): what each side
//! sends goes to the other. The request lifecycle is that of
//! crate::upstream_rt.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::inet::Url;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::request::*;
use crate::script::Part;
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, NGX_CONF_BITMASK_SET};
use crate::upstream_rt::{Upstream, UpstreamConf, UpstreamLocal, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::*;

crate::http_module_index!("ngx_http_tunnel_module");

/// ngx_http_tunnel_next_upstream_masks
const TUNNEL_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[("error", NGX_HTTP_UPSTREAM_FT_ERROR), ("timeout", NGX_HTTP_UPSTREAM_FT_TIMEOUT), ("off", NGX_HTTP_UPSTREAM_FT_OFF)];

/// ngx_http_tunnel_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module uses.
pub struct NgxHttpTunnelLocConf {
    /// upstream.upstream: the upstream of tunnel_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    pub next_upstream_tries: Val<i64>,

    /// upstream.local: unset, NULL ("off") or the address
    pub local: Val<Option<Rc<UpstreamLocal>>>,
    pub socket_keepalive: Val<bool>,
    pub socket_rcvbuf: Val<usize>,
    pub socket_sndbuf: Val<usize>,

    pub connect_timeout: Val<u64>,
    pub send_timeout: Val<u64>,
    pub read_timeout: Val<u64>,
    pub next_upstream_timeout: Val<u64>,

    pub send_lowat: Val<usize>,
    pub buffer_size: Val<usize>,

    /// upstream.next_upstream: a bitmask, 0 when not set
    pub next_upstream: u32,

    /// tunnel_lengths and tunnel_values: the codes of a tunnel_pass with
    /// variables
    pub tunnel_values: Option<Rc<Vec<Part>>>,

    /// tlcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

/// ngx_http_tunnel_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    Rc::new(RefCell::new(new_loc_conf()))
}

fn new_loc_conf() -> NgxHttpTunnelLocConf {
    // set by ngx_pcalloc():
    //
    // next_upstream = 0; and upstream.ignore_input = 1, upstream.module
    // "tunnel" are those of upstream_conf()

    NgxHttpTunnelLocConf {
        upstream: None,
        next_upstream_tries: Val::unset(),
        local: Val::unset(),
        socket_keepalive: Val::unset(),
        socket_rcvbuf: Val::unset(),
        socket_sndbuf: Val::unset(),
        connect_timeout: Val::unset(),
        send_timeout: Val::unset(),
        read_timeout: Val::unset(),
        next_upstream_timeout: Val::unset(),
        send_lowat: Val::unset(),
        buffer_size: Val::unset(),
        next_upstream: 0,
        tunnel_values: None,
        upstream_conf: None,
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// The module's callbacks: a request has no state of the module.
struct TunnelModule;

/// ngx_http_tunnel_handler
async fn tunnel_handler(r: R) -> i64 {
    if r.method.get() != NGX_HTTP_CONNECT {
        return NGX_HTTP_NOT_ALLOWED;
    }

    let lcf = r.loc_conf::<NgxHttpTunnelLocConf>(ctx_index());

    let (conf, tunnel_values) = {
        let c = lcf.borrow();
        (c.upstream_conf.clone(), c.tunnel_values.clone())
    };

    let conf = match conf {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // ngx_http_upstream_create: the module sets no u->schema

    let mut u = Upstream::create(&r, conf, Rc::new(Vec::new()), b"");

    if let Some(codes) = tunnel_values {
        if tunnel_eval(&r, &codes, &mut u) != NGX_OK {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    crate::upstream_rt::init(r, u, &mut TunnelModule).await
}

/// ngx_http_tunnel_eval: the address of tunnel_pass with variables, and the
/// upstream it names (u->resolved: the first address, the host and the
/// port).
fn tunnel_eval(r: &R, codes: &[Part], u: &mut Upstream) -> i64 {
    let url = match crate::script::script_run(r, codes) {
        Some(v) => v,
        None => return NGX_ERROR,
    };

    let mut url = Url::new(&url);
    url.no_resolve = true;

    if ngx_core::inet::parse_url(&mut url).is_err() {
        if let Some(err) = url.err {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "{} in upstream \"{}\"", err, B(&url.url));
        }

        return NGX_ERROR;
    }

    // u->resolved->no_port is not set
    url.no_port = false;

    u.resolved = Some(url);

    NGX_OK
}

impl UpstreamModule for TunnelModule {
    fn create_key(&self, _r: &R, _keys: &mut Vec<Vec<u8>>) -> i64 {
        NGX_OK
    }

    /// ngx_http_tunnel_create_request: nothing to send
    fn create_request(&mut self, _r: &R, u: &mut Upstream) -> i64 {
        u.request_bufs = Chain::new();

        NGX_OK
    }

    /// ngx_http_tunnel_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        NGX_OK
    }

    /// ngx_http_tunnel_process_header: the connection is the response
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        u.resp.status_n = NGX_HTTP_OK;
        u.resp.status_line = b"200 OK".to_vec();

        http_debug!(r, "http tunnel status {} \"{}\"", u.resp.status_n, B(&u.resp.status_line));

        r.keepalive.set(false);
        u.keepalive = false;
        u.upgrade = true;

        NGX_OK
    }

    /// u->input_filter_init is not set: the response is an upgraded
    /// connection
    fn input_filter_init(&mut self, _r: &R, _u: &mut Upstream, _p: Option<&mut crate::event_pipe::EventPipe>) -> i64 {
        NGX_OK
    }

    /// ngx_http_tunnel_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize http tunnel request");
    }
}

// ---------------------------------------------------------------------------
// the configuration
// ---------------------------------------------------------------------------

/// ngx_http_tunnel_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpTunnelLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpTunnelLocConf>(conf).borrow_mut();

    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);

    crate::upstream_ssl::merge_ptr(&mut c.local, &p.local);

    c.socket_keepalive.merge(&p.socket_keepalive, false);

    c.socket_rcvbuf.merge(&p.socket_rcvbuf, 0);

    c.socket_sndbuf.merge(&p.socket_sndbuf, 0);

    c.connect_timeout.merge(&p.connect_timeout, 60000);

    c.send_timeout.merge(&p.send_timeout, 60000);

    c.read_timeout.merge(&p.read_timeout, 60000);

    c.next_upstream_timeout.merge(&p.next_upstream_timeout, 0);

    c.send_lowat.merge(&p.send_lowat, 0);

    c.buffer_size.merge(&p.buffer_size, ngx_core::os::pagesize());

    if c.next_upstream == 0 {
        c.next_upstream = if p.next_upstream == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT } else { p.next_upstream };
    }

    if c.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF != 0 {
        c.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.tunnel_values.is_none() {
        c.upstream = p.upstream.clone();

        c.tunnel_values = p.tunnel_values.clone();
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.tunnel_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(tunnel_handler(r))));
    }

    c.upstream_conf = Some(Rc::new(upstream_conf(&c)));

    Ok(())
}

/// tlcf->upstream, the ngx_http_upstream_conf_t of the location, as merged:
/// the fields the module has no directives for are those of ngx_pcalloc()
fn upstream_conf(c: &NgxHttpTunnelLocConf) -> UpstreamConf {
    UpstreamConf {
        upstream: c.upstream.clone(),
        connect_timeout: *c.connect_timeout,
        send_timeout: *c.send_timeout,
        read_timeout: *c.read_timeout,
        next_upstream_timeout: *c.next_upstream_timeout,
        send_lowat: *c.send_lowat,
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
        request_buffering: false,
        pass_request_headers: false,
        pass_request_body: false,
        pass_trailers: false,
        pass_early_hints: false,
        ignore_client_abort: false,
        intercept_errors: false,
        cyclic_temp_file: false,
        force_ranges: false,
        temp_path: None,
        hide_headers_hash: None,
        local: c.local.as_option().cloned().flatten(),
        socket_keepalive: *c.socket_keepalive,
        socket_rcvbuf: *c.socket_rcvbuf,
        socket_sndbuf: *c.socket_sndbuf,
        cache: UpstreamCacheConf::default(),
        store: false,
        store_values: None,
        intercept_404: false,
        change_buffering: false,
        preserve_output: false,
        ignore_input: true,
        ssl: UpstreamSslConf::default(),
        module: "tunnel",
    }
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn tlcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpTunnelLocConf>> {
    conf_rc::<NgxHttpTunnelLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_tunnel_pass
fn tunnel_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = tlcf_of(&conf);

    {
        let tlcf = cell.borrow();

        if tlcf.upstream.is_some() || tlcf.tunnel_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(tunnel_handler(r))));

    crate::core::core_srv_conf(cf).borrow_mut().allow_connect = true;

    let url = if cf.args.len() == 1 { b"$host:$request_port".to_vec() } else { cf.args[1].clone() };

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        cell.borrow_mut().tunnel_values = Some(Rc::new(codes));

        return Ok(());
    }

    let mut u = Url::new(&url);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    cell.borrow_mut().upstream = Some(uscf);

    Ok(())
}

/// tunnel_bind: ngx_http_upstream_bind_set_slot
fn tunnel_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = tlcf_of(&conf);
    let mut local = std::mem::take(&mut cell.borrow_mut().local);
    let rc = crate::upstream_rt::bind_set_slot(cf, &mut local);
    cell.borrow_mut().local = local;
    rc
}

/// tunnel_send_lowat: ngx_conf_set_size_slot with
/// ngx_http_tunnel_lowat_check (no NGX_HAVE_SO_SNDLOWAT: ignored)
fn tunnel_send_lowat(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = tlcf_of(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().send_lowat);

    let rc = set_size(cf, cmd, &mut slot);

    if rc.is_ok() {
        cf.warn(format_args!("\"tunnel_send_lowat\" is not supported, ignored"));
        slot = Val::set(0);
    }

    cell.borrow_mut().send_lowat = slot;
    rc
}

/// tunnel_next_upstream: ngx_conf_set_bitmask_slot
fn tunnel_next_upstream(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = tlcf_of(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.next_upstream, TUNNEL_NEXT_UPSTREAM_MASKS)
}

pub fn tunnel_module() -> ModuleDef {
    use ngx_core::cmd;

    type C = NgxHttpTunnelLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("tunnel_pass", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1, ConfLevel::Loc, tunnel_pass),
        cmd_fn!("tunnel_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, tunnel_bind),
        cmd!("tunnel_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("tunnel_socket_rcvbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_rcvbuf, set_size),
        cmd!("tunnel_socket_sndbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_sndbuf, set_size),
        cmd!("tunnel_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("tunnel_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd_fn!("tunnel_send_lowat", F | NGX_CONF_TAKE1, ConfLevel::Loc, tunnel_send_lowat),
        cmd!("tunnel_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("tunnel_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd_fn!("tunnel_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, tunnel_next_upstream),
        cmd!("tunnel_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("tunnel_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
    ];

    let def = HttpModuleDef { create_loc_conf: Some(create_loc_conf), merge_loc_conf: Some(merge_loc_conf), ..Default::default() };

    http_module_def("ngx_http_tunnel_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_loc_conf_unset() {
        let c = new_loc_conf();
        assert!(!c.connect_timeout.is_set());
        assert!(c.tunnel_values.is_none());
        assert!(c.upstream.is_none());
        assert_eq!(c.next_upstream, 0);
    }

    #[test]
    fn test_upstream_conf() {
        let mut c = new_loc_conf();

        c.next_upstream_tries = Val::set(2);
        c.local = Val::set(None);
        c.socket_keepalive = Val::set(false);
        c.socket_rcvbuf = Val::set(0);
        c.socket_sndbuf = Val::set(0);
        c.connect_timeout = Val::set(1000);
        c.send_timeout = Val::set(60000);
        c.read_timeout = Val::set(2000);
        c.next_upstream_timeout = Val::set(0);
        c.send_lowat = Val::set(0);
        c.buffer_size = Val::set(4096);
        c.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR;

        let u = upstream_conf(&c);

        assert!(u.ignore_input);
        assert!(!u.buffering);
        assert!(!u.pass_request_body);
        assert_eq!(u.module, "tunnel");
        assert_eq!((u.connect_timeout, u.read_timeout, u.buffer_size, u.next_upstream_tries), (1000, 2000, 4096, 2));
        assert_eq!(u.next_upstream, NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR);
    }
}
