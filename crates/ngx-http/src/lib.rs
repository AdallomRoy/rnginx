//! ngx-http: HTTP core and modules.

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

pub mod core;
pub mod core_rt;
pub mod request;
pub mod request_rt;
pub mod request_headers;
pub mod parse;
pub mod variables;
pub mod script;
pub mod header_filter;
pub mod write_filter;
pub mod special_response;
pub mod static_module;
pub mod index;
pub mod log;
pub mod request_body;
pub mod output;
pub mod chunked_filter;
pub mod not_modified_filter;
pub mod headers_filter;
pub mod postpone_filter;
pub mod copy_filter;
pub mod rewrite;
pub mod try_files;
pub mod access;
pub mod auth_basic;
pub mod auth_request;
pub mod realip;
pub mod stub_status;
pub mod flv;
pub mod mp4;
pub mod stubs;

pub use request::{Request, R};

// --- constants (ngx_http.h / ngx_http_request.h) ---

pub const NGX_HTTP_MAIN_CONF: u32 = 0x02000000;
pub const NGX_HTTP_SRV_CONF: u32 = 0x04000000;
pub const NGX_HTTP_LOC_CONF: u32 = 0x08000000;
pub const NGX_HTTP_UPS_CONF: u32 = 0x10000000;
pub const NGX_HTTP_SIF_CONF: u32 = 0x20000000;
pub const NGX_HTTP_LIF_CONF: u32 = 0x40000000;
pub const NGX_HTTP_LMT_CONF: u32 = 0x80000000;

pub const NGX_HTTP_POST_READ_PHASE: usize = 0;
pub const NGX_HTTP_SERVER_REWRITE_PHASE: usize = 1;
pub const NGX_HTTP_FIND_CONFIG_PHASE: usize = 2;
pub const NGX_HTTP_REWRITE_PHASE: usize = 3;
pub const NGX_HTTP_POST_REWRITE_PHASE: usize = 4;
pub const NGX_HTTP_PREACCESS_PHASE: usize = 5;
pub const NGX_HTTP_ACCESS_PHASE: usize = 6;
pub const NGX_HTTP_POST_ACCESS_PHASE: usize = 7;
pub const NGX_HTTP_PRECONTENT_PHASE: usize = 8;
pub const NGX_HTTP_CONTENT_PHASE: usize = 9;
pub const NGX_HTTP_LOG_PHASE: usize = 10;

pub const NGX_HTTP_MAX_URI_CHANGES: u32 = 10;
pub const NGX_HTTP_MAX_SUBREQUESTS: u32 = 50;
pub const NGX_HTTP_LC_HEADER_LEN: usize = 32;
pub const NGX_HTTP_DISCARD_BUFFER_SIZE: usize = 4096;
pub const NGX_HTTP_LINGERING_BUFFER_SIZE: usize = 4096;

pub const NGX_HTTP_VERSION_9: u32 = 9;
pub const NGX_HTTP_VERSION_10: u32 = 1000;
pub const NGX_HTTP_VERSION_11: u32 = 1001;
pub const NGX_HTTP_VERSION_20: u32 = 2000;
pub const NGX_HTTP_VERSION_30: u32 = 3000;

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

pub const NGX_HTTP_CONNECTION_CLOSE: u32 = 1;
pub const NGX_HTTP_CONNECTION_KEEP_ALIVE: u32 = 2;

pub const NGX_HTTP_CLIENT_ERROR: i64 = 10;
pub const NGX_HTTP_PARSE_INVALID_METHOD: i64 = 10;
pub const NGX_HTTP_PARSE_INVALID_REQUEST: i64 = 11;
pub const NGX_HTTP_PARSE_INVALID_VERSION: i64 = 12;
pub const NGX_HTTP_PARSE_INVALID_09_METHOD: i64 = 13;
pub const NGX_HTTP_PARSE_INVALID_HEADER: i64 = 14;
pub const NGX_HTTP_PARSE_HEADER_DONE: i64 = 1;

pub const NGX_HTTP_SUBREQUEST_IN_MEMORY: u32 = 2;
pub const NGX_HTTP_SUBREQUEST_WAITED: u32 = 4;
pub const NGX_HTTP_SUBREQUEST_CLONE: u32 = 8;
pub const NGX_HTTP_SUBREQUEST_BACKGROUND: u32 = 16;

pub const NGX_HTTP_CONTINUE: i64 = 100;
pub const NGX_HTTP_SWITCHING_PROTOCOLS: i64 = 101;
pub const NGX_HTTP_PROCESSING: i64 = 102;
pub const NGX_HTTP_EARLY_HINTS: i64 = 103;
pub const NGX_HTTP_OK: i64 = 200;
pub const NGX_HTTP_CREATED: i64 = 201;
pub const NGX_HTTP_ACCEPTED: i64 = 202;
pub const NGX_HTTP_NO_CONTENT: i64 = 204;
pub const NGX_HTTP_PARTIAL_CONTENT: i64 = 206;
pub const NGX_HTTP_SPECIAL_RESPONSE: i64 = 300;
pub const NGX_HTTP_MOVED_PERMANENTLY: i64 = 301;
pub const NGX_HTTP_MOVED_TEMPORARILY: i64 = 302;
pub const NGX_HTTP_SEE_OTHER: i64 = 303;
pub const NGX_HTTP_NOT_MODIFIED: i64 = 304;
pub const NGX_HTTP_TEMPORARY_REDIRECT: i64 = 307;
pub const NGX_HTTP_PERMANENT_REDIRECT: i64 = 308;
pub const NGX_HTTP_BAD_REQUEST: i64 = 400;
pub const NGX_HTTP_UNAUTHORIZED: i64 = 401;
pub const NGX_HTTP_FORBIDDEN: i64 = 403;
pub const NGX_HTTP_NOT_FOUND: i64 = 404;
pub const NGX_HTTP_NOT_ALLOWED: i64 = 405;
pub const NGX_HTTP_PROXY_AUTH_REQUIRED: i64 = 407;
pub const NGX_HTTP_REQUEST_TIME_OUT: i64 = 408;
pub const NGX_HTTP_CONFLICT: i64 = 409;
pub const NGX_HTTP_LENGTH_REQUIRED: i64 = 411;
pub const NGX_HTTP_PRECONDITION_FAILED: i64 = 412;
pub const NGX_HTTP_REQUEST_ENTITY_TOO_LARGE: i64 = 413;
pub const NGX_HTTP_REQUEST_URI_TOO_LARGE: i64 = 414;
pub const NGX_HTTP_UNSUPPORTED_MEDIA_TYPE: i64 = 415;
pub const NGX_HTTP_RANGE_NOT_SATISFIABLE: i64 = 416;
pub const NGX_HTTP_MISDIRECTED_REQUEST: i64 = 421;
pub const NGX_HTTP_TOO_MANY_REQUESTS: i64 = 429;
pub const NGX_HTTP_CLOSE: i64 = 444;
pub const NGX_HTTP_NGINX_CODES: i64 = 494;
pub const NGX_HTTP_REQUEST_HEADER_TOO_LARGE: i64 = 494;
pub const NGX_HTTPS_CERT_ERROR: i64 = 495;
pub const NGX_HTTPS_NO_CERT: i64 = 496;
pub const NGX_HTTP_TO_HTTPS: i64 = 497;
pub const NGX_HTTP_CLIENT_CLOSED_REQUEST: i64 = 499;
pub const NGX_HTTP_INTERNAL_SERVER_ERROR: i64 = 500;
pub const NGX_HTTP_NOT_IMPLEMENTED: i64 = 501;
pub const NGX_HTTP_BAD_GATEWAY: i64 = 502;
pub const NGX_HTTP_SERVICE_UNAVAILABLE: i64 = 503;
pub const NGX_HTTP_GATEWAY_TIME_OUT: i64 = 504;
pub const NGX_HTTP_VERSION_NOT_SUPPORTED: i64 = 505;
pub const NGX_HTTP_INSUFFICIENT_STORAGE: i64 = 507;

pub const NGX_HTTP_LOWLEVEL_BUFFERED: u32 = 0xf0;
pub const NGX_HTTP_WRITE_BUFFERED: u32 = 0x10;
pub const NGX_HTTP_GZIP_BUFFERED: u32 = 0x20;
pub const NGX_HTTP_SSI_BUFFERED: u32 = 0x01;
pub const NGX_HTTP_SUB_BUFFERED: u32 = 0x02;
pub const NGX_HTTP_COPY_BUFFERED: u32 = 0x04;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T>>>;

// --- http module definition (ngx_http_module_t) ---

pub type HttpConfCreate = fn(&mut Conf) -> Rc<dyn Any>;
pub type HttpConfInit = fn(&mut Conf, &Rc<dyn Any>) -> ConfResult;
pub type HttpConfMerge = fn(&mut Conf, &Rc<dyn Any>, &Rc<dyn Any>) -> ConfResult;
pub type HttpConfHook = fn(&mut Conf) -> ConfResult;

#[derive(Default)]
pub struct HttpModuleDef {
    pub preconfiguration: Option<HttpConfHook>,
    pub postconfiguration: Option<HttpConfHook>,
    pub create_main_conf: Option<HttpConfCreate>,
    pub init_main_conf: Option<HttpConfInit>,
    pub create_srv_conf: Option<HttpConfCreate>,
    pub merge_srv_conf: Option<HttpConfMerge>,
    pub create_loc_conf: Option<HttpConfCreate>,
    pub merge_loc_conf: Option<HttpConfMerge>,
}

/// Build an http ModuleDef.
pub fn http_module_def(name: &'static str, def: HttpModuleDef, commands: Vec<Command>) -> ModuleDef {
    let mut m = ModuleDef::new(name, NGX_HTTP_MODULE);
    m.ctx = Some(Rc::new(def));
    m.commands = commands;
    m
}

// --- per-module ctx index registry ---

thread_local! {
    static MODULE_INDEX: RefCell<std::collections::HashMap<&'static str, usize>> = RefCell::new(std::collections::HashMap::new());
    static HTTP_MAX_MODULE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// ctx_index of an http module by name (set up when the module list is built).
pub fn module_index(name: &'static str) -> usize {
    MODULE_INDEX.with(|m| *m.borrow().get(name).unwrap_or_else(|| panic!("unknown http module {}", name)))
}

pub fn http_max_module() -> usize {
    HTTP_MAX_MODULE.with(|m| m.get())
}

/// Register ctx indexes for all http modules in `modules`.
pub fn init_module_indexes(modules: &[Module]) {
    MODULE_INDEX.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        for md in modules.iter().filter(|m| m.def.ty == NGX_HTTP_MODULE) {
            m.insert(md.def.name, md.ctx_index);
        }
    });
    HTTP_MAX_MODULE.with(|m| m.set(count_modules(modules, NGX_HTTP_MODULE)));
}

/// Declares a `pub fn ctx_index() -> usize` for a module name.
#[macro_export]
macro_rules! http_module_index {
    ($name:expr) => {
        thread_local! {
            static CTX_INDEX: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
        }
        pub fn ctx_index() -> usize {
            CTX_INDEX.with(|c| {
                let v = c.get();
                if v != usize::MAX {
                    return v;
                }
                let i = $crate::module_index($name);
                c.set(i);
                i
            })
        }
    };
}

// --- filter chains ---

pub type HeaderFilter = Rc<dyn Fn(R) -> BoxFut<i64>>;
pub type BodyFilter = Rc<dyn Fn(R, ngx_core::buf::Chain) -> BoxFut<i64>>;
pub type RequestBodyFilter = Rc<dyn Fn(R, ngx_core::buf::Chain) -> BoxFut<i64>>;

thread_local! {
    static TOP_HEADER_FILTER: RefCell<Option<HeaderFilter>> = const { RefCell::new(None) };
    static TOP_BODY_FILTER: RefCell<Option<BodyFilter>> = const { RefCell::new(None) };
    static TOP_REQUEST_BODY_FILTER: RefCell<Option<RequestBodyFilter>> = const { RefCell::new(None) };
}

pub fn top_header_filter() -> HeaderFilter {
    TOP_HEADER_FILTER.with(|t| t.borrow().clone().expect("header filter chain not initialized"))
}

pub fn set_top_header_filter(f: HeaderFilter) {
    TOP_HEADER_FILTER.with(|t| *t.borrow_mut() = Some(f));
}

pub fn top_body_filter() -> BodyFilter {
    TOP_BODY_FILTER.with(|t| t.borrow().clone().expect("body filter chain not initialized"))
}

pub fn set_top_body_filter(f: BodyFilter) {
    TOP_BODY_FILTER.with(|t| *t.borrow_mut() = Some(f));
}

pub fn top_request_body_filter() -> RequestBodyFilter {
    TOP_REQUEST_BODY_FILTER.with(|t| t.borrow().clone().expect("request body filter chain not initialized"))
}

pub fn set_top_request_body_filter(f: RequestBodyFilter) {
    TOP_REQUEST_BODY_FILTER.with(|t| *t.borrow_mut() = Some(f));
}

/// Install a header filter wrapping the current top.
pub fn install_header_filter<F, Fut>(f: F)
where
    F: Fn(R, HeaderFilter) -> Fut + 'static,
    Fut: Future<Output = i64> + 'static,
{
    let next = top_header_filter();
    let f = Rc::new(f);
    set_top_header_filter(Rc::new(move |r| {
        let f = f.clone();
        let next = next.clone();
        Box::pin(async move { f(r, next).await })
    }));
}

/// Install a body filter wrapping the current top.
pub fn install_body_filter<F, Fut>(f: F)
where
    F: Fn(R, ngx_core::buf::Chain, BodyFilter) -> Fut + 'static,
    Fut: Future<Output = i64> + 'static,
{
    let next = top_body_filter();
    let f = Rc::new(f);
    set_top_body_filter(Rc::new(move |r, chain| {
        let f = f.clone();
        let next = next.clone();
        Box::pin(async move { f(r, chain, next).await })
    }));
}

pub fn install_request_body_filter<F, Fut>(f: F)
where
    F: Fn(R, ngx_core::buf::Chain, RequestBodyFilter) -> Fut + 'static,
    Fut: Future<Output = i64> + 'static,
{
    let next = top_request_body_filter();
    let f = Rc::new(f);
    set_top_request_body_filter(Rc::new(move |r, chain| {
        let f = f.clone();
        let next = next.clone();
        Box::pin(async move { f(r, chain, next).await })
    }));
}

// --- http conf ctx helpers ---

/// The http {} main context slots (main_conf) etc live in ConfCtx (main/srv/loc).
pub fn http_conf_ctx(cf: &Conf) -> ConfCtx {
    cf.ctx.clone()
}

/// Get module conf from a ConfCtx level as Rc<RefCell<T>>.
pub fn get_conf<T: 'static>(ctx: &ConfCtx, level: ConfLevel, idx: usize) -> Rc<RefCell<T>> {
    conf_rc::<T>(&ctx.get(level, idx).expect("http conf slot missing"))
}

pub fn get_main_conf<T: 'static>(cf: &Conf, idx: usize) -> Rc<RefCell<T>> {
    get_conf::<T>(&cf.ctx, ConfLevel::Main, idx)
}

pub fn get_srv_conf<T: 'static>(cf: &Conf, idx: usize) -> Rc<RefCell<T>> {
    get_conf::<T>(&cf.ctx, ConfLevel::Srv, idx)
}

pub fn get_loc_conf<T: 'static>(cf: &Conf, idx: usize) -> Rc<RefCell<T>> {
    get_conf::<T>(&cf.ctx, ConfLevel::Loc, idx)
}

/// Fetch a module's main conf from the cycle (runtime).
pub fn cycle_main_conf<T: 'static>(cycle: &ngx_core::cycle::Cycle, idx: usize) -> Option<Rc<RefCell<T>>> {
    let m = find_module(&cycle.modules, "ngx_http_module")?;
    let holder = cycle.conf_ctx[m.index].as_ref()?;
    let ctx = holder.downcast_ref::<ConfCtx>()?;
    Some(get_conf::<T>(ctx, ConfLevel::Main, idx))
}

// --- the http {} block (ngx_http_block) ---

fn http_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let idx = cf.module_index;
    if cf.cycle.conf_ctx[idx].is_some() {
        return Err(msg("is duplicate"));
    }
    let modules = cf.cycle.modules.clone();
    init_module_indexes(&modules);
    let n = http_max_module();

    let ctx = ConfCtx { main: Some(new_slots(n)), srv: Some(new_slots(n)), loc: Some(new_slots(n)) };
    cf.cycle.conf_ctx[idx] = Some(Rc::new(ctx.clone()));

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx.clone());
    let saved_mt = cf.module_type;
    let saved_ct = cf.cmd_type;

    let rv = http_block_inner(cf, &modules, &ctx);

    cf.ctx = saved_ctx;
    cf.module_type = saved_mt;
    cf.cmd_type = saved_ct;
    rv
}

fn http_modules(modules: &Rc<Vec<Module>>) -> Vec<(usize, &'static HttpModuleDef)> {
    // SAFETY: modules live for the whole process (Rc held by cycle); we hand out
    // references tied to the Rc by leaking a clone once.
    let mut v = Vec::new();
    for m in modules.iter().filter(|m| m.def.ty == NGX_HTTP_MODULE) {
        if let Some(d) = m.ctx::<HttpModuleDef>() {
            let d: &'static HttpModuleDef = unsafe { &*(d as *const HttpModuleDef) };
            v.push((m.ctx_index, d));
        }
    }
    v
}

fn http_block_inner(cf: &mut Conf, modules: &Rc<Vec<Module>>, ctx: &ConfCtx) -> ConfResult {
    let mods = http_modules(modules);
    // create main/srv/loc confs
    for (mi, d) in mods.iter() {
        if let Some(f) = d.create_main_conf {
            let c = f(cf);
            ctx.main.as_ref().unwrap().borrow_mut()[*mi] = Some(c);
        }
        if let Some(f) = d.create_srv_conf {
            let c = f(cf);
            ctx.srv.as_ref().unwrap().borrow_mut()[*mi] = Some(c);
        }
        if let Some(f) = d.create_loc_conf {
            let c = f(cf);
            ctx.loc.as_ref().unwrap().borrow_mut()[*mi] = Some(c);
        }
    }

    for (_, d) in mods.iter() {
        if let Some(f) = d.preconfiguration {
            f(cf)?;
        }
    }

    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.parse_block()?;

    let cmcf = core::main_conf_from_ctx(ctx);

    for (mi, d) in mods.iter() {
        if let Some(f) = d.init_main_conf {
            let c = ctx.main.as_ref().unwrap().borrow()[*mi].clone().expect("main conf");
            f(cf, &c)?;
        }
        merge_servers(cf, &cmcf, d, *mi)?;
    }

    // create location trees
    let servers = cmcf.borrow().servers.clone();
    for cscf in servers.iter() {
        let clcf = core::loc_conf_from_ctx(&cscf.borrow().ctx);
        core::init_locations(cf, Some(cscf), &clcf)?;
        core::init_static_location_trees(cf, &clcf)?;
    }

    core::init_phases(cf, &cmcf)?;
    core::init_headers_in_hash(cf, &cmcf)?;

    for (_, d) in mods.iter() {
        if let Some(f) = d.postconfiguration {
            f(cf)?;
        }
    }

    variables::init_vars(cf)?;

    core::init_phase_handlers(cf, &cmcf)?;

    core::optimize_servers(cf, &cmcf)?;

    Ok(())
}

fn merge_servers(cf: &mut Conf, cmcf: &Rc<RefCell<core::CoreMainConf>>, d: &HttpModuleDef, mi: usize) -> ConfResult {
    let servers = cmcf.borrow().servers.clone();
    let saved = cf.ctx.clone();
    let mut rv = Ok(());
    for cscf in servers.iter() {
        let sctx = cscf.borrow().ctx.clone();
        cf.ctx.srv = sctx.srv.clone();
        if let Some(f) = d.merge_srv_conf {
            let prev = saved.srv.as_ref().unwrap().borrow()[mi].clone().expect("srv conf");
            let conf = sctx.srv.as_ref().unwrap().borrow()[mi].clone().expect("srv conf");
            rv = f(cf, &prev, &conf);
            if rv.is_err() {
                break;
            }
        }
        if let Some(f) = d.merge_loc_conf {
            cf.ctx.loc = sctx.loc.clone();
            let prev = saved.loc.as_ref().unwrap().borrow()[mi].clone().expect("loc conf");
            let conf = sctx.loc.as_ref().unwrap().borrow()[mi].clone().expect("loc conf");
            rv = f(cf, &prev, &conf);
            if rv.is_err() {
                break;
            }
            let clcf = core::loc_conf_from_ctx(&sctx);
            let locations = std::mem::take(&mut clcf.borrow_mut().locations);
            rv = merge_locations(cf, &locations, sctx.loc.as_ref().unwrap(), f, mi);
            clcf.borrow_mut().locations = locations;
            if rv.is_err() {
                break;
            }
        }
    }
    cf.ctx = saved;
    rv
}

fn merge_locations(cf: &mut Conf, locations: &[core::LocationQueue], loc_conf: &Rc<ConfSlots>, f: HttpConfMerge, mi: usize) -> ConfResult {
    let saved = cf.ctx.clone();
    for lq in locations {
        let clcf = lq.clcf();
        let lctx = clcf.borrow().loc_conf.clone().expect("location loc_conf");
        cf.ctx.loc = Some(lctx.clone());
        let prev = loc_conf.borrow()[mi].clone().expect("loc conf");
        let conf = lctx.borrow()[mi].clone().expect("loc conf");
        f(cf, &prev, &conf)?;
        let sub = std::mem::take(&mut clcf.borrow_mut().locations);
        let r = merge_locations(cf, &sub, &lctx, f, mi);
        clcf.borrow_mut().locations = sub;
        r?;
    }
    cf.ctx = saved;
    Ok(())
}

pub fn http_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_http_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "http", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("http", NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, http_block)];
    m
}

/// All http modules in nginx order (nginx-c/objs/ngx_modules.c).
pub fn modules() -> Vec<ModuleDef> {
    vec![
        http_module(),
        core::core_module(),
        log::log_module(),
        stubs::upstream_module(),
        stubs::v2_module(),
        stubs::v3_module(),
        static_module::static_module(),
        stubs::gzip_static_module(),
        stubs::dav_module(),
        stubs::autoindex_module(),
        index::index_module(),
        stubs::random_index_module(),
        stubs::mirror_module(),
        try_files::try_files_module(),
        auth_request::auth_request_module(),
        auth_basic::auth_basic_module(),
        access::access_module(),
        stubs::limit_conn_module(),
        stubs::limit_req_module(),
        realip::realip_module(),
        stubs::json_module(),
        stubs::geo_module(),
        stubs::geoip_module(),
        stubs::map_module(),
        stubs::split_clients_module(),
        stubs::referer_module(),
        rewrite::rewrite_module(),
        stubs::ssl_module(),
        stubs::proxy_module(),
        stubs::fastcgi_module(),
        stubs::uwsgi_module(),
        stubs::scgi_module(),
        stubs::grpc_module(),
        stubs::proxy_v2_module(),
        stubs::tunnel_module(),
        stubs::perl_module(),
        stubs::memcached_module(),
        stubs::empty_gif_module(),
        stubs::browser_module(),
        stubs::secure_link_module(),
        stubs::degradation_module(),
        flv::flv_module(),
        mp4::mp4_module(),
        stubs::upstream_hash_module(),
        stubs::upstream_ip_hash_module(),
        stubs::upstream_least_conn_module(),
        stubs::upstream_least_time_module(),
        stubs::upstream_random_module(),
        stubs::upstream_keepalive_module(),
        stubs::upstream_zone_module(),
        stubs::upstream_sticky_module(),
        stub_status::stub_status_module(),
        write_filter::write_filter_module(),
        header_filter::header_filter_module(),
        chunked_filter::chunked_filter_module(),
        stubs::v2_filter_module(),
        stubs::v3_filter_module(),
        stubs::range_header_filter_module(),
        stubs::gzip_filter_module(),
        postpone_filter::postpone_filter_module(),
        stubs::ssi_filter_module(),
        stubs::charset_filter_module(),
        stubs::xslt_filter_module(),
        stubs::image_filter_module(),
        stubs::sub_filter_module(),
        stubs::addition_filter_module(),
        stubs::gunzip_filter_module(),
        stubs::userid_filter_module(),
        headers_filter::headers_filter_module(),
        copy_filter::copy_filter_module(),
        stubs::range_body_filter_module(),
        not_modified_filter::not_modified_filter_module(),
        stubs::slice_filter_module(),
    ]
}

/// Log an http-level configuration error helper.
pub fn conf_error(cf: &Conf, args: std::fmt::Arguments<'_>) -> ConfError {
    cf.log_error(NGX_LOG_EMERG, None, args);
    ConfError::Logged
}

pub fn dbg_str(s: &[u8]) -> String {
    B(s).to_string()
}

#[allow(dead_code)]
fn _log_use(log: &Log) {
    ngx_log_error!(NGX_LOG_DEBUG, log, None, "unused");
    let _ = NGX_OK;
}
