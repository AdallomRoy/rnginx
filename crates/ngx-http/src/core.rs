//! ngx_http_core_module: configuration side (structs, directives, merging,
//! location trees, listen/server optimisation). Runtime parts are in core_rt.rs.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::inet::*;
use ngx_core::listening::Listening;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::resolver::Resolver;
use ngx_core::string::{atoi, filename_cmp, eq_ignore_case, B};
use ngx_core::{cmd, cmd_fn, ngx_log_error, parse};

use crate::request::*;
use crate::script::*;
use crate::variables::HttpRegex;
use crate::*;

pub use crate::core_rt::*;

crate::http_module_index!("ngx_http_core_module");

pub const NGX_HTTP_SATISFY_ALL: u32 = 0;
pub const NGX_HTTP_SATISFY_ANY: u32 = 1;
pub const NGX_HTTP_LINGERING_OFF: u32 = 0;
pub const NGX_HTTP_LINGERING_ON: u32 = 1;
pub const NGX_HTTP_LINGERING_ALWAYS: u32 = 2;
pub const NGX_HTTP_IMS_OFF: u32 = 0;
pub const NGX_HTTP_IMS_EXACT: u32 = 1;
pub const NGX_HTTP_IMS_BEFORE: u32 = 2;
pub const NGX_HTTP_KEEPALIVE_DISABLE_NONE: u32 = 0x0002;
pub const NGX_HTTP_KEEPALIVE_DISABLE_MSIE6: u32 = 0x0004;
pub const NGX_HTTP_KEEPALIVE_DISABLE_SAFARI: u32 = 0x0008;
pub const NGX_HTTP_SERVER_TOKENS_OFF: u32 = 0;
pub const NGX_HTTP_SERVER_TOKENS_ON: u32 = 1;
pub const NGX_HTTP_SERVER_TOKENS_BUILD: u32 = 2;
pub const NGX_HTTP_REQUEST_BODY_FILE_OFF: u32 = 0;
pub const NGX_HTTP_REQUEST_BODY_FILE_ON: u32 = 1;
pub const NGX_HTTP_REQUEST_BODY_FILE_CLEAN: u32 = 2;
pub const NGX_HTTP_AIO_OFF: i64 = 0;
pub const NGX_HTTP_AIO_ON: i64 = 1;
pub const NGX_HTTP_AIO_THREADS: i64 = 2;
pub const NGX_HTTP_GZIP_PROXIED_OFF: u32 = 0x0002;
pub const NGX_HTTP_GZIP_PROXIED_EXPIRED: u32 = 0x0004;
pub const NGX_HTTP_GZIP_PROXIED_NO_CACHE: u32 = 0x0008;
pub const NGX_HTTP_GZIP_PROXIED_NO_STORE: u32 = 0x0010;
pub const NGX_HTTP_GZIP_PROXIED_PRIVATE: u32 = 0x0020;
pub const NGX_HTTP_GZIP_PROXIED_NO_LM: u32 = 0x0040;
pub const NGX_HTTP_GZIP_PROXIED_NO_ETAG: u32 = 0x0080;
pub const NGX_HTTP_GZIP_PROXIED_AUTH: u32 = 0x0100;
pub const NGX_HTTP_GZIP_PROXIED_ANY: u32 = 0x0200;
pub const NGX_DISABLE_SYMLINKS_OFF: u32 = 0;
pub const NGX_DISABLE_SYMLINKS_ON: u32 = 1;
pub const NGX_DISABLE_SYMLINKS_NOTOWNER: u32 = 2;
pub const NGX_OPEN_FILE_DIRECTIO_OFF: i64 = i64::MAX;
pub const NGX_LISTEN_BACKLOG: i32 = 511;
pub const NGX_CONF_BITMASK_SET: u32 = 1;

pub type HandlerFn = Rc<dyn Fn(R) -> BoxFut<i64>>;
pub type HeaderInFn = fn(&R, Header) -> i64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checker {
    Generic,
    Rewrite,
    FindConfig,
    PostRewrite,
    Access,
    PostAccess,
    Content,
}

#[derive(Clone)]
pub struct PhaseHandler {
    pub checker: Checker,
    pub handler: Option<HandlerFn>,
    pub next: usize,
}

#[derive(Default)]
pub struct PhaseEngine {
    pub handlers: Vec<PhaseHandler>,
    pub server_rewrite_index: usize,
    pub location_rewrite_index: usize,
}

#[derive(Default, Clone)]
pub struct Phase {
    pub handlers: Vec<HandlerFn>,
}

pub struct CoreMainConf {
    pub servers: Vec<Rc<RefCell<CoreSrvConf>>>,
    pub phase_engine: PhaseEngine,
    pub headers_in_hash: Option<Hash<HeaderInFn>>,
    pub variables_hash: Option<Hash<Rc<crate::variables::Variable>>>,
    pub variables: Vec<Rc<crate::variables::Variable>>,
    pub prefix_variables: Vec<Rc<crate::variables::Variable>>,
    pub ncaptures: usize,
    pub server_names_hash_max_size: Val<i64>,
    pub server_names_hash_bucket_size: Val<i64>,
    pub variables_hash_max_size: Val<i64>,
    pub variables_hash_bucket_size: Val<i64>,
    pub variables_keys: Option<HashKeysArrays<Rc<crate::variables::Variable>>>,
    pub ports: Vec<ConfPort>,
    pub phases: Vec<Phase>,
    pub log_handlers: Vec<Rc<dyn Fn(&R) -> i64>>,
}

pub struct ServerName {
    pub regex: Option<Rc<HttpRegex>>,
    pub server: Rc<RefCell<CoreSrvConf>>,
    pub name: Vec<u8>,
}

pub struct CoreSrvConf {
    pub server_names: Vec<ServerName>,
    pub ctx: ConfCtx,
    pub listen: bool,
    pub server_name: Vec<u8>,
    pub connection_pool_size: Val<usize>,
    pub request_pool_size: Val<usize>,
    pub client_header_timeout: Val<u64>,
    pub client_header_buffer_size: Val<usize>,
    pub large_client_header_buffers: Bufs,
    pub max_headers: Val<i64>,
    pub ignore_invalid_headers: Val<bool>,
    pub merge_slashes: Val<bool>,
    pub underscores_in_headers: Val<bool>,
    pub client_body_early_read: Val<Option<Rc<Vec<ComplexValue>>>>,
    pub allow_connect: bool,
    pub captures: bool,
    pub named_locations: Vec<Rc<RefCell<CoreLocConf>>>,
    pub file_name: Vec<u8>,
    pub line: usize,
    /// Weak self reference for ServerName entries.
    pub me: std::rc::Weak<RefCell<CoreSrvConf>>,
}

#[derive(Clone)]
pub struct ErrPage {
    pub status: i64,
    pub overwrite: i64,
    pub value: ComplexValue,
    pub args: Vec<u8>,
}

pub struct LocationQueue {
    pub exact: Option<Rc<RefCell<CoreLocConf>>>,
    pub inclusive: Option<Rc<RefCell<CoreLocConf>>>,
    pub name: Vec<u8>,
    pub file_name: Vec<u8>,
    pub line: usize,
    pub list: Vec<LocationQueue>,
}

impl LocationQueue {
    pub fn clcf(&self) -> Rc<RefCell<CoreLocConf>> {
        self.exact.clone().or_else(|| self.inclusive.clone()).expect("location")
    }
}

pub struct LocationTreeNode {
    pub left: Option<Box<LocationTreeNode>>,
    pub right: Option<Box<LocationTreeNode>>,
    pub tree: Option<Box<LocationTreeNode>>,
    pub exact: Option<Rc<RefCell<CoreLocConf>>>,
    pub inclusive: Option<Rc<RefCell<CoreLocConf>>>,
    pub auto_redirect: bool,
    pub name: Vec<u8>,
}

pub struct CoreLocConf {
    pub name: Vec<u8>,
    pub escaped_name: Vec<u8>,
    pub regex: Option<Rc<HttpRegex>>,
    pub predicate: usize,
    pub noname: bool,
    pub lmt_excpt: bool,
    pub named: bool,
    pub exact_match: bool,
    pub noregex: bool,
    pub auto_redirect: bool,
    pub alias: usize,
    pub root: Vec<u8>,
    pub root_set: bool,
    pub root_script: Option<Rc<ComplexValue>>,
    pub post_action: Vec<u8>,
    pub loc_conf: Option<Rc<ConfSlots>>,
    pub handler: Option<ContentHandler>,
    pub locations: Vec<LocationQueue>,
    pub static_locations: Option<Box<LocationTreeNode>>,
    pub regex_locations: Vec<Rc<RefCell<CoreLocConf>>>,
    pub predicate_locations: Vec<Rc<RefCell<CoreLocConf>>>,
    pub types: Option<Rc<RefCell<Vec<HashKey<Rc<Vec<u8>>>>>>>,
    pub types_hash: Option<Rc<Hash<Rc<Vec<u8>>>>>,
    pub default_type: Val<Vec<u8>>,
    pub client_max_body_size: Val<i64>,
    pub client_body_buffer_size: Val<usize>,
    pub client_body_timeout: Val<u64>,
    pub satisfy: Val<u32>,
    pub auth_delay: Val<u64>,
    pub if_modified_since: Val<u32>,
    pub max_ranges: Val<i64>,
    pub client_body_in_file_only: Val<u32>,
    pub client_body_in_single_buffer: Val<bool>,
    pub internal: Val<bool>,
    pub sendfile: Val<bool>,
    pub sendfile_max_chunk: Val<usize>,
    pub subrequest_output_buffer_size: Val<usize>,
    pub aio: Val<i64>,
    pub aio_write: Val<bool>,
    pub thread_pool: Val<Option<Vec<u8>>>,
    pub read_ahead: Val<usize>,
    pub directio: Val<i64>,
    pub directio_alignment: Val<i64>,
    pub tcp_nopush: Val<bool>,
    pub tcp_nodelay: Val<bool>,
    pub send_timeout: Val<u64>,
    pub send_lowat: Val<usize>,
    pub postpone_output: Val<usize>,
    pub limit_rate: Val<Option<Rc<ComplexValue>>>,
    pub limit_rate_after: Val<Option<Rc<ComplexValue>>>,
    pub keepalive_time: Val<u64>,
    pub keepalive_timeout: Val<u64>,
    pub keepalive_header: Val<i64>,
    pub keepalive_min_timeout: Val<u64>,
    pub keepalive_requests: Val<i64>,
    pub keepalive_disable: u32,
    pub lingering_close: Val<u32>,
    pub lingering_time: Val<u64>,
    pub lingering_timeout: Val<u64>,
    pub resolver: Option<Rc<Resolver>>,
    pub resolver_timeout: Val<u64>,
    pub client_body_temp_path: Val<Rc<PathConf>>,
    pub reset_timedout_connection: Val<bool>,
    pub absolute_redirect: Val<bool>,
    pub server_name_in_redirect: Val<bool>,
    pub port_in_redirect: Val<bool>,
    pub msie_padding: Val<bool>,
    pub msie_refresh: Val<bool>,
    pub log_not_found: Val<bool>,
    pub log_subrequest: Val<bool>,
    pub recursive_error_pages: Val<bool>,
    pub chunked_transfer_encoding: Val<bool>,
    pub etag: Val<bool>,
    pub server_tokens: Val<u32>,
    pub early_hints: Val<Option<Rc<Vec<ComplexValue>>>>,
    pub error_pages: Option<Rc<Vec<ErrPage>>>,
    pub error_log: Option<Rc<LogChain>>,
    pub open_file_cache: Val<Option<Rc<ngx_core::open_file_cache::OpenFileCache>>>,
    pub open_file_cache_valid: Val<i64>,
    pub open_file_cache_min_uses: Val<i64>,
    pub open_file_cache_errors: Val<bool>,
    pub open_file_cache_events: Val<bool>,
    pub gzip_vary: Val<bool>,
    pub gzip_http_version: Val<u32>,
    pub gzip_proxied: u32,
    pub gzip_disable: Val<Option<Rc<Vec<Rc<Regex>>>>>,
    pub gzip_disable_msie6: u8,
    pub gzip_disable_degradation: u8,
    pub disable_symlinks: Val<u32>,
    pub disable_symlinks_from: Val<Option<Rc<ComplexValue>>>,
    pub types_hash_max_size: Val<i64>,
    pub types_hash_bucket_size: Val<i64>,
    pub limit_except: u32,
    pub limit_except_loc_conf: Option<Rc<ConfSlots>>,
}

// --- listen / addresses -------------------------------------------------

#[derive(Clone)]
pub struct ListenOpt {
    pub sockaddr: SockAddr,
    pub addr_text: Vec<u8>,
    pub set: bool,
    pub default_server: bool,
    pub bind: bool,
    pub wildcard: bool,
    pub ssl: bool,
    pub http2: bool,
    pub quic: bool,
    pub proxy_protocol: bool,
    pub deferred_accept: bool,
    pub reuseport: bool,
    pub so_keepalive: u8,
    pub tcp_keepidle: i32,
    pub tcp_keepintvl: i32,
    pub tcp_keepcnt: i32,
    pub backlog: i32,
    pub rcvbuf: i32,
    pub sndbuf: i32,
    pub ty: i32,
    pub fastopen: i32,
    pub ipv6only: bool,
}

pub struct ConfAddr {
    pub opt: ListenOpt,
    pub protocols: u32,
    pub protocols_set: bool,
    pub protocols_changed: bool,
    pub hash: Option<Hash<Rc<RefCell<CoreSrvConf>>>>,
    pub wc_head: Option<HashWildcard<Rc<RefCell<CoreSrvConf>>>>,
    pub wc_tail: Option<HashWildcard<Rc<RefCell<CoreSrvConf>>>>,
    pub regex: Vec<ServerNameRef>,
    pub default_server: Rc<RefCell<CoreSrvConf>>,
    pub servers: Vec<Rc<RefCell<CoreSrvConf>>>,
}

#[derive(Clone)]
pub struct ServerNameRef {
    pub regex: Rc<HttpRegex>,
    pub server: Rc<RefCell<CoreSrvConf>>,
    pub name: Vec<u8>,
}

pub struct ConfPort {
    pub family: i32,
    pub ty: i32,
    pub port: u16,
    pub addrs: Vec<ConfAddr>,
}

pub struct VirtualNames {
    pub names: HashCombined<Rc<RefCell<CoreSrvConf>>>,
    pub regex: Vec<ServerNameRef>,
}

pub struct AddrConf {
    pub default_server: Rc<RefCell<CoreSrvConf>>,
    pub virtual_names: Option<Rc<VirtualNames>>,
    pub ssl: bool,
    pub http2: bool,
    pub quic: bool,
    pub proxy_protocol: bool,
}

pub struct HttpPort {
    pub naddrs: usize,
    /// (ip bytes, conf) in the order of ngx_http_port_t.addrs
    pub addrs: Vec<(Vec<u8>, Rc<AddrConf>)>,
}

// --- conf helpers -------------------------------------------------------

pub fn main_conf_from_ctx(ctx: &ConfCtx) -> Rc<RefCell<CoreMainConf>> {
    get_conf::<CoreMainConf>(ctx, ConfLevel::Main, ctx_index())
}

pub fn srv_conf_from_ctx(ctx: &ConfCtx) -> Rc<RefCell<CoreSrvConf>> {
    get_conf::<CoreSrvConf>(ctx, ConfLevel::Srv, ctx_index())
}

pub fn loc_conf_from_ctx(ctx: &ConfCtx) -> Rc<RefCell<CoreLocConf>> {
    get_conf::<CoreLocConf>(ctx, ConfLevel::Loc, ctx_index())
}

pub fn core_main_conf(cf: &Conf) -> Rc<RefCell<CoreMainConf>> {
    get_main_conf::<CoreMainConf>(cf, ctx_index())
}

pub fn core_srv_conf(cf: &Conf) -> Rc<RefCell<CoreSrvConf>> {
    get_srv_conf::<CoreSrvConf>(cf, ctx_index())
}

pub fn core_loc_conf(cf: &Conf) -> Rc<RefCell<CoreLocConf>> {
    get_loc_conf::<CoreLocConf>(cf, ctx_index())
}

fn clcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<CoreLocConf>> {
    conf_rc::<CoreLocConf>(conf.as_ref().expect("loc conf"))
}

fn cscf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<CoreSrvConf>> {
    conf_rc::<CoreSrvConf>(conf.as_ref().expect("srv conf"))
}

// --- create / init / merge -----------------------------------------------

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CoreMainConf {
        servers: Vec::new(),
        phase_engine: PhaseEngine::default(),
        headers_in_hash: None,
        variables_hash: None,
        variables: Vec::new(),
        prefix_variables: Vec::new(),
        ncaptures: 0,
        server_names_hash_max_size: Val::unset(),
        server_names_hash_bucket_size: Val::unset(),
        variables_hash_max_size: Val::unset(),
        variables_hash_bucket_size: Val::unset(),
        variables_keys: None,
        ports: Vec::new(),
        phases: vec![Phase::default(); NGX_HTTP_LOG_PHASE + 1],
        log_handlers: Vec::new(),
    })
}

fn init_main_conf(_cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let c = conf_cell::<CoreMainConf>(conf);
    let mut cmcf = c.borrow_mut();
    cmcf.server_names_hash_max_size.init(512);
    cmcf.server_names_hash_bucket_size.init(ngx_core::os::cacheline_size() as i64);
    let cl = ngx_core::os::cacheline_size() as i64;
    let v = *cmcf.server_names_hash_bucket_size;
    cmcf.server_names_hash_bucket_size = Val::set((v + cl - 1) / cl * cl);
    cmcf.variables_hash_max_size.init(1024);
    cmcf.variables_hash_bucket_size.init(64);
    let v = *cmcf.variables_hash_bucket_size;
    cmcf.variables_hash_bucket_size = Val::set((v + cl - 1) / cl * cl);
    if cmcf.ncaptures != 0 {
        cmcf.ncaptures = (cmcf.ncaptures + 1) * 3;
    }
    Ok(())
}

fn create_srv_conf(cf: &mut Conf) -> Rc<dyn Any> {
    let cscf = Rc::new(RefCell::new(CoreSrvConf {
        server_names: Vec::new(),
        ctx: ConfCtx::default(),
        listen: false,
        server_name: Vec::new(),
        connection_pool_size: Val::unset(),
        request_pool_size: Val::unset(),
        client_header_timeout: Val::unset(),
        client_header_buffer_size: Val::unset(),
        large_client_header_buffers: Bufs::default(),
        max_headers: Val::unset(),
        ignore_invalid_headers: Val::unset(),
        merge_slashes: Val::unset(),
        underscores_in_headers: Val::unset(),
        client_body_early_read: Val::unset(),
        allow_connect: false,
        captures: false,
        named_locations: Vec::new(),
        file_name: cf.conf_file_name(),
        line: cf.conf_line(),
        me: std::rc::Weak::new(),
    }));
    cscf.borrow_mut().me = Rc::downgrade(&cscf);
    cscf
}

fn merge_srv_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<CoreSrvConf>(prev).borrow();
    let cell = conf_cell::<CoreSrvConf>(conf);
    let mut conf = cell.borrow_mut();
    conf.connection_pool_size.merge(&prev.connection_pool_size, 64 * std::mem::size_of::<usize>());
    conf.request_pool_size.merge(&prev.request_pool_size, 4096);
    conf.client_header_timeout.merge(&prev.client_header_timeout, 60000);
    conf.client_header_buffer_size.merge(&prev.client_header_buffer_size, 1024);
    conf.large_client_header_buffers.merge(&prev.large_client_header_buffers, 4, 8192);
    if conf.large_client_header_buffers.size < *conf.connection_pool_size {
        return Err(cf.emerg(format_args!("the \"large_client_header_buffers\" size must be equal to or greater than \"connection_pool_size\"")));
    }
    conf.max_headers.merge(&prev.max_headers, 1000);
    conf.ignore_invalid_headers.merge(&prev.ignore_invalid_headers, true);
    conf.merge_slashes.merge(&prev.merge_slashes, true);
    conf.underscores_in_headers.merge(&prev.underscores_in_headers, false);
    conf.client_body_early_read.merge(&prev.client_body_early_read, None);
    if conf.server_names.is_empty() {
        let me = conf.me.upgrade().unwrap();
        conf.server_names.push(ServerName { regex: None, server: me, name: Vec::new() });
    }
    let sn = &conf.server_names[0];
    let mut name = sn.name.clone();
    if sn.regex.is_some() {
        name.insert(0, b'~');
    } else if name.first() == Some(&b'.') {
        name.remove(0);
    }
    conf.server_name = name;
    Ok(())
}

pub fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CoreLocConf {
        name: Vec::new(),
        escaped_name: Vec::new(),
        regex: None,
        predicate: 0,
        noname: false,
        lmt_excpt: false,
        named: false,
        exact_match: false,
        noregex: false,
        auto_redirect: false,
        alias: 0,
        root: Vec::new(),
        root_set: false,
        root_script: None,
        post_action: Vec::new(),
        loc_conf: None,
        handler: None,
        locations: Vec::new(),
        static_locations: None,
        regex_locations: Vec::new(),
        predicate_locations: Vec::new(),
        types: None,
        types_hash: None,
        default_type: Val::unset(),
        client_max_body_size: Val::unset(),
        client_body_buffer_size: Val::unset(),
        client_body_timeout: Val::unset(),
        satisfy: Val::unset(),
        auth_delay: Val::unset(),
        if_modified_since: Val::unset(),
        max_ranges: Val::unset(),
        client_body_in_file_only: Val::unset(),
        client_body_in_single_buffer: Val::unset(),
        internal: Val::unset(),
        sendfile: Val::unset(),
        sendfile_max_chunk: Val::unset(),
        subrequest_output_buffer_size: Val::unset(),
        aio: Val::unset(),
        aio_write: Val::unset(),
        thread_pool: Val::unset(),
        read_ahead: Val::unset(),
        directio: Val::unset(),
        directio_alignment: Val::unset(),
        tcp_nopush: Val::unset(),
        tcp_nodelay: Val::unset(),
        send_timeout: Val::unset(),
        send_lowat: Val::unset(),
        postpone_output: Val::unset(),
        limit_rate: Val::unset(),
        limit_rate_after: Val::unset(),
        keepalive_time: Val::unset(),
        keepalive_timeout: Val::unset(),
        keepalive_header: Val::unset(),
        keepalive_min_timeout: Val::unset(),
        keepalive_requests: Val::unset(),
        keepalive_disable: 0,
        lingering_close: Val::unset(),
        lingering_time: Val::unset(),
        lingering_timeout: Val::unset(),
        resolver: None,
        resolver_timeout: Val::unset(),
        client_body_temp_path: Val::unset(),
        reset_timedout_connection: Val::unset(),
        absolute_redirect: Val::unset(),
        server_name_in_redirect: Val::unset(),
        port_in_redirect: Val::unset(),
        msie_padding: Val::unset(),
        msie_refresh: Val::unset(),
        log_not_found: Val::unset(),
        log_subrequest: Val::unset(),
        recursive_error_pages: Val::unset(),
        chunked_transfer_encoding: Val::unset(),
        etag: Val::unset(),
        server_tokens: Val::unset(),
        early_hints: Val::unset(),
        error_pages: None,
        error_log: None,
        open_file_cache: Val::unset(),
        open_file_cache_valid: Val::unset(),
        open_file_cache_min_uses: Val::unset(),
        open_file_cache_errors: Val::unset(),
        open_file_cache_events: Val::unset(),
        gzip_vary: Val::unset(),
        gzip_http_version: Val::unset(),
        gzip_proxied: 0,
        gzip_disable: Val::unset(),
        gzip_disable_msie6: 3,
        gzip_disable_degradation: 3,
        disable_symlinks: Val::unset(),
        disable_symlinks_from: Val::unset(),
        types_hash_max_size: Val::unset(),
        types_hash_bucket_size: Val::unset(),
        limit_except: 0,
        limit_except_loc_conf: None,
    })
}

pub static DEFAULT_TYPES: &[(&str, &str)] = &[
    ("html", "text/html"),
    ("gif", "image/gif"),
    ("jpg", "image/jpeg"),
    ("js", "application/javascript"),
    ("atom", "application/atom+xml"),
    ("rss", "application/rss+xml"),
];

fn build_types_hash(cf: &Conf, types: &[HashKey<Rc<Vec<u8>>>], max_size: i64, bucket_size: i64) -> Result<Hash<Rc<Vec<u8>>>, ConfError> {
    let hinit = HashInit { name: "types_hash", max_size: max_size as usize, bucket_size: bucket_size as usize, log: &cf.log };
    let names: Vec<HashKey<Rc<Vec<u8>>>> = types.iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
    Hash::init(&hinit, names).map_err(|e| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    })
}

fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let prev_cell = conf_cell::<CoreLocConf>(prev);
    let cell = conf_cell::<CoreLocConf>(conf);

    if !cell.borrow().root_set {
        let p = prev_cell.borrow();
        let mut c = cell.borrow_mut();
        c.alias = p.alias;
        c.root = p.root.clone();
        c.root_script = p.root_script.clone();
        if !p.root_set {
            c.root = cf.cycle.full_name(b"html", false);
        }
    }
    {
        let p = prev_cell.borrow();
        let mut c = cell.borrow_mut();
        if c.post_action.is_empty() {
            c.post_action = p.post_action.clone();
        }
        c.types_hash_max_size.merge(&p.types_hash_max_size, 1024);
        c.types_hash_bucket_size.merge(&p.types_hash_bucket_size, 64);
        let cl = ngx_core::os::cacheline_size() as i64;
        let v = *c.types_hash_bucket_size;
        c.types_hash_bucket_size = Val::set((v + cl - 1) / cl * cl);
    }

    // build prev types hash if needed
    let (pmax, pbucket) = {
        let c = cell.borrow();
        (*c.types_hash_max_size, *c.types_hash_bucket_size)
    };
    let prev_types = prev_cell.borrow().types.clone();
    if let Some(pt) = &prev_types {
        if prev_cell.borrow().types_hash.is_none() {
            let h = build_types_hash(cf, &pt.borrow(), pmax, pbucket)?;
            prev_cell.borrow_mut().types_hash = Some(Rc::new(h));
        }
    }
    {
        let p = prev_cell.borrow();
        let mut c = cell.borrow_mut();
        if c.types.is_none() {
            c.types = p.types.clone();
            c.types_hash = p.types_hash.clone();
        }
        if c.types.is_none() {
            let v: Vec<HashKey<Rc<Vec<u8>>>> = DEFAULT_TYPES
                .iter()
                .map(|(k, v)| HashKey { key: k.as_bytes().to_vec(), key_hash: hash_key_lc(k.as_bytes()), value: Rc::new(v.as_bytes().to_vec()) })
                .collect();
            c.types = Some(Rc::new(RefCell::new(v)));
        }
    }
    if cell.borrow().types_hash.is_none() {
        let types = cell.borrow().types.clone().unwrap();
        let h = build_types_hash(cf, &types.borrow(), pmax, pbucket)?;
        cell.borrow_mut().types_hash = Some(Rc::new(h));
    }

    let p = prev_cell.borrow();
    let mut c = cell.borrow_mut();
    if c.error_log.is_none() {
        c.error_log = Some(p.error_log.clone().unwrap_or_else(|| cf.cycle.new_log.clone()));
    }
    if c.error_pages.is_none() && p.error_pages.is_some() {
        c.error_pages = p.error_pages.clone();
    }
    c.default_type.merge(&p.default_type, b"text/plain".to_vec());
    c.client_max_body_size.merge(&p.client_max_body_size, 1024 * 1024);
    c.client_body_buffer_size.merge(&p.client_body_buffer_size, 2 * ngx_core::os::pagesize());
    c.client_body_timeout.merge(&p.client_body_timeout, 60000);
    if c.keepalive_disable == 0 {
        c.keepalive_disable = if p.keepalive_disable != 0 { p.keepalive_disable } else { NGX_CONF_BITMASK_SET | NGX_HTTP_KEEPALIVE_DISABLE_MSIE6 };
    }
    c.satisfy.merge(&p.satisfy, NGX_HTTP_SATISFY_ALL);
    c.auth_delay.merge(&p.auth_delay, 0);
    c.if_modified_since.merge(&p.if_modified_since, NGX_HTTP_IMS_EXACT);
    c.max_ranges.merge(&p.max_ranges, i32::MAX as i64);
    c.client_body_in_file_only.merge(&p.client_body_in_file_only, NGX_HTTP_REQUEST_BODY_FILE_OFF);
    c.client_body_in_single_buffer.merge(&p.client_body_in_single_buffer, false);
    c.internal.merge(&p.internal, false);
    c.sendfile.merge(&p.sendfile, false);
    c.sendfile_max_chunk.merge(&p.sendfile_max_chunk, 2 * 1024 * 1024);
    c.subrequest_output_buffer_size.merge(&p.subrequest_output_buffer_size, ngx_core::os::pagesize());
    c.aio.merge(&p.aio, NGX_HTTP_AIO_OFF);
    c.aio_write.merge(&p.aio_write, false);
    c.thread_pool.merge(&p.thread_pool, None);
    c.read_ahead.merge(&p.read_ahead, 0);
    c.directio.merge(&p.directio, NGX_OPEN_FILE_DIRECTIO_OFF);
    c.directio_alignment.merge(&p.directio_alignment, 512);
    c.tcp_nopush.merge(&p.tcp_nopush, false);
    c.tcp_nodelay.merge(&p.tcp_nodelay, true);
    c.send_timeout.merge(&p.send_timeout, 60000);
    c.send_lowat.merge(&p.send_lowat, 0);
    c.postpone_output.merge(&p.postpone_output, 1460);
    c.limit_rate.merge(&p.limit_rate, None);
    c.limit_rate_after.merge(&p.limit_rate_after, None);
    c.keepalive_time.merge(&p.keepalive_time, 3600000);
    c.keepalive_timeout.merge(&p.keepalive_timeout, 75000);
    c.keepalive_header.merge(&p.keepalive_header, 0);
    c.keepalive_min_timeout.merge(&p.keepalive_min_timeout, 0);
    c.keepalive_requests.merge(&p.keepalive_requests, 1000);
    c.lingering_close.merge(&p.lingering_close, NGX_HTTP_LINGERING_ON);
    c.lingering_time.merge(&p.lingering_time, 30000);
    c.lingering_timeout.merge(&p.lingering_timeout, 5000);
    c.resolver_timeout.merge(&p.resolver_timeout, 30000);
    if c.resolver.is_none() {
        c.resolver = Some(p.resolver.clone().unwrap_or_else(Resolver::empty));
    }
    drop(p);
    drop(c);
    {
        let mut c = cell.borrow_mut();
        let p = prev_cell.borrow();
        let mut slot = std::mem::take(&mut c.client_body_temp_path);
        let prev_path = p.client_body_temp_path.clone();
        drop(p);
        drop(c);
        merge_path_value(cf, &mut slot, &prev_path, ngx_core::NGX_HTTP_CLIENT_TEMP_PATH, [0, 0, 0])?;
        cell.borrow_mut().client_body_temp_path = slot;
    }
    let p = prev_cell.borrow();
    let mut c = cell.borrow_mut();
    c.reset_timedout_connection.merge(&p.reset_timedout_connection, false);
    c.absolute_redirect.merge(&p.absolute_redirect, true);
    c.server_name_in_redirect.merge(&p.server_name_in_redirect, false);
    c.port_in_redirect.merge(&p.port_in_redirect, true);
    c.msie_padding.merge(&p.msie_padding, true);
    c.msie_refresh.merge(&p.msie_refresh, false);
    c.log_not_found.merge(&p.log_not_found, true);
    c.log_subrequest.merge(&p.log_subrequest, false);
    c.recursive_error_pages.merge(&p.recursive_error_pages, false);
    c.chunked_transfer_encoding.merge(&p.chunked_transfer_encoding, true);
    c.etag.merge(&p.etag, true);
    c.server_tokens.merge(&p.server_tokens, NGX_HTTP_SERVER_TOKENS_ON);
    c.early_hints.merge(&p.early_hints, None);
    c.open_file_cache.merge(&p.open_file_cache, None);
    c.open_file_cache_valid.merge(&p.open_file_cache_valid, 60);
    c.open_file_cache_min_uses.merge(&p.open_file_cache_min_uses, 1);
    c.open_file_cache_errors.merge(&p.open_file_cache_errors, false);
    c.open_file_cache_events.merge(&p.open_file_cache_events, false);
    c.gzip_vary.merge(&p.gzip_vary, false);
    c.gzip_http_version.merge(&p.gzip_http_version, NGX_HTTP_VERSION_11);
    if c.gzip_proxied == 0 {
        c.gzip_proxied = if p.gzip_proxied != 0 { p.gzip_proxied } else { NGX_CONF_BITMASK_SET | NGX_HTTP_GZIP_PROXIED_OFF };
    }
    c.gzip_disable.merge(&p.gzip_disable, None);
    if c.gzip_disable_msie6 == 3 {
        c.gzip_disable_msie6 = if p.gzip_disable_msie6 == 3 { 0 } else { p.gzip_disable_msie6 };
    }
    if c.gzip_disable_degradation == 3 {
        c.gzip_disable_degradation = if p.gzip_disable_degradation == 3 { 0 } else { p.gzip_disable_degradation };
    }
    c.disable_symlinks.merge(&p.disable_symlinks, NGX_DISABLE_SYMLINKS_OFF);
    c.disable_symlinks_from.merge(&p.disable_symlinks_from, None);
    Ok(())
}

// --- directives -----------------------------------------------------------

fn server_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let n = http_max_module();
    let pctx = cf.ctx.clone();
    let ctx = ConfCtx { main: pctx.main.clone(), srv: Some(new_slots(n)), loc: Some(new_slots(n)) };
    let modules = cf.cycle.modules.clone();
    for m in modules.iter().filter(|m| m.def.ty == NGX_HTTP_MODULE) {
        if let Some(d) = m.ctx::<HttpModuleDef>() {
            if let Some(f) = d.create_srv_conf {
                let c = f(cf);
                ctx.srv.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(c);
            }
            if let Some(f) = d.create_loc_conf {
                let c = f(cf);
                ctx.loc.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(c);
            }
        }
    }
    let cscf = srv_conf_from_ctx(&ctx);
    cscf.borrow_mut().ctx = ctx.clone();
    let cmcf = main_conf_from_ctx(&ctx);
    cmcf.borrow_mut().servers.push(cscf.clone());

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx);
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_SRV_CONF;
    let rv = cf.parse_block();
    cf.ctx = saved_ctx;
    cf.cmd_type = saved_ct;
    rv?;

    if !cscf.borrow().listen {
        let port = if ngx_core::os::geteuid() == 0 { 80 } else { 8000 };
        let sa = SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, port);
        let lsopt = ListenOpt {
            addr_text: sa.to_text(true),
            sockaddr: sa,
            set: false,
            default_server: false,
            bind: false,
            wildcard: true,
            ssl: false,
            http2: false,
            quic: false,
            proxy_protocol: false,
            deferred_accept: false,
            reuseport: false,
            so_keepalive: 0,
            tcp_keepidle: 0,
            tcp_keepintvl: 0,
            tcp_keepcnt: 0,
            backlog: NGX_LISTEN_BACKLOG,
            rcvbuf: -1,
            sndbuf: -1,
            ty: libc::SOCK_STREAM,
            fastopen: -1,
            ipv6only: false,
        };
        add_listen(cf, &cscf, lsopt)?;
    }
    Ok(())
}

fn regex_location(cf: &mut Conf, clcf: &mut CoreLocConf, regex: &[u8], caseless: bool) -> ConfResult {
    let options = if caseless { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };
    let re = crate::variables::regex_compile(cf, regex, options)?;
    clcf.regex = Some(re);
    clcf.name = regex.to_vec();
    Ok(())
}

fn location_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let n = http_max_module();
    let pctx = cf.ctx.clone();
    let ctx = ConfCtx { main: pctx.main.clone(), srv: pctx.srv.clone(), loc: Some(new_slots(n)) };
    let modules = cf.cycle.modules.clone();
    for m in modules.iter().filter(|m| m.def.ty == NGX_HTTP_MODULE) {
        if let Some(d) = m.ctx::<HttpModuleDef>() {
            if let Some(f) = d.create_loc_conf {
                let c = f(cf);
                ctx.loc.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(c);
            }
        }
    }
    let clcf = loc_conf_from_ctx(&ctx);
    clcf.borrow_mut().loc_conf = ctx.loc.clone();

    let args = cf.args.clone();
    {
        let mut c = clcf.borrow_mut();
        if args.len() == 3 {
            let m = &args[1];
            let name = &args[2];
            if m == b"=" {
                c.name = name.clone();
                c.exact_match = true;
            } else if m == b"^~" {
                c.name = name.clone();
                c.noregex = true;
            } else if m == b"~" {
                regex_location(cf, &mut c, name, false)?;
            } else if m == b"~*" {
                regex_location(cf, &mut c, name, true)?;
            } else {
                return Err(cf.emerg(format_args!("invalid location modifier \"{}\"", B(m))));
            }
        } else {
            let name = &args[1];
            if name.first() == Some(&b'=') {
                c.name = name[1..].to_vec();
                c.exact_match = true;
            } else if name.starts_with(b"^~") {
                c.name = name[2..].to_vec();
                c.noregex = true;
            } else if name.first() == Some(&b'~') {
                let rest = &name[1..];
                if rest.first() == Some(&b'*') {
                    regex_location(cf, &mut c, &rest[1..], true)?;
                } else {
                    regex_location(cf, &mut c, rest, false)?;
                }
            } else if name.first() == Some(&b'$') {
                c.name = name.clone();
                let index = crate::variables::get_variable_index(cf, &name[1..])?;
                c.predicate = index + 1;
            } else {
                c.name = name.clone();
                if name.first() == Some(&b'@') {
                    c.named = true;
                }
            }
        }
    }

    let pclcf = loc_conf_from_ctx(&pctx);
    if cf.cmd_type == NGX_HTTP_LOC_CONF {
        let c = clcf.borrow();
        let p = pclcf.borrow();
        if p.exact_match {
            return Err(cf.emerg(format_args!("location \"{}\" cannot be inside the exact location \"{}\"", B(&c.name), B(&p.name))));
        }
        if p.named {
            return Err(cf.emerg(format_args!("location \"{}\" cannot be inside the named location \"{}\"", B(&c.name), B(&p.name))));
        }
        if c.named {
            return Err(cf.emerg(format_args!("named location \"{}\" can be on the server level only", B(&c.name))));
        }
        let len = p.name.len();
        if c.predicate == 0 && p.predicate == 0 && c.regex.is_none() && filename_cmp(&c.name, &p.name, len) != 0 {
            return Err(cf.emerg(format_args!("location \"{}\" is outside location \"{}\"", B(&c.name), B(&p.name))));
        }
    }

    add_location(cf, &pclcf, &clcf)?;

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx);
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_LOC_CONF;
    let rv = cf.parse_block();
    cf.ctx = saved_ctx;
    cf.cmd_type = saved_ct;
    rv
}

/// ngx_http_escape_location_name
fn escape_location_name(clcf: &mut CoreLocConf) {
    let escape = ngx_core::string::escape_uri_count(&clcf.name, ngx_core::string::NGX_ESCAPE_URI);
    if escape == 0 {
        clcf.escaped_name = clcf.name.clone();
        return;
    }
    clcf.escaped_name = ngx_core::string::escape_uri(&clcf.name, ngx_core::string::NGX_ESCAPE_URI);
}

/// ngx_http_add_location
pub fn add_location(cf: &Conf, pclcf: &Rc<RefCell<CoreLocConf>>, clcf: &Rc<RefCell<CoreLocConf>>) -> ConfResult {
    let (name, exact) = {
        let c = clcf.borrow();
        (c.name.clone(), c.exact_match || c.regex.is_some() || c.predicate != 0 || c.named || c.noname)
    };
    let lq = LocationQueue {
        exact: if exact { Some(clcf.clone()) } else { None },
        inclusive: if exact { None } else { Some(clcf.clone()) },
        name,
        file_name: cf.conf_file_name(),
        line: cf.conf_line(),
        list: Vec::new(),
    };
    pclcf.borrow_mut().locations.push(lq);
    escape_location_name(&mut clcf.borrow_mut());
    Ok(())
}

fn server_name(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);
    let args = cf.args.clone();
    for v in &args[1..] {
        let ch = v[0];
        if (ch == b'*' && (v.len() < 3 || v[1] != b'.')) || (ch == b'.' && v.len() < 2) {
            return Err(cf.emerg(format_args!("server name \"{}\" is invalid", B(v))));
        }
        if v.contains(&b'/') {
            cf.warn(format_args!("server name \"{}\" has suspicious symbols", B(v)));
        }
        let me = cscf.borrow().me.upgrade().unwrap();
        let mut sn = ServerName { regex: None, server: me, name: if eq_ignore_case(v, b"$hostname") { cf.cycle.hostname.clone() } else { v.clone() } };
        if v[0] != b'~' {
            sn.name = ngx_core::string::to_lower_vec(&sn.name);
            cscf.borrow_mut().server_names.push(sn);
            continue;
        }
        if v.len() == 1 {
            return Err(cf.emerg(format_args!("empty regex in server name \"{}\"", B(v))));
        }
        let pat = &v[1..];
        let options = if pat.iter().any(|c| c.is_ascii_uppercase()) { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };
        let re = crate::variables::regex_compile(cf, pat, options)?;
        let captures = re.regex.captures > 0;
        sn.regex = Some(re);
        sn.name = pat.to_vec();
        let mut c = cscf.borrow_mut();
        c.server_names.push(sn);
        c.captures = captures;
    }
    Ok(())
}

fn root_alias(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let alias = cmd.name == "alias";
    {
        let c = clcf.borrow();
        if c.root_set {
            if (c.alias != 0) == alias {
                return Err(msg("is duplicate"));
            }
            return Err(cf.emerg(format_args!("\"{}\" directive is duplicate, \"{}\" directive was specified earlier", cmd.name, if c.alias != 0 { "alias" } else { "root" })));
        }
        if c.named && alias {
            return Err(cf.emerg(format_args!("the \"alias\" directive cannot be used inside the named location")));
        }
    }
    let value = cf.args[1].clone();
    if ngx_core::string::strstr(&value, b"$document_root").is_some() || ngx_core::string::strstr(&value, b"${document_root}").is_some() {
        return Err(cf.emerg(format_args!("the $document_root variable cannot be used in the \"{}\" directive", cmd.name)));
    }
    if ngx_core::string::strstr(&value, b"$realpath_root").is_some() || ngx_core::string::strstr(&value, b"${realpath_root}").is_some() {
        return Err(cf.emerg(format_args!("the $realpath_root variable cannot be used in the \"{}\" directive", cmd.name)));
    }
    let mut c = clcf.borrow_mut();
    c.alias = if alias { c.name.len() } else { 0 };
    c.root = value;
    c.root_set = true;
    if !alias && c.root.len() > 0 && c.root.last() == Some(&b'/') {
        c.root.pop();
    }
    if c.root.first() != Some(&b'$') {
        c.root = cf.cycle.full_name(&c.root, false);
    }
    let mut n = script_variables_count(&c.root);
    if alias && (c.predicate != 0 || c.regex.is_some()) {
        c.alias = usize::MAX;
        n = 1;
    }
    if n > 0 {
        let root = c.root.clone();
        drop(c);
        let cv = compile_complex_value(cf, &root, 0)?;
        clcf.borrow_mut().root_script = Some(Rc::new(cv));
    }
    Ok(())
}

fn error_page(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let value = cf.args.clone();
    let i = value.len() - 2;
    let (overwrite, n) = if value[i][0] == b'=' {
        if i == 1 {
            return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value[i]))));
        }
        let ow = if value[i].len() > 1 {
            match atoi(&value[i][1..]) {
                Some(v) => v,
                None => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value[i])))),
            }
        } else {
            0
        };
        (ow, 2)
    } else {
        (-1, 1)
    };
    let uri = value[value.len() - 1].clone();
    let mut cv = compile_complex_value(cf, &uri, 0)?;
    let mut args = Vec::new();
    if cv.is_constant() && !uri.is_empty() && uri[0] == b'/' {
        if let Some(p) = memchr::memchr(b'?', &uri) {
            cv.set_constant(&uri[..p]);
            args = uri[p + 1..].to_vec();
        }
    }
    let mut pages: Vec<ErrPage> = clcf.borrow().error_pages.as_ref().map(|p| (**p).clone()).unwrap_or_default();
    for v in &value[1..value.len() - n] {
        let status = match atoi(v) {
            Some(s) if s != 499 => s,
            _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(v)))),
        };
        if !(300..=599).contains(&status) {
            return Err(cf.emerg(format_args!("value \"{}\" must be between 300 and 599", B(v))));
        }
        let mut ow = overwrite;
        if overwrite == -1 {
            match status {
                NGX_HTTP_TO_HTTPS | NGX_HTTPS_CERT_ERROR | NGX_HTTPS_NO_CERT | NGX_HTTP_REQUEST_HEADER_TOO_LARGE => ow = NGX_HTTP_BAD_REQUEST,
                _ => {}
            }
        }
        pages.push(ErrPage { status, overwrite: ow, value: cv.clone(), args: args.clone() });
    }
    clcf.borrow_mut().error_pages = Some(Rc::new(pages));
    Ok(())
}

fn internal_directive(_cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let mut c = clcf.borrow_mut();
    if c.internal.is_set() {
        return Err(msg("is duplicate"));
    }
    c.internal = Val::set(true);
    Ok(())
}

fn listen(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);
    cscf.borrow_mut().listen = true;
    let value = cf.args.clone();
    let mut u = Url::new(&value[1]);
    u.listen = true;
    u.default_port = 80;
    if parse_url(&mut u).is_err() {
        if let Some(e) = u.err {
            return Err(cf.emerg(format_args!("{} in \"{}\" of the \"listen\" directive", e, B(&u.url))));
        }
        return Err(ConfError::Logged);
    }
    let mut lsopt = ListenOpt {
        sockaddr: SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, 0),
        addr_text: Vec::new(),
        set: false,
        default_server: false,
        bind: false,
        wildcard: false,
        ssl: false,
        http2: false,
        quic: false,
        proxy_protocol: false,
        deferred_accept: false,
        reuseport: false,
        so_keepalive: 0,
        tcp_keepidle: 0,
        tcp_keepintvl: 0,
        tcp_keepcnt: 0,
        backlog: NGX_LISTEN_BACKLOG,
        rcvbuf: -1,
        sndbuf: -1,
        ty: libc::SOCK_STREAM,
        fastopen: -1,
        ipv6only: true,
    };
    let mut backlog = false;
    for v in &value[2..] {
        let s: &[u8] = v;
        if s == b"default_server" || s == b"default" {
            lsopt.default_server = true;
            continue;
        }
        if s == b"bind" {
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"fastopen=") {
            match atoi(rest) {
                Some(n) => lsopt.fastopen = n as i32,
                None => return Err(cf.emerg(format_args!("invalid fastopen \"{}\"", B(s)))),
            }
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"backlog=") {
            match atoi(rest) {
                Some(n) if n != 0 => lsopt.backlog = n as i32,
                _ => return Err(cf.emerg(format_args!("invalid backlog \"{}\"", B(s)))),
            }
            lsopt.set = true;
            lsopt.bind = true;
            backlog = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"rcvbuf=") {
            match parse::parse_size(rest) {
                Some(n) => lsopt.rcvbuf = n as i32,
                None => return Err(cf.emerg(format_args!("invalid rcvbuf \"{}\"", B(s)))),
            }
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"sndbuf=") {
            match parse::parse_size(rest) {
                Some(n) => lsopt.sndbuf = n as i32,
                None => return Err(cf.emerg(format_args!("invalid sndbuf \"{}\"", B(s)))),
            }
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if s.starts_with(b"accept_filter=") {
            cf.log_error(NGX_LOG_EMERG, None, format_args!("accept filters \"{}\" are not supported on this platform, ignored", B(s)));
            continue;
        }
        if s == b"deferred" {
            lsopt.deferred_accept = true;
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"ipv6only=o") {
            if rest == b"n" {
                lsopt.ipv6only = true;
            } else if rest == b"ff" {
                lsopt.ipv6only = false;
            } else {
                return Err(cf.emerg(format_args!("invalid ipv6only flags \"{}\"", B(&s[9..]))));
            }
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if s == b"reuseport" {
            lsopt.reuseport = true;
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if s == b"multipath" {
            cf.log_error(NGX_LOG_EMERG, None, format_args!("multipath is not supported on this platform, ignored"));
            continue;
        }
        if s == b"ssl" {
            lsopt.ssl = true;
            continue;
        }
        if s == b"http2" {
            cf.warn(format_args!("the \"listen ... http2\" directive is deprecated, use the \"http2\" directive instead"));
            lsopt.http2 = true;
            continue;
        }
        if s == b"quic" {
            return Err(cf.emerg(format_args!("the \"quic\" parameter requires ngx_http_v3_module")));
        }
        if let Some(rest) = s.strip_prefix(b"so_keepalive=") {
            if rest == b"on" {
                lsopt.so_keepalive = 1;
            } else if rest == b"off" {
                lsopt.so_keepalive = 2;
            } else {
                let invalid = || cf.emerg(format_args!("invalid so_keepalive value: \"{}\"", B(rest)));
                let parts: Vec<&[u8]> = rest.splitn(3, |&c| c == b':').collect();
                let get = |i: usize| -> &[u8] { parts.get(i).copied().unwrap_or(b"") };
                if !get(0).is_empty() {
                    match parse::parse_time(get(0), true) {
                        Some(t) => lsopt.tcp_keepidle = t as i32,
                        None => return Err(invalid()),
                    }
                }
                if !get(1).is_empty() {
                    match parse::parse_time(get(1), true) {
                        Some(t) => lsopt.tcp_keepintvl = t as i32,
                        None => return Err(invalid()),
                    }
                }
                if !get(2).is_empty() {
                    match atoi(get(2)) {
                        Some(n) => lsopt.tcp_keepcnt = n as i32,
                        None => return Err(invalid()),
                    }
                }
                if lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0 && lsopt.tcp_keepcnt == 0 {
                    return Err(invalid());
                }
                lsopt.so_keepalive = 1;
            }
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }
        if s == b"proxy_protocol" {
            lsopt.proxy_protocol = true;
            continue;
        }
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(s))));
    }
    let _ = backlog;

    let mut seen: Vec<SockAddr> = Vec::new();
    for a in &u.addrs {
        if seen.iter().any(|s| s.cmp(&a.sockaddr, true)) {
            continue;
        }
        seen.push(a.sockaddr.clone());
        let mut o = lsopt.clone();
        o.sockaddr = a.sockaddr.clone();
        o.addr_text = a.name.clone();
        o.wildcard = a.sockaddr.is_wildcard();
        add_listen(cf, &cscf, o)?;
    }
    Ok(())
}

/// ngx_http_add_listen
pub fn add_listen(cf: &mut Conf, cscf: &Rc<RefCell<CoreSrvConf>>, lsopt: ListenOpt) -> ConfResult {
    let cmcf = core_main_conf(cf);
    let p = lsopt.sockaddr.port();
    let family = lsopt.sockaddr.family();
    let mut m = cmcf.borrow_mut();
    for port in m.ports.iter_mut() {
        if p != port.port || lsopt.ty != port.ty || family != port.family {
            continue;
        }
        return add_addresses(cf, cscf, port, lsopt);
    }
    let mut port = ConfPort { family, ty: lsopt.ty, port: p, addrs: Vec::new() };
    add_address(cf, cscf, &mut port, lsopt)?;
    m.ports.push(port);
    Ok(())
}

fn add_addresses(cf: &Conf, cscf: &Rc<RefCell<CoreSrvConf>>, port: &mut ConfPort, lsopt: ListenOpt) -> ConfResult {
    for addr in port.addrs.iter_mut() {
        if !lsopt.sockaddr.cmp(&addr.opt.sockaddr, false) {
            continue;
        }
        add_server(cf, cscf, addr)?;
        let mut default_server = addr.opt.default_server;
        let proxy_protocol = lsopt.proxy_protocol || addr.opt.proxy_protocol;
        let mut protocols = lsopt.proxy_protocol as u32;
        let mut protocols_prev = addr.opt.proxy_protocol as u32;
        let ssl = lsopt.ssl || addr.opt.ssl;
        protocols |= (lsopt.ssl as u32) << 1;
        protocols_prev |= (addr.opt.ssl as u32) << 1;
        let http2 = lsopt.http2 || addr.opt.http2;
        protocols |= (lsopt.http2 as u32) << 2;
        protocols_prev |= (addr.opt.http2 as u32) << 2;
        let quic = lsopt.quic || addr.opt.quic;

        if lsopt.set {
            if addr.opt.set {
                return Err(cf.emerg(format_args!("duplicate listen options for {}", B(&addr.opt.addr_text))));
            }
            addr.opt = lsopt.clone();
        }
        if lsopt.default_server {
            if default_server {
                return Err(cf.emerg(format_args!("a duplicate default server for {}", B(&addr.opt.addr_text))));
            }
            default_server = true;
            addr.default_server = cscf.clone();
        }
        if (protocols | protocols_prev) != protocols_prev {
            if (addr.opt.set && !lsopt.set) || addr.protocols_changed || (protocols | protocols_prev) != protocols {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }
            addr.protocols = protocols_prev;
            addr.protocols_set = true;
            addr.protocols_changed = true;
        } else if (protocols_prev | protocols) != protocols {
            if lsopt.set || (addr.protocols_set && protocols != addr.protocols) {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }
            addr.protocols = protocols;
            addr.protocols_set = true;
            addr.protocols_changed = true;
        } else {
            if (lsopt.set && addr.protocols_changed) || (addr.protocols_set && protocols != addr.protocols) {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }
            addr.protocols = protocols;
            addr.protocols_set = true;
        }
        addr.opt.default_server = default_server;
        addr.opt.proxy_protocol = proxy_protocol;
        addr.opt.ssl = ssl;
        addr.opt.http2 = http2;
        addr.opt.quic = quic;
        return Ok(());
    }
    add_address(cf, cscf, port, lsopt)
}

fn add_address(cf: &Conf, cscf: &Rc<RefCell<CoreSrvConf>>, port: &mut ConfPort, lsopt: ListenOpt) -> ConfResult {
    let mut addr = ConfAddr {
        opt: lsopt,
        protocols: 0,
        protocols_set: false,
        protocols_changed: false,
        hash: None,
        wc_head: None,
        wc_tail: None,
        regex: Vec::new(),
        default_server: cscf.clone(),
        servers: Vec::new(),
    };
    add_server(cf, cscf, &mut addr)?;
    port.addrs.push(addr);
    Ok(())
}

fn add_server(cf: &Conf, cscf: &Rc<RefCell<CoreSrvConf>>, addr: &mut ConfAddr) -> ConfResult {
    if addr.servers.iter().any(|s| Rc::ptr_eq(s, cscf)) {
        return Err(cf.emerg(format_args!("a duplicate listen {}", B(&addr.opt.addr_text))));
    }
    addr.servers.push(cscf.clone());
    Ok(())
}

// --- other directives ------------------------------------------------------

fn types_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    if clcf.borrow().types.is_none() {
        clcf.borrow_mut().types = Some(Rc::new(RefCell::new(Vec::new())));
    }
    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(types_type);
    cf.handler_conf = conf.clone();
    let rv = cf.parse_block();
    cf.handler = saved_h;
    cf.handler_conf = saved_hc;
    rv
}

fn types_type(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let clcf = conf_rc::<CoreLocConf>(&conf);
    let value = cf.args.clone();
    if value[0] == b"include" {
        if value.len() != 2 {
            return Err(cf.emerg(format_args!("invalid number of arguments in \"include\" directive")));
        }
        let cmd = Command::new("include", 0, ConfLevel::None, conf_include);
        return conf_include(cf, &cmd, None);
    }
    let content_type = Rc::new(value[0].clone());
    let types = clcf.borrow().types.clone().unwrap();
    for v in &value[1..] {
        let mut lower = v.clone();
        let hash = hash_strlow(&mut lower, v);
        let mut t = types.borrow_mut();
        if let Some(existing) = t.iter_mut().find(|k| k.key == lower) {
            let old = existing.value.clone();
            existing.value = content_type.clone();
            drop(t);
            cf.warn(format_args!("duplicate extension \"{}\", content type: \"{}\", previous content type: \"{}\"", B(v), B(&content_type), B(&old)));
            continue;
        }
        t.push(HashKey { key: lower, key_hash: hash, value: content_type.clone() });
    }
    Ok(())
}

fn limit_except(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pclcf = clcf_of(&conf);
    if pclcf.borrow().limit_except != 0 {
        return Err(msg("is duplicate"));
    }
    let mut mask: u32 = 0xffffffff;
    let value = cf.args.clone();
    for v in &value[1..] {
        let m = match METHOD_NAMES.iter().find(|(n, _)| eq_ignore_case(n.as_bytes(), v)) {
            Some((_, m)) => *m,
            None => return Err(cf.emerg(format_args!("invalid method \"{}\"", B(v)))),
        };
        mask &= m;
    }
    if mask & NGX_HTTP_GET == 0 {
        mask &= !NGX_HTTP_HEAD;
    }
    pclcf.borrow_mut().limit_except = mask;

    let n = http_max_module();
    let pctx = cf.ctx.clone();
    let ctx = ConfCtx { main: pctx.main.clone(), srv: pctx.srv.clone(), loc: Some(new_slots(n)) };
    let modules = cf.cycle.modules.clone();
    for m in modules.iter().filter(|m| m.def.ty == NGX_HTTP_MODULE) {
        if let Some(d) = m.ctx::<HttpModuleDef>() {
            if let Some(f) = d.create_loc_conf {
                let c = f(cf);
                ctx.loc.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(c);
            }
        }
    }
    let clcf = loc_conf_from_ctx(&ctx);
    pclcf.borrow_mut().limit_except_loc_conf = ctx.loc.clone();
    {
        let mut c = clcf.borrow_mut();
        c.loc_conf = ctx.loc.clone();
        c.name = pclcf.borrow().name.clone();
        c.noname = true;
        c.lmt_excpt = true;
    }
    add_location(cf, &pclcf, &clcf)?;
    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx);
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_LMT_CONF;
    let rv = cf.parse_block();
    cf.ctx = saved_ctx;
    cf.cmd_type = saved_ct;
    rv
}

pub static METHOD_NAMES: &[(&str, u32)] = &[
    ("GET", !NGX_HTTP_GET),
    ("HEAD", !NGX_HTTP_HEAD),
    ("POST", !NGX_HTTP_POST),
    ("PUT", !NGX_HTTP_PUT),
    ("DELETE", !NGX_HTTP_DELETE),
    ("MKCOL", !NGX_HTTP_MKCOL),
    ("COPY", !NGX_HTTP_COPY),
    ("MOVE", !NGX_HTTP_MOVE),
    ("OPTIONS", !NGX_HTTP_OPTIONS),
    ("PROPFIND", !NGX_HTTP_PROPFIND),
    ("PROPPATCH", !NGX_HTTP_PROPPATCH),
    ("LOCK", !NGX_HTTP_LOCK),
    ("UNLOCK", !NGX_HTTP_UNLOCK),
    ("PATCH", !NGX_HTTP_PATCH),
];

fn set_aio(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let mut c = clcf.borrow_mut();
    if c.aio.is_set() {
        return Err(msg("is duplicate"));
    }
    c.thread_pool = Val::set(None);
    let v = cf.args[1].clone();
    if v == b"off" {
        c.aio = Val::set(NGX_HTTP_AIO_OFF);
        return Ok(());
    }
    if v == b"on" {
        c.aio = Val::set(NGX_HTTP_AIO_ON);
        return Ok(());
    }
    if v.starts_with(b"threads") && (v.len() == 7 || v[7] == b'=') {
        c.aio = Val::set(NGX_HTTP_AIO_THREADS);
        if v.len() >= 8 {
            c.thread_pool = Val::set(Some(v[8..].to_vec()));
        } else {
            c.thread_pool = Val::set(Some(b"default".to_vec()));
        }
        return Ok(());
    }
    Err(msg("invalid value"))
}

fn directio(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let mut c = clcf.borrow_mut();
    if c.directio.is_set() {
        return Err(msg("is duplicate"));
    }
    if cf.args[1] == b"off" {
        c.directio = Val::set(NGX_OPEN_FILE_DIRECTIO_OFF);
        return Ok(());
    }
    match parse::parse_offset(&cf.args[1]) {
        Some(v) => c.directio = Val::set(v),
        None => return Err(msg("invalid value")),
    }
    Ok(())
}

fn open_file_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    if clcf.borrow().open_file_cache.is_set() {
        return Err(msg("is duplicate"));
    }
    let value = cf.args.clone();
    let mut max: i64 = 0;
    let mut inactive: i64 = 60;
    let mut off = false;
    for v in &value[1..] {
        let s: &[u8] = v;
        if let Some(rest) = s.strip_prefix(b"max=") {
            match atoi(rest) {
                Some(m) if m > 0 => max = m,
                _ => return Err(cf.emerg(format_args!("invalid \"open_file_cache\" parameter \"{}\"", B(s)))),
            }
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"inactive=") {
            match parse::parse_time(rest, true) {
                Some(t) => inactive = t,
                None => return Err(cf.emerg(format_args!("invalid \"open_file_cache\" parameter \"{}\"", B(s)))),
            }
            continue;
        }
        if s == b"off" {
            off = true;
            continue;
        }
        return Err(cf.emerg(format_args!("invalid \"open_file_cache\" parameter \"{}\"", B(s))));
    }
    if off {
        clcf.borrow_mut().open_file_cache = Val::set(None);
        return Ok(());
    }
    if max == 0 {
        return Err(cf.emerg(format_args!("\"open_file_cache\" must have the \"max\" parameter")));
    }
    clcf.borrow_mut().open_file_cache = Val::set(Some(ngx_core::open_file_cache::OpenFileCache::new(max as usize, inactive)));
    Ok(())
}

fn error_log_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let chain = {
        let mut c = clcf.borrow_mut();
        if c.error_log.is_none() {
            c.error_log = Some(LogChain::new());
        }
        c.error_log.clone().unwrap()
    };
    ngx_core::core_module::log_set_log(cf, &chain)
}

fn keepalive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let mut c = clcf.borrow_mut();
    if c.keepalive_timeout.is_set() {
        return Err(msg("is duplicate"));
    }
    match parse::parse_time(&cf.args[1], false) {
        Some(v) => c.keepalive_timeout = Val::set(v as u64),
        None => return Err(msg("invalid value")),
    }
    if cf.args.len() == 2 {
        return Ok(());
    }
    match parse::parse_time(&cf.args[2], true) {
        Some(v) => c.keepalive_header = Val::set(v),
        None => return Err(msg("invalid value")),
    }
    Ok(())
}

fn resolver(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    if clcf.borrow().resolver.is_some() {
        return Err(msg("is duplicate"));
    }
    let args = cf.args[1..].to_vec();
    let r = Resolver::create(cf, &args)?;
    clcf.borrow_mut().resolver = Some(r);
    Ok(())
}

fn gzip_disable(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    let mut list: Vec<Rc<Regex>> = clcf.borrow().gzip_disable.as_option().and_then(|o| o.clone()).map(|v| (*v).clone()).unwrap_or_default();
    for v in &cf.args.clone()[1..] {
        if v == b"msie6" {
            clcf.borrow_mut().gzip_disable_msie6 = 1;
            continue;
        }
        if v == b"degradation" {
            clcf.borrow_mut().gzip_disable_degradation = 1;
            continue;
        }
        match Regex::compile(v, ngx_core::regex::NGX_REGEX_CASELESS) {
            Ok(re) => list.push(re),
            Err(e) => return Err(cf.emerg(format_args!("{}", e))),
        }
    }
    clcf.borrow_mut().gzip_disable = Val::set(Some(Rc::new(list)));
    Ok(())
}

fn disable_symlinks(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = clcf_of(&conf);
    if clcf.borrow().disable_symlinks.is_set() {
        return Err(msg("is duplicate"));
    }
    let value = cf.args.clone();
    let mut mode: Option<u32> = None;
    let mut from: Option<Rc<ComplexValue>> = None;
    let mut from_set = false;
    for v in &value[1..] {
        let s: &[u8] = v;
        if s == b"off" {
            mode = Some(NGX_DISABLE_SYMLINKS_OFF);
            continue;
        }
        if s == b"if_not_owner" {
            mode = Some(NGX_DISABLE_SYMLINKS_NOTOWNER);
            continue;
        }
        if s == b"on" {
            mode = Some(NGX_DISABLE_SYMLINKS_ON);
            continue;
        }
        if let Some(rest) = s.strip_prefix(b"from=") {
            let cv = compile_complex_value(cf, rest, 0)?;
            from = Some(Rc::new(cv));
            from_set = true;
            continue;
        }
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(s))));
    }
    let mode = match mode {
        Some(m) => m,
        None => return Err(cf.emerg(format_args!("\"{}\" must have \"off\", \"on\" or \"if_not_owner\" parameter", cmd.name))),
    };
    let mut c = clcf.borrow_mut();
    c.disable_symlinks = Val::set(mode);
    if value.len() == 2 {
        c.disable_symlinks_from = Val::set(None);
        return Ok(());
    }
    if !from_set {
        return Err(cf.emerg(format_args!("duplicate parameters \"{} {}\"", B(&value[1]), B(&value[2]))));
    }
    if mode == NGX_DISABLE_SYMLINKS_OFF {
        return Err(cf.emerg(format_args!("\"from=\" cannot be used with \"off\" parameter")));
    }
    c.disable_symlinks_from = Val::set(from);
    Ok(())
}

fn pool_size_check(cf: &Conf, v: usize) -> ConfResult {
    if v < 16 {
        return Err(cf.emerg(format_args!("the pool size must be no less than {}", 16)));
    }
    if v % 16 != 0 {
        return Err(cf.emerg(format_args!("the pool size must be a multiple of {}", 16)));
    }
    Ok(())
}

fn set_pool_size(cf: &Conf, cmd: &Command, slot: &mut Val<usize>) -> ConfResult {
    set_size(cf, cmd, slot)?;
    pool_size_check(cf, *slot.get())
}

fn set_lowat(cf: &Conf, cmd: &Command, slot: &mut Val<usize>) -> ConfResult {
    set_size(cf, cmd, slot)?;
    cf.warn(format_args!("\"send_lowat\" is not supported, ignored"));
    Ok(())
}

pub fn set_default_type_slot(cf: &Conf, cmd: &Command, slot: &mut Val<Vec<u8>>) -> ConfResult {
    set_str(cf, cmd, slot)
}

const MSL: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
const MS: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF;

pub fn core_module() -> ModuleDef {
    type L = CoreLocConf;
    type S = CoreSrvConf;
    type M = CoreMainConf;
    let commands = vec![
        cmd!("variables_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, M, variables_hash_max_size, set_num),
        cmd!("variables_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, M, variables_hash_bucket_size, set_num),
        cmd!("server_names_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, M, server_names_hash_max_size, set_num),
        cmd!("server_names_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, M, server_names_hash_bucket_size, set_num),
        cmd_fn!("server", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, server_block),
        ngx_core::cmdp!("connection_pool_size", MS | NGX_CONF_TAKE1, ConfLevel::Srv, S, connection_pool_size, set_pool_size),
        ngx_core::cmdp!("request_pool_size", MS | NGX_CONF_TAKE1, ConfLevel::Srv, S, request_pool_size, set_pool_size),
        cmd!("client_header_timeout", MS | NGX_CONF_TAKE1, ConfLevel::Srv, S, client_header_timeout, set_msec),
        cmd!("client_header_buffer_size", MS | NGX_CONF_TAKE1, ConfLevel::Srv, S, client_header_buffer_size, set_size),
        cmd!("large_client_header_buffers", MS | NGX_CONF_TAKE2, ConfLevel::Srv, S, large_client_header_buffers, set_bufs),
        cmd!("max_headers", MS | NGX_CONF_TAKE1, ConfLevel::Srv, S, max_headers, set_num),
        cmd!("ignore_invalid_headers", MS | NGX_CONF_FLAG, ConfLevel::Srv, S, ignore_invalid_headers, set_flag),
        cmd!("merge_slashes", MS | NGX_CONF_FLAG, ConfLevel::Srv, S, merge_slashes, set_flag),
        cmd!("underscores_in_headers", MS | NGX_CONF_FLAG, ConfLevel::Srv, S, underscores_in_headers, set_flag),
        cmd_fn!("location", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE12, ConfLevel::Srv, location_block),
        cmd_fn!("listen", NGX_HTTP_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, listen),
        cmd_fn!("server_name", NGX_HTTP_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, server_name),
        cmd!("types_hash_max_size", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, types_hash_max_size, set_num),
        cmd!("types_hash_bucket_size", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, types_hash_bucket_size, set_num),
        cmd_fn!("types", MSL | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::Loc, types_block),
        cmd!("default_type", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, default_type, set_str),
        cmd_fn!("root", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, root_alias),
        cmd_fn!("alias", NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, root_alias),
        cmd_fn!("limit_except", NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_1MORE, ConfLevel::Loc, limit_except),
        cmd!("client_max_body_size", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, client_max_body_size, set_off),
        cmd!("client_body_buffer_size", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, client_body_buffer_size, set_size),
        cmd!("client_body_timeout", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, client_body_timeout, set_msec),
        cmd_fn!("client_body_temp_path", MSL | NGX_CONF_TAKE1234, ConfLevel::Loc, |cf, cmd, conf| {
            let clcf = clcf_of(&conf);
            let mut slot = std::mem::take(&mut clcf.borrow_mut().client_body_temp_path);
            let r = set_path(cf, cmd, &mut slot);
            clcf.borrow_mut().client_body_temp_path = slot;
            r
        }),
        cmd!("client_body_in_file_only", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, client_body_in_file_only, set_enum, &[("off", NGX_HTTP_REQUEST_BODY_FILE_OFF), ("on", NGX_HTTP_REQUEST_BODY_FILE_ON), ("clean", NGX_HTTP_REQUEST_BODY_FILE_CLEAN)]),
        cmd!("client_body_in_single_buffer", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, client_body_in_single_buffer, set_flag),
        cmd_fn!("client_body_early_read", MS | NGX_CONF_1MORE, ConfLevel::Srv, |cf, cmd, conf| {
            let cscf = cscf_of(&conf);
            let mut slot = std::mem::take(&mut cscf.borrow_mut().client_body_early_read);
            let r = set_predicate_slot(cf, cmd, &mut slot);
            cscf.borrow_mut().client_body_early_read = slot;
            r
        }),
        cmd!("sendfile", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, L, sendfile, set_flag),
        cmd!("sendfile_max_chunk", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, sendfile_max_chunk, set_size),
        cmd!("subrequest_output_buffer_size", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, subrequest_output_buffer_size, set_size),
        cmd_fn!("aio", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, set_aio),
        cmd!("aio_write", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, aio_write, set_flag),
        cmd!("read_ahead", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, read_ahead, set_size),
        cmd_fn!("directio", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, directio),
        cmd!("directio_alignment", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, directio_alignment, set_off),
        cmd!("tcp_nopush", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, tcp_nopush, set_flag),
        cmd!("tcp_nodelay", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, tcp_nodelay, set_flag),
        cmd!("send_timeout", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, send_timeout, set_msec),
        ngx_core::cmdp!("send_lowat", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, send_lowat, set_lowat),
        cmd!("postpone_output", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, postpone_output, set_size),
        cmd_fn!("limit_rate", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf, cmd, conf| {
            let clcf = clcf_of(&conf);
            let mut slot = std::mem::take(&mut clcf.borrow_mut().limit_rate);
            let r = set_complex_value_size_slot(cf, cmd, &mut slot);
            clcf.borrow_mut().limit_rate = slot;
            r
        }),
        cmd_fn!("limit_rate_after", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf, cmd, conf| {
            let clcf = clcf_of(&conf);
            let mut slot = std::mem::take(&mut clcf.borrow_mut().limit_rate_after);
            let r = set_complex_value_size_slot(cf, cmd, &mut slot);
            clcf.borrow_mut().limit_rate_after = slot;
            r
        }),
        cmd!("keepalive_time", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, keepalive_time, set_msec),
        cmd_fn!("keepalive_timeout", MSL | NGX_CONF_TAKE12, ConfLevel::Loc, keepalive),
        cmd!("keepalive_min_timeout", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, keepalive_min_timeout, set_msec),
        cmd!("keepalive_requests", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, keepalive_requests, set_num),
        cmd!("keepalive_disable", MSL | NGX_CONF_TAKE12, ConfLevel::Loc, L, keepalive_disable, set_bitmask, &[("none", NGX_HTTP_KEEPALIVE_DISABLE_NONE), ("msie6", NGX_HTTP_KEEPALIVE_DISABLE_MSIE6), ("safari", NGX_HTTP_KEEPALIVE_DISABLE_SAFARI)]),
        cmd!("satisfy", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, satisfy, set_enum, &[("all", NGX_HTTP_SATISFY_ALL), ("any", NGX_HTTP_SATISFY_ANY)]),
        cmd!("auth_delay", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, auth_delay, set_msec),
        cmd_fn!("internal", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::Loc, internal_directive),
        cmd!("lingering_close", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, lingering_close, set_enum, &[("off", NGX_HTTP_LINGERING_OFF), ("on", NGX_HTTP_LINGERING_ON), ("always", NGX_HTTP_LINGERING_ALWAYS)]),
        cmd!("lingering_time", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, lingering_time, set_msec),
        cmd!("lingering_timeout", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, lingering_timeout, set_msec),
        cmd!("reset_timedout_connection", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, reset_timedout_connection, set_flag),
        cmd!("absolute_redirect", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, absolute_redirect, set_flag),
        cmd!("server_name_in_redirect", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, server_name_in_redirect, set_flag),
        cmd!("port_in_redirect", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, port_in_redirect, set_flag),
        cmd!("msie_padding", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, msie_padding, set_flag),
        cmd!("msie_refresh", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, msie_refresh, set_flag),
        cmd!("log_not_found", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, log_not_found, set_flag),
        cmd!("log_subrequest", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, log_subrequest, set_flag),
        cmd!("recursive_error_pages", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, recursive_error_pages, set_flag),
        cmd!("server_tokens", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, server_tokens, set_enum, &[("off", NGX_HTTP_SERVER_TOKENS_OFF), ("on", NGX_HTTP_SERVER_TOKENS_ON), ("build", NGX_HTTP_SERVER_TOKENS_BUILD)]),
        cmd!("if_modified_since", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, if_modified_since, set_enum, &[("off", NGX_HTTP_IMS_OFF), ("exact", NGX_HTTP_IMS_EXACT), ("before", NGX_HTTP_IMS_BEFORE)]),
        cmd!("max_ranges", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, max_ranges, set_num),
        cmd!("chunked_transfer_encoding", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, chunked_transfer_encoding, set_flag),
        cmd!("etag", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, etag, set_flag),
        cmd_fn!("early_hints", MSL | NGX_CONF_1MORE, ConfLevel::Loc, |cf, cmd, conf| {
            let clcf = clcf_of(&conf);
            let mut slot = std::mem::take(&mut clcf.borrow_mut().early_hints);
            let r = set_predicate_slot(cf, cmd, &mut slot);
            clcf.borrow_mut().early_hints = slot;
            r
        }),
        cmd_fn!("error_page", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_2MORE, ConfLevel::Loc, error_page),
        cmd_fn!("post_action", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf, _cmd, conf| {
            let clcf = clcf_of(&conf);
            let mut c = clcf.borrow_mut();
            if !c.post_action.is_empty() {
                return Err(msg("is duplicate"));
            }
            c.post_action = cf.args[1].clone();
            Ok(())
        }),
        cmd_fn!("error_log", MSL | NGX_CONF_1MORE, ConfLevel::Loc, error_log_directive),
        cmd_fn!("open_file_cache", MSL | NGX_CONF_TAKE12, ConfLevel::Loc, open_file_cache),
        cmd!("open_file_cache_valid", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, open_file_cache_valid, set_sec),
        cmd!("open_file_cache_min_uses", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, open_file_cache_min_uses, set_num),
        cmd!("open_file_cache_errors", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, open_file_cache_errors, set_flag),
        cmd!("open_file_cache_events", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, open_file_cache_events, set_flag),
        cmd_fn!("resolver", MSL | NGX_CONF_1MORE, ConfLevel::Loc, resolver),
        cmd!("resolver_timeout", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, resolver_timeout, set_msec),
        cmd!("gzip_vary", MSL | NGX_CONF_FLAG, ConfLevel::Loc, L, gzip_vary, set_flag),
        cmd!("gzip_http_version", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, L, gzip_http_version, set_enum, &[("1.0", NGX_HTTP_VERSION_10), ("1.1", NGX_HTTP_VERSION_11)]),
        cmd!("gzip_proxied", MSL | NGX_CONF_1MORE, ConfLevel::Loc, L, gzip_proxied, set_bitmask, &[
            ("off", NGX_HTTP_GZIP_PROXIED_OFF), ("expired", NGX_HTTP_GZIP_PROXIED_EXPIRED), ("no-cache", NGX_HTTP_GZIP_PROXIED_NO_CACHE),
            ("no-store", NGX_HTTP_GZIP_PROXIED_NO_STORE), ("private", NGX_HTTP_GZIP_PROXIED_PRIVATE), ("no_last_modified", NGX_HTTP_GZIP_PROXIED_NO_LM),
            ("no_etag", NGX_HTTP_GZIP_PROXIED_NO_ETAG), ("auth", NGX_HTTP_GZIP_PROXIED_AUTH), ("any", NGX_HTTP_GZIP_PROXIED_ANY)]),
        cmd_fn!("gzip_disable", MSL | NGX_CONF_1MORE, ConfLevel::Loc, gzip_disable),
        cmd_fn!("disable_symlinks", MSL | NGX_CONF_TAKE12, ConfLevel::Loc, disable_symlinks),
    ];
    let def = HttpModuleDef {
        preconfiguration: Some(crate::variables::core_variables_add),
        postconfiguration: Some(core_postconfiguration),
        create_main_conf: Some(create_main_conf),
        init_main_conf: Some(init_main_conf),
        create_srv_conf: Some(create_srv_conf),
        merge_srv_conf: Some(merge_srv_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
    };
    http_module_def("ngx_http_core_module", def, commands)
}

fn core_postconfiguration(_cf: &mut Conf) -> ConfResult {
    set_top_request_body_filter(Rc::new(|r, chain| Box::pin(crate::request_body::request_body_save_filter(r, chain))));
    Ok(())
}

// --- location trees ------------------------------------------------------------

fn cmp_locations(a: &LocationQueue, b: &LocationQueue) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let first = a.clcf();
    let second = b.clcf();
    let f = first.borrow();
    let s = second.borrow();
    if f.noname && !s.noname {
        return Greater;
    }
    if !f.noname && s.noname {
        return Less;
    }
    if f.noname || s.noname {
        return Equal;
    }
    if f.named && !s.named {
        return Greater;
    }
    if !f.named && s.named {
        return Less;
    }
    if f.named && s.named {
        return f.name.cmp(&s.name);
    }
    if f.predicate != 0 && s.predicate == 0 {
        return Greater;
    }
    if f.predicate == 0 && s.predicate != 0 {
        return Less;
    }
    if f.predicate != 0 || s.predicate != 0 {
        return Equal;
    }
    if f.regex.is_some() && s.regex.is_none() {
        return Greater;
    }
    if f.regex.is_none() && s.regex.is_some() {
        return Less;
    }
    if f.regex.is_some() || s.regex.is_some() {
        return Equal;
    }
    let rc = filename_cmp(&f.name, &s.name, f.name.len().min(s.name.len()) + 1);
    if rc == 0 && !f.exact_match && s.exact_match {
        return Greater;
    }
    rc.cmp(&0)
}

/// ngx_http_init_locations
pub fn init_locations(cf: &mut Conf, cscf: Option<&Rc<RefCell<CoreSrvConf>>>, pclcf: &Rc<RefCell<CoreLocConf>>) -> ConfResult {
    let mut locations = std::mem::take(&mut pclcf.borrow_mut().locations);
    if locations.is_empty() {
        return Ok(());
    }
    // stable sort like ngx_queue_sort (insertion sort, stable)
    locations.sort_by(cmp_locations);

    let mut named = Vec::new();
    let mut predicate = Vec::new();
    let mut regex = Vec::new();
    let mut statics = Vec::new();
    let mut noname_seen = false;
    for lq in locations.into_iter() {
        let clcf = lq.clcf();
        init_locations(cf, None, &clcf)?;
        let c = clcf.borrow();
        if noname_seen {
            // after the first noname location everything is dropped (split tail)
            continue;
        }
        if c.regex.is_some() {
            regex.push(clcf.clone());
            continue;
        }
        if c.predicate != 0 {
            predicate.push(clcf.clone());
            continue;
        }
        if c.named {
            named.push(clcf.clone());
            continue;
        }
        if c.noname {
            noname_seen = true;
            continue;
        }
        drop(c);
        statics.push(lq);
    }
    if let Some(cscf) = cscf {
        if !named.is_empty() {
            cscf.borrow_mut().named_locations = named;
        }
    }
    let mut p = pclcf.borrow_mut();
    p.predicate_locations = predicate;
    p.regex_locations = regex;
    p.locations = statics;
    Ok(())
}

/// ngx_http_init_static_location_trees
pub fn init_static_location_trees(cf: &mut Conf, pclcf: &Rc<RefCell<CoreLocConf>>) -> ConfResult {
    let preds = pclcf.borrow().predicate_locations.clone();
    for p in preds.iter() {
        init_static_location_trees(cf, p)?;
    }
    let mut locations = std::mem::take(&mut pclcf.borrow_mut().locations);
    if locations.is_empty() {
        return Ok(());
    }
    for lq in locations.iter() {
        let clcf = lq.clcf();
        init_static_location_trees(cf, &clcf)?;
    }
    join_exact_locations(cf, &mut locations)?;
    create_locations_list(&mut locations, 0);
    let tree = create_locations_tree(locations, 0);
    pclcf.borrow_mut().static_locations = Some(tree);
    Ok(())
}

fn join_exact_locations(cf: &Conf, locations: &mut Vec<LocationQueue>) -> ConfResult {
    let mut q = 0;
    while q + 1 < locations.len() {
        let x = q + 1;
        let same = locations[q].name.len() == locations[x].name.len() && filename_cmp(&locations[q].name, &locations[x].name, locations[x].name.len()) == 0;
        if same {
            if (locations[q].exact.is_some() && locations[x].exact.is_some()) || (locations[q].inclusive.is_some() && locations[x].inclusive.is_some()) {
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "duplicate location \"{}\" in {}:{}", B(&locations[x].name), B(&locations[x].file_name), locations[x].line);
                return Err(ConfError::Logged);
            }
            let lx = locations.remove(x);
            locations[q].inclusive = lx.inclusive;
            continue;
        }
        q += 1;
    }
    Ok(())
}

fn create_locations_list(locations: &mut Vec<LocationQueue>, q: usize) {
    if q + 1 >= locations.len() {
        return;
    }
    if locations[q].inclusive.is_none() {
        create_locations_list(locations, q + 1);
        return;
    }
    let name = locations[q].name.clone();
    let len = name.len();
    let mut x = q + 1;
    while x < locations.len() {
        let lx = &locations[x];
        if len > lx.name.len() || filename_cmp(&name, &lx.name, len) != 0 {
            break;
        }
        x += 1;
    }
    if q + 1 == x {
        create_locations_list(locations, x);
        return;
    }
    let tail: Vec<LocationQueue> = locations.drain(q + 1..x).collect();
    locations[q].list = tail;
    let has_rest = q + 1 < locations.len();
    {
        let mut list = std::mem::take(&mut locations[q].list);
        create_locations_list(&mut list, 0);
        locations[q].list = list;
    }
    if has_rest {
        create_locations_list(locations, q + 1);
    }
}

fn create_locations_tree(mut locations: Vec<LocationQueue>, prefix: usize) -> Box<LocationTreeNode> {
    let n = locations.len();
    let mid = n / 2;
    let right: Vec<LocationQueue> = locations.drain(mid + 1..).collect();
    let mut lq = locations.pop().unwrap();
    let left = locations;
    let name = lq.name[prefix..].to_vec();
    let len = name.len();
    let auto_redirect = lq.exact.as_ref().map(|e| e.borrow().auto_redirect).unwrap_or(false) || lq.inclusive.as_ref().map(|e| e.borrow().auto_redirect).unwrap_or(false);
    let list = std::mem::take(&mut lq.list);
    let mut node = Box::new(LocationTreeNode { left: None, right: None, tree: None, exact: lq.exact.clone(), inclusive: lq.inclusive.clone(), auto_redirect, name });
    if !left.is_empty() {
        node.left = Some(create_locations_tree(left, prefix));
    }
    if !right.is_empty() {
        node.right = Some(create_locations_tree(right, prefix));
    }
    if !list.is_empty() {
        node.tree = Some(create_locations_tree(list, prefix + len));
    }
    node
}

// --- phases ---------------------------------------------------------------

pub fn init_phases(_cf: &mut Conf, cmcf: &Rc<RefCell<CoreMainConf>>) -> ConfResult {
    let mut m = cmcf.borrow_mut();
    if m.phases.len() < NGX_HTTP_LOG_PHASE + 1 {
        m.phases.resize(NGX_HTTP_LOG_PHASE + 1, Phase::default());
    }
    Ok(())
}

/// Add a phase handler (called by modules in postconfiguration).
pub fn add_phase_handler(cf: &Conf, phase: usize, h: HandlerFn) {
    let cmcf = core_main_conf(cf);
    cmcf.borrow_mut().phases[phase].handlers.push(h);
}

/// Add a log phase handler (synchronous).
pub fn add_log_handler(cf: &Conf, h: Rc<dyn Fn(&R) -> i64>) {
    let cmcf = core_main_conf(cf);
    cmcf.borrow_mut().log_handlers.push(h);
}

pub fn init_headers_in_hash(cf: &mut Conf, cmcf: &Rc<RefCell<CoreMainConf>>) -> ConfResult {
    let names: Vec<HashKey<HeaderInFn>> = crate::request_headers::HEADERS_IN
        .iter()
        .map(|(name, f)| {
            let lc = ngx_core::string::to_lower_vec(name.as_bytes());
            HashKey { key_hash: hash_key(&lc), key: lc, value: *f }
        })
        .collect();
    let hinit = HashInit { name: "headers_in_hash", max_size: 512, bucket_size: ngx_core::os::cacheline_size(), log: &cf.log };
    let h = Hash::init(&hinit, names).map_err(|e| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    })?;
    cmcf.borrow_mut().headers_in_hash = Some(h);
    Ok(())
}

pub fn init_phase_handlers(_cf: &mut Conf, cmcf: &Rc<RefCell<CoreMainConf>>) -> ConfResult {
    let mut m = cmcf.borrow_mut();
    let use_rewrite = !m.phases[NGX_HTTP_REWRITE_PHASE].handlers.is_empty();
    let use_access = !m.phases[NGX_HTTP_ACCESS_PHASE].handlers.is_empty();
    let mut ph: Vec<PhaseHandler> = Vec::new();
    let mut n = 0usize;
    let mut find_config_index = 0;
    let mut server_rewrite_index = usize::MAX;
    let mut location_rewrite_index = usize::MAX;
    for i in 0..NGX_HTTP_LOG_PHASE {
        let handlers = m.phases[i].handlers.clone();
        let checker;
        match i {
            NGX_HTTP_SERVER_REWRITE_PHASE => {
                if server_rewrite_index == usize::MAX {
                    server_rewrite_index = n;
                }
                checker = Checker::Rewrite;
            }
            NGX_HTTP_FIND_CONFIG_PHASE => {
                find_config_index = n;
                ph.push(PhaseHandler { checker: Checker::FindConfig, handler: None, next: 0 });
                n += 1;
                continue;
            }
            NGX_HTTP_REWRITE_PHASE => {
                if location_rewrite_index == usize::MAX {
                    location_rewrite_index = n;
                }
                checker = Checker::Rewrite;
            }
            NGX_HTTP_POST_REWRITE_PHASE => {
                if use_rewrite {
                    ph.push(PhaseHandler { checker: Checker::PostRewrite, handler: None, next: find_config_index });
                    n += 1;
                }
                continue;
            }
            NGX_HTTP_ACCESS_PHASE => {
                checker = Checker::Access;
                n += 1;
            }
            NGX_HTTP_POST_ACCESS_PHASE => {
                if use_access {
                    ph.push(PhaseHandler { checker: Checker::PostAccess, handler: None, next: n });
                }
                continue;
            }
            NGX_HTTP_CONTENT_PHASE => checker = Checker::Content,
            _ => checker = Checker::Generic,
        }
        n += handlers.len();
        for h in handlers.iter().rev() {
            ph.push(PhaseHandler { checker, handler: Some(h.clone()), next: n });
        }
    }
    m.phase_engine = PhaseEngine { handlers: ph, server_rewrite_index, location_rewrite_index };
    Ok(())
}

// --- servers / listening ------------------------------------------------------

fn cmp_conf_addrs(a: &ConfAddr, b: &ConfAddr) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    if a.opt.wildcard {
        return Greater;
    }
    if b.opt.wildcard {
        return Less;
    }
    if a.opt.bind && !b.opt.bind {
        return Less;
    }
    if !a.opt.bind && b.opt.bind {
        return Greater;
    }
    Equal
}

pub fn optimize_servers(cf: &mut Conf, cmcf: &Rc<RefCell<CoreMainConf>>) -> ConfResult {
    let mut ports = std::mem::take(&mut cmcf.borrow_mut().ports);
    for port in ports.iter_mut() {
        port.addrs.sort_by(cmp_conf_addrs);
        for a in 0..port.addrs.len() {
            let need = port.addrs[a].servers.len() > 1 || port.addrs[a].default_server.borrow().captures;
            if need {
                server_names(cf, cmcf, &mut port.addrs[a])?;
            }
        }
        init_listening(cf, port)?;
    }
    cmcf.borrow_mut().ports = ports;
    Ok(())
}

fn server_names(cf: &Conf, cmcf: &Rc<RefCell<CoreMainConf>>, addr: &mut ConfAddr) -> ConfResult {
    let mut ha: HashKeysArrays<Rc<RefCell<CoreSrvConf>>> = HashKeysArrays::new(HashKind::Large);
    let mut regex: Vec<ServerNameRef> = Vec::new();
    for cscf in addr.servers.iter() {
        let c = cscf.borrow();
        for name in c.server_names.iter() {
            if let Some(re) = &name.regex {
                regex.push(ServerNameRef { regex: re.clone(), server: name.server.clone(), name: name.name.clone() });
                continue;
            }
            let rc = ha.add_key(name.name.clone(), name.server.clone(), NGX_HASH_WILDCARD_KEY);
            if rc == NGX_ERROR {
                return Err(ConfError::Logged);
            }
            if rc == NGX_DECLINED {
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "invalid server name or wildcard \"{}\" on {}", B(&name.name), B(&addr.opt.addr_text));
                return Err(ConfError::Logged);
            }
            if rc == NGX_BUSY {
                ngx_log_error!(NGX_LOG_WARN, cf.log, None, "conflicting server name \"{}\" on {}, ignored", B(&name.name), B(&addr.opt.addr_text));
            }
        }
    }
    let (max_size, bucket_size) = {
        let m = cmcf.borrow();
        (*m.server_names_hash_max_size as usize, *m.server_names_hash_bucket_size as usize)
    };
    let hinit = HashInit { name: "server_names_hash", max_size, bucket_size, log: &cf.log };
    let fail = |e: String| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    };
    if !ha.keys().is_empty() {
        let keys: Vec<HashKey<Rc<RefCell<CoreSrvConf>>>> = ha.keys().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        addr.hash = Some(Hash::init(&hinit, keys).map_err(fail)?);
    }
    if !ha.dns_wc_head().is_empty() {
        let mut keys: Vec<HashKey<Rc<RefCell<CoreSrvConf>>>> = ha.dns_wc_head().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        keys.sort_by(|a, b| a.key.cmp(&b.key));
        addr.wc_head = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }
    if !ha.dns_wc_tail().is_empty() {
        let mut keys: Vec<HashKey<Rc<RefCell<CoreSrvConf>>>> = ha.dns_wc_tail().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        keys.sort_by(|a, b| a.key.cmp(&b.key));
        addr.wc_tail = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }
    addr.regex = regex;
    Ok(())
}

fn init_listening(cf: &mut Conf, port: &mut ConfPort) -> ConfResult {
    let last = port.addrs.len();
    let bind_wildcard = if port.addrs[last - 1].opt.wildcard {
        port.addrs[last - 1].opt.bind = true;
        true
    } else {
        false
    };
    let mut i = 0;
    let mut start = 0;
    let mut remaining = last;
    while i < remaining {
        if bind_wildcard && !port.addrs[start + i].opt.bind {
            i += 1;
            continue;
        }
        let ls = add_listening(cf, &port.addrs[start + i])?;
        let naddrs = i + 1;
        let mut addrs = Vec::with_capacity(naddrs);
        for a in port.addrs[start..start + naddrs].iter_mut() {
            let vn = if a.hash.is_some() || a.wc_head.is_some() || a.wc_tail.is_some() || !a.regex.is_empty() {
                Some(Rc::new(VirtualNames {
                    names: HashCombined { hash: a.hash.take().unwrap_or_else(|| Hash::init(&HashInit { name: "server_names_hash", max_size: 1, bucket_size: 64, log: &cf.log }, Vec::new()).unwrap()), wc_head: a.wc_head.take(), wc_tail: a.wc_tail.take() },
                    regex: a.regex.clone(),
                }))
            } else {
                None
            };
            let conf = Rc::new(AddrConf { default_server: a.default_server.clone(), virtual_names: vn, ssl: a.opt.ssl, http2: a.opt.http2, quic: a.opt.quic, proxy_protocol: a.opt.proxy_protocol });
            addrs.push((a.opt.sockaddr.ip_bytes(), conf));
        }
        let hport: Rc<dyn Any> = Rc::new(HttpPort { naddrs, addrs });
        *ls.servers.borrow_mut() = Some(hport);
        cf.cycle.listening.push(ls);
        start += 1;
        remaining -= 1;
    }
    Ok(())
}

fn add_listening(cf: &mut Conf, addr: &ConfAddr) -> Result<Rc<Listening>, ConfError> {
    let ls = Listening::new(addr.opt.sockaddr.clone(), cf.log.clone());
    ls.addr_ntop.set(true);
    let handler: ngx_core::connection::ListenHandler = Rc::new(crate::request_rt::init_connection);
    *ls.handler.borrow_mut() = Some(handler);
    let cscf = addr.default_server.clone();
    ls.pool_size.set(*cscf.borrow().connection_pool_size);
    let clcf = loc_conf_from_ctx(&cscf.borrow().ctx);
    let chain = clcf.borrow().error_log.clone().unwrap_or_else(|| cf.cycle.new_log.clone());
    *ls.log.borrow_mut() = Log::new(chain);
    let mut ls = ls;
    ls.ty = addr.opt.ty;
    *ls.protocol.borrow_mut() = "http";
    ls.backlog.set(addr.opt.backlog);
    ls.rcvbuf.set(addr.opt.rcvbuf);
    ls.sndbuf.set(addr.opt.sndbuf);
    ls.keepalive.set(addr.opt.so_keepalive);
    ls.keepidle.set(addr.opt.tcp_keepidle);
    ls.keepintvl.set(addr.opt.tcp_keepintvl);
    ls.keepcnt.set(addr.opt.tcp_keepcnt);
    ls.deferred_accept.set(addr.opt.deferred_accept);
    ls.ipv6only.set(addr.opt.ipv6only);
    ls.fastopen.set(addr.opt.fastopen);
    ls.reuseport.set(addr.opt.reuseport);
    ls.wildcard.set(addr.opt.wildcard);
    ls.quic.set(addr.opt.quic);
    Ok(Rc::new(ls))
}
