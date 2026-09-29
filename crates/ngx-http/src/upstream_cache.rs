//! The cache of ngx_http_upstream.c (NGX_HTTP_CACHE): the cache fields of
//! ngx_http_upstream_conf_t and their directives, which proxy, fastcgi and
//! the other upstream modules share; ngx_http_upstream_cache (the lookup
//! before connecting), ngx_http_upstream_cache_send,
//! ngx_http_upstream_cache_background_update and
//! ngx_http_upstream_cache_check_range; the cache parts of the headers_in
//! handlers, of ngx_http_upstream_send_response, process_request,
//! test_next, next and finalize_request; and the $upstream_cache_*
//! variables.
//!
//! The upstream drivers (proxy.rs, fastcgi.rs) are not ports of
//! ngx_http_upstream.c, so they call these where ngx_http_upstream.c does
//! the same.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::file_cache::*;
use crate::http_debug;
use crate::request::*;
use crate::script::ComplexValue;
use crate::upstream::*;

/// NGX_CONF_BITMASK_SET
pub const NGX_CONF_BITMASK_SET: u32 = 1;

/// NGX_HTTP_UPSTREAM_INVALID_HEADER
pub const NGX_HTTP_UPSTREAM_INVALID_HEADER: i64 = 40;
/// NGX_HTTP_UPSTREAM_EARLY_HINTS
pub const NGX_HTTP_UPSTREAM_EARLY_HINTS: i64 = 41;

/// ngx_http_upstream_cache_method_mask
pub const CACHE_METHOD_MASK: &[(&str, u32)] = &[("GET", crate::NGX_HTTP_GET), ("HEAD", crate::NGX_HTTP_HEAD), ("POST", crate::NGX_HTTP_POST)];

/// ngx_http_upstream_ignore_headers_masks
pub const IGNORE_HEADERS_MASKS: &[(&str, u32)] = &[
    ("X-Accel-Redirect", NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT),
    ("X-Accel-Expires", NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES),
    ("X-Accel-Limit-Rate", NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE),
    ("X-Accel-Buffering", NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING),
    ("X-Accel-Charset", NGX_HTTP_UPSTREAM_IGN_XA_CHARSET),
    ("Expires", NGX_HTTP_UPSTREAM_IGN_EXPIRES),
    ("Cache-Control", NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL),
    ("Set-Cookie", NGX_HTTP_UPSTREAM_IGN_SET_COOKIE),
    ("Vary", NGX_HTTP_UPSTREAM_IGN_VARY),
];

/// The cache fields of ngx_http_upstream_conf_t (and ignore_headers, which
/// the cache handlers of the response headers test), with the cache_key of
/// the module's location configuration.
#[derive(Clone, Default)]
pub struct UpstreamCacheConf {
    /// upstream.cache: unset, 0 ("off"), or 1 (a zone or a variable)
    pub cache: Val<bool>,
    pub cache_zone: Option<Rc<ShmZone>>,
    pub cache_value: Option<Rc<ComplexValue>>,

    pub cache_min_uses: Val<usize>,
    /// a bitmask, 0 when not set
    pub cache_use_stale: u32,
    /// a bitmask, 0 when not set
    pub cache_methods: u32,

    pub cache_max_range_offset: Val<i64>,

    pub cache_lock: Val<bool>,
    pub cache_lock_timeout: Val<u64>,
    pub cache_lock_age: Val<u64>,

    pub cache_revalidate: Val<bool>,
    pub cache_convert_head: Val<bool>,
    pub cache_background_update: Val<bool>,

    pub cache_valid: Val<Option<Rc<Vec<CacheValid>>>>,
    pub cache_bypass: Val<Option<Rc<Vec<ComplexValue>>>>,
    pub no_cache: Val<Option<Rc<Vec<ComplexValue>>>>,

    /// plcf->cache_key, flcf->cache_key
    pub cache_key: Option<Rc<ComplexValue>>,

    /// upstream.ignore_headers: a bitmask, 0 when not set
    pub ignore_headers: u32,
}

impl UpstreamCacheConf {
    /// u->conf->cache > 0
    pub fn enabled(&self) -> bool {
        self.cache.get_or(false)
    }

    /// u->conf->ignore_headers & mask
    pub fn ignores(&self, mask: u32) -> bool {
        self.ignore_headers & mask != 0
    }

    /// The cache part of ngx_http_proxy_merge_loc_conf and
    /// ngx_http_fastcgi_merge_loc_conf. `module` is "proxy" or "fastcgi"
    /// for the messages; `convert_head` is whether the module has the
    /// cache_convert_head directive (fastcgi does not: the response to HEAD
    /// is cached as it is).
    pub fn merge(&mut self, cf: &Conf, prev: &UpstreamCacheConf, module: &str, convert_head: bool) -> ConfResult {
        // ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
        // prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET)
        if self.ignore_headers == 0 {
            self.ignore_headers = if prev.ignore_headers == 0 { NGX_CONF_BITMASK_SET } else { prev.ignore_headers };
        }

        if !self.cache.is_set() {
            self.cache.merge(&prev.cache, false);

            self.cache_zone = prev.cache_zone.clone();
            self.cache_value = prev.cache_value.clone();
        }

        if let Some(shm_zone) = &self.cache_zone {
            if shm_zone.data.borrow().is_none() {
                return Err(cf.emerg(format_args!("\"{}_cache\" zone \"{}\" is unknown", module, B(shm_zone.name()))));
            }
        }

        self.cache_min_uses.merge(&prev.cache_min_uses, 1);

        self.cache_max_range_offset.merge(&prev.cache_max_range_offset, i64::MAX);

        if self.cache_use_stale == 0 {
            self.cache_use_stale = if prev.cache_use_stale == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF } else { prev.cache_use_stale };
        }

        if self.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF != 0 {
            self.cache_use_stale = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
        }

        if self.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR != 0 {
            self.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
        }

        if self.cache_methods == 0 {
            self.cache_methods = prev.cache_methods;
        }

        self.cache_methods |= crate::NGX_HTTP_GET | crate::NGX_HTTP_HEAD;

        self.cache_bypass.merge_opt(&prev.cache_bypass);
        if !self.cache_bypass.is_set() {
            self.cache_bypass = Val::set(None);
        }

        self.no_cache.merge_opt(&prev.no_cache);
        if !self.no_cache.is_set() {
            self.no_cache = Val::set(None);
        }

        self.cache_valid.merge_opt(&prev.cache_valid);
        if !self.cache_valid.is_set() {
            self.cache_valid = Val::set(None);
        }

        if self.cache_key.is_none() {
            self.cache_key = prev.cache_key.clone();
        }

        if self.enabled() && self.cache_key.is_none() && module == "fastcgi" {
            cf.warn(format_args!("no \"{}_cache_key\" for \"{}_cache\"", module, module));
        }

        self.cache_lock.merge(&prev.cache_lock, false);
        self.cache_lock_timeout.merge(&prev.cache_lock_timeout, 5000);
        self.cache_lock_age.merge(&prev.cache_lock_age, 5000);
        self.cache_revalidate.merge(&prev.cache_revalidate, false);
        if convert_head {
            self.cache_convert_head.merge(&prev.cache_convert_head, true);
        } else {
            // not a directive of the module: 0 from ngx_pcalloc()
            self.cache_convert_head = Val::set(false);
        }
        self.cache_background_update.merge(&prev.cache_background_update, false);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

/// A location configuration with the cache fields of an upstream (the
/// offsets of the ngx_conf_set_*_slot directives into conf->upstream).
pub trait UpstreamCacheLocConf: 'static {
    fn upstream_cache(&mut self) -> &mut UpstreamCacheConf;
}

fn ucf_of<T: UpstreamCacheLocConf>(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<T>> {
    conf_rc::<T>(conf.as_ref().expect("conf"))
}

/// ngx_http_proxy_cache, ngx_http_fastcgi_cache: "proxy_cache zone | off"
/// (the "is incompatible with *_store" check is the module's). `tag` is
/// the module of the keys zone.
pub fn cache_slot(cf: &mut Conf, ucf: &mut UpstreamCacheConf, tag: &'static str) -> ConfResult {
    let value = cf.args.clone();

    if ucf.cache.is_set() {
        return Err(msg("is duplicate"));
    }

    if value[1] == b"off" {
        ucf.cache = Val::set(false);
        return Ok(());
    }

    ucf.cache = Val::set(true);

    let cv = crate::script::compile_complex_value(cf, &value[1], 0)?;

    if !cv.is_constant() {
        ucf.cache_value = Some(Rc::new(cv));
        return Ok(());
    }

    ucf.cache_zone = Some(ngx_core::cycle::shared_memory_add(cf, &value[1], 0, tag)?);

    Ok(())
}

/// ngx_http_proxy_cache_key, ngx_http_fastcgi_cache_key
pub fn cache_key_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);

    if cell.borrow_mut().upstream_cache().cache_key.is_some() {
        return Err(msg("is duplicate"));
    }

    let v = cf.args[1].clone();
    let cv = crate::script::compile_complex_value(cf, &v, 0)?;

    cell.borrow_mut().upstream_cache().cache_key = Some(Rc::new(cv));

    Ok(())
}

/// ngx_http_set_predicate_slot: the values are added to those of a
/// previous directive.
fn set_predicate_slot(cf: &mut Conf, a: &mut Val<Option<Rc<Vec<ComplexValue>>>>) -> ConfResult {
    let mut list: Vec<ComplexValue> = match a.as_option().cloned().flatten() {
        Some(v) => (*v).clone(),
        None => Vec::new(),
    };

    let args = cf.args.clone();

    for v in &args[1..] {
        list.push(crate::script::compile_complex_value(cf, v, 0)?);
    }

    *a = Val::set(Some(Rc::new(list)));

    Ok(())
}

/// "*_cache_bypass string ..."
pub fn cache_bypass_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().upstream_cache().cache_bypass);
    let rc = set_predicate_slot(cf, &mut slot);
    cell.borrow_mut().upstream_cache().cache_bypass = slot;
    rc
}

/// "*_no_cache string ..."
pub fn no_cache_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().upstream_cache().no_cache);
    let rc = set_predicate_slot(cf, &mut slot);
    cell.borrow_mut().upstream_cache().no_cache = slot;
    rc
}

/// "*_cache_valid [code ...] time" (ngx_http_file_cache_valid_set_slot)
pub fn cache_valid_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().upstream_cache().cache_valid);
    let rc = file_cache_valid_set_slot(cf, cmd, &mut slot);
    cell.borrow_mut().upstream_cache().cache_valid = slot;
    rc
}

/// "*_cache_min_uses number" (ngx_conf_set_num_slot)
pub fn cache_min_uses_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    let slot = &mut c.upstream_cache().cache_min_uses;

    let mut n: Val<i64> = if slot.is_set() { Val::set(*slot.get() as i64) } else { Val::unset() };
    set_num(cf, cmd, &mut n)?;
    *slot = Val::set(*n.get() as usize);

    Ok(())
}

/// "*_cache_max_range_offset number" (ngx_conf_set_off_slot)
pub fn cache_max_range_offset_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_off(cf, cmd, &mut c.upstream_cache().cache_max_range_offset)
}

/// "*_cache_methods GET | HEAD | POST ..." (ngx_conf_set_bitmask_slot with
/// ngx_http_upstream_cache_method_mask)
pub fn cache_methods_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.upstream_cache().cache_methods, CACHE_METHOD_MASK)
}

/// "*_ignore_headers field ..." (ngx_conf_set_bitmask_slot with
/// ngx_http_upstream_ignore_headers_masks)
pub fn ignore_headers_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.upstream_cache().ignore_headers, IGNORE_HEADERS_MASKS)
}

/// "*_cache_use_stale ..." with the next_upstream masks of the module
pub fn cache_use_stale_slot(cf: &mut Conf, cmd: &Command, ucf: &mut UpstreamCacheConf, masks: &[(&str, u32)]) -> ConfResult {
    set_bitmask(cf, cmd, &mut ucf.cache_use_stale, masks)
}

/// "*_cache_lock on | off"
pub fn cache_lock_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_flag(cf, cmd, &mut c.upstream_cache().cache_lock)
}

/// "*_cache_lock_timeout time"
pub fn cache_lock_timeout_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_msec(cf, cmd, &mut c.upstream_cache().cache_lock_timeout)
}

/// "*_cache_lock_age time"
pub fn cache_lock_age_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_msec(cf, cmd, &mut c.upstream_cache().cache_lock_age)
}

/// "*_cache_revalidate on | off"
pub fn cache_revalidate_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_flag(cf, cmd, &mut c.upstream_cache().cache_revalidate)
}

/// "*_cache_convert_head on | off"
pub fn cache_convert_head_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_flag(cf, cmd, &mut c.upstream_cache().cache_convert_head)
}

/// "*_cache_background_update on | off"
pub fn cache_background_update_slot<T: UpstreamCacheLocConf>(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = ucf_of::<T>(&conf);
    let mut c = cell.borrow_mut();
    set_flag(cf, cmd, &mut c.upstream_cache().cache_background_update)
}

/// The main configuration of an upstream module with caches:
/// ngx_http_proxy_main_conf_t, ngx_http_fastcgi_main_conf_t.
#[derive(Default)]
pub struct UpstreamCacheMainConf {
    /// caches: the ngx_http_file_cache_t of *_cache_path
    pub caches: Vec<Rc<FileCache>>,
}

pub fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UpstreamCacheMainConf::default())
}

/// "*_cache_path ..." (ngx_http_file_cache_set_slot with cmd->post the
/// module)
pub fn cache_path_slot(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>, tag: &'static str) -> ConfResult {
    let cell = conf_rc::<UpstreamCacheMainConf>(conf.as_ref().expect("conf"));
    let mut caches = std::mem::take(&mut cell.borrow_mut().caches);
    let rc = file_cache_set_slot(cf, cmd, &mut caches, tag);
    cell.borrow_mut().caches = caches;
    rc
}

// ---------------------------------------------------------------------------
// r->upstream
// ---------------------------------------------------------------------------

/// The fields of ngx_http_upstream_t the cache works with, in r->upstream.
pub struct UpstreamCache {
    /// u->conf: the cache fields
    pub conf: UpstreamCacheConf,
    /// u->caches
    pub caches: Rc<Vec<Rc<FileCache>>>,
    /// u->conf->module
    pub module: &'static str,
    /// u->conf->buffer_size
    pub buffer_size: usize,

    /// u->cache_status
    pub cache_status: Cell<usize>,
    /// u->cacheable
    pub cacheable: Cell<bool>,
    /// u->method: GET instead of HEAD to cache the response
    pub method: RefCell<Option<&'static [u8]>>,
}

/// ngx_http_upstream_create: r->upstream anew, r->cache NULL.
pub fn upstream_create(r: &R, conf: UpstreamCacheConf, caches: Rc<Vec<Rc<FileCache>>>, module: &'static str, buffer_size: usize) -> Rc<UpstreamCache> {
    let u = Rc::new(UpstreamCache {
        conf,
        caches,
        module,
        buffer_size,
        cache_status: Cell::new(0),
        cacheable: Cell::new(false),
        method: RefCell::new(None),
    });

    let any: Rc<dyn Any> = u.clone();
    *r.upstream.borrow_mut() = Some(any);

    *r.cache.borrow_mut() = None;

    u
}

/// r->upstream
pub fn upstream_of(r: &Request) -> Option<Rc<UpstreamCache>> {
    r.upstream.borrow().clone().and_then(|u| u.downcast::<UpstreamCache>().ok())
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_init_request
// ---------------------------------------------------------------------------

/// ngx_http_upstream_cache: NGX_OK to send the response from the cache
/// (ngx_http_upstream_cache_send), NGX_DECLINED to go to the upstream,
/// NGX_BUSY to wait for the cache lock (file_cache_lock_wait_handler) and
/// call again, NGX_ERROR, or the status of a cached error.
pub fn upstream_cache(r: &R, u: &UpstreamCache, create_key: &dyn Fn(&R, &mut Vec<Vec<u8>>) -> i64) -> i64 {
    let conf = &u.conf;

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => {
            if r.method.get() & conf.cache_methods == 0 {
                return NGX_DECLINED;
            }

            let cache = match upstream_cache_get(r, u) {
                Ok(c) => c,
                Err(rc) => return rc,
            };

            if r.method.get() == crate::NGX_HTTP_HEAD && conf.cache_convert_head.get_or(true) {
                *u.method.borrow_mut() = Some(b"GET");
            }

            let c_rc = file_cache_new(r);

            let mut c = c_rc.borrow_mut();

            let mut keys = Vec::new();

            if create_key(r, &mut keys) != NGX_OK {
                return NGX_ERROR;
            }

            c.keys = keys;

            // TODO: add keys

            file_cache_create_key(r, &mut c);

            if c.header_start + 256 > u.buffer_size {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "{}_buffer_size {} is not enough for cache key, it should be increased to at least {}",
                    u.module,
                    u.buffer_size,
                    (c.header_start + 256 + 1023) & !1023
                );

                drop(c);
                *r.cache.borrow_mut() = None;
                return NGX_DECLINED;
            }

            u.cacheable.set(true);

            c.body_start = u.buffer_size;
            c.min_uses = conf.cache_min_uses.get_or(1);
            c.file_cache = Some(cache);

            match crate::script::test_predicates(r, conf.cache_bypass.as_option().unwrap_or(&None)) {
                NGX_ERROR => return NGX_ERROR,
                NGX_DECLINED => {
                    u.cache_status.set(NGX_HTTP_CACHE_BYPASS);
                    return NGX_DECLINED;
                }
                _ => {}
            }

            c.lock = conf.cache_lock.get_or(false);
            c.lock_timeout = conf.cache_lock_timeout.get_or(5000);
            c.lock_age = conf.cache_lock_age.get_or(5000);

            u.cache_status.set(NGX_HTTP_CACHE_MISS);

            drop(c);

            c_rc
        }
    };

    let mut rc = file_cache_open(r);

    http_debug!(r, "http upstream cache: {}", rc);

    let use_updating = conf.cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING != 0;

    if rc == NGX_HTTP_CACHE_STALE as i64 {
        let stale_updating = c_rc.borrow().stale_updating;

        if (use_updating || stale_updating) && !r.background.get() && conf.cache_background_update.get_or(false) {
            if upstream_cache_background_update(r) == NGX_OK {
                c_rc.borrow_mut().background = true;
                u.cache_status.set(rc as usize);
                rc = NGX_OK;
            } else {
                rc = NGX_ERROR;
            }
        }
    } else if rc == NGX_HTTP_CACHE_UPDATING as i64 {
        let stale_updating = c_rc.borrow().stale_updating;

        if (use_updating || stale_updating) && !r.background.get() {
            u.cache_status.set(rc as usize);
            rc = NGX_OK;
        } else {
            rc = NGX_HTTP_CACHE_STALE as i64;
        }
    } else if rc == NGX_OK {
        u.cache_status.set(NGX_HTTP_CACHE_HIT);
    }

    match rc {
        NGX_OK => return NGX_OK,

        rc if rc == NGX_HTTP_CACHE_STALE as i64 => {
            let mut c = c_rc.borrow_mut();

            c.valid_sec = 0;
            c.updating_sec = 0;
            c.error_sec = 0;

            u.cache_status.set(NGX_HTTP_CACHE_EXPIRED);
        }

        NGX_DECLINED => {}

        rc if rc == NGX_HTTP_CACHE_SCARCE as i64 => {
            u.cacheable.set(false);
        }

        NGX_AGAIN => return NGX_BUSY,

        NGX_ERROR => return NGX_ERROR,

        _ => {
            // cached NGX_HTTP_BAD_GATEWAY, NGX_HTTP_GATEWAY_TIME_OUT, etc.

            u.cache_status.set(NGX_HTTP_CACHE_HIT);

            return rc;
        }
    }

    if upstream_cache_check_range(r, u) == NGX_DECLINED {
        u.cacheable.set(false);
    }

    r.cached.set(false);

    NGX_DECLINED
}

/// ngx_http_upstream_init_request with a cache: ngx_http_upstream_cache
/// until it does not return NGX_BUSY, waiting for the cache lock meanwhile
/// (r->write_event_handler = ngx_http_upstream_init_request).
pub async fn upstream_cache_wait(r: &R, u: &UpstreamCache, create_key: &dyn Fn(&R, &mut Vec<Vec<u8>>) -> i64) -> i64 {
    loop {
        let rc = upstream_cache(r, u, create_key);

        if rc != NGX_BUSY {
            return rc;
        }

        file_cache_lock_wait_handler(r).await;
    }
}

/// ngx_http_upstream_cache_get: the cache of *_cache, or of the value of
/// its variables.
fn upstream_cache_get(r: &R, u: &UpstreamCache) -> Result<Rc<FileCache>, i64> {
    if let Some(zone) = &u.conf.cache_zone {
        return zone.data::<FileCache>().ok_or(NGX_ERROR);
    }

    let cv = match &u.conf.cache_value {
        Some(cv) => cv.clone(),
        None => return Err(NGX_DECLINED),
    };

    let val = crate::script::complex_value(r, &cv).map_err(|_| NGX_ERROR)?;

    if val.is_empty() || val == b"off" {
        return Err(NGX_DECLINED);
    }

    for cache in u.caches.iter() {
        if cache.name == val {
            return Ok(cache.clone());
        }
    }

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "cache \"{}\" not found", B(&val));

    Err(NGX_ERROR)
}

/// ngx_http_upstream_cache_send: the response header of the cache file
/// goes through the module's process_header and
/// ngx_http_upstream_process_headers (`process`, given the buffer from
/// header_start: NGX_OK, NGX_DONE when the request was finalized,
/// NGX_ERROR, or NGX_AGAIN, NGX_HTTP_UPSTREAM_EARLY_HINTS or
/// NGX_HTTP_UPSTREAM_INVALID_HEADER for an invalid header), then the body
/// is sent from the file.
pub async fn upstream_cache_send<F, Fut>(r: &R, process: F) -> i64
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = i64>,
{
    r.cached.set(true);

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let (header_start, body_start, buf, name) = {
        let c = c_rc.borrow();
        (c.header_start, c.body_start, c.buf.clone(), c.file_name.clone())
    };

    if header_start == body_start {
        r.http_version.set(crate::NGX_HTTP_VERSION_9);
        return cache_send(r).await;
    }

    // TODO: cache stack

    // u->buffer = *c->buf; u->buffer.pos += c->header_start
    let header = buf.get(header_start..).unwrap_or(&[]).to_vec();

    let mut rc = process(header).await;

    if rc == NGX_OK {
        return cache_send(r).await;
    }

    if rc == NGX_DONE {
        return NGX_DONE;
    }

    if rc == NGX_ERROR {
        return NGX_ERROR;
    }

    if rc == NGX_AGAIN || rc == NGX_HTTP_UPSTREAM_EARLY_HINTS {
        rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    // rc == NGX_HTTP_UPSTREAM_INVALID_HEADER

    ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" contains invalid header", B(&name));

    // TODO: delete file

    rc
}

/// ngx_http_upstream_cache_background_update: a cloned background
/// subrequest updates the cache while the stale response is sent.
fn upstream_cache_background_update(r: &R) -> i64 {
    if r.is_main() {
        r.preserve_body.set(true);
    }

    let uri = r.uri.borrow().clone();
    let args = r.args.borrow().clone();

    match crate::request_rt::background_subrequest(r, &uri, Some(&args), crate::NGX_HTTP_SUBREQUEST_CLONE | crate::NGX_HTTP_SUBREQUEST_BACKGROUND, true) {
        Ok(()) => NGX_OK,
        Err(()) => NGX_ERROR,
    }
}

/// ngx_http_upstream_cache_check_range: NGX_DECLINED (the response is not
/// cached) for a range at *_cache_max_range_offset or later, or at the end.
fn upstream_cache_check_range(r: &R, u: &UpstreamCache) -> i64 {
    let h = match r.headers_in.borrow().range.first() {
        Some(h) => h.value.borrow().clone(),
        None => return NGX_OK,
    };

    let max_range_offset = u.conf.cache_max_range_offset.get_or(i64::MAX);

    if !u.cacheable.get() || max_range_offset == i64::MAX {
        return NGX_OK;
    }

    if max_range_offset == 0 {
        return NGX_DECLINED;
    }

    if h.len() < 7 || !h[..6].eq_ignore_ascii_case(b"bytes=") {
        return NGX_OK;
    }

    let mut p = 6;

    while p < h.len() && h[p] == b' ' {
        p += 1;
    }

    if p < h.len() && h[p] == b'-' {
        return NGX_DECLINED;
    }

    let start = p;

    while p < h.len() && h[p].is_ascii_digit() {
        p += 1;
    }

    // ngx_atoof(): NGX_ERROR for no digits
    let offset = ngx_core::string::atoof(&h[start..p]).unwrap_or(-1);

    if offset >= max_range_offset {
        return NGX_DECLINED;
    }

    NGX_OK
}

// ---------------------------------------------------------------------------
// the headers_in handlers
// ---------------------------------------------------------------------------

/// The fields of u->headers_in the cache handlers of the response headers
/// set.
#[derive(Default, Clone)]
pub struct CacheHeadersIn {
    pub no_cache: bool,
    pub expired: bool,
    /// u->headers_in.x_accel_expires, u->headers_in.expires were seen
    pub x_accel_expires: bool,
    pub expires: bool,
    /// u->headers_in.vary
    pub vary: Vec<Vec<u8>>,
    /// u->headers_in.last_modified_time (-1 when none)
    pub last_modified_time: i64,
    /// u->headers_in.etag
    pub etag: Option<Vec<u8>>,
}

impl CacheHeadersIn {
    pub fn new() -> CacheHeadersIn {
        CacheHeadersIn { last_modified_time: -1, ..Default::default() }
    }
}

/// The cache handlers of ngx_http_upstream_headers_in[] for a response
/// header of the upstream (after the duplicate checks of "Expires" and
/// "X-Accel-Expires", whose duplicates are not processed):
/// ngx_http_upstream_process_set_cookie, _cache_control, _expires,
/// _accel_expires, _vary, _last_modified and the etag of
/// ngx_http_upstream_process_header_line.
pub fn process_header_line(r: &R, hin: &mut CacheHeadersIn, lowcase_key: &[u8], value: &[u8]) {
    let u = upstream_of(r);

    match lowcase_key {
        b"set-cookie" => {
            if let Some(u) = &u {
                if !u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_SET_COOKIE) {
                    u.cacheable.set(false);
                }
            }
        }

        b"cache-control" => {
            if let Some(u) = &u {
                process_cache_control(r, u, hin, value);
            }
        }

        b"expires" => {
            hin.expires = true;

            if let Some(u) = &u {
                process_expires(r, u, hin, value);
            }
        }

        b"x-accel-expires" => {
            hin.x_accel_expires = true;

            if let Some(u) = &u {
                process_accel_expires(r, u, hin, value);
            }
        }

        b"vary" => {
            hin.vary.push(value.to_vec());

            if let Some(u) = &u {
                process_vary(r, u, hin);
            }
        }

        b"last-modified" => {
            // ngx_http_upstream_process_last_modified
            if u.as_ref().is_some_and(|u| u.cacheable.get()) {
                hin.last_modified_time = ngx_core::parse::parse_http_time(value).unwrap_or(-1);
            }
        }

        b"etag" => {
            hin.etag = Some(value.to_vec());
        }

        _ => {}
    }
}

/// ngx_strlcasestrn: the position of `needle` in `s`, case-insensitively.
fn strlcasestrn(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > s.len() {
        return None;
    }

    (0..=s.len() - needle.len()).find(|&i| s[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// ngx_http_upstream_process_cache_control
fn process_cache_control(r: &R, u: &UpstreamCache, hin: &mut CacheHeadersIn, value: &[u8]) {
    if u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
        return;
    }

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let mut c = c_rc.borrow_mut();

    'extensions: {
        if c.valid_sec != 0 && hin.x_accel_expires {
            break 'extensions;
        }

        if strlcasestrn(value, b"no-cache").is_some() || strlcasestrn(value, b"no-store").is_some() || strlcasestrn(value, b"private").is_some() {
            hin.no_cache = true;
            return;
        }

        let (p, offset) = match strlcasestrn(value, b"s-maxage=") {
            Some(p) => (Some(p), 9),
            None => (strlcasestrn(value, b"max-age="), 8),
        };

        if let Some(p) = p {
            let n = process_delta_seconds(&value[p + offset..]);

            if n == NGX_ERROR {
                u.cacheable.set(false);
                return;
            }

            if n == 0 {
                hin.no_cache = true;
                return;
            }

            c.valid_sec = (ngx_core::times::time() as u64).saturating_add(n as u64).min(i64::MAX as u64) as i64;
            hin.expired = false;
        }
    }

    // extensions:

    if let Some(p) = strlcasestrn(value, b"stale-while-revalidate=") {
        let n = process_delta_seconds(&value[p + 23..]);

        if n == NGX_ERROR {
            u.cacheable.set(false);
            return;
        }

        c.updating_sec = n;
        c.error_sec = n;
    }

    if let Some(p) = strlcasestrn(value, b"stale-if-error=") {
        let n = process_delta_seconds(&value[p + 15..]);

        if n == NGX_ERROR {
            u.cacheable.set(false);
            return;
        }

        c.error_sec = n;
    }
}

/// ngx_http_upstream_process_delta_seconds
fn process_delta_seconds(p: &[u8]) -> i64 {
    let cutoff = i64::MAX / 10;
    let cutlim = i64::MAX % 10;

    let mut n: i64 = 0;

    for &ch in p {
        if ch == b',' || ch == b';' || ch == b' ' {
            break;
        }

        if !ch.is_ascii_digit() {
            return NGX_ERROR;
        }

        let d = (ch - b'0') as i64;

        if n >= cutoff && (n > cutoff || d > cutlim) {
            n = i64::MAX;
            break;
        }

        n = n * 10 + d;
    }

    n
}

/// ngx_http_upstream_process_expires
fn process_expires(r: &R, u: &UpstreamCache, hin: &mut CacheHeadersIn, value: &[u8]) {
    if u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_EXPIRES) {
        return;
    }

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let mut c = c_rc.borrow_mut();

    if c.valid_sec != 0 {
        return;
    }

    let expires = ngx_core::parse::parse_http_time(value);

    match expires {
        Some(e) if e >= ngx_core::times::time() => c.valid_sec = e,
        _ => hin.expired = true,
    }
}

/// ngx_http_upstream_process_accel_expires
fn process_accel_expires(r: &R, u: &UpstreamCache, hin: &mut CacheHeadersIn, value: &[u8]) {
    if u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
        return;
    }

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let mut c = c_rc.borrow_mut();

    if value.first() != Some(&b'@') {
        match ngx_core::string::atoi(value) {
            Some(0) => {
                u.cacheable.set(false);
            }
            None => {}
            Some(n) => {
                c.valid_sec = ngx_core::times::time() + n;
                hin.no_cache = false;
                hin.expired = false;
            }
        }

        return;
    }

    if let Some(n) = ngx_core::string::atoi(&value[1..]) {
        c.valid_sec = n;
        hin.no_cache = false;
        hin.expired = false;
    }
}

/// ngx_http_upstream_process_vary (the header is added to hin.vary first)
fn process_vary(r: &R, u: &UpstreamCache, hin: &mut CacheHeadersIn) {
    if u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_VARY) {
        return;
    }

    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    if !u.cacheable.get() {
        return;
    }

    let last = hin.vary.last().cloned().unwrap_or_default();

    if last == b"*" {
        u.cacheable.set(false);
        return;
    }

    let vary = if hin.vary.len() > 1 { hin.vary.join(&b", "[..]) } else { last };

    if vary.len() > NGX_HTTP_CACHE_VARY_LEN {
        u.cacheable.set(false);
    }

    c_rc.borrow_mut().vary = vary;
}

/// The beginning of ngx_http_upstream_process_headers: a response marked
/// "no-cache" or expired is not cacheable.
pub fn process_headers_cacheable(r: &R, hin: &CacheHeadersIn) {
    if let Some(u) = upstream_of(r) {
        if hin.no_cache || hin.expired {
            u.cacheable.set(false);
        }
    }
}

/// u->cacheable (0 without r->upstream)
pub fn cacheable(r: &R) -> bool {
    upstream_of(r).map(|u| u.cacheable.get()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_test_next, ngx_http_upstream_next,
// ngx_http_upstream_intercept_errors
// ---------------------------------------------------------------------------

/// The stale response of ngx_http_upstream_test_next for a status the
/// upstream sent: u->cache_status is EXPIRED and *_cache_use_stale has the
/// status.
pub fn test_next_stale(r: &R, mask: u32) -> bool {
    match upstream_of(r) {
        Some(u) => u.cache_status.get() == NGX_HTTP_CACHE_EXPIRED && u.conf.cache_use_stale & mask != 0,
        None => false,
    }
}

/// The stale response of ngx_http_upstream_next when there is no next
/// upstream to try: u->cache_status is EXPIRED and *_cache_use_stale has
/// the failure, or the response may be stale on errors (stale-if-error).
pub fn next_stale(r: &R, ft_type: u32) -> bool {
    let u = match upstream_of(r) {
        Some(u) => u,
        None => return false,
    };

    if u.cache_status.get() != NGX_HTTP_CACHE_EXPIRED {
        return false;
    }

    let stale_error = cache_of(r).map(|c| c.borrow().stale_error).unwrap_or(false);

    u.conf.cache_use_stale & ft_type != 0 || stale_error
}

/// The 304 of ngx_http_upstream_test_next: the expired response was
/// revalidated.
pub fn test_next_not_modified(r: &R, status: i64) -> bool {
    match upstream_of(r) {
        Some(u) => status == crate::NGX_HTTP_NOT_MODIFIED && u.cache_status.get() == NGX_HTTP_CACHE_EXPIRED && u.conf.cache_revalidate.get_or(false),
        None => false,
    }
}

/// What ngx_http_upstream_test_next saves of the cache before the
/// revalidated response is sent (valid_sec, updating_sec, error_sec of the
/// 304, and the time).
pub struct NotModified {
    now: i64,
    valid: i64,
    updating: i64,
    error: i64,
}

/// The first part of the 304 case of ngx_http_upstream_test_next.
pub fn not_modified_start(r: &R) -> NotModified {
    http_debug!(r, "http upstream not modified");

    let now = ngx_core::times::time();

    let (valid, updating, error) = match cache_of(r) {
        Some(c) => {
            let c = c.borrow();
            (c.valid_sec, c.updating_sec, c.error_sec)
        }
        None => (0, 0, 0),
    };

    if let Some(u) = upstream_of(r) {
        u.cache_status.set(NGX_HTTP_CACHE_REVALIDATED);
    }

    NotModified { now, valid, updating, error }
}

/// The part of the 304 case after ngx_http_upstream_cache_send: the time
/// the revalidated response is valid, to the cache file header. `status`
/// is u->headers_in.status_n, now that of the cached response.
pub fn not_modified_finish(r: &R, saved: NotModified, status: i64) {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let mut valid = saved.valid;
    let mut updating = saved.updating;
    let mut error = saved.error;

    let mut c = c_rc.borrow_mut();

    if valid == 0 {
        valid = c.valid_sec;
        updating = c.updating_sec;
        error = c.error_sec;
    }

    if valid == 0 {
        let cache_valid = upstream_of(r).and_then(|u| u.conf.cache_valid.as_option().cloned().flatten());

        valid = file_cache_valid(cache_valid.as_deref().map(|v| v.as_slice()), status as usize);

        if valid != 0 {
            valid += saved.now;
        }
    }

    if valid != 0 {
        c.valid_sec = valid;
        c.updating_sec = updating;
        c.error_sec = error;

        c.date = saved.now;

        file_cache_update_header(r, &mut c);
    }
}

/// The cache part of ngx_http_upstream_intercept_errors: the status is
/// cached (in the keys zone) for its *_cache_valid time.
pub fn intercept_errors(r: &R, status: i64, hin: &CacheHeadersIn) {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let u = match upstream_of(r) {
        Some(u) => u,
        None => return,
    };

    if hin.no_cache || hin.expired {
        u.cacheable.set(false);
    }

    let mut c = c_rc.borrow_mut();

    if u.cacheable.get() {
        let mut valid = c.valid_sec;

        if valid == 0 {
            let cache_valid = u.conf.cache_valid.as_option().cloned().flatten();

            valid = file_cache_valid(cache_valid.as_deref().map(|v| v.as_slice()), status as usize);

            if valid != 0 {
                c.valid_sec = ngx_core::times::time() + valid;
            }
        }

        if valid != 0 {
            c.error = status as usize;
        }
    }

    file_cache_free(&mut c, None);
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_send_response, ngx_http_upstream_process_request,
// ngx_http_upstream_finalize_request
// ---------------------------------------------------------------------------

/// The cache part of ngx_http_upstream_send_response for a buffered
/// response, after the header was sent: the cache file is closed, the
/// response checked against *_no_cache and the valid times, and, if it is
/// cacheable, the header of the new cache file made (the key line after
/// it). `raw_header_len` is the length of the response header as the
/// upstream sent it (u->buffer.pos - start - header_start).
pub fn send_response(r: &R, status: i64, hin: &CacheHeadersIn, raw_header_len: usize) -> Result<Option<Vec<u8>>, ()> {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return Ok(None),
    };

    let u = match upstream_of(r) {
        Some(u) => u,
        None => return Ok(None),
    };

    c_rc.borrow_mut().close_file();

    match crate::script::test_predicates(r, u.conf.no_cache.as_option().unwrap_or(&None)) {
        NGX_ERROR => return Err(()),

        NGX_DECLINED => u.cacheable.set(false),

        _ => {
            if u.cache_status.get() == NGX_HTTP_CACHE_BYPASS {
                // create cache if previously bypassed

                if file_cache_create(r) != NGX_OK {
                    return Err(());
                }
            }
        }
    }

    let mut header = None;

    if u.cacheable.get() {
        let mut c = c_rc.borrow_mut();

        let now = ngx_core::times::time();

        let mut valid = c.valid_sec;

        if valid == 0 {
            let cache_valid = u.conf.cache_valid.as_option().cloned().flatten();

            valid = file_cache_valid(cache_valid.as_deref().map(|v| v.as_slice()), status as usize);

            if valid != 0 {
                c.valid_sec = now + valid;
            }
        }

        if valid != 0 {
            c.date = now;
            c.body_start = c.header_start + raw_header_len;

            if status == crate::NGX_HTTP_OK || status == crate::NGX_HTTP_PARTIAL_CONTENT {
                c.last_modified = hin.last_modified_time;

                c.etag = hin.etag.clone().unwrap_or_default();
            } else {
                c.last_modified = -1;
                c.etag.clear();
            }

            match file_cache_set_header(r, &mut c) {
                Ok(h) => header = Some(h),
                Err(()) => return Err(()),
            }
        } else {
            u.cacheable.set(false);
        }
    }

    http_debug!(r, "http cacheable: {}", u.cacheable.get() as i32);

    if !u.cacheable.get() {
        file_cache_free(&mut c_rc.borrow_mut(), None);
    }

    Ok(header)
}

/// The cache free of ngx_http_upstream_send_response for an unbuffered
/// response or an upgraded connection, and that of
/// ngx_http_upstream_finalize_request.
pub fn free(r: &R, tf: Option<&CacheTempFile>) {
    if let Some(c) = cache_of(r) {
        file_cache_free(&mut c.borrow_mut(), tf);
    }
}

/// The cache free of ngx_http_upstream_finalize_request on the ways out of
/// an upstream request which do not call finalize() (the request finalized
/// before a response, the client closing the connection): the cache of the
/// request when the upstream starts.
pub struct CacheGuard(Option<Rc<RefCell<HttpCache>>>);

impl CacheGuard {
    pub fn new(r: &R) -> CacheGuard {
        CacheGuard(cache_of(r))
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            if let Ok(mut c) = c.try_borrow_mut() {
                file_cache_free(&mut c, None);
            }
        }
    }
}

/// The cache part of ngx_http_upstream_finalize_request: an error of the
/// upstream (502, 504) is cached for its *_cache_valid time.
pub fn finalize(r: &R, rc: i64, tf: Option<&CacheTempFile>) {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    let mut c = c_rc.borrow_mut();

    if let Some(u) = upstream_of(r) {
        if u.cacheable.get() && (rc == crate::NGX_HTTP_BAD_GATEWAY || rc == crate::NGX_HTTP_GATEWAY_TIME_OUT) {
            let cache_valid = u.conf.cache_valid.as_option().cloned().flatten();

            let valid = file_cache_valid(cache_valid.as_deref().map(|v| v.as_slice()), rc as usize);

            if valid != 0 {
                c.valid_sec = ngx_core::times::time() + valid;
                c.error = rc as usize;
            }
        }
    }

    file_cache_free(&mut c, tf);
}

/// p->temp_file of a cacheable response, with the header of the cache file
/// written first (p->buf_to_file).
pub struct CacheWriter {
    pub tf: CacheTempFile,
    pub failed: bool,
}

impl CacheWriter {
    /// The temporary file in `temp_path`, or next to the cache file when
    /// the cache does not use the temp path; the header (`header` and the
    /// response header as the upstream sent it) written to it.
    pub fn new(r: &R, temp_path: Option<&ngx_core::conf::PathConf>, header: &[u8], raw_header: &[u8]) -> Option<CacheWriter> {
        let (use_temp_path, file_name) = match cache_of(r) {
            Some(c) => {
                let c = c.borrow();
                (c.file_cache.as_ref().map(|fc| fc.use_temp_path).unwrap_or(true), c.file_name.clone())
            }
            None => return None,
        };

        let tf = if use_temp_path { CacheTempFile::create(r, temp_path, None) } else { CacheTempFile::create(r, None, Some(&file_name)) };

        let mut tf = tf.ok()?;

        let mut failed = tf.write(header, &r.connection.log).is_err();

        if !failed {
            failed = tf.write(raw_header, &r.connection.log).is_err();
        }

        Some(CacheWriter { tf, failed })
    }

    /// The body data read (ngx_event_pipe_write_chain_to_temp_file).
    pub fn write(&mut self, r: &R, data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }

        if self.tf.write(data, &r.connection.log).is_err() {
            self.failed = true;
        }
    }

    /// The cache part of ngx_http_upstream_process_request at the end of
    /// the response: the file becomes the cache file when the response was
    /// read in full (p->upstream_done, or the end of a response without a
    /// length whose Content-Length, if any, matches), else it is deleted.
    pub fn finish(self, r: &R, done: bool, eof: bool, content_length_n: i64) {
        if !cacheable(r) {
            return;
        }

        let c_rc = match cache_of(r) {
            Some(c) => c,
            None => return,
        };

        let mut c = c_rc.borrow_mut();

        if self.failed {
            file_cache_free(&mut c, Some(&self.tf));
            return;
        }

        if done {
            file_cache_update(r, &mut c, &self.tf);
        } else if eof {
            if content_length_n == -1 || content_length_n == self.tf.offset - c.body_start as i64 {
                file_cache_update(r, &mut c, &self.tf);
            } else {
                file_cache_free(&mut c, Some(&self.tf));
            }
        } else {
            file_cache_free(&mut c, Some(&self.tf));
        }
    }
}

// ---------------------------------------------------------------------------
// the variables
// ---------------------------------------------------------------------------

/// ngx_http_upstream_cache_status
fn cache_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = upstream_of(r).map(|u| u.cache_status.get()).unwrap_or(0);

    if status == 0 || status > NGX_HTTP_CACHE_STATUS.len() {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = NGX_HTTP_CACHE_STATUS[status - 1].to_vec();

    NGX_OK
}

/// ngx_http_upstream_cache_last_modified
fn cache_last_modified_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let u = upstream_of(r);
    let c = cache_of(r);

    let last_modified = match (&u, &c) {
        (Some(u), Some(c)) if u.conf.cache_revalidate.get_or(false) && u.cache_status.get() == NGX_HTTP_CACHE_EXPIRED => c.borrow().last_modified,
        _ => -1,
    };

    if last_modified == -1 {
        v.not_found = true;
        return NGX_OK;
    }

    v.data = ngx_core::times::http_time(last_modified).into_bytes();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_upstream_cache_etag
fn cache_etag_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let u = upstream_of(r);
    let c = cache_of(r);

    let etag = match (&u, &c) {
        (Some(u), Some(c)) if u.conf.cache_revalidate.get_or(false) && u.cache_status.get() == NGX_HTTP_CACHE_EXPIRED => c.borrow().etag.clone(),
        _ => Vec::new(),
    };

    if etag.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = etag;

    NGX_OK
}

/// The cache variables of ngx_http_upstream_add_variables.
pub fn add_variables(cf: &mut Conf) -> ConfResult {
    use crate::variables::{VarDef, NGX_HTTP_VAR_NOCACHEABLE, NGX_HTTP_VAR_NOHASH};

    let vars = [
        VarDef { name: "upstream_cache_status", set: None, get: Some(cache_status_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
        VarDef { name: "upstream_cache_last_modified", set: None, get: Some(cache_last_modified_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH },
        VarDef { name: "upstream_cache_etag", set: None, get: Some(cache_etag_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH },
    ];

    crate::variables::add_variables(cf, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_seconds() {
        assert_eq!(process_delta_seconds(b"10"), 10);
        assert_eq!(process_delta_seconds(b"10, private"), 10);
        assert_eq!(process_delta_seconds(b"5;x"), 5);
        assert_eq!(process_delta_seconds(b""), 0);
        assert_eq!(process_delta_seconds(b"1a"), NGX_ERROR);
        assert_eq!(process_delta_seconds(b"99999999999999999999999"), i64::MAX);
    }

    #[test]
    fn test_strlcasestrn() {
        assert_eq!(strlcasestrn(b"public, Max-Age=10", b"max-age="), Some(8));
        assert_eq!(strlcasestrn(b"no-store", b"no-cache"), None);
        assert_eq!(strlcasestrn(b"x", b"max-age="), None);
    }

    #[test]
    fn test_merge_use_stale() {
        let mut c = UpstreamCacheConf::default();
        c.cache_use_stale = NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_UPDATING;

        // ngx_conf_merge_bitmask_value and the NOLIVE of "error"
        let prev = UpstreamCacheConf::default();
        let mut cc = c.clone();
        if cc.cache_use_stale == 0 {
            cc.cache_use_stale = prev.cache_use_stale;
        }
        assert!(cc.cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING != 0);
    }
}
