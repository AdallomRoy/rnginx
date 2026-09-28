//! ngx_event_openssl_cache.c: the cache of the objects loaded with
//! OpenSSL (certificate chains, keys, CRLs and CA lists).
//!
//! The configuration cache (ngx_openssl_cache_module's configuration)
//! holds the objects loaded while parsing a configuration, and the objects
//! of the previous configuration are reused on reload when the files are
//! unchanged (ssl_object_cache_inheritable).  The connection caches
//! (ssl_certificate_cache) hold the objects loaded at runtime for
//! certificates with variables.
//!
//! Values are raw OpenSSL pointers as in C: fetch functions return a new
//! reference the caller owns (a STACK_OF(X509) or STACK_OF(X509_CRL) whose
//! elements are referenced, or an EVP_PKEY).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::rc::Rc;

use crate::conf::*;
use crate::cycle::Cycle;
use crate::event_openssl::SslPasswords;
use crate::log::*;
use crate::module::*;
use crate::openssl_ffi::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

pub const NGX_SSL_CACHE_CERT: u32 = 0;
pub const NGX_SSL_CACHE_PKEY: u32 = 1;
pub const NGX_SSL_CACHE_CRL: u32 = 2;
pub const NGX_SSL_CACHE_CA: u32 = 3;

pub const NGX_SSL_CACHE_INVALIDATE: u32 = 0x80000000;

const NGX_SSL_CACHE_PATH: u32 = 0;
const NGX_SSL_CACHE_DATA: u32 = 1;
const NGX_SSL_CACHE_ENGINE: u32 = 2;
const NGX_SSL_CACHE_STORE: u32 = 3;

/// ngx_ssl_cache_key_t
struct CacheKey {
    ty: u32,
    data: Vec<u8>,
}

/// ngx_ssl_cache_node_t
struct CacheNode {
    value: *mut c_void,

    created: i64,
    accessed: i64,

    mtime: i64,
    uniq: u64,

    /// the node is in the expire queue (the connection caches)
    queued: bool,
}

/// ngx_ssl_cache_t
pub struct SslCache {
    /// the nodes by (type index, id)
    nodes: RefCell<HashMap<(u32, Vec<u8>), CacheNode>>,
    /// the expire queue, the most recently used at the front
    expire_queue: RefCell<VecDeque<(u32, Vec<u8>)>>,

    /// ssl_object_cache_inheritable (-1: unset)
    pub inheritable: Cell<i64>,

    current: Cell<usize>,
    max: usize,
    valid: i64,
    inactive: i64,
}

/// ngx_ssl_cache_init
pub fn ngx_ssl_cache_init(max: usize, valid: i64, inactive: i64) -> SslCache {
    SslCache {
        nodes: RefCell::new(HashMap::new()),
        expire_queue: RefCell::new(VecDeque::new()),
        inheritable: Cell::new(0),
        current: Cell::new(0),
        max,
        valid,
        inactive,
    }
}

impl Drop for SslCache {
    /// ngx_ssl_cache_cleanup
    fn drop(&mut self) {
        let nodes = std::mem::take(&mut *self.nodes.borrow_mut());

        if nodes.is_empty() {
            return;
        }

        for ((ty, _), cn) in nodes.into_iter() {
            type_free(ty, cn.value);

            if cn.queued && self.max != 0 {
                self.current.set(self.current.get().saturating_sub(1));
            }
        }

        self.expire_queue.borrow_mut().clear();

        let log = crate::cycle::try_cycle().map(|c| c.log.clone());

        if let Some(log) = log {
            if self.current.get() != 0 {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "{} items still left in ssl cache", self.current.get());
            }
        }
    }
}

/// The time and the id of a file (ngx_file_mtime(), ngx_file_uniq()).
fn file_info(path: &[u8]) -> Option<(i64, u64)> {
    let name = CString::new(path.to_vec()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(name.as_ptr(), &mut st) } == -1 {
        return None;
    }
    Some((st.st_mtime, st.st_ino))
}

/// ngx_get_full_name(pool, prefix, name)
fn get_full_name(prefix: &[u8], name: &mut Vec<u8>) {
    if name.first() == Some(&b'/') {
        return;
    }

    let mut v = Vec::with_capacity(prefix.len() + name.len());
    v.extend_from_slice(prefix);
    v.extend_from_slice(name);
    *name = v;
}

/// ngx_ssl_cache_init_key: the id type; relative paths are resolved
/// against the configuration prefix (in place, as in C)
fn ngx_ssl_cache_init_key(conf_prefix: &[u8], index: u32, path: &mut Vec<u8>) -> CacheKey {
    let ty = if index <= NGX_SSL_CACHE_PKEY && path.starts_with(b"data:") {
        NGX_SSL_CACHE_DATA
    } else if index == NGX_SSL_CACHE_PKEY && path.starts_with(b"engine:") {
        NGX_SSL_CACHE_ENGINE
    } else if index == NGX_SSL_CACHE_PKEY && path.starts_with(b"store:") {
        NGX_SSL_CACHE_STORE
    } else {
        get_full_name(conf_prefix, path);
        NGX_SSL_CACHE_PATH
    };

    CacheKey { ty, data: path.clone() }
}

/// ngx_ssl_cache_fetch: an object for the configuration being parsed
pub fn ngx_ssl_cache_fetch(cf: &mut Conf, index: u32, err: &mut Option<&'static str>, path: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> *mut c_void {
    *err = None;

    let mut invalidate = index & NGX_SSL_CACHE_INVALIDATE != 0;
    let index = index & !NGX_SSL_CACHE_INVALIDATE;

    let conf_prefix = cf.cycle.conf_prefix.clone();

    let id = ngx_ssl_cache_init_key(&conf_prefix, index, path);

    if id.ty == NGX_SSL_CACHE_DATA {
        invalidate = false;
    }

    let cache = match cf.cycle.module_conf::<SslCache>("ngx_openssl_cache_module") {
        Some(c) => c,
        None => {
            // no configuration cache: load the object
            let (value, _) = type_create(index, &id, err, passwords);
            return value;
        }
    };

    let cache = cache.borrow();

    let key = (index, id.data.clone());

    {
        let mut nodes = cache.nodes.borrow_mut();

        if let Some(cn) = nodes.get(&key) {
            if !invalidate {
                return type_ref(index, err, cn.value);
            }

            let cn = nodes.remove(&key).unwrap();
            type_free(index, cn.value);
        }
    }

    let mut value: *mut c_void = std::ptr::null_mut();

    let (rc, mtime, uniq) = if id.ty == NGX_SSL_CACHE_PATH {
        match file_info(&id.data) {
            Some((m, u)) => (true, m, u),
            None => (false, 0, 0),
        }
    } else {
        (false, 0, 0)
    };

    /* try to use a reference from the old cycle */

    let old_cache = cf.cycle.old_cycle.as_ref().and_then(|old| old.module_conf::<SslCache>("ngx_openssl_cache_module"));

    if let Some(old_cache) = old_cache {
        let old_cache = old_cache.borrow();

        if old_cache.inheritable.get() == 1 && !invalidate {
            if let Some(cn) = old_cache.nodes.borrow().get(&key) {
                match id.ty {
                    NGX_SSL_CACHE_DATA => {
                        value = type_ref(index, err, cn.value);
                    }

                    _ => {
                        if rc && uniq == cn.uniq && mtime == cn.mtime {
                            value = type_ref(index, err, cn.value);
                        }
                    }
                }
            }
        }
    }

    if value.is_null() {
        let (v, disabled) = type_create(index, &id, err, passwords);

        if v.is_null() || disabled {
            return v;
        }

        value = v;
    }

    cache.nodes.borrow_mut().insert(key, CacheNode { value, created: 0, accessed: 0, mtime, uniq, queued: false });

    type_ref(index, err, value)
}

/// ngx_ssl_cache_connection_fetch: an object for a connection, through
/// the connection cache (ssl_certificate_cache) if any
pub fn ngx_ssl_cache_connection_fetch(cache: Option<&Rc<RefCell<SslCache>>>, log: &Log, index: u32, err: &mut Option<&'static str>, path: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> *mut c_void {
    *err = None;

    let invalidate = index & NGX_SSL_CACHE_INVALIDATE != 0;
    let index = index & !NGX_SSL_CACHE_INVALIDATE;

    let conf_prefix = crate::cycle::try_cycle().map(|c| c.conf_prefix.clone()).unwrap_or_default();

    let id = ngx_ssl_cache_init_key(&conf_prefix, index, path);

    let cache = match cache {
        None => return type_create(index, &id, err, passwords).0,
        Some(c) => c.borrow(),
    };

    let now = crate::times::time();

    let key = (index, id.data.clone());

    let found = cache.nodes.borrow().contains_key(&key);

    if found {
        cache.queue_remove(&key);

        let mut update = false;

        {
            let mut nodes = cache.nodes.borrow_mut();
            let cn = nodes.get_mut(&key).unwrap();

            if id.ty != NGX_SSL_CACHE_DATA && (invalidate || now - cn.created > cache.valid) {
                match id.ty {
                    NGX_SSL_CACHE_PATH => match file_info(&id.data) {
                        Some((mtime, uniq)) => {
                            if !invalidate && uniq == cn.uniq && mtime == cn.mtime {
                                // unchanged
                            } else {
                                cn.mtime = mtime;
                                cn.uniq = uniq;
                                update = true;
                            }
                        }
                        None => {
                            cn.mtime = 0;
                            cn.uniq = 0;
                            update = true;
                        }
                    },

                    _ => update = true,
                }

                if !update {
                    cn.created = now;
                }
            }
        }

        if update {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "update cached ssl object: {}", B(&id.data));

            let old = cache.nodes.borrow().get(&key).unwrap().value;
            type_free(index, old);

            let (value, disabled) = type_create(index, &id, err, passwords);

            if value.is_null() || disabled {
                cache.nodes.borrow_mut().remove(&key);

                cache.current.set(cache.current.get() - 1);

                return value;
            }

            let mut nodes = cache.nodes.borrow_mut();
            let cn = nodes.get_mut(&key).unwrap();
            cn.value = value;
            cn.created = now;
        }
    } else {
        let (value, disabled) = type_create(index, &id, err, passwords);

        if value.is_null() || disabled {
            return value;
        }

        let (mtime, uniq) = if id.ty == NGX_SSL_CACHE_PATH { file_info(&id.data).unwrap_or((0, 0)) } else { (0, 0) };

        ngx_ssl_cache_expire(&cache, 1, log);

        if cache.current.get() >= cache.max {
            ngx_ssl_cache_expire(&cache, 0, log);
        }

        cache.nodes.borrow_mut().insert(key.clone(), CacheNode { value, created: now, accessed: now, mtime, uniq, queued: false });

        cache.current.set(cache.current.get() + 1);
    }

    // found:

    let value = {
        let mut nodes = cache.nodes.borrow_mut();
        let cn = nodes.get_mut(&key).unwrap();
        cn.accessed = now;
        cn.queued = true;
        cn.value
    };

    cache.expire_queue.borrow_mut().push_front(key);

    type_ref(index, err, value)
}

impl SslCache {
    fn queue_remove(&self, key: &(u32, Vec<u8>)) {
        let mut q = self.expire_queue.borrow_mut();
        if let Some(i) = q.iter().position(|k| k == key) {
            q.remove(i);
        }
        if let Some(cn) = self.nodes.borrow_mut().get_mut(key) {
            cn.queued = false;
        }
    }
}

/// ngx_ssl_cache_expire: the least recently used node, and up to two more
/// inactive ones
fn ngx_ssl_cache_expire(cache: &SslCache, mut n: usize, log: &Log) {
    let now = crate::times::time();

    while n < 3 {
        let key = match cache.expire_queue.borrow().back() {
            None => return,
            Some(k) => k.clone(),
        };

        let accessed = cache.nodes.borrow().get(&key).map(|cn| cn.accessed).unwrap_or(0);

        let first = n == 0;
        n += 1;

        if !first && now - accessed <= cache.inactive {
            return;
        }

        // ngx_ssl_cache_node_free

        cache.expire_queue.borrow_mut().pop_back();

        if let Some(cn) = cache.nodes.borrow_mut().remove(&key) {
            type_free(key.0, cn.value);
        }

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "delete cached ssl object: {}", B(&key.1));

        cache.current.set(cache.current.get().saturating_sub(1));
    }
}

// --- the object types (ngx_ssl_cache_types) ---

/// type->create: the object and whether it must not be cached (a key
/// decrypted with a password: NGX_SSL_CACHE_DISABLED)
fn type_create(index: u32, id: &CacheKey, err: &mut Option<&'static str>, passwords: Option<&Rc<SslPasswords>>) -> (*mut c_void, bool) {
    unsafe {
        match index {
            NGX_SSL_CACHE_CERT => (ngx_ssl_cache_cert_create(id, err), false),
            NGX_SSL_CACHE_PKEY => ngx_ssl_cache_pkey_create(id, err, passwords),
            NGX_SSL_CACHE_CRL => (ngx_ssl_cache_crl_create(id, err), false),
            _ => (ngx_ssl_cache_ca_create(id, err), false),
        }
    }
}

/// type->free
fn type_free(index: u32, value: *mut c_void) {
    if value.is_null() {
        return;
    }

    unsafe {
        match index {
            NGX_SSL_CACHE_PKEY => EVP_PKEY_free(value as *mut EVP_PKEY),
            NGX_SSL_CACHE_CRL => sk_X509_CRL_pop_free(value as *mut OPENSSL_STACK),
            _ => sk_X509_pop_free(value as *mut OPENSSL_STACK),
        }
    }
}

/// type->ref
fn type_ref(index: u32, err: &mut Option<&'static str>, value: *mut c_void) -> *mut c_void {
    unsafe {
        match index {
            NGX_SSL_CACHE_PKEY => {
                EVP_PKEY_up_ref(value as *mut EVP_PKEY);
                value
            }

            NGX_SSL_CACHE_CRL => {
                let chain = OPENSSL_sk_dup(value as *const OPENSSL_STACK);
                if chain.is_null() {
                    *err = Some("sk_X509_CRL_dup() failed");
                    return std::ptr::null_mut();
                }

                let n = OPENSSL_sk_num(chain);

                for i in 0..n {
                    X509_CRL_up_ref(OPENSSL_sk_value(chain, i) as *mut X509_CRL);
                }

                chain as *mut c_void
            }

            _ => {
                let chain = OPENSSL_sk_dup(value as *const OPENSSL_STACK);
                if chain.is_null() {
                    *err = Some("sk_X509_dup() failed");
                    return std::ptr::null_mut();
                }

                let n = OPENSSL_sk_num(chain);

                for i in 0..n {
                    X509_up_ref(OPENSSL_sk_value(chain, i) as *mut X509);
                }

                chain as *mut c_void
            }
        }
    }
}

/// ngx_ssl_cache_cert_create: the certificate and the rest of the chain
unsafe fn ngx_ssl_cache_cert_create(id: &CacheKey, err: &mut Option<&'static str>) -> *mut c_void {
    let chain = OPENSSL_sk_new_null();
    if chain.is_null() {
        *err = Some("sk_X509_new_null() failed");
        return std::ptr::null_mut();
    }

    let bio = ngx_ssl_cache_create_bio(id, err);
    if bio.is_null() {
        sk_X509_pop_free(chain);
        return std::ptr::null_mut();
    }

    /* certificate itself */

    let x509 = PEM_read_bio_X509_AUX(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
    if x509.is_null() {
        *err = Some("PEM_read_bio_X509_AUX() failed");
        BIO_free(bio);
        sk_X509_pop_free(chain);
        return std::ptr::null_mut();
    }

    if OPENSSL_sk_push(chain, x509 as *const c_void) == 0 {
        *err = Some("sk_X509_push() failed");
        BIO_free(bio);
        X509_free(x509);
        sk_X509_pop_free(chain);
        return std::ptr::null_mut();
    }

    /* rest of the chain */

    loop {
        let x509 = PEM_read_bio_X509(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x509.is_null() {
            let n = ERR_peek_last_error();

            if ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = Some("PEM_read_bio_X509() failed");
            BIO_free(bio);
            sk_X509_pop_free(chain);
            return std::ptr::null_mut();
        }

        if OPENSSL_sk_push(chain, x509 as *const c_void) == 0 {
            *err = Some("sk_X509_push() failed");
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain);
            return std::ptr::null_mut();
        }
    }

    BIO_free(bio);

    chain as *mut c_void
}

/// ngx_ssl_cache_pwd_t
struct PwdCbData<'a> {
    pwds: &'a [Vec<u8>],
    i: usize,
    encrypted: bool,
}

extern "C" {
    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_load_private_key(e: *mut ENGINE, key_id: *const c_char, ui_method: *mut c_void, callback_data: *mut c_void) -> *mut EVP_PKEY;
    fn OSSL_STORE_open(uri: *const c_char, ui_method: *const c_void, ui_data: *mut c_void, post_process: *mut c_void, post_process_data: *mut c_void) -> *mut c_void;
    fn OSSL_STORE_eof(ctx: *mut c_void) -> c_int;
    fn OSSL_STORE_load(ctx: *mut c_void) -> *mut c_void;
    fn OSSL_STORE_close(ctx: *mut c_void) -> c_int;
    fn OSSL_STORE_INFO_get_type(info: *const c_void) -> c_int;
    fn OSSL_STORE_INFO_get1_PKEY(info: *const c_void) -> *mut EVP_PKEY;
    fn OSSL_STORE_INFO_free(info: *mut c_void);
    fn UI_UTIL_wrap_read_pem_callback(cb: Option<pem_password_cb>, rwflag: c_int) -> *mut c_void;
    fn UI_destroy_method(method: *mut c_void);
    fn UI_set_default_method(method: *const c_void);
    fn UI_null() -> *const c_void;
}

const OSSL_STORE_INFO_PKEY: c_int = 4;

/// ngx_ssl_cache_pkey_create
unsafe fn ngx_ssl_cache_pkey_create(id: &CacheKey, err: &mut Option<&'static str>, passwords: Option<&Rc<SslPasswords>>) -> (*mut c_void, bool) {
    if id.ty == NGX_SSL_CACHE_ENGINE {
        let rest = &id.data[b"engine:".len()..];

        let last = match rest.iter().position(|&c| c == b':') {
            Some(i) => i,
            None => {
                *err = Some("invalid syntax");
                return (std::ptr::null_mut(), false);
            }
        };

        let name = CString::new(rest[..last].to_vec()).unwrap_or_default();

        let engine = ENGINE_by_id(name.as_ptr());

        if engine.is_null() {
            *err = Some("ENGINE_by_id() failed");
            return (std::ptr::null_mut(), false);
        }

        let key_id = CString::new(rest[last + 1..].to_vec()).unwrap_or_default();

        let pkey = ENGINE_load_private_key(engine, key_id.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut());

        if pkey.is_null() {
            *err = Some("ENGINE_load_private_key() failed");
            ENGINE_free(engine);
            return (std::ptr::null_mut(), false);
        }

        ENGINE_free(engine);

        return (pkey as *mut c_void, false);
    }

    let empty: [Vec<u8>; 0] = [];

    let mut cb_data = PwdCbData { pwds: &empty, i: 0, encrypted: false };

    let (mut tries, pwd, cb): (usize, *mut c_void, Option<pem_password_cb>) = match passwords {
        Some(p) => {
            cb_data.pwds = &p.0;
            (p.0.len(), &mut cb_data as *mut PwdCbData as *mut c_void, Some(ngx_ssl_cache_pkey_password_callback))
        }
        None => (1, std::ptr::null_mut(), None),
    };

    if id.ty == NGX_SSL_CACHE_STORE {
        let method = if cb.is_some() { UI_UTIL_wrap_read_pem_callback(cb, 0) } else { std::ptr::null_mut() };

        let uri = CString::new(id.data[b"store:".len()..].to_vec()).unwrap_or_default();

        let store = OSSL_STORE_open(uri.as_ptr(), method, pwd, std::ptr::null_mut(), std::ptr::null_mut());

        if store.is_null() {
            *err = Some("OSSL_STORE_open() failed");

            if !method.is_null() {
                UI_destroy_method(method);
            }

            return (std::ptr::null_mut(), false);
        }

        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();

        while pkey.is_null() && OSSL_STORE_eof(store) == 0 {
            let info = OSSL_STORE_load(store);

            if info.is_null() {
                continue;
            }

            if OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(store);

        if !method.is_null() {
            UI_destroy_method(method);
        }

        if pkey.is_null() {
            *err = Some("OSSL_STORE_load() failed");
            return (std::ptr::null_mut(), false);
        }

        return (pkey as *mut c_void, cb_data.encrypted);
    }

    let bio = ngx_ssl_cache_create_bio(id, err);
    if bio.is_null() {
        return (std::ptr::null_mut(), false);
    }

    let pkey;

    loop {
        let p = PEM_read_bio_PrivateKey(bio, std::ptr::null_mut(), cb, pwd);
        if !p.is_null() {
            pkey = p;
            break;
        }

        if tries > 1 {
            tries -= 1;
            ERR_clear_error();
            BIO_reset(bio);
            cb_data.i += 1;
            continue;
        }

        *err = Some("PEM_read_bio_PrivateKey() failed");
        BIO_free(bio);
        return (std::ptr::null_mut(), false);
    }

    BIO_free(bio);

    (pkey as *mut c_void, cb_data.encrypted)
}

/// ngx_ssl_cache_pkey_password_callback
unsafe extern "C" fn ngx_ssl_cache_pkey_password_callback(buf: *mut c_char, size: c_int, rwflag: c_int, userdata: *mut c_void) -> c_int {
    let log = crate::cycle::try_cycle().map(|c| c.log.clone());

    if rwflag != 0 {
        if let Some(log) = log {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "ngx_ssl_cache_pkey_password_callback() is called for encryption");
        }
        return 0;
    }

    let data = &mut *(userdata as *mut PwdCbData);

    data.encrypted = true;

    let pwd = match data.pwds.get(data.i) {
        None => return 0,
        Some(p) => p,
    };

    let mut size = size;

    if pwd.len() > size as usize {
        if let Some(log) = log {
            ngx_log_error!(NGX_LOG_ERR, log, None, "password is truncated to {} bytes", size);
        }
    } else {
        size = pwd.len() as c_int;
    }

    std::ptr::copy_nonoverlapping(pwd.as_ptr(), buf as *mut u8, size as usize);

    size
}

/// ngx_ssl_cache_crl_create
unsafe fn ngx_ssl_cache_crl_create(id: &CacheKey, err: &mut Option<&'static str>) -> *mut c_void {
    let chain = OPENSSL_sk_new_null();
    if chain.is_null() {
        *err = Some("sk_X509_CRL_new_null() failed");
        return std::ptr::null_mut();
    }

    let bio = ngx_ssl_cache_create_bio(id, err);
    if bio.is_null() {
        sk_X509_CRL_pop_free(chain);
        return std::ptr::null_mut();
    }

    loop {
        let x509 = PEM_read_bio_X509_CRL(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x509.is_null() {
            let n = ERR_peek_last_error();

            if ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE && OPENSSL_sk_num(chain) > 0 {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = Some("PEM_read_bio_X509_CRL() failed");
            BIO_free(bio);
            sk_X509_CRL_pop_free(chain);
            return std::ptr::null_mut();
        }

        if OPENSSL_sk_push(chain, x509 as *const c_void) == 0 {
            *err = Some("sk_X509_CRL_push() failed");
            BIO_free(bio);
            X509_CRL_free(x509);
            sk_X509_CRL_pop_free(chain);
            return std::ptr::null_mut();
        }
    }

    BIO_free(bio);

    chain as *mut c_void
}

/// ngx_ssl_cache_ca_create
unsafe fn ngx_ssl_cache_ca_create(id: &CacheKey, err: &mut Option<&'static str>) -> *mut c_void {
    let chain = OPENSSL_sk_new_null();
    if chain.is_null() {
        *err = Some("sk_X509_new_null() failed");
        return std::ptr::null_mut();
    }

    let bio = ngx_ssl_cache_create_bio(id, err);
    if bio.is_null() {
        sk_X509_pop_free(chain);
        return std::ptr::null_mut();
    }

    loop {
        let x509 = PEM_read_bio_X509_AUX(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x509.is_null() {
            let n = ERR_peek_last_error();

            if ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE && OPENSSL_sk_num(chain) > 0 {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = Some("PEM_read_bio_X509_AUX() failed");
            BIO_free(bio);
            sk_X509_pop_free(chain);
            return std::ptr::null_mut();
        }

        if OPENSSL_sk_push(chain, x509 as *const c_void) == 0 {
            *err = Some("sk_X509_push() failed");
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain);
            return std::ptr::null_mut();
        }
    }

    BIO_free(bio);

    chain as *mut c_void
}

/// ngx_ssl_cache_create_bio
unsafe fn ngx_ssl_cache_create_bio(id: &CacheKey, err: &mut Option<&'static str>) -> *mut BIO {
    if id.ty == NGX_SSL_CACHE_DATA {
        let data = &id.data[b"data:".len()..];

        let bio = BIO_new_mem_buf(data.as_ptr() as *const c_void, data.len() as c_int);
        if bio.is_null() {
            *err = Some("BIO_new_mem_buf() failed");
        }

        // the memory BIO reads id.data, which outlives it (the BIO is
        // freed by the create functions)
        return bio;
    }

    let name = match CString::new(id.data.clone()) {
        Ok(n) => n,
        Err(_) => {
            *err = Some("BIO_new_file() failed");
            return std::ptr::null_mut();
        }
    };

    let bio = BIO_new_file(name.as_ptr(), b"r\0".as_ptr() as *const c_char);
    if bio.is_null() {
        *err = Some("BIO_new_file() failed");
    }

    bio
}

// --- ngx_openssl_cache_module ---

/// ngx_openssl_cache_create_conf
fn ngx_openssl_cache_create_conf(_cycle: &mut Cycle) -> std::rc::Rc<dyn std::any::Any> {
    let cache = ngx_ssl_cache_init(0, 0, 0);

    cache.inheritable.set(-1);

    make_slot(cache)
}

/// ngx_openssl_cache_init_conf
fn ngx_openssl_cache_init_conf(_cycle: &mut Cycle, conf: &std::rc::Rc<dyn std::any::Any>) -> Result<(), ()> {
    let cache = conf_cell::<SslCache>(conf).borrow();

    if cache.inheritable.get() == -1 {
        cache.inheritable.set(1);
    }

    Ok(())
}

/// ngx_openssl_cache_init_worker
fn ngx_openssl_cache_init_worker(_cycle: &std::rc::Rc<Cycle>) -> Result<(), ()> {
    if crate::cycle::process_type() != crate::cycle::ProcessType::Worker {
        return Ok(());
    }

    unsafe { UI_set_default_method(UI_null()) };

    Ok(())
}

/// ssl_object_cache_inheritable (ngx_conf_set_flag_slot on the
/// configuration cache)
fn ssl_object_cache_inheritable(cf: &mut Conf, cmd: &Command, conf: Option<std::rc::Rc<dyn std::any::Any>>) -> ConfResult {
    let conf = conf.expect("openssl cache conf");
    let cache = conf_cell::<SslCache>(&conf).borrow();

    if cache.inheritable.get() != -1 {
        return Err(msg("is duplicate"));
    }

    let mut v: Val<bool> = Val::unset();
    set_flag(cf, cmd, &mut v)?;

    cache.inheritable.set(*v as i64);

    Ok(())
}

/// ngx_openssl_cache_module
pub fn openssl_cache_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_openssl_cache_module", NGX_CORE_MODULE);
    m.ctx = Some(std::rc::Rc::new(CoreModuleCtx { name: "openssl_cache", create_conf: Some(ngx_openssl_cache_create_conf), init_conf: Some(ngx_openssl_cache_init_conf) }));
    m.commands = vec![Command::new("ssl_object_cache_inheritable", NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_FLAG, ConfLevel::None, ssl_object_cache_inheritable)];
    m.init_process = Some(ngx_openssl_cache_init_worker);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_key_types() {
        let mut p = b"data:xyz".to_vec();
        assert_eq!(ngx_ssl_cache_init_key(b"/prefix/", NGX_SSL_CACHE_CERT, &mut p).ty, NGX_SSL_CACHE_DATA);

        let mut p = b"engine:x:y".to_vec();
        assert_eq!(ngx_ssl_cache_init_key(b"/prefix/", NGX_SSL_CACHE_PKEY, &mut p).ty, NGX_SSL_CACHE_ENGINE);

        // "engine:" is a path for certificates
        let mut p = b"engine:x:y".to_vec();
        assert_eq!(ngx_ssl_cache_init_key(b"/prefix/", NGX_SSL_CACHE_CERT, &mut p).ty, NGX_SSL_CACHE_PATH);
        assert_eq!(p, b"/prefix/engine:x:y");

        let mut p = b"/abs/cert.pem".to_vec();
        ngx_ssl_cache_init_key(b"/prefix/", NGX_SSL_CACHE_CA, &mut p);
        assert_eq!(p, b"/abs/cert.pem");
    }

    #[test]
    fn missing_file_is_an_error() {
        let mut err = None;
        let id = CacheKey { ty: NGX_SSL_CACHE_PATH, data: b"/nonexistent/x.crt".to_vec() };
        let (v, _) = type_create(NGX_SSL_CACHE_CERT, &id, &mut err, None);
        assert!(v.is_null());
        assert_eq!(err, Some("BIO_new_file() failed"));
        unsafe { ERR_clear_error() };
    }
}
