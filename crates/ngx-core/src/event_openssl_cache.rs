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
//! Values are the openssl crate's objects: a certificate chain or a CA
//! list (Vec<X509>), a private key, a CRL list; fetch functions return a
//! reference the caller owns (the C ones up-reference the objects).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::rc::Rc;

use ngx_sys::ssl as sys;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Crl, X509};

use crate::conf::*;
use crate::cycle::Cycle;
use crate::event_openssl::SslPasswords;
use crate::log::*;
use crate::module::*;
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

/// An object of the cache.
#[derive(Clone)]
pub enum SslObject {
    /// a certificate and the rest of its chain, or a CA list
    Certs(Rc<Vec<X509>>),
    /// a private key
    Pkey(PKey<Private>),
    /// a CRL list
    Crls(Rc<Vec<X509Crl>>),
}

/// ngx_ssl_cache_node_t
struct CacheNode {
    value: SslObject,

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

        for (_, cn) in nodes.into_iter() {
            // type->free(): the reference of the cache is dropped
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
    let st = crate::os::stat(path).ok()?;
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
pub fn ngx_ssl_cache_fetch(cf: &mut Conf, index: u32, err: &mut Option<&'static str>, path: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> Option<SslObject> {
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
                return Some(cn.value.clone());
            }

            nodes.remove(&key);
        }
    }

    let mut value: Option<SslObject> = None;

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
                        value = Some(cn.value.clone());
                    }

                    _ => {
                        if rc && uniq == cn.uniq && mtime == cn.mtime {
                            value = Some(cn.value.clone());
                        }
                    }
                }
            }
        }
    }

    let value = match value {
        Some(v) => v,
        None => {
            let (v, disabled) = type_create(index, &id, err, passwords);

            match v {
                Some(v) if !disabled => v,
                v => return v,
            }
        }
    };

    cache.nodes.borrow_mut().insert(key, CacheNode { value: value.clone(), created: 0, accessed: 0, mtime, uniq, queued: false });

    Some(value)
}

/// ngx_ssl_cache_connection_fetch: an object for a connection, through
/// the connection cache (ssl_certificate_cache) if any
pub fn ngx_ssl_cache_connection_fetch(cache: Option<&Rc<RefCell<SslCache>>>, log: &Log, index: u32, err: &mut Option<&'static str>, path: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> Option<SslObject> {
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

            let (value, disabled) = type_create(index, &id, err, passwords);

            let value = match value {
                Some(v) if !disabled => v,
                value => {
                    cache.nodes.borrow_mut().remove(&key);

                    cache.current.set(cache.current.get() - 1);

                    return value;
                }
            };

            let mut nodes = cache.nodes.borrow_mut();
            let cn = nodes.get_mut(&key).unwrap();
            cn.value = value;
            cn.created = now;
        }
    } else {
        let (value, disabled) = type_create(index, &id, err, passwords);

        let value = match value {
            Some(v) if !disabled => v,
            value => return value,
        };

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
        cn.value.clone()
    };

    cache.expire_queue.borrow_mut().push_front(key);

    Some(value)
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

        cache.nodes.borrow_mut().remove(&key);

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "delete cached ssl object: {}", B(&key.1));

        cache.current.set(cache.current.get().saturating_sub(1));
    }
}

// --- the object types (ngx_ssl_cache_types) ---

/// type->create: the object and whether it must not be cached (a key
/// decrypted with a password: NGX_SSL_CACHE_DISABLED)
fn type_create(index: u32, id: &CacheKey, err: &mut Option<&'static str>, passwords: Option<&Rc<SslPasswords>>) -> (Option<SslObject>, bool) {
    match index {
        NGX_SSL_CACHE_CERT => (ngx_ssl_cache_cert_create(id, err), false),
        NGX_SSL_CACHE_PKEY => ngx_ssl_cache_pkey_create(id, err, passwords),
        NGX_SSL_CACHE_CRL => (ngx_ssl_cache_crl_create(id, err), false),
        _ => (ngx_ssl_cache_ca_create(id, err), false),
    }
}

/// The end of the PEM objects of a BIO: the last error is
/// PEM_R_NO_START_LINE.
fn pem_end() -> bool {
    let n = sys::err_peek_last_error();
    sys::err_get_lib(n) == sys::ERR_LIB_PEM && sys::err_get_reason(n) == sys::PEM_R_NO_START_LINE
}

/// ngx_ssl_cache_cert_create: the certificate and the rest of the chain
fn ngx_ssl_cache_cert_create(id: &CacheKey, err: &mut Option<&'static str>) -> Option<SslObject> {
    let mut bio = ngx_ssl_cache_create_bio(id, err)?;

    /* certificate itself */

    let x509 = match sys::pem_read_x509_aux(&mut bio) {
        Some(x) => x,
        None => {
            *err = Some("PEM_read_bio_X509_AUX() failed");
            return None;
        }
    };

    let mut chain = vec![x509];

    /* rest of the chain */

    loop {
        match sys::pem_read_x509(&mut bio) {
            Some(x) => chain.push(x),

            None => {
                if pem_end() {
                    /* end of file */
                    sys::err_clear_error();
                    break;
                }

                /* some real error */

                *err = Some("PEM_read_bio_X509() failed");
                return None;
            }
        }
    }

    Some(SslObject::Certs(Rc::new(chain)))
}

/// ngx_ssl_cache_pkey_password_callback: the password `i` of the list
fn ngx_ssl_cache_pkey_password_callback(pwds: &[Vec<u8>], i: &Cell<usize>, encrypted: &Cell<bool>, buf: &mut [u8], rwflag: bool) -> usize {
    let log = crate::cycle::try_cycle().map(|c| c.log.clone());

    if rwflag {
        if let Some(log) = log {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "ngx_ssl_cache_pkey_password_callback() is called for encryption");
        }
        return 0;
    }

    encrypted.set(true);

    let pwd = match pwds.get(i.get()) {
        None => return 0,
        Some(p) => p,
    };

    let mut size = buf.len();

    if pwd.len() > size {
        if let Some(log) = log {
            ngx_log_error!(NGX_LOG_ERR, log, None, "password is truncated to {} bytes", size);
        }
    } else {
        size = pwd.len();
    }

    buf[..size].copy_from_slice(&pwd[..size]);

    size
}

/// ngx_ssl_cache_pkey_create
fn ngx_ssl_cache_pkey_create(id: &CacheKey, err: &mut Option<&'static str>, passwords: Option<&Rc<SslPasswords>>) -> (Option<SslObject>, bool) {
    if id.ty == NGX_SSL_CACHE_ENGINE {
        let rest = &id.data[b"engine:".len()..];

        let last = match rest.iter().position(|&c| c == b':') {
            Some(i) => i,
            None => {
                *err = Some("invalid syntax");
                return (None, false);
            }
        };

        let name = CString::new(rest[..last].to_vec()).unwrap_or_default();
        let key_id = CString::new(rest[last + 1..].to_vec()).unwrap_or_default();

        return match sys::engine_load_private_key(&name, &key_id) {
            Ok(pkey) => (Some(SslObject::Pkey(pkey)), false),
            Err(sys::EngineError::ById) => {
                *err = Some("ENGINE_by_id() failed");
                (None, false)
            }
            Err(sys::EngineError::Load) => {
                *err = Some("ENGINE_load_private_key() failed");
                (None, false)
            }
        };
    }

    // ngx_ssl_cache_pwd_t
    let pwds: &[Vec<u8>] = passwords.map(|p| &p.0[..]).unwrap_or(&[]);
    let i = Cell::new(0usize);
    let encrypted = Cell::new(false);

    let mut cb = |buf: &mut [u8], rwflag: bool| ngx_ssl_cache_pkey_password_callback(pwds, &i, &encrypted, buf, rwflag);

    let mut tries = if passwords.is_some() { pwds.len() } else { 1 };

    if id.ty == NGX_SSL_CACHE_STORE {
        let uri = CString::new(id.data[b"store:".len()..].to_vec()).unwrap_or_default();

        let r = if passwords.is_some() { sys::store_load_private_key(&uri, Some(&mut cb)) } else { sys::store_load_private_key(&uri, None) };

        return match r {
            Ok(pkey) => (Some(SslObject::Pkey(pkey)), encrypted.get()),
            Err(sys::StoreError::Open) => {
                *err = Some("OSSL_STORE_open() failed");
                (None, false)
            }
            Err(sys::StoreError::Load) => {
                *err = Some("OSSL_STORE_load() failed");
                (None, false)
            }
        };
    }

    let mut bio = match ngx_ssl_cache_create_bio(id, err) {
        Some(b) => b,
        None => return (None, false),
    };

    loop {
        let p = if passwords.is_some() { sys::pem_read_private_key(&mut bio, Some(&mut cb)) } else { sys::pem_read_private_key(&mut bio, None) };

        if let Some(pkey) = p {
            return (Some(SslObject::Pkey(pkey)), encrypted.get());
        }

        if tries > 1 {
            tries -= 1;
            sys::err_clear_error();
            bio.reset();
            i.set(i.get() + 1);
            continue;
        }

        *err = Some("PEM_read_bio_PrivateKey() failed");
        return (None, false);
    }
}

/// ngx_ssl_cache_crl_create
fn ngx_ssl_cache_crl_create(id: &CacheKey, err: &mut Option<&'static str>) -> Option<SslObject> {
    let mut bio = ngx_ssl_cache_create_bio(id, err)?;

    let mut chain = Vec::new();

    loop {
        match sys::pem_read_x509_crl(&mut bio) {
            Some(x) => chain.push(x),

            None => {
                if pem_end() && !chain.is_empty() {
                    /* end of file */
                    sys::err_clear_error();
                    break;
                }

                /* some real error */

                *err = Some("PEM_read_bio_X509_CRL() failed");
                return None;
            }
        }
    }

    Some(SslObject::Crls(Rc::new(chain)))
}

/// ngx_ssl_cache_ca_create
fn ngx_ssl_cache_ca_create(id: &CacheKey, err: &mut Option<&'static str>) -> Option<SslObject> {
    let mut bio = ngx_ssl_cache_create_bio(id, err)?;

    let mut chain = Vec::new();

    loop {
        match sys::pem_read_x509_aux(&mut bio) {
            Some(x) => chain.push(x),

            None => {
                if pem_end() && !chain.is_empty() {
                    /* end of file */
                    sys::err_clear_error();
                    break;
                }

                /* some real error */

                *err = Some("PEM_read_bio_X509_AUX() failed");
                return None;
            }
        }
    }

    Some(SslObject::Certs(Rc::new(chain)))
}

/// ngx_ssl_cache_create_bio: a memory BIO of the "data:" of the key (which
/// it reads, borrowed), or a file BIO
fn ngx_ssl_cache_create_bio<'a>(id: &'a CacheKey, err: &mut Option<&'static str>) -> Option<sys::Bio<'a>> {
    if id.ty == NGX_SSL_CACHE_DATA {
        let data = &id.data[b"data:".len()..];

        let bio = sys::Bio::new_mem_buf(data);
        if bio.is_none() {
            *err = Some("BIO_new_mem_buf() failed");
        }

        return bio;
    }

    let name = match CString::new(id.data.clone()) {
        Ok(n) => n,
        Err(_) => {
            *err = Some("BIO_new_file() failed");
            return None;
        }
    };

    let bio = sys::Bio::new_file(&name, c"r");
    if bio.is_none() {
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

    sys::ui_set_default_null();

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
        assert!(v.is_none());
        assert_eq!(err, Some("BIO_new_file() failed"));
        sys::err_clear_error();
    }
}
