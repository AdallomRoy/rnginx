//! ngx_http_file_cache.c: the keys zone of a cache (the nodes of its keys
//! in shared memory, with the uses, the updating flag of the cache lock and
//! the cached errors), the cache files with their ngx_http_file_cache_header_t,
//! and the cache manager and loader.
//!
//! A cache file is laid out as C lays it out: the header struct (336 bytes
//! on LP64), "\nKEY: " and the key, "\n", the response header as the
//! upstream sent it, then the body from body_start. A cache directory
//! written by nginx can be read here, and the other way round.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicUsize, Ordering};

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::open_file_cache::{open_cached_file, CachedFileHandle, OpenFileInfo};
use ngx_core::queue::{queue_empty, queue_init, queue_insert_head, queue_last, queue_remove, Queue};
use ngx_core::rbtree::{rbt_red, Rbtree, RbtreeNode};
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::http_debug;
use crate::request::*;

pub const NGX_HTTP_CACHE_MISS: usize = 1;
pub const NGX_HTTP_CACHE_BYPASS: usize = 2;
pub const NGX_HTTP_CACHE_EXPIRED: usize = 3;
pub const NGX_HTTP_CACHE_STALE: usize = 4;
pub const NGX_HTTP_CACHE_UPDATING: usize = 5;
pub const NGX_HTTP_CACHE_REVALIDATED: usize = 6;
pub const NGX_HTTP_CACHE_HIT: usize = 7;
pub const NGX_HTTP_CACHE_SCARCE: usize = 8;

pub const NGX_HTTP_CACHE_KEY_LEN: usize = 16;
pub const NGX_HTTP_CACHE_ETAG_LEN: usize = 128;
pub const NGX_HTTP_CACHE_VARY_LEN: usize = 128;

pub const NGX_HTTP_CACHE_VERSION: usize = 5;

/// NGX_MAX_PATH_LEVEL
const NGX_MAX_PATH_LEVEL: usize = 3;

/// NGX_FILE_OWNER_ACCESS
const NGX_FILE_OWNER_ACCESS: u32 = 0o600;

/// ngx_http_cache_status
pub static NGX_HTTP_CACHE_STATUS: [&[u8]; 7] = [b"MISS", b"BYPASS", b"EXPIRED", b"STALE", b"UPDATING", b"REVALIDATED", b"HIT"];

/// ngx_http_file_cache_key
const NGX_HTTP_FILE_CACHE_KEY: &[u8] = b"\nKEY: ";

/// sizeof(ngx_rbtree_key_t)
const RBTREE_KEY_SIZE: usize = std::mem::size_of::<usize>();

/// ngx_http_cache_valid_t: status 0 is "any".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheValid {
    pub status: usize,
    pub valid: i64,
}

/// ngx_http_file_cache_node_t, in the keys zone. The bit fields of C
/// (count:20, uses:10, valid_msec:10, error:10) are kept to their widths.
#[repr(C)]
pub struct FileCacheNode {
    pub node: RbtreeNode,
    pub queue: Queue,
    pub key: [u8; NGX_HTTP_CACHE_KEY_LEN - RBTREE_KEY_SIZE],
    pub count: u32,
    pub uses: u32,
    pub valid_msec: u32,
    pub error: u32,
    pub exists: bool,
    pub updating: bool,
    pub deleting: bool,
    pub purged: bool,
    pub uniq: u64,
    pub expire: i64,
    pub valid_sec: i64,
    pub body_start: usize,
    pub fs_size: i64,
    pub lock_time: u64,
}

const COUNT_MASK: u32 = (1 << 20) - 1;
const USES_MASK: u32 = (1 << 10) - 1;
const MSEC_MASK: u32 = (1 << 10) - 1;
const ERROR_MASK: u32 = (1 << 10) - 1;

impl FileCacheNode {
    fn count_inc(&mut self) {
        self.count = (self.count + 1) & COUNT_MASK;
    }

    fn count_dec(&mut self) {
        self.count = self.count.wrapping_sub(1) & COUNT_MASK;
    }

    fn uses_inc(&mut self) {
        self.uses = (self.uses + 1) & USES_MASK;
    }
}

/// ngx_http_file_cache_sh_t
#[repr(C)]
pub struct FileCacheSh {
    pub rbtree: Rbtree,
    pub sentinel: RbtreeNode,
    pub queue: Queue,
    pub cold: AtomicUsize,
    pub loading: AtomicUsize,
    pub size: i64,
    pub count: usize,
    pub watermark: usize,
}

/// ngx_http_file_cache_header_t, as C lays it out
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileCacheHeader {
    pub version: usize,
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    pub last_modified: i64,
    pub date: i64,
    pub crc32: u32,
    pub valid_msec: u16,
    pub header_start: u16,
    pub body_start: u16,
    pub etag_len: u8,
    pub etag: [u8; NGX_HTTP_CACHE_ETAG_LEN],
    pub vary_len: u8,
    pub vary: [u8; NGX_HTTP_CACHE_VARY_LEN],
    pub variant: [u8; NGX_HTTP_CACHE_KEY_LEN],
}

/// sizeof(ngx_http_file_cache_header_t)
pub const FILE_CACHE_HEADER_SIZE: usize = std::mem::size_of::<FileCacheHeader>();

impl FileCacheHeader {
    /// ngx_memzero(h, sizeof(ngx_http_file_cache_header_t))
    pub fn zeroed() -> FileCacheHeader {
        FileCacheHeader {
            version: 0,
            valid_sec: 0,
            updating_sec: 0,
            error_sec: 0,
            last_modified: 0,
            date: 0,
            crc32: 0,
            valid_msec: 0,
            header_start: 0,
            body_start: 0,
            etag_len: 0,
            etag: [0; NGX_HTTP_CACHE_ETAG_LEN],
            vary_len: 0,
            vary: [0; NGX_HTTP_CACHE_VARY_LEN],
            variant: [0; NGX_HTTP_CACHE_KEY_LEN],
        }
    }

    /// The bytes of the struct in memory (native byte order, zero padding).
    pub fn to_bytes(&self) -> [u8; FILE_CACHE_HEADER_SIZE] {
        use std::mem::offset_of;

        let mut b = [0u8; FILE_CACHE_HEADER_SIZE];

        let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);

        put(offset_of!(FileCacheHeader, version), &self.version.to_ne_bytes());
        put(offset_of!(FileCacheHeader, valid_sec), &self.valid_sec.to_ne_bytes());
        put(offset_of!(FileCacheHeader, updating_sec), &self.updating_sec.to_ne_bytes());
        put(offset_of!(FileCacheHeader, error_sec), &self.error_sec.to_ne_bytes());
        put(offset_of!(FileCacheHeader, last_modified), &self.last_modified.to_ne_bytes());
        put(offset_of!(FileCacheHeader, date), &self.date.to_ne_bytes());
        put(offset_of!(FileCacheHeader, crc32), &self.crc32.to_ne_bytes());
        put(offset_of!(FileCacheHeader, valid_msec), &self.valid_msec.to_ne_bytes());
        put(offset_of!(FileCacheHeader, header_start), &self.header_start.to_ne_bytes());
        put(offset_of!(FileCacheHeader, body_start), &self.body_start.to_ne_bytes());
        put(offset_of!(FileCacheHeader, etag_len), &[self.etag_len]);
        put(offset_of!(FileCacheHeader, etag), &self.etag);
        put(offset_of!(FileCacheHeader, vary_len), &[self.vary_len]);
        put(offset_of!(FileCacheHeader, vary), &self.vary);
        put(offset_of!(FileCacheHeader, variant), &self.variant);

        b
    }

    /// The struct from its bytes (at least FILE_CACHE_HEADER_SIZE).
    pub fn from_bytes(b: &[u8]) -> FileCacheHeader {
        use std::mem::offset_of;

        fn get<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
            let mut a = [0u8; N];
            a.copy_from_slice(&b[off..off + N]);
            a
        }

        FileCacheHeader {
            version: usize::from_ne_bytes(get(b, offset_of!(FileCacheHeader, version))),
            valid_sec: i64::from_ne_bytes(get(b, offset_of!(FileCacheHeader, valid_sec))),
            updating_sec: i64::from_ne_bytes(get(b, offset_of!(FileCacheHeader, updating_sec))),
            error_sec: i64::from_ne_bytes(get(b, offset_of!(FileCacheHeader, error_sec))),
            last_modified: i64::from_ne_bytes(get(b, offset_of!(FileCacheHeader, last_modified))),
            date: i64::from_ne_bytes(get(b, offset_of!(FileCacheHeader, date))),
            crc32: u32::from_ne_bytes(get(b, offset_of!(FileCacheHeader, crc32))),
            valid_msec: u16::from_ne_bytes(get(b, offset_of!(FileCacheHeader, valid_msec))),
            header_start: u16::from_ne_bytes(get(b, offset_of!(FileCacheHeader, header_start))),
            body_start: u16::from_ne_bytes(get(b, offset_of!(FileCacheHeader, body_start))),
            etag_len: b[offset_of!(FileCacheHeader, etag_len)],
            etag: get(b, offset_of!(FileCacheHeader, etag)),
            vary_len: b[offset_of!(FileCacheHeader, vary_len)],
            vary: get(b, offset_of!(FileCacheHeader, vary)),
            variant: get(b, offset_of!(FileCacheHeader, variant)),
        }
    }
}

/// ngx_http_file_cache_t: a cache of proxy_cache_path and the like, the
/// data of its keys zone and of its path (the manager and the loader).
pub struct FileCache {
    pub sh: Cell<*mut FileCacheSh>,
    pub shpool: Cell<*mut SlabPool>,

    pub path: Rc<PathConf>,

    pub min_free: i64,
    pub max_size: Cell<i64>,
    pub bsize: Cell<usize>,

    pub inactive: i64,

    pub fail_time: Cell<i64>,

    pub files: Cell<usize>,
    pub loader_files: usize,
    pub last: Cell<u64>,
    pub loader_sleep: u64,
    pub loader_threshold: u64,

    pub manager_files: usize,
    pub manager_sleep: u64,
    pub manager_threshold: u64,

    /// the name of the keys zone (cache->shm_zone->shm.name)
    pub name: Vec<u8>,
    pub shm_zone: Weak<ShmZone>,

    pub use_temp_path: bool,
}

impl FileCache {
    fn sh(&self) -> &mut FileCacheSh {
        // the zone is mapped at the same address in all processes and
        // is initialized before any request or the manager uses it
        unsafe { &mut *self.sh.get() }
    }

    fn shpool(&self) -> &SlabPool {
        unsafe { &*self.shpool.get() }
    }

    /// &cache->sh->queue
    fn queue(&self) -> *mut Queue {
        unsafe { std::ptr::addr_of_mut!((*self.sh.get()).queue) }
    }
}


/// The data of a cache path (cache->path->data).
struct PathData(Weak<FileCache>);

/// ngx_http_cache_t: the cache of a request (r->cache).
pub struct HttpCache {
    /// c->file: the name of the cache file, and the file once open
    pub file_name: Vec<u8>,
    pub fd: i32,
    pub file_handle: Option<Rc<CachedFileHandle>>,
    pub log: Log,

    pub keys: Vec<Vec<u8>>,
    pub crc32: u32,
    pub key: [u8; NGX_HTTP_CACHE_KEY_LEN],
    pub main: [u8; NGX_HTTP_CACHE_KEY_LEN],

    pub uniq: u64,
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    pub last_modified: i64,
    pub date: i64,

    pub etag: Vec<u8>,
    pub vary: Vec<u8>,
    pub variant: [u8; NGX_HTTP_CACHE_KEY_LEN],

    pub buffer_size: usize,
    pub header_start: usize,
    pub body_start: usize,
    pub length: i64,
    pub fs_size: i64,

    pub min_uses: usize,
    pub error: usize,
    pub valid_msec: usize,
    pub vary_tag: usize,

    /// c->buf: what was read of the cache file (up to body_start)
    pub buf: Vec<u8>,

    pub file_cache: Option<Rc<FileCache>>,
    pub node: *mut FileCacheNode,

    pub lock_timeout: u64,
    pub lock_age: u64,
    pub lock_time: u64,
    pub wait_time: u64,
    /// the timer of c->wait_event
    pub wait_timer: u64,

    pub lock: bool,
    pub waiting: bool,

    pub updated: bool,
    pub updating: bool,
    pub exists: bool,
    pub temp_file: bool,
    pub purged: bool,
    pub reading: bool,
    pub secondary: bool,
    pub update_variant: bool,
    pub background: bool,

    pub stale_updating: bool,
    pub stale_error: bool,
}

impl HttpCache {
    fn new(log: Log) -> HttpCache {
        HttpCache {
            file_name: Vec::new(),
            fd: -1,
            file_handle: None,
            log,
            keys: Vec::new(),
            crc32: 0,
            key: [0; NGX_HTTP_CACHE_KEY_LEN],
            main: [0; NGX_HTTP_CACHE_KEY_LEN],
            uniq: 0,
            valid_sec: 0,
            updating_sec: 0,
            error_sec: 0,
            last_modified: 0,
            date: 0,
            etag: Vec::new(),
            vary: Vec::new(),
            variant: [0; NGX_HTTP_CACHE_KEY_LEN],
            buffer_size: 0,
            header_start: 0,
            body_start: 0,
            length: 0,
            fs_size: 0,
            min_uses: 0,
            error: 0,
            valid_msec: 0,
            vary_tag: 0,
            buf: Vec::new(),
            file_cache: None,
            node: std::ptr::null_mut(),
            lock_timeout: 0,
            lock_age: 0,
            lock_time: 0,
            wait_time: 0,
            wait_timer: 0,
            lock: false,
            waiting: false,
            updated: false,
            updating: false,
            exists: false,
            temp_file: false,
            purged: false,
            reading: false,
            secondary: false,
            update_variant: false,
            background: false,
            stale_updating: false,
            stale_error: false,
        }
    }

    fn cache(&self) -> Rc<FileCache> {
        self.file_cache.clone().expect("file cache")
    }

    fn node<'a>(&self) -> &'a mut FileCacheNode {
        // c->node is set by ngx_http_file_cache_exists() and stays valid
        // while the node's count holds it
        unsafe { &mut *self.node }
    }

    /// ngx_pool_run_cleanup_file(r->pool, c->file.fd): the cache file is
    /// closed.
    pub fn close_file(&mut self) {
        self.file_handle = None;
        self.fd = -1;
    }
}

/// r->cache
pub fn cache_of(r: &Request) -> Option<Rc<RefCell<HttpCache>>> {
    r.cache.borrow().clone().and_then(|c| c.downcast::<RefCell<HttpCache>>().ok())
}

fn hex(src: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(src.len() * 2);
    ngx_core::string::hex_dump(&mut v, src);
    v
}

/// ngx_fs_bsize
fn fs_bsize(name: &[u8]) -> usize {
    let path = ngx_core::os::cstr(name);
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };

    if unsafe { libc::statfs(path.as_ptr(), &mut fs) } == -1 {
        return 512;
    }

    let bsize = fs.f_bsize as usize;

    if bsize % 512 != 0 {
        return 512;
    }

    if bsize > ngx_core::os::pagesize() {
        return 512;
    }

    bsize
}

/// ngx_fs_available
fn fs_available(name: &[u8]) -> i64 {
    let path = ngx_core::os::cstr(name);
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };

    if unsafe { libc::statfs(path.as_ptr(), &mut fs) } == -1 {
        return i64::MAX;
    }

    fs.f_bavail as i64 * fs.f_bsize as i64
}

/// ngx_file_uniq, as the open file cache has it (of.uniq)
fn file_uniq(st: &libc::stat) -> u64 {
    ((st.st_dev as u64) << 32) ^ (st.st_ino as u64)
}

/// ngx_file_fs_size
fn file_fs_size(st: &libc::stat) -> i64 {
    (st.st_size as i64).max(st.st_blocks as i64 * 512)
}

/// ngx_read_file: pread() of up to `buf.len()` bytes at `offset`.
fn read_file(fd: i32, name: &[u8], buf: &mut [u8], offset: i64, log: &Log) -> isize {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "read: {}, {:p}, {}, {}", fd, buf.as_ptr(), buf.len(), offset);

    let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), offset) };

    if n == -1 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "pread() \"{}\" failed", B(name));
        return NGX_ERROR as isize;
    }

    n
}

// ---------------------------------------------------------------------------
// the keys zone
// ---------------------------------------------------------------------------

/// ngx_http_file_cache_init: the shm_zone->init of a keys zone.
fn file_cache_init(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let cache = match shm_zone.data::<FileCache>() {
        Some(c) => c,
        None => return Err(()),
    };

    let log = shm_zone.shm.log.borrow().clone().unwrap_or_else(|| ngx_core::cycle::cycle().log.clone());

    if let Some(ocache) = data.and_then(|d| d.downcast::<FileCache>().ok()) {
        if cache.path.name != ocache.path.name {
            ngx_log_error!(
                NGX_LOG_EMERG,
                log,
                None,
                "cache \"{}\" uses the \"{}\" cache path while previously it used the \"{}\" cache path",
                B(shm_zone.name()),
                B(&cache.path.name),
                B(&ocache.path.name)
            );

            return Err(());
        }

        for n in 0..NGX_MAX_PATH_LEVEL {
            if cache.path.level[n] != ocache.path.level[n] {
                ngx_log_error!(NGX_LOG_EMERG, log, None, "cache \"{}\" had previously different levels", B(shm_zone.name()));
                return Err(());
            }
        }

        cache.sh.set(ocache.sh.get());

        cache.shpool.set(ocache.shpool.get());
        cache.bsize.set(ocache.bsize.get());

        cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

        let sh = cache.sh();

        if sh.cold.load(Ordering::SeqCst) == 0 || sh.loading.load(Ordering::SeqCst) != 0 {
            *cache.path.loader.borrow_mut() = None;
        }

        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    cache.shpool.set(shpool);

    unsafe {
        if shm_zone.shm.exists.get() {
            cache.sh.set((*shpool).data as *mut FileCacheSh);
            cache.bsize.set(fs_bsize(&cache.path.name));
            cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

            return Ok(());
        }

        let sh = (*shpool).alloc(std::mem::size_of::<FileCacheSh>()) as *mut FileCacheSh;

        if sh.is_null() {
            return Err(());
        }

        cache.sh.set(sh);

        (*shpool).data = sh as *mut u8;

        (*sh).rbtree.init(&mut (*sh).sentinel, file_cache_rbtree_insert_value);

        queue_init(std::ptr::addr_of_mut!((*sh).queue));

        std::ptr::write(&mut (*sh).cold, AtomicUsize::new(1));
        std::ptr::write(&mut (*sh).loading, AtomicUsize::new(0));
        (*sh).size = 0;
        (*sh).count = 0;
        (*sh).watermark = usize::MAX;

        cache.bsize.set(fs_bsize(&cache.path.name));

        cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

        let ctx = format!(" in cache keys zone \"{}\"", B(shm_zone.name()));

        (*shpool).set_log_ctx(ctx.as_bytes())?;

        (*shpool).log_nomem = false;
    }

    Ok(())
}

/// ngx_http_file_cache_new
pub fn file_cache_new(r: &R) -> Rc<RefCell<HttpCache>> {
    let c = Rc::new(RefCell::new(HttpCache::new(r.connection.log.clone())));

    let any: Rc<dyn Any> = c.clone();
    *r.cache.borrow_mut() = Some(any);

    c
}

/// The cleanup of ngx_pool_cleanup_add(r->pool): the pool of a request is
/// that of its main request.
fn add_cleanup(r: &R, c: &Rc<RefCell<HttpCache>>) {
    let c = c.clone();

    r.main().add_cleanup(Box::new(move || {
        let mut c = c.borrow_mut();
        file_cache_cleanup(&mut c);
        c.close_file();
    }));
}

/// ngx_http_file_cache_create: the cache of a request that bypassed it.
pub fn file_cache_create(r: &R) -> i64 {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    add_cleanup(r, &c_rc);

    let mut c = c_rc.borrow_mut();

    let cache = c.cache();

    if file_cache_exists(&cache, &mut c) == NGX_ERROR {
        return NGX_ERROR;
    }

    if file_cache_name(r, &mut c, &cache.path) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_http_file_cache_create_key: the crc32 and md5 of the keys.
pub fn file_cache_create_key(r: &R, c: &mut HttpCache) {
    use md5::{Digest, Md5};

    let mut len = 0;

    let mut crc = crc32fast::Hasher::new();
    let mut md5 = Md5::new();

    for key in c.keys.iter() {
        http_debug!(r, "http cache key: \"{}\"", B(key));

        len += key.len();

        crc.update(key);
        md5.update(key);
    }

    c.header_start = FILE_CACHE_HEADER_SIZE + NGX_HTTP_FILE_CACHE_KEY.len() + len + 1;

    c.crc32 = crc.finalize();
    c.key.copy_from_slice(&md5.finalize());

    c.main = c.key;
}

/// ngx_http_file_cache_open
pub fn file_cache_open(r: &R) -> i64 {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let mut c = c_rc.borrow_mut();

    open(r, &c_rc, &mut c)
}

fn open(r: &R, c_rc: &Rc<RefCell<HttpCache>>, c: &mut HttpCache) -> i64 {
    if c.waiting {
        return NGX_AGAIN;
    }

    if c.reading {
        return file_cache_read(r, c_rc, c);
    }

    let cache = c.cache();

    if c.node.is_null() {
        add_cleanup(r, c_rc);
    }

    c.buffer_size = c.body_start;

    let rc = file_cache_exists(&cache, c);

    http_debug!(r, "http file cache exists: {} e:{}", rc, c.exists as i32);

    if rc == NGX_ERROR {
        return rc;
    }

    if rc == NGX_AGAIN {
        return NGX_HTTP_CACHE_SCARCE as i64;
    }

    let test;
    let rv;

    if rc == NGX_OK {
        if c.error != 0 {
            return c.error as i64;
        }

        c.temp_file = true;
        test = c.exists;
        rv = NGX_DECLINED;
    } else {
        // rc == NGX_DECLINED

        test = cache.sh().cold.load(Ordering::SeqCst) != 0;

        if c.min_uses > 1 {
            if !test {
                return NGX_HTTP_CACHE_SCARCE as i64;
            }

            rv = NGX_HTTP_CACHE_SCARCE as i64;
        } else {
            c.temp_file = true;
            rv = NGX_DECLINED;
        }
    }

    if file_cache_name(r, c, &cache.path) != NGX_OK {
        return NGX_ERROR;
    }

    'done: {
        if !test {
            break 'done;
        }

        let clcf = r.clcf();

        let mut of = OpenFileInfo::default();

        {
            let l = clcf.borrow();
            of.uniq = c.uniq;
            of.valid = *l.open_file_cache_valid;
            of.min_uses = *l.open_file_cache_min_uses as u32;
            of.events = *l.open_file_cache_events;
            of.directio = usize::MAX;
            of.read_ahead = *l.read_ahead;
        }

        let ofc = clcf.borrow().open_file_cache.get().clone();

        let handle = match open_cached_file(ofc.as_ref(), &c.file_name, &mut of, &r.connection.log) {
            Ok(h) => h,
            Err(()) => match of.err {
                0 => return NGX_ERROR,
                libc::ENOENT | libc::ENOTDIR => break 'done,
                err => {
                    ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "open() \"{}\" failed", B(&c.file_name));
                    return NGX_ERROR;
                }
            },
        };

        http_debug!(r, "http file cache fd: {}", of.fd);

        c.fd = of.fd;
        c.file_handle = handle;
        c.log = r.connection.log.clone();
        c.uniq = of.uniq;
        c.length = of.size;
        c.fs_size = (of.fs_size + cache.bsize.get() as i64 - 1) / cache.bsize.get() as i64;

        c.buf = vec![0u8; c.body_start];

        return file_cache_read(r, c_rc, c);
    }

    // done:

    if rv == NGX_DECLINED {
        return file_cache_lock(r, c);
    }

    rv
}

/// ngx_http_file_cache_lock
fn file_cache_lock(r: &R, c: &mut HttpCache) -> i64 {
    if !c.lock {
        return NGX_DECLINED;
    }

    let now = ngx_core::times::current_msec();

    let cache = c.cache();

    cache.shpool().lock();

    {
        let node = c.node();

        let timer = node.lock_time.wrapping_sub(now) as i64;

        if !node.updating || timer <= 0 {
            node.updating = true;
            node.lock_time = now.wrapping_add(c.lock_age);
            c.updating = true;
            c.lock_time = node.lock_time;
        }
    }

    cache.shpool().unlock();

    http_debug!(r, "http file cache lock u:{} wt:{}", c.updating as i32, c.wait_time);

    if c.updating {
        return NGX_DECLINED;
    }

    if c.lock_timeout == 0 {
        return NGX_HTTP_CACHE_SCARCE as i64;
    }

    c.waiting = true;

    if c.wait_time == 0 {
        c.wait_time = now.wrapping_add(c.lock_timeout);
    }

    let timer = c.wait_time.wrapping_sub(now);

    // ngx_add_timer(&c->wait_event, ...)
    c.wait_timer = if timer > 500 { 500 } else { timer };

    let main = r.main();
    main.blocked.set(main.blocked.get() + 1);

    NGX_AGAIN
}

/// The c->wait_event timer and ngx_http_file_cache_lock_wait_handler: the
/// request waits for the cache lock to be released or to time out, then
/// goes on (r->write_event_handler) with c->waiting cleared.
pub async fn file_cache_lock_wait_handler(r: &R) {
    let c_rc = match cache_of(r) {
        Some(c) => c,
        None => return,
    };

    loop {
        let timer = c_rc.borrow().wait_timer;

        tokio::time::sleep(std::time::Duration::from_millis(timer)).await;

        r.set_log_request();

        http_debug!(r, "http file cache wait: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

        let rc = {
            let mut c = c_rc.borrow_mut();
            file_cache_lock_wait(r, &mut c)
        };

        if rc == NGX_AGAIN {
            continue;
        }

        c_rc.borrow_mut().waiting = false;

        let main = r.main();
        main.blocked.set(main.blocked.get().saturating_sub(1));

        return;
    }
}

/// ngx_http_file_cache_lock_wait
fn file_cache_lock_wait(r: &R, c: &mut HttpCache) -> i64 {
    let now = ngx_core::times::current_msec();

    let timer = c.wait_time.wrapping_sub(now) as i64;

    if timer <= 0 {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "cache lock timeout");
        c.lock_timeout = 0;
        return NGX_OK;
    }

    let cache = c.cache();

    let mut wait = false;

    cache.shpool().lock();

    let timer = {
        let node = c.node();

        let timer = node.lock_time.wrapping_sub(now) as i64;

        if node.updating && timer > 0 {
            wait = true;
        }

        timer
    };

    cache.shpool().unlock();

    if wait {
        c.wait_timer = if timer > 500 { 500 } else { timer as u64 };
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_file_cache_read
fn file_cache_read(r: &R, c_rc: &Rc<RefCell<HttpCache>>, c: &mut HttpCache) -> i64 {
    // ngx_http_file_cache_aio_read: without aio, ngx_read_file()
    let body_start = c.body_start;

    let n = {
        let (fd, name, log) = (c.fd, c.file_name.clone(), r.connection.log.clone());
        read_file(fd, &name, &mut c.buf[..body_start], 0, &log)
    };

    if n < 0 {
        return n as i64;
    }

    let n = n as usize;

    if n < c.header_start {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" is too small", B(&c.file_name));
        return NGX_DECLINED;
    }

    let h = FileCacheHeader::from_bytes(&c.buf);

    if h.version != NGX_HTTP_CACHE_VERSION {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "cache file \"{}\" version mismatch", B(&c.file_name));
        return NGX_DECLINED;
    }

    if h.crc32 != c.crc32 || h.header_start as usize != c.header_start {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has md5 collision", B(&c.file_name));
        return NGX_DECLINED;
    }

    let mut p = FILE_CACHE_HEADER_SIZE + NGX_HTTP_FILE_CACHE_KEY.len();

    for key in c.keys.iter() {
        if &c.buf[p..p + key.len()] != key.as_slice() {
            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has md5 collision", B(&c.file_name));
            return NGX_DECLINED;
        }

        p += key.len();
    }

    if h.body_start as usize > c.body_start {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has too long header", B(&c.file_name));
        return NGX_DECLINED;
    }

    if h.vary_len as usize > NGX_HTTP_CACHE_VARY_LEN {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has incorrect vary length", B(&c.file_name));
        return NGX_DECLINED;
    }

    if h.vary_len != 0 {
        c.variant = file_cache_vary(r, &h.vary[..h.vary_len as usize], &c.main);

        if c.variant != h.variant {
            http_debug!(r, "http file cache vary mismatch");
            return file_cache_reopen(r, c_rc, c);
        }
    }

    // c->buf->last += n
    c.buf.truncate(n);

    c.valid_sec = h.valid_sec;
    c.updating_sec = h.updating_sec;
    c.error_sec = h.error_sec;
    c.last_modified = h.last_modified;
    c.date = h.date;
    c.valid_msec = h.valid_msec as usize;
    c.body_start = h.body_start as usize;
    c.etag = h.etag[..h.etag_len as usize].to_vec();

    r.cached.set(true);

    let cache = c.cache();

    if cache.sh().cold.load(Ordering::SeqCst) != 0 {
        cache.shpool().lock();

        let (body_start, uniq, fs_size) = (c.body_start, c.uniq, c.fs_size);
        let node = c.node();

        if !node.exists {
            node.uses = 1;
            node.body_start = body_start;
            node.exists = true;
            node.uniq = uniq;
            node.fs_size = fs_size;

            cache.sh().size += fs_size;
        }

        cache.shpool().unlock();
    }

    let now = ngx_core::times::time();

    if c.valid_sec < now {
        c.stale_updating = c.valid_sec + c.updating_sec >= now;
        c.stale_error = c.valid_sec + c.error_sec >= now;

        cache.shpool().lock();

        let rc;

        if c.node().updating {
            rc = NGX_HTTP_CACHE_UPDATING as i64;
        } else {
            c.node().updating = true;
            c.updating = true;
            c.lock_time = c.node().lock_time;
            rc = NGX_HTTP_CACHE_STALE as i64;
        }

        cache.shpool().unlock();

        http_debug!(r, "http file cache expired: {} {} {}", rc, c.valid_sec, now);

        return rc;
    }

    NGX_OK
}

/// ngx_http_file_cache_exists: the node of the key, found or created; its
/// uses and the time it is inactive after.
fn file_cache_exists(cache: &FileCache, c: &mut HttpCache) -> i64 {
    let rc;

    cache.shpool().lock();

    let mut fcn = c.node;

    if fcn.is_null() {
        fcn = unsafe { file_cache_lookup(cache, &c.key) };
    }

    unsafe {
        'done: {
            'renew: {
                if !fcn.is_null() {
                    queue_remove(std::ptr::addr_of_mut!((*fcn).queue));

                    if c.node.is_null() {
                        (*fcn).uses_inc();
                        (*fcn).count_inc();
                    }

                    if (*fcn).error != 0 {
                        if (*fcn).valid_sec < ngx_core::times::time() {
                            break 'renew;
                        }

                        rc = NGX_OK;

                        break 'done;
                    }

                    if (*fcn).exists || (*fcn).uses as usize >= c.min_uses {
                        c.exists = (*fcn).exists;

                        if (*fcn).body_start != 0 && !c.update_variant {
                            c.body_start = (*fcn).body_start;
                        }

                        rc = NGX_OK;

                        break 'done;
                    }

                    rc = NGX_AGAIN;

                    break 'done;
                }

                fcn = cache.shpool().calloc_locked(std::mem::size_of::<FileCacheNode>()) as *mut FileCacheNode;

                if fcn.is_null() {
                    file_cache_set_watermark(cache);

                    cache.shpool().unlock();

                    let _ = file_cache_forced_expire(cache);

                    cache.shpool().lock();

                    fcn = cache.shpool().calloc_locked(std::mem::size_of::<FileCacheNode>()) as *mut FileCacheNode;

                    if fcn.is_null() {
                        ngx_log_error!(NGX_LOG_ALERT, cycle_log(), None, "could not allocate node{}", B(cache.shpool().log_ctx()));

                        cache.shpool().unlock();

                        return NGX_ERROR;
                    }
                }

                cache.sh().count += 1;

                (*fcn).node.key = usize::from_ne_bytes(c.key[..RBTREE_KEY_SIZE].try_into().unwrap());

                (*fcn).key.copy_from_slice(&c.key[RBTREE_KEY_SIZE..]);

                cache.sh().rbtree.insert(&mut (*fcn).node);

                (*fcn).uses = 1;
                (*fcn).count = 1;
            }

            // renew:

            rc = NGX_DECLINED;

            (*fcn).valid_msec = 0;
            (*fcn).error = 0;
            (*fcn).exists = false;
            (*fcn).valid_sec = 0;
            (*fcn).uniq = 0;
            (*fcn).body_start = 0;
            (*fcn).fs_size = 0;
        }

        // done:

        (*fcn).expire = ngx_core::times::time() + cache.inactive;

        queue_insert_head(cache.queue(), std::ptr::addr_of_mut!((*fcn).queue));

        c.uniq = (*fcn).uniq;
        c.error = (*fcn).error as usize;
        c.node = fcn;
    }

    cache.shpool().unlock();

    rc
}

/// ngx_cycle->log
fn cycle_log() -> Log {
    ngx_core::cycle::cycle().log.clone()
}

/// ngx_http_file_cache_name
fn file_cache_name(r: &R, c: &mut HttpCache, path: &PathConf) -> i64 {
    if !c.file_name.is_empty() {
        return NGX_OK;
    }

    c.file_name = path.hashed_filename(&hex(&c.key));

    http_debug!(r, "cache file: \"{}\"", B(&c.file_name));

    NGX_OK
}

/// ngx_http_file_cache_lookup
unsafe fn file_cache_lookup(cache: &FileCache, key: &[u8; NGX_HTTP_CACHE_KEY_LEN]) -> *mut FileCacheNode {
    let node_key = usize::from_ne_bytes(key[..RBTREE_KEY_SIZE].try_into().unwrap());

    let sh = cache.sh();

    let mut node = sh.rbtree.root;
    let sentinel = sh.rbtree.sentinel;

    while node != sentinel {
        if node_key < (*node).key {
            node = (*node).left;
            continue;
        }

        if node_key > (*node).key {
            node = (*node).right;
            continue;
        }

        // node_key == node->key

        let fcn = node as *mut FileCacheNode;

        let fkey = &(*fcn).key;
        let rc = key[RBTREE_KEY_SIZE..].cmp(&fkey[..]);

        if rc == std::cmp::Ordering::Equal {
            return fcn;
        }

        node = if rc == std::cmp::Ordering::Less { (*node).left } else { (*node).right };
    }

    // not found

    std::ptr::null_mut()
}

/// ngx_http_file_cache_rbtree_insert_value
unsafe fn file_cache_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        if (*node).key < (*temp).key {
            p = &mut (*temp).left;
        } else if (*node).key > (*temp).key {
            p = &mut (*temp).right;
        } else {
            // node->key == temp->key

            let cn = node as *mut FileCacheNode;
            let cnt = temp as *mut FileCacheNode;

            let (a, b) = (&(*cn).key, &(*cnt).key);

            p = if a[..] < b[..] { &mut (*temp).left } else { &mut (*temp).right };
        }

        if *p == sentinel {
            break;
        }

        temp = *p;
    }

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

/// ngx_http_file_cache_vary: the md5 of the main key and of the request
/// headers the response varies on.
pub fn file_cache_vary(r: &R, vary: &[u8], main: &[u8; NGX_HTTP_CACHE_KEY_LEN]) -> [u8; NGX_HTTP_CACHE_KEY_LEN] {
    use md5::{Digest, Md5};

    http_debug!(r, "http file cache vary: \"{}\"", B(vary));

    let mut md5 = Md5::new();
    md5.update(main);

    let buf = vary.to_ascii_lowercase();

    let mut p = 0;
    let last = buf.len();

    while p < last {
        while p < last && (buf[p] == b' ' || buf[p] == b',') {
            p += 1;
        }

        let start = p;

        while p < last && buf[p] != b',' && buf[p] != b' ' {
            p += 1;
        }

        let name = &buf[start..p];

        if name.is_empty() {
            break;
        }

        http_debug!(r, "http file cache vary: {}", B(name));

        md5.update(name);
        md5.update(b":");

        file_cache_vary_header(r, &mut md5, name);

        md5.update(b"\r\n");
    }

    let mut hash = [0u8; NGX_HTTP_CACHE_KEY_LEN];
    hash.copy_from_slice(&md5.finalize());
    hash
}

/// ngx_http_file_cache_vary_header
fn file_cache_vary_header(r: &R, md5: &mut md5::Md5, name: &[u8]) {
    use md5::Digest;

    let mut multiple = false;

    let normalize = name.eq_ignore_ascii_case(b"Accept-Charset") || name.eq_ignore_ascii_case(b"Accept-Encoding") || name.eq_ignore_ascii_case(b"Accept-Language");

    let headers = r.headers_in.borrow().headers.clone();

    for h in headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        if h.key.len() != name.len() {
            continue;
        }

        if !h.key.eq_ignore_ascii_case(name) {
            continue;
        }

        let value = h.value.borrow();

        if !normalize {
            if multiple {
                md5.update(b",");
            }

            md5.update(&value[..]);

            multiple = true;

            continue;
        }

        // normalize spaces

        let mut p = 0;
        let last = value.len();

        while p < last {
            while p < last && (value[p] == b' ' || value[p] == b',') {
                p += 1;
            }

            let start = p;

            while p < last && value[p] != b',' && value[p] != b' ' {
                p += 1;
            }

            if p == start {
                break;
            }

            if multiple {
                md5.update(b",");
            }

            md5.update(&value[start..p]);

            multiple = true;
        }
    }
}

/// ngx_http_file_cache_reopen: the secondary key of a variant.
fn file_cache_reopen(r: &R, c_rc: &Rc<RefCell<HttpCache>>, c: &mut HttpCache) -> i64 {
    http_debug!(r, "http file cache reopen");

    if c.secondary {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has incorrect vary hash", B(&c.file_name));
        return NGX_DECLINED;
    }

    let cache = c.cache();

    cache.shpool().lock();

    c.node().count_dec();
    c.node = std::ptr::null_mut();

    cache.shpool().unlock();

    c.secondary = true;
    c.file_name.clear();
    c.close_file();
    c.body_start = c.buffer_size;

    c.key = c.variant;

    open(r, c_rc, c)
}

/// ngx_http_file_cache_set_header: the header of a cache file, the key
/// line after it (header_start bytes, which precede the response header in
/// the file).
pub fn file_cache_set_header(r: &R, c: &mut HttpCache) -> Result<Vec<u8>, ()> {
    http_debug!(r, "http file cache set header");

    let mut h = FileCacheHeader::zeroed();

    h.version = NGX_HTTP_CACHE_VERSION;
    h.valid_sec = c.valid_sec;
    h.updating_sec = c.updating_sec;
    h.error_sec = c.error_sec;
    h.last_modified = c.last_modified;
    h.date = c.date;
    h.crc32 = c.crc32;
    h.valid_msec = c.valid_msec as u16;
    h.header_start = c.header_start as u16;
    h.body_start = c.body_start as u16;

    if c.etag.len() <= NGX_HTTP_CACHE_ETAG_LEN {
        h.etag_len = c.etag.len() as u8;
        h.etag[..c.etag.len()].copy_from_slice(&c.etag);
    }

    if !c.vary.is_empty() {
        if c.vary.len() > NGX_HTTP_CACHE_VARY_LEN {
            // should not happen
            c.vary.truncate(NGX_HTTP_CACHE_VARY_LEN);
        }

        h.vary_len = c.vary.len() as u8;
        h.vary[..c.vary.len()].copy_from_slice(&c.vary);

        c.variant = file_cache_vary(r, &c.vary, &c.main);
        h.variant = c.variant;
    }

    if file_cache_update_variant(r, c) != NGX_OK {
        return Err(());
    }

    let mut buf = Vec::with_capacity(c.header_start);

    buf.extend_from_slice(&h.to_bytes());
    buf.extend_from_slice(NGX_HTTP_FILE_CACHE_KEY);

    for key in c.keys.iter() {
        buf.extend_from_slice(key);
    }

    buf.push(b'\n');

    Ok(buf)
}

/// ngx_http_file_cache_update_variant
fn file_cache_update_variant(r: &R, c: &mut HttpCache) -> i64 {
    if !c.secondary {
        return NGX_OK;
    }

    if !c.vary.is_empty() && c.variant == c.key {
        return NGX_OK;
    }

    // if the variant hash doesn't match one we used as a secondary
    // cache key, switch back to the original key

    let cache = c.cache();

    http_debug!(r, "http file cache main key");

    cache.shpool().lock();

    c.node().count_dec();
    c.node().updating = false;
    c.node = std::ptr::null_mut();

    cache.shpool().unlock();

    c.file_name.clear();
    c.update_variant = true;

    c.key = c.main;

    if file_cache_exists(&cache, c) == NGX_ERROR {
        return NGX_ERROR;
    }

    if file_cache_name(r, c, &cache.path) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_http_file_cache_update: the temporary file with the response
/// becomes the cache file.
pub fn file_cache_update(r: &R, c: &mut HttpCache, tf: &CacheTempFile) {
    if c.updated {
        return;
    }

    http_debug!(r, "http file cache update");

    let cache = c.cache();

    c.updated = true;
    c.updating = false;

    let mut uniq = 0;
    let mut fs_size = 0;

    http_debug!(r, "http file cache rename: \"{}\" to \"{}\"", B(&tf.name), B(&c.file_name));

    let mut rc = ext_rename_file(&tf.name, &c.file_name, NGX_FILE_OWNER_ACCESS, NGX_FILE_OWNER_ACCESS, true, true, &r.connection.log);

    if rc == NGX_OK {
        match ngx_core::os::fstat(tf.fd) {
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "fstat() \"{}\" failed", B(&tf.name));

                rc = NGX_ERROR;
            }
            Ok(fi) => {
                uniq = file_uniq(&fi);
                fs_size = (file_fs_size(&fi) + cache.bsize.get() as i64 - 1) / cache.bsize.get() as i64;
            }
        }
    }

    cache.shpool().lock();

    let body_start = c.body_start;
    let node = c.node();

    node.count_dec();
    node.error = 0;
    node.uniq = uniq;
    node.body_start = body_start;

    cache.sh().size += fs_size - node.fs_size;
    node.fs_size = fs_size;

    if rc == NGX_OK {
        node.exists = true;
    }

    node.updating = false;

    cache.shpool().unlock();
}

/// ngx_http_file_cache_update_header: the header of the cache file, after
/// the response was revalidated (notably h.valid_sec and h.date).
pub fn file_cache_update_header(r: &R, c: &mut HttpCache) {
    http_debug!(r, "http file cache update header");

    let name = c.file_name.clone();

    let fd = match ngx_core::os::open(&name, libc::O_RDWR, 0) {
        Ok(fd) => fd,
        Err(err) => {
            // cache file may have been deleted

            if err == libc::ENOENT {
                http_debug!(r, "http file cache \"{}\" not found", B(&name));
                return;
            }

            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "open() \"{}\" failed", B(&name));
            return;
        }
    };

    'done: {
        // make sure cache file wasn't replaced;
        // if it was, do nothing

        let fi = match ngx_core::os::fstat(fd) {
            Ok(fi) => fi,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "fstat() \"{}\" failed", B(&name));
                break 'done;
            }
        };

        if c.uniq != file_uniq(&fi) || c.length != fi.st_size as i64 {
            http_debug!(r, "http file cache \"{}\" changed", B(&name));
            break 'done;
        }

        let mut hb = [0u8; FILE_CACHE_HEADER_SIZE];

        let n = read_file(fd, &name, &mut hb, 0, &r.connection.log);

        if n == NGX_ERROR as isize {
            break 'done;
        }

        if n as usize != FILE_CACHE_HEADER_SIZE {
            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "pread() read only {} of {} from \"{}\"", n, FILE_CACHE_HEADER_SIZE, B(&name));
            break 'done;
        }

        let h = FileCacheHeader::from_bytes(&hb);

        if h.version != NGX_HTTP_CACHE_VERSION
            || h.last_modified != c.last_modified
            || h.crc32 != c.crc32
            || h.header_start as usize != c.header_start
            || h.body_start as usize != c.body_start
        {
            http_debug!(r, "http file cache \"{}\" content changed", B(&name));
            break 'done;
        }

        // update cache file header with new data,
        // notably h.valid_sec and h.date

        let mut h = FileCacheHeader::zeroed();

        h.version = NGX_HTTP_CACHE_VERSION;
        h.valid_sec = c.valid_sec;
        h.updating_sec = c.updating_sec;
        h.error_sec = c.error_sec;
        h.last_modified = c.last_modified;
        h.date = c.date;
        h.crc32 = c.crc32;
        h.valid_msec = c.valid_msec as u16;
        h.header_start = c.header_start as u16;
        h.body_start = c.body_start as u16;

        if c.etag.len() <= NGX_HTTP_CACHE_ETAG_LEN {
            h.etag_len = c.etag.len() as u8;
            h.etag[..c.etag.len()].copy_from_slice(&c.etag);
        }

        if !c.vary.is_empty() {
            if c.vary.len() > NGX_HTTP_CACHE_VARY_LEN {
                // should not happen
                c.vary.truncate(NGX_HTTP_CACHE_VARY_LEN);
            }

            h.vary_len = c.vary.len() as u8;
            h.vary[..c.vary.len()].copy_from_slice(&c.vary);

            c.variant = file_cache_vary(r, &c.vary, &c.main);
            h.variant = c.variant;
        }

        // ngx_write_file()
        let bytes = h.to_bytes();

        let n = unsafe { libc::pwrite(fd, bytes.as_ptr() as *const libc::c_void, bytes.len(), 0) };

        if n == -1 {
            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(ngx_core::os::errno()), "pwrite() \"{}\" failed", B(&name));
        } else if n as usize != bytes.len() {
            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "pwrite() \"{}\" has written only {} of {}", B(&name), n, bytes.len());
        }
    }

    // done:

    if unsafe { libc::close(fd) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, Some(ngx_core::os::errno()), "close() \"{}\" failed", B(&name));
    }
}

/// ngx_http_cache_send: the header, then the body from the cache file.
pub async fn cache_send(r: &R) -> i64 {
    let (fd, name, body_start, length) = match cache_of(r) {
        Some(c) => {
            let c = c.borrow();
            (c.fd, c.file_name.clone(), c.body_start as i64, c.length)
        }
        None => return crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http file cache send: {}", B(&name));

    let rc = crate::core_rt::send_header(r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }

    let file = Rc::new(BufFile { fd, name, directio: false });

    let mut b = Buf::file(file, body_start, length);

    b.in_file = length - body_start != 0;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.in_file);

    let mut out = Chain::new();
    out.push_back(b);

    crate::core_rt::output_filter(r, out).await
}

/// ngx_http_file_cache_free: the node is released, an incomplete temporary
/// file deleted.
pub fn file_cache_free(c: &mut HttpCache, tf: Option<&CacheTempFile>) {
    if c.updated || c.node.is_null() {
        return;
    }

    let cache = c.cache();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http file cache free, fd: {}", c.fd);

    cache.shpool().lock();

    unsafe {
        let fcn = c.node;

        (*fcn).count_dec();

        if c.updating && (*fcn).lock_time == c.lock_time {
            (*fcn).updating = false;
        }

        if c.error != 0 {
            (*fcn).error = c.error as u32 & ERROR_MASK;

            if c.valid_sec != 0 {
                (*fcn).valid_sec = c.valid_sec;
                (*fcn).valid_msec = c.valid_msec as u32 & MSEC_MASK;
            }
        } else if !(*fcn).exists && (*fcn).count == 0 && c.min_uses == 1 {
            queue_remove(std::ptr::addr_of_mut!((*fcn).queue));
            cache.sh().rbtree.delete(&mut (*fcn).node);
            cache.shpool().free_locked(fcn as *mut u8);
            cache.sh().count -= 1;
            c.node = std::ptr::null_mut();
        }
    }

    cache.shpool().unlock();

    c.updated = true;
    c.updating = false;

    if c.temp_file {
        if let Some(tf) = tf {
            if tf.fd != -1 {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http file cache incomplete: \"{}\"", B(&tf.name));

                if let Err(err) = ngx_core::os::unlink(&tf.name) {
                    ngx_log_error!(NGX_LOG_CRIT, c.log, Some(err), "unlink() \"{}\" failed", B(&tf.name));
                }
            }
        }
    }

    // the c->wait_event timer goes with the waiting task
}

/// ngx_http_file_cache_cleanup
fn file_cache_cleanup(c: &mut HttpCache) {
    if c.updated {
        return;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http file cache cleanup");

    if c.updating && !c.background {
        ngx_log_error!(NGX_LOG_ALERT, c.log, None, "stalled cache updating, error:{}", c.error);
    }

    file_cache_free(c, None);
}

// ---------------------------------------------------------------------------
// the temporary file of a response being cached
// ---------------------------------------------------------------------------

/// p->temp_file of a cacheable response (ngx_temp_file_t): in the
/// temp_path of the module, or, with use_temp_path=off, next to the cache
/// file.
pub struct CacheTempFile {
    pub name: Vec<u8>,
    pub fd: i32,
    pub offset: i64,
}

impl Drop for CacheTempFile {
    fn drop(&mut self) {
        // ngx_pool_cleanup_file: the fd; a persistent temporary file is
        // renamed or deleted by the cache
        if self.fd != -1 {
            ngx_core::os::close(self.fd);
            self.fd = -1;
        }
    }
}

impl CacheTempFile {
    /// ngx_create_temp_file(&p->temp_file->file, path, r->pool, 1, 0, 0600):
    /// in the temp path of the module with its levels, or, with file.name
    /// preset to the cache file name when the cache does not use the temp
    /// path, next to it ("name.NNNNNNNNNN").
    pub fn create(r: &R, path: &PathConf, cache_file: Option<&[u8]>) -> Result<CacheTempFile, ()> {
        let log = &r.connection.log;

        let stats = ngx_core::connection::stats();

        let mut n = stats.temp_number.fetch_add(1, Ordering::Relaxed) as u32;

        loop {
            let name = match cache_file {
                Some(prefix) => {
                    let mut name = prefix.to_vec();
                    name.push(b'.');
                    name.extend_from_slice(format!("{:010}", n).as_bytes());
                    name
                }
                None => path.hashed_filename(format!("{:010}", n).as_bytes()),
            };

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "hashed path: {}", B(&name));

            match ngx_core::os::open(&name, libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, NGX_FILE_OWNER_ACCESS) {
                Ok(fd) => {
                    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "temp fd:{}", fd);
                    return Ok(CacheTempFile { name, fd, offset: 0 });
                }
                Err(err) if err == libc::EEXIST => {
                    // ngx_next_temp_number(1)
                    n = stats.temp_number.fetch_add(123456, Ordering::Relaxed).wrapping_add(123456) as u32;
                    continue;
                }
                Err(err) => {
                    if path.level[0] == 0 || err != libc::ENOENT {
                        ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "open() \"{}\" failed", B(&name));
                        return Err(());
                    }

                    // ngx_create_path(): the level directories
                    create_path(&name, path, log)?;
                }
            }
        }
    }

    /// ngx_write_chain_to_temp_file: the data at the end of the file.
    pub fn write(&mut self, data: &[u8], log: &Log) -> Result<(), ()> {
        let mut off = 0;

        while off < data.len() {
            let n = unsafe { libc::pwrite(self.fd, data[off..].as_ptr() as *const libc::c_void, data.len() - off, self.offset) };

            if n == -1 {
                let err = ngx_core::os::errno();

                if err == libc::EINTR {
                    continue;
                }

                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pwrite() \"{}\" failed", B(&self.name));
                return Err(());
            }

            off += n as usize;
            self.offset += n as i64;
        }

        Ok(())
    }
}

/// ngx_dir_access
fn dir_access(a: u32) -> u32 {
    a | ((a & 0o444) >> 2)
}

/// ngx_create_path: the level directories of a temporary file.
fn create_path(name: &[u8], path: &PathConf, log: &Log) -> Result<(), ()> {
    let mut pos = path.name.len();

    for n in 0..NGX_MAX_PATH_LEVEL {
        if path.level[n] == 0 {
            break;
        }

        pos += path.level[n] + 1;

        let dir = &name[..pos];

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "temp file: \"{}\"", B(dir));

        if let Err(err) = ngx_core::os::mkdir(dir, 0o700) {
            if err != libc::EEXIST {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "mkdir() \"{}\" failed", B(dir));
                return Err(());
            }
        }
    }

    Ok(())
}

/// ngx_create_full_path
fn create_full_path(dir: &[u8], access: u32) -> Result<(), i32> {
    let mut err = 0;

    for i in 1..dir.len() {
        if dir[i] != b'/' {
            continue;
        }

        if let Err(e) = ngx_core::os::mkdir(&dir[..i], access) {
            err = e;

            match e {
                libc::EEXIST => err = 0,
                libc::EACCES => {}
                _ => return Err(e),
            }
        }
    }

    if err != 0 {
        return Err(err);
    }

    Ok(())
}

/// ngx_ext_rename_file with ext->time = -1
pub(crate) fn ext_rename_file(src: &[u8], to: &[u8], access: u32, path_access: u32, create_path: bool, delete_file: bool, log: &Log) -> i64 {
    let mut err;

    'failed: {
        if access != 0 {
            let s = ngx_core::os::cstr(src);

            if unsafe { libc::chmod(s.as_ptr(), access as libc::mode_t) } == -1 {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "chmod() \"{}\" failed", B(src));
                err = 0;
                break 'failed;
            }
        }

        if rename(src, to).is_ok() {
            return NGX_OK;
        }

        err = ngx_core::os::errno();

        if err == libc::ENOENT {
            if !create_path {
                break 'failed;
            }

            if let Err(e) = create_full_path(to, dir_access(path_access)) {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "mkdir() \"{}\" failed", B(to));
                err = 0;
                break 'failed;
            }

            if rename(src, to).is_ok() {
                return NGX_OK;
            }

            err = ngx_core::os::errno();
        }

        if err == libc::EXDEV {
            // the copy of ngx_copy_file() to "to.NNNNNNNNNN", renamed
            let n = ngx_core::connection::stats().temp_number.fetch_add(1, Ordering::Relaxed) as u32;

            let mut name = to.to_vec();
            name.push(b'.');
            name.extend_from_slice(format!("{:010}", n).as_bytes());

            if copy_file(src, &name, access, log).is_ok() {
                if rename(&name, to).is_ok() {
                    if let Err(e) = ngx_core::os::unlink(src) {
                        ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(src));
                        return NGX_ERROR;
                    }

                    return NGX_OK;
                }

                ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "rename() \"{}\" to \"{}\" failed", B(&name), B(to));

                if let Err(e) = ngx_core::os::unlink(&name) {
                    ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(&name));
                }
            }

            err = 0;
        }
    }

    // failed:

    if delete_file {
        if let Err(e) = ngx_core::os::unlink(src) {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(src));
        }
    }

    if err != 0 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "rename() \"{}\" to \"{}\" failed", B(src), B(to));
    }

    NGX_ERROR
}

fn rename(from: &[u8], to: &[u8]) -> Result<(), ()> {
    let f = ngx_core::os::cstr(from);
    let t = ngx_core::os::cstr(to);

    if unsafe { libc::rename(f.as_ptr(), t.as_ptr()) } == -1 {
        return Err(());
    }

    Ok(())
}

/// ngx_copy_file
fn copy_file(from: &[u8], to: &[u8], access: u32, log: &Log) -> Result<(), ()> {
    let data = match std::fs::read(ngx_core::os::path(from)) {
        Ok(d) => d,
        Err(e) => {
            ngx_log_error!(NGX_LOG_CRIT, log, e.raw_os_error(), "open() \"{}\" failed", B(from));
            return Err(());
        }
    };

    let fd = match ngx_core::os::open(to, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, access) {
        Ok(fd) => fd,
        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "open() \"{}\" failed", B(to));
            return Err(());
        }
    };

    let rc = match ngx_core::os::write_fd(fd, &data) {
        Ok(n) if n == data.len() => Ok(()),
        _ => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "write() \"{}\" failed", B(to));
            Err(())
        }
    };

    ngx_core::os::close(fd);

    rc
}

// ---------------------------------------------------------------------------
// the cache manager and the cache loader
// ---------------------------------------------------------------------------

fn quitting() -> bool {
    ngx_core::process::SIG_TERMINATE.load(Ordering::SeqCst) || ngx_core::process::SIG_QUIT.load(Ordering::SeqCst)
}

/// The name of the cache file of a node: the path, the levels and the hex
/// of the key.
fn node_file_name(path: &PathConf, fcn: &FileCacheNode) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 * NGX_HTTP_CACHE_KEY_LEN);

    ngx_core::string::hex_dump(&mut key, &fcn.node.key.to_ne_bytes());
    ngx_core::string::hex_dump(&mut key, &fcn.key);

    path.hashed_filename(&key)
}

/// ngx_http_file_cache_forced_expire: the least recently used node that is
/// not in use goes, when the zone or the cache is full.
fn file_cache_forced_expire(cache: &FileCache) -> i64 {
    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache forced expire");

    let mut wait = 10;
    let mut tries = 20;
    let mut sentinel: *mut Queue = std::ptr::null_mut();

    cache.shpool().lock();

    unsafe {
        loop {
            if queue_empty(cache.queue()) {
                break;
            }

            let q = queue_last(cache.queue());

            if q == sentinel {
                break;
            }

            let fcn = queue_data(q);

            ngx_log_debug!(
                NGX_LOG_DEBUG_HTTP,
                log,
                "http file cache forced expire: #{} {} {:02x}{:02x}{:02x}{:02x}",
                (*fcn).count,
                (*fcn).exists as i32,
                (*fcn).key[0],
                (*fcn).key[1],
                (*fcn).key[2],
                (*fcn).key[3]
            );

            if (*fcn).count == 0 {
                file_cache_delete(cache, q);
                wait = 0;
                break;
            }

            if (*fcn).deleting {
                wait = 1;
                break;
            }

            let mut key = Vec::with_capacity(2 * NGX_HTTP_CACHE_KEY_LEN);
            ngx_core::string::hex_dump(&mut key, &(*fcn).node.key.to_ne_bytes());
            ngx_core::string::hex_dump(&mut key, &(*fcn).key);

            // abnormally exited workers may leave locked cache entries,
            // and although it may be safe to remove them completely,
            // we prefer to just move them to the top of the inactive queue

            queue_remove(q);
            (*fcn).expire = ngx_core::times::time() + cache.inactive;
            queue_insert_head(cache.queue(), std::ptr::addr_of_mut!((*fcn).queue));

            ngx_log_error!(NGX_LOG_ALERT, log, None, "ignore long locked inactive cache entry {}, count:{}", B(&key), (*fcn).count);

            if sentinel.is_null() {
                sentinel = q;
            }

            tries -= 1;

            if tries != 0 {
                continue;
            }

            wait = 1;
            break;
        }
    }

    cache.shpool().unlock();

    wait
}

/// ngx_queue_data(q, ngx_http_file_cache_node_t, queue)
unsafe fn queue_data(q: *mut Queue) -> *mut FileCacheNode {
    (q as *mut u8).sub(std::mem::offset_of!(FileCacheNode, queue)) as *mut FileCacheNode
}

/// ngx_http_file_cache_expire: the nodes inactive for too long go.
fn file_cache_expire(cache: &FileCache) -> i64 {
    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache expire");

    let now = ngx_core::times::time();

    let mut wait;

    cache.shpool().lock();

    unsafe {
        loop {
            if quitting() {
                wait = 1;
                break;
            }

            if queue_empty(cache.queue()) {
                wait = 10;
                break;
            }

            let q = queue_last(cache.queue());

            let fcn = queue_data(q);

            wait = (*fcn).expire - now;

            if wait > 0 {
                wait = if wait > 10 { 10 } else { wait };
                break;
            }

            ngx_log_debug!(
                NGX_LOG_DEBUG_HTTP,
                log,
                "http file cache expire: #{} {} {:02x}{:02x}{:02x}{:02x}",
                (*fcn).count,
                (*fcn).exists as i32,
                (*fcn).key[0],
                (*fcn).key[1],
                (*fcn).key[2],
                (*fcn).key[3]
            );

            'next: {
                if (*fcn).count == 0 {
                    file_cache_delete(cache, q);
                    break 'next;
                }

                if (*fcn).deleting {
                    wait = 1;
                    cache.shpool().unlock();
                    return wait;
                }

                let mut key = Vec::with_capacity(2 * NGX_HTTP_CACHE_KEY_LEN);
                ngx_core::string::hex_dump(&mut key, &(*fcn).node.key.to_ne_bytes());
                ngx_core::string::hex_dump(&mut key, &(*fcn).key);

                // abnormally exited workers may leave locked cache entries,
                // and although it may be safe to remove them completely,
                // we prefer to just move them to the top of the inactive queue

                queue_remove(q);
                (*fcn).expire = ngx_core::times::time() + cache.inactive;
                queue_insert_head(cache.queue(), std::ptr::addr_of_mut!((*fcn).queue));

                ngx_log_error!(NGX_LOG_ALERT, log, None, "ignore long locked inactive cache entry {}, count:{}", B(&key), (*fcn).count);
            }

            // next:

            cache.files.set(cache.files.get() + 1);

            if cache.files.get() >= cache.manager_files {
                wait = 0;
                break;
            }

            ngx_core::times::update();

            let elapsed = (ngx_core::times::current_msec().wrapping_sub(cache.last.get()) as i64).unsigned_abs();

            if elapsed >= cache.manager_threshold {
                wait = 0;
                break;
            }
        }
    }

    cache.shpool().unlock();

    wait
}

/// ngx_http_file_cache_delete: the file of a node, and the node when it is
/// not used. The zone is locked on entry and on return.
unsafe fn file_cache_delete(cache: &FileCache, q: *mut Queue) {
    let fcn = queue_data(q);

    if (*fcn).exists {
        cache.sh().size -= (*fcn).fs_size;

        let name = node_file_name(&cache.path, &*fcn);

        (*fcn).count_inc();
        (*fcn).deleting = true;
        cache.shpool().unlock();

        let log = cycle_log();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache expire: \"{}\"", B(&name));

        if let Err(err) = ngx_core::os::unlink(&name) {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "unlink() \"{}\" failed", B(&name));
        }

        cache.shpool().lock();
        (*fcn).count_dec();
        (*fcn).deleting = false;
    }

    if (*fcn).count == 0 {
        queue_remove(q);
        cache.sh().rbtree.delete(&mut (*fcn).node);
        cache.shpool().free_locked(fcn as *mut u8);
        cache.sh().count -= 1;
    }
}

/// ngx_http_file_cache_manager: the path manager of a cache, the time till
/// its next run.
fn file_cache_manager(cache: &FileCache) -> u64 {
    let log = cycle_log();

    cache.last.set(ngx_core::times::current_msec());
    cache.files.set(0);

    let mut next = file_cache_expire(cache) as u64 * 1000;

    'done: {
        if next == 0 {
            next = cache.manager_sleep;
            break 'done;
        }

        loop {
            cache.shpool().lock();

            let size = cache.sh().size;
            let count = cache.sh().count;
            let watermark = cache.sh().watermark;

            cache.shpool().unlock();

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache size: {} c:{} w:{}", size, count, watermark as i64);

            if size < cache.max_size.get() && count < watermark {
                if cache.min_free == 0 {
                    break;
                }

                let free = fs_available(&cache.path.name);

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache free: {}", free);

                if free > cache.min_free {
                    break;
                }
            }

            let wait = file_cache_forced_expire(cache);

            if wait > 0 {
                next = wait as u64 * 1000;
                break;
            }

            if quitting() {
                break;
            }

            cache.files.set(cache.files.get() + 1);

            if cache.files.get() >= cache.manager_files {
                next = cache.manager_sleep;
                break;
            }

            ngx_core::times::update();

            let elapsed = (ngx_core::times::current_msec().wrapping_sub(cache.last.get()) as i64).unsigned_abs();

            if elapsed >= cache.manager_threshold {
                next = cache.manager_sleep;
                break;
            }
        }
    }

    // done:

    let elapsed = (ngx_core::times::current_msec().wrapping_sub(cache.last.get()) as i64).unsigned_abs();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache manager: {} e:{} n:{}", cache.files.get(), elapsed, next);

    next
}

/// ngx_http_file_cache_loader: the nodes of the files in the cache
/// directory, once after the start.
fn file_cache_loader(cache: &FileCache) {
    let sh = cache.sh();

    if sh.cold.load(Ordering::SeqCst) == 0 || sh.loading.load(Ordering::SeqCst) != 0 {
        return;
    }

    let pid = ngx_core::os::getpid() as usize;

    if sh.loading.compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }

    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache loader");

    cache.last.set(ngx_core::times::current_msec());
    cache.files.set(0);

    if walk_tree(cache, &cache.path.name, &log) == NGX_ABORT {
        sh.loading.store(0, Ordering::SeqCst);
        return;
    }

    sh.cold.store(0, Ordering::SeqCst);
    sh.loading.store(0, Ordering::SeqCst);

    ngx_log_error!(
        NGX_LOG_NOTICE,
        log,
        None,
        "http file cache: {} {:.3}M, bsize: {}",
        B(&cache.path.name),
        (sh.size as f64 * cache.bsize.get() as f64) / (1024.0 * 1024.0),
        cache.bsize.get()
    );
}

/// ngx_walk_tree with the handlers of the loader: file_handler
/// ngx_http_file_cache_manage_file, pre_tree_handler
/// ngx_http_file_cache_manage_directory, post_tree_handler
/// ngx_http_file_cache_noop and spec_handler
/// ngx_http_file_cache_delete_file.
fn walk_tree(cache: &FileCache, tree: &[u8], log: &Log) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "walk tree \"{}\"", B(tree));

    let dir = match std::fs::read_dir(ngx_core::os::path(tree)) {
        Ok(d) => d,
        Err(e) => {
            ngx_log_error!(NGX_LOG_CRIT, log, e.raw_os_error(), "opendir() \"{}\" failed", B(tree));
            return NGX_ERROR;
        }
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                ngx_log_error!(NGX_LOG_CRIT, log, e.raw_os_error(), "readdir() \"{}\" failed", B(tree));
                return NGX_ERROR;
            }
        };

        use std::os::unix::ffi::OsStrExt;

        let name = entry.file_name();
        let name = name.as_bytes();

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "tree name {}:\"{}\"", name.len(), B(name));

        let mut file = tree.to_vec();
        file.push(b'/');
        file.extend_from_slice(name);

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "tree path \"{}\"", B(&file));

        let st = match ngx_core::os::lstat(&file) {
            Ok(st) => st,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "lstat() \"{}\" failed", B(&file));
                continue;
            }
        };

        if ngx_core::os::is_file(&st) {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "tree file \"{}\"", B(&file));

            if file_cache_manage_file(cache, &file, st.st_size as i64, file_fs_size(&st), log) == NGX_ABORT {
                return NGX_ABORT;
            }
        } else if ngx_core::os::is_dir(&st) {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "tree enter dir \"{}\"", B(&file));

            // ngx_http_file_cache_manage_directory
            if file.len() >= 5 && file.ends_with(b"/temp") {
                continue;
            }

            let rc = walk_tree(cache, &file, log);

            if rc == NGX_ABORT {
                return NGX_ABORT;
            }

            // ngx_http_file_cache_noop
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "tree special \"{}\"", B(&file));

            file_cache_delete_file(&file, log);
        }
    }

    NGX_OK
}

/// ngx_http_file_cache_manage_file
fn file_cache_manage_file(cache: &FileCache, path: &[u8], size: i64, fs_size: i64, log: &Log) -> i64 {
    if file_cache_add_file(cache, path, size, fs_size, log) != NGX_OK {
        file_cache_delete_file(path, log);
    }

    cache.files.set(cache.files.get() + 1);

    if cache.files.get() >= cache.loader_files {
        file_cache_loader_sleep(cache);
    } else {
        ngx_core::times::update();

        let elapsed = (ngx_core::times::current_msec().wrapping_sub(cache.last.get()) as i64).unsigned_abs();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache loader time elapsed: {}", elapsed);

        if elapsed >= cache.loader_threshold {
            file_cache_loader_sleep(cache);
        }
    }

    if quitting() {
        NGX_ABORT
    } else {
        NGX_OK
    }
}

/// ngx_http_file_cache_loader_sleep
fn file_cache_loader_sleep(cache: &FileCache) {
    // ngx_msleep() in the cache loader process
    std::thread::sleep(std::time::Duration::from_millis(cache.loader_sleep));

    ngx_core::times::update();

    cache.last.set(ngx_core::times::current_msec());
    cache.files.set(0);
}

/// ngx_http_file_cache_add_file
fn file_cache_add_file(cache: &FileCache, name: &[u8], size: i64, fs_size: i64, log: &Log) -> i64 {
    if name.len() < 2 * NGX_HTTP_CACHE_KEY_LEN {
        return NGX_ERROR;
    }

    // Temporary files in cache have a suffix consisting of a dot
    // followed by 10 digits.

    if name.len() >= 2 * NGX_HTTP_CACHE_KEY_LEN + 1 + 10 && name[name.len() - 10 - 1] == b'.' {
        return NGX_OK;
    }

    if size < FILE_CACHE_HEADER_SIZE as i64 {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "cache file \"{}\" is too small", B(name));
        return NGX_ERROR;
    }

    let fs_size = (fs_size + cache.bsize.get() as i64 - 1) / cache.bsize.get() as i64;

    let p = &name[name.len() - 2 * NGX_HTTP_CACHE_KEY_LEN..];

    let mut key = [0u8; NGX_HTTP_CACHE_KEY_LEN];

    for i in 0..NGX_HTTP_CACHE_KEY_LEN {
        match ngx_core::string::hextoi(&p[2 * i..2 * i + 2]) {
            Some(n) => key[i] = n as u8,
            None => return NGX_ERROR,
        }
    }

    file_cache_add(cache, &key, fs_size)
}

/// ngx_http_file_cache_add
fn file_cache_add(cache: &FileCache, key: &[u8; NGX_HTTP_CACHE_KEY_LEN], fs_size: i64) -> i64 {
    cache.shpool().lock();

    unsafe {
        let mut fcn = file_cache_lookup(cache, key);

        if fcn.is_null() {
            fcn = cache.shpool().calloc_locked(std::mem::size_of::<FileCacheNode>()) as *mut FileCacheNode;

            if fcn.is_null() {
                file_cache_set_watermark(cache);

                if cache.fail_time.get() != ngx_core::times::time() {
                    cache.fail_time.set(ngx_core::times::time());
                    ngx_log_error!(NGX_LOG_ALERT, cycle_log(), None, "could not allocate node{}", B(cache.shpool().log_ctx()));
                }

                cache.shpool().unlock();
                return NGX_ERROR;
            }

            cache.sh().count += 1;

            (*fcn).node.key = usize::from_ne_bytes(key[..RBTREE_KEY_SIZE].try_into().unwrap());

            (*fcn).key.copy_from_slice(&key[RBTREE_KEY_SIZE..]);

            cache.sh().rbtree.insert(&mut (*fcn).node);

            (*fcn).uses = 1;
            (*fcn).exists = true;
            (*fcn).fs_size = fs_size;

            cache.sh().size += fs_size;
        } else {
            queue_remove(std::ptr::addr_of_mut!((*fcn).queue));
        }

        (*fcn).expire = ngx_core::times::time() + cache.inactive;

        queue_insert_head(cache.queue(), std::ptr::addr_of_mut!((*fcn).queue));
    }

    cache.shpool().unlock();

    NGX_OK
}

/// ngx_http_file_cache_delete_file
fn file_cache_delete_file(path: &[u8], log: &Log) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache delete: \"{}\"", B(path));

    if let Err(err) = ngx_core::os::unlink(path) {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "unlink() \"{}\" failed", B(path));
    }
}

/// ngx_http_file_cache_set_watermark
fn file_cache_set_watermark(cache: &FileCache) {
    let sh = cache.sh();

    sh.watermark = sh.count - sh.count / 8;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, cycle_log(), "http file cache watermark: {}", sh.watermark);
}

/// ngx_http_file_cache_valid: the time a response of the status is valid
/// for, 0 if none.
pub fn file_cache_valid(cache_valid: Option<&[CacheValid]>, status: usize) -> i64 {
    let valid = match cache_valid {
        Some(v) => v,
        None => return 0,
    };

    for v in valid {
        if v.status == 0 {
            return v.valid;
        }

        if v.status == status {
            return v.valid;
        }
    }

    0
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

/// ngx_http_file_cache_set_slot: "proxy_cache_path path [levels=levels]
/// [use_temp_path=on|off] keys_zone=name:size [inactive=time]
/// [max_size=size] [min_free=size] [manager_files=number]
/// [manager_sleep=time] [manager_threshold=time] [loader_files=number]
/// [loader_sleep=time] [loader_threshold=time]"; `tag` is cmd->post, the
/// module the keys zone is for, and the cache goes to `caches`.
pub fn file_cache_set_slot(cf: &mut Conf, cmd: &Command, caches: &mut Vec<Rc<FileCache>>, tag: &'static str) -> ConfResult {
    let value = cf.args.clone();

    let mut use_temp_path = true;

    let mut inactive: i64 = 600;

    let mut loader_files: i64 = 100;
    let mut loader_sleep: u64 = 50;
    let mut loader_threshold: u64 = 200;

    let mut manager_files: i64 = 100;
    let mut manager_sleep: u64 = 50;
    let mut manager_threshold: u64 = 200;

    let mut name: Vec<u8> = Vec::new();
    let mut size: usize = 0;
    let mut max_size: i64 = i64::MAX;
    let mut min_free: i64 = 0;

    let mut path_name = value[1].clone();

    if path_name.last() == Some(&b'/') {
        path_name.pop();
    }

    let path_name = cf.full_name(&path_name, false);

    let mut level = [0usize; NGX_MAX_PATH_LEVEL];

    for v in value.iter().skip(2) {
        if v.starts_with(b"levels=") {
            let s = &v[7..];

            let mut p = 0;
            let last = s.len();

            let mut invalid = false;

            let mut n = 0;

            while n < NGX_MAX_PATH_LEVEL && p < last {
                if s[p] > b'0' && s[p] < b'3' {
                    level[n] = (s[p] - b'0') as usize;
                    p += 1;

                    if p == last {
                        break;
                    }

                    let ch = s[p];
                    p += 1;

                    if ch == b':' && n < NGX_MAX_PATH_LEVEL - 1 && p < last {
                        n += 1;
                        continue;
                    }

                    invalid = true;
                    break;
                }

                invalid = true;
                break;
            }

            if !invalid {
                continue;
            }

            return Err(cf.emerg(format_args!("invalid \"levels\" \"{}\"", B(v))));
        }

        if v.starts_with(b"use_temp_path=") {
            let s = &v[14..];

            if s == b"on" {
                use_temp_path = true;
            } else if s == b"off" {
                use_temp_path = false;
            } else {
                return Err(cf.emerg(format_args!("invalid use_temp_path value \"{}\", it must be \"on\" or \"off\"", B(v))));
            }

            continue;
        }

        if v.starts_with(b"keys_zone=") {
            let s = &v[10..];

            let colon = match s.iter().position(|&b| b == b':') {
                Some(c) => c,
                None => return Err(cf.emerg(format_args!("invalid keys zone size \"{}\"", B(v)))),
            };

            name = s[..colon].to_vec();

            size = match ngx_core::parse::parse_size(&s[colon + 1..]) {
                Some(n) => n,
                None => return Err(cf.emerg(format_args!("invalid keys zone size \"{}\"", B(v)))),
            };

            if size < 2 * ngx_core::os::pagesize() {
                return Err(cf.emerg(format_args!("keys zone \"{}\" is too small", B(v))));
            }

            continue;
        }

        if v.starts_with(b"inactive=") {
            inactive = match ngx_core::parse::parse_time(&v[9..], true) {
                Some(t) => t,
                None => return Err(cf.emerg(format_args!("invalid inactive value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"max_size=") {
            max_size = match ngx_core::parse::parse_offset(&v[9..]) {
                Some(n) if n >= 0 => n,
                _ => return Err(cf.emerg(format_args!("invalid max_size value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"min_free=") {
            min_free = match ngx_core::parse::parse_offset(&v[9..]) {
                Some(n) if n >= 0 => n,
                _ => return Err(cf.emerg(format_args!("invalid min_free value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"loader_files=") {
            loader_files = match ngx_core::string::atoi(&v[13..]) {
                Some(n) => n,
                None => return Err(cf.emerg(format_args!("invalid loader_files value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"loader_sleep=") {
            loader_sleep = match ngx_core::parse::parse_time(&v[13..], false) {
                Some(t) => t as u64,
                None => return Err(cf.emerg(format_args!("invalid loader_sleep value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"loader_threshold=") {
            loader_threshold = match ngx_core::parse::parse_time(&v[17..], false) {
                Some(t) => t as u64,
                None => return Err(cf.emerg(format_args!("invalid loader_threshold value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"manager_files=") {
            manager_files = match ngx_core::string::atoi(&v[14..]) {
                Some(n) => n,
                None => return Err(cf.emerg(format_args!("invalid manager_files value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"manager_sleep=") {
            manager_sleep = match ngx_core::parse::parse_time(&v[14..], false) {
                Some(t) => t as u64,
                None => return Err(cf.emerg(format_args!("invalid manager_sleep value \"{}\"", B(v)))),
            };

            continue;
        }

        if v.starts_with(b"manager_threshold=") {
            manager_threshold = match ngx_core::parse::parse_time(&v[18..], false) {
                Some(t) => t as u64,
                None => return Err(cf.emerg(format_args!("invalid manager_threshold value \"{}\"", B(v)))),
            };

            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    if name.is_empty() || size == 0 {
        return Err(cf.emerg(format_args!("\"{}\" must have \"keys_zone\" parameter", cmd.name)));
    }

    let mut path = PathConf::new(path_name, level);

    path.conf_file = cf.conf_file_name();
    path.line = cf.conf_line();

    *path.manager.borrow_mut() = Some(Rc::new(|data: &Rc<dyn Any>| match data.clone().downcast::<PathData>().ok().and_then(|d| d.0.upgrade()) {
        Some(cache) => file_cache_manager(&cache),
        None => 60 * 60 * 1000,
    }));

    *path.loader.borrow_mut() = Some(Rc::new(|data: &Rc<dyn Any>| {
        if let Some(cache) = data.clone().downcast::<PathData>().ok().and_then(|d| d.0.upgrade()) {
            file_cache_loader(&cache);
        }
    }));

    // ngx_add_path(): the same path is not used by another cache
    let (log, cfn, line) = (cf.log.clone(), cf.conf_file_name(), cf.conf_line());

    if let Some(p) = cf.cycle.paths.iter().find(|p| p.name == path.name) {
        if p.data.borrow().is_some() {
            return Err(cf.emerg(format_args!("the same path name \"{}\" used in {}:{} and", B(&p.name), B(&p.conf_file), p.line)));
        }
    }

    let path = cf.cycle.add_path(path, &log, &cfn, line)?;

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &name, size, tag)?;

    if shm_zone.data.borrow().is_some() {
        return Err(cf.emerg(format_args!("duplicate zone \"{}\"", B(&name))));
    }

    let cache = Rc::new(FileCache {
        sh: Cell::new(std::ptr::null_mut()),
        shpool: Cell::new(std::ptr::null_mut()),
        path: path.clone(),
        min_free,
        max_size: Cell::new(max_size),
        bsize: Cell::new(512),
        inactive,
        fail_time: Cell::new(0),
        files: Cell::new(0),
        loader_files: loader_files as usize,
        last: Cell::new(0),
        loader_sleep,
        loader_threshold,
        manager_files: manager_files as usize,
        manager_sleep,
        manager_threshold,
        name: name.clone(),
        shm_zone: Rc::downgrade(&shm_zone),
        use_temp_path,
    });

    *path.data.borrow_mut() = Some(Rc::new(PathData(Rc::downgrade(&cache))));

    *shm_zone.init.borrow_mut() = Some(Rc::new(file_cache_init));
    *shm_zone.data.borrow_mut() = Some(cache.clone());

    caches.push(cache);

    Ok(())
}

/// ngx_http_file_cache_valid_set_slot: "proxy_cache_valid [code ...] time"
pub fn file_cache_valid_set_slot(cf: &mut Conf, _cmd: &Command, a: &mut Val<Option<Rc<Vec<CacheValid>>>>) -> ConfResult {
    let mut valid_list: Vec<CacheValid> = match a.as_option().cloned().flatten() {
        Some(v) => (*v).clone(),
        None => Vec::new(),
    };

    let value = cf.args.clone();
    let n = value.len() - 1;

    let valid = match ngx_core::parse::parse_time(&value[n], true) {
        Some(t) => t,
        None => return Err(cf.emerg(format_args!("invalid time value \"{}\"", B(&value[n])))),
    };

    if n == 1 {
        for status in [200, 301, 302] {
            valid_list.push(CacheValid { status, valid });
        }

        *a = Val::set(Some(Rc::new(valid_list)));

        return Ok(());
    }

    for v in &value[1..n] {
        let status = if v == b"any" {
            0
        } else {
            match ngx_core::string::atoi(v) {
                Some(s) if (100..=599).contains(&s) => s as usize,
                _ => return Err(cf.emerg(format_args!("invalid status \"{}\"", B(v)))),
            }
        };

        valid_list.push(CacheValid { status, valid });
    }

    *a = Val::set(Some(Rc::new(valid_list)));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_layout() {
        // sizeof(ngx_http_file_cache_header_t) and its offsets on LP64
        use std::mem::offset_of;

        if std::mem::size_of::<usize>() == 8 {
            assert_eq!(FILE_CACHE_HEADER_SIZE, 336);
            assert_eq!(offset_of!(FileCacheHeader, crc32), 48);
            assert_eq!(offset_of!(FileCacheHeader, valid_msec), 52);
            assert_eq!(offset_of!(FileCacheHeader, header_start), 54);
            assert_eq!(offset_of!(FileCacheHeader, body_start), 56);
            assert_eq!(offset_of!(FileCacheHeader, etag_len), 58);
            assert_eq!(offset_of!(FileCacheHeader, etag), 59);
            assert_eq!(offset_of!(FileCacheHeader, vary_len), 187);
            assert_eq!(offset_of!(FileCacheHeader, vary), 188);
            assert_eq!(offset_of!(FileCacheHeader, variant), 316);
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let mut h = FileCacheHeader::zeroed();
        h.version = NGX_HTTP_CACHE_VERSION;
        h.valid_sec = 1700000000;
        h.updating_sec = 10;
        h.error_sec = 5;
        h.last_modified = -1;
        h.date = 1699999999;
        h.crc32 = 0xdeadbeef;
        h.valid_msec = 123;
        h.header_start = 400;
        h.body_start = 600;
        h.etag_len = 5;
        h.etag[..5].copy_from_slice(b"\"abc\"");
        h.vary_len = 15;
        h.vary[..15].copy_from_slice(b"Accept-Encoding");
        h.variant = [7; 16];

        let b = h.to_bytes();
        assert_eq!(&b[0..8], &5usize.to_ne_bytes());
        assert_eq!(b[FILE_CACHE_HEADER_SIZE - 1], 0);

        let g = FileCacheHeader::from_bytes(&b);
        assert_eq!(g.version, 5);
        assert_eq!(g.valid_sec, 1700000000);
        assert_eq!(g.updating_sec, 10);
        assert_eq!(g.error_sec, 5);
        assert_eq!(g.last_modified, -1);
        assert_eq!(g.date, 1699999999);
        assert_eq!(g.crc32, 0xdeadbeef);
        assert_eq!(g.valid_msec, 123);
        assert_eq!(g.header_start, 400);
        assert_eq!(g.body_start, 600);
        assert_eq!(&g.etag[..5], b"\"abc\"");
        assert_eq!(&g.vary[..15], b"Accept-Encoding");
        assert_eq!(g.variant, [7; 16]);
    }

    #[test]
    fn test_valid() {
        let v = vec![CacheValid { status: 200, valid: 60 }, CacheValid { status: 404, valid: 5 }, CacheValid { status: 0, valid: 1 }];

        assert_eq!(file_cache_valid(Some(&v), 200), 60);
        assert_eq!(file_cache_valid(Some(&v), 404), 5);
        assert_eq!(file_cache_valid(Some(&v), 500), 1);
        assert_eq!(file_cache_valid(None, 200), 0);

        let v = vec![CacheValid { status: 0, valid: 1 }, CacheValid { status: 200, valid: 60 }];
        assert_eq!(file_cache_valid(Some(&v), 200), 1);
    }

    #[test]
    fn test_node_bits() {
        let mut n: FileCacheNode = unsafe { std::mem::zeroed() };
        n.uses = USES_MASK;
        n.uses_inc();
        assert_eq!(n.uses, 0);
        n.count_dec();
        assert_eq!(n.count, COUNT_MASK);
        n.count_inc();
        assert_eq!(n.count, 0);
    }

    #[test]
    fn test_dir_access() {
        assert_eq!(dir_access(0o600), 0o700);
        assert_eq!(dir_access(0o644), 0o755);
    }
}
