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
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::shmem::queue;
use ngx_core::shmem::rbtree::{self as rb, RbTree, ShmRbtree};
use ngx_core::shmem::slab::SlabPool;
use ngx_core::shmem::{Field, ShmMem};
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error, shm_struct};

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

shm_struct! {
    /// ngx_http_file_cache_node_t, in the keys zone, laid out as C lays it
    /// out (120 bytes on LP64): the rbtree node, the queue, the rest of the
    /// key, then the bit fields of C in their two 32-bit units: count:20
    /// and uses:10 in bits0; valid_msec:10, error:10, exists:1, updating:1,
    /// deleting:1 and purged:1 in bits1 (the first field in the low bits,
    /// as gcc allocates them).
    pub struct FileCacheNode {
        node_key: usize,
        node_left: usize,
        node_right: usize,
        node_parent: usize,
        node_color: u8,
        node_data: u8,
        queue_prev: usize,
        queue_next: usize,
        /// u_char key[NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t)]:
        /// its bytes (word aligned after the queue, as in C)
        key: u64,
        bits0: u32,
        bits1: u32,
        /// ngx_file_uniq_t
        uniq: u64,
        expire: i64,
        valid_sec: i64,
        body_start: usize,
        fs_size: i64,
        /// ngx_msec_t
        lock_time: u64,
    }
}

/// fcn->count (bits0)
const COUNT_MASK: u32 = (1 << 20) - 1;
/// fcn->uses (bits0)
const USES_SHIFT: u32 = 20;
const USES_MASK: u32 = (1 << 10) - 1;
/// fcn->valid_msec (bits1)
const MSEC_MASK: u32 = (1 << 10) - 1;
/// fcn->error (bits1)
const ERROR_SHIFT: u32 = 10;
const ERROR_MASK: u32 = (1 << 10) - 1;
/// fcn->exists, fcn->updating, fcn->deleting (bits1)
const EXISTS_SHIFT: u32 = 20;
const UPDATING_SHIFT: u32 = 21;
const DELETING_SHIFT: u32 = 22;

/// sizeof(fcn->key)
const NODE_KEY_LEN: usize = NGX_HTTP_CACHE_KEY_LEN - RBTREE_KEY_SIZE;

/// The bit fields and the key of a node. The node is changed under the
/// zone's mutex.
impl FileCacheNode<'_> {
    fn bits(&self, f: Field<u32>, shift: u32, mask: u32) -> u32 {
        (self.get(f) >> shift) & mask
    }

    /// The bit field set to `v`, cut to its width as C does.
    fn set_bits(&self, f: Field<u32>, shift: u32, mask: u32, v: u32) {
        let w = self.get(f);
        self.set(f, (w & !(mask << shift)) | ((v & mask) << shift));
    }

    /// fcn->count
    fn count(&self) -> u32 {
        self.bits(Self::bits0, 0, COUNT_MASK)
    }

    fn set_count(&self, v: u32) {
        self.set_bits(Self::bits0, 0, COUNT_MASK, v)
    }

    /// fcn->count++
    fn count_inc(&self) {
        self.set_count(self.count().wrapping_add(1))
    }

    /// fcn->count--
    fn count_dec(&self) {
        self.set_count(self.count().wrapping_sub(1))
    }

    /// fcn->uses
    fn uses(&self) -> u32 {
        self.bits(Self::bits0, USES_SHIFT, USES_MASK)
    }

    fn set_uses(&self, v: u32) {
        self.set_bits(Self::bits0, USES_SHIFT, USES_MASK, v)
    }

    /// fcn->uses++
    fn uses_inc(&self) {
        self.set_uses(self.uses().wrapping_add(1))
    }

    /// fcn->valid_msec
    fn set_valid_msec(&self, v: u32) {
        self.set_bits(Self::bits1, 0, MSEC_MASK, v)
    }

    /// fcn->error
    fn error(&self) -> u32 {
        self.bits(Self::bits1, ERROR_SHIFT, ERROR_MASK)
    }

    fn set_error(&self, v: u32) {
        self.set_bits(Self::bits1, ERROR_SHIFT, ERROR_MASK, v)
    }

    /// fcn->exists
    fn exists(&self) -> bool {
        self.bits(Self::bits1, EXISTS_SHIFT, 1) != 0
    }

    fn set_exists(&self, on: bool) {
        self.set_bits(Self::bits1, EXISTS_SHIFT, 1, on as u32)
    }

    /// fcn->updating
    fn updating(&self) -> bool {
        self.bits(Self::bits1, UPDATING_SHIFT, 1) != 0
    }

    fn set_updating(&self, on: bool) {
        self.set_bits(Self::bits1, UPDATING_SHIFT, 1, on as u32)
    }

    /// fcn->deleting
    fn deleting(&self) -> bool {
        self.bits(Self::bits1, DELETING_SHIFT, 1) != 0
    }

    fn set_deleting(&self, on: bool) {
        self.set_bits(Self::bits1, DELETING_SHIFT, 1, on as u32)
    }

    /// fcn->key
    fn key_bytes(&self) -> [u8; NODE_KEY_LEN] {
        let mut key = [0u8; NODE_KEY_LEN];
        self.mem.read(self.field(Self::key), &mut key);
        key
    }

    /// The hex of the whole key: fcn->node.key, then fcn->key.
    fn key_hex(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 * NGX_HTTP_CACHE_KEY_LEN);

        ngx_core::string::hex_dump(&mut key, &self.get(Self::node_key).to_ne_bytes());
        ngx_core::string::hex_dump(&mut key, &self.key_bytes());

        key
    }
}

shm_struct! {
    /// ngx_http_file_cache_sh_t: the rbtree, its sentinel node, the LRU
    /// queue of the nodes, then the counters
    pub struct FileCacheSh {
        rbtree_root: usize,
        rbtree_sentinel: usize,
        rbtree_insert: usize,
        sentinel_key: usize,
        sentinel_left: usize,
        sentinel_right: usize,
        sentinel_parent: usize,
        sentinel_color: u8,
        sentinel_data: u8,
        queue_prev: usize,
        queue_next: usize,
        /// ngx_atomic_t
        cold: usize,
        /// ngx_atomic_t
        loading: usize,
        /// off_t
        size: i64,
        count: usize,
        watermark: usize,
    }
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
    /// cache->sh: the offset of the ngx_http_file_cache_sh_t in the zone
    pub sh: Cell<usize>,
    /// the keys zone's memory, its slab pool at the start (cache->shpool)
    pub mem: RefCell<Option<Rc<ShmMem>>>,

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
    /// The memory of the keys zone: it is initialized before any request
    /// or the manager uses it.
    fn mem(&self) -> Rc<ShmMem> {
        self.mem.borrow().clone().expect("cache keys zone memory")
    }

    /// cache->sh
    fn sh<'a>(&self, mem: &'a ShmMem) -> FileCacheSh<'a> {
        FileCacheSh::at(mem, self.sh.get())
    }

    /// &cache->sh->rbtree
    fn rbtree<'a>(&self, mem: &'a ShmMem) -> ShmRbtree<'a> {
        ShmRbtree::at(mem, self.sh.get() + FileCacheSh::rbtree_root.off)
    }

    /// &cache->sh->queue
    fn queue(&self) -> usize {
        self.sh.get() + FileCacheSh::queue_prev.off
    }

    /// cache->sh->cold, used without the mutex
    fn cold<'a>(&self, mem: &'a ShmMem) -> &'a AtomicUsize {
        mem.word(self.sh.get() + FileCacheSh::cold.off)
    }

    /// cache->sh->loading, used without the mutex
    fn loading<'a>(&self, mem: &'a ShmMem) -> &'a AtomicUsize {
        mem.word(self.sh.get() + FileCacheSh::loading.off)
    }
}

/// ngx_queue_data(q, ngx_http_file_cache_node_t, queue)
fn queue_data(mem: &ShmMem, q: usize) -> FileCacheNode<'_> {
    FileCacheNode::at(mem, q - FileCacheNode::queue_prev.off)
}

/// cache->sh->size += n (the zone is locked)
fn sh_size_add(sh: FileCacheSh<'_>, n: i64) {
    sh.set(FileCacheSh::size, sh.get(FileCacheSh::size) + n);
}

/// cache->sh->count++ or count-- (the zone is locked)
fn sh_count_add(sh: FileCacheSh<'_>, n: isize) {
    sh.set(FileCacheSh::count, sh.get(FileCacheSh::count).wrapping_add_signed(n));
}


/// The data of a cache path (cache->path->data).
struct PathData(Weak<FileCache>);

/// c->keys: the parts of the key, one after another in one buffer (as
/// they are hashed, written to the cache file and compared with it), and
/// where each ends (up to 4 in place).
#[derive(Clone, Default)]
pub struct CacheKeys {
    data: Vec<u8>,
    ends: [usize; 4],
    n: usize,
    more: Vec<usize>,
}

impl CacheKeys {
    pub fn new() -> CacheKeys {
        CacheKeys::default()
    }

    /// A part of the key.
    pub fn push(&mut self, part: &[u8]) {
        self.data.extend_from_slice(part);
        self.end();
    }

    /// A part of the key made for it: taken as the buffer when it is the
    /// first part.
    pub fn push_vec(&mut self, part: Vec<u8>) {
        if self.data.is_empty() {
            self.data = part;
            self.end();
        } else {
            self.push(&part);
        }
    }

    /// The buffer to append the next part to, ended by end().
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// The part appended to data_mut() ends here.
    pub fn end(&mut self) {
        if self.n < self.ends.len() {
            self.ends[self.n] = self.data.len();
        } else {
            self.more.push(self.data.len());
        }

        self.n += 1;
    }

    /// The bytes of all the parts.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// The parts.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let ends = self.ends[..self.n.min(self.ends.len())].iter().chain(self.more.iter());

        ends.scan(0, move |start, &end| {
            let part = &self.data[*start..end];
            *start = end;
            Some(part)
        })
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

/// c->etag: kept in place up to the length of the cache file header's (C
/// points it at h->etag of c->buf), a longer one of a response allocated.
#[derive(Clone)]
pub enum CacheEtag {
    Short(u8, [u8; NGX_HTTP_CACHE_ETAG_LEN]),
    Long(Vec<u8>),
}

impl CacheEtag {
    pub fn new() -> CacheEtag {
        CacheEtag::Short(0, [0; NGX_HTTP_CACHE_ETAG_LEN])
    }

    pub fn set(&mut self, v: &[u8]) {
        if v.len() <= NGX_HTTP_CACHE_ETAG_LEN {
            let mut data = [0; NGX_HTTP_CACHE_ETAG_LEN];
            data[..v.len()].copy_from_slice(v);
            *self = CacheEtag::Short(v.len() as u8, data);
        } else {
            *self = CacheEtag::Long(v.to_vec());
        }
    }

    pub fn clear(&mut self) {
        *self = CacheEtag::new();
    }
}

impl Default for CacheEtag {
    fn default() -> CacheEtag {
        CacheEtag::new()
    }
}

impl std::ops::Deref for CacheEtag {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            CacheEtag::Short(len, data) => &data[..*len as usize],
            CacheEtag::Long(v) => v,
        }
    }
}

/// ngx_http_cache_t: the cache of a request (r->cache).
pub struct HttpCache {
    /// c->file: the name of the cache file, and the file once open
    pub file_name: Vec<u8>,
    pub fd: i32,
    pub file_handle: Option<Rc<CachedFileHandle>>,
    pub log: Log,

    pub keys: CacheKeys,
    pub crc32: u32,
    pub key: [u8; NGX_HTTP_CACHE_KEY_LEN],
    pub main: [u8; NGX_HTTP_CACHE_KEY_LEN],

    pub uniq: u64,
    pub valid_sec: i64,
    pub updating_sec: i64,
    pub error_sec: i64,
    pub last_modified: i64,
    pub date: i64,

    pub etag: CacheEtag,
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
    /// c->node: the offset of the node in the keys zone, 0 for NULL; set
    /// by ngx_http_file_cache_exists(), it stays valid while the node's
    /// count holds it
    pub node: usize,

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
            keys: CacheKeys::new(),
            crc32: 0,
            key: [0; NGX_HTTP_CACHE_KEY_LEN],
            main: [0; NGX_HTTP_CACHE_KEY_LEN],
            uniq: 0,
            valid_sec: 0,
            updating_sec: 0,
            error_sec: 0,
            last_modified: 0,
            date: 0,
            etag: CacheEtag::new(),
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
            node: 0,
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

    /// c->node, in the memory of the keys zone
    fn node<'a>(&self, mem: &'a ShmMem) -> FileCacheNode<'a> {
        FileCacheNode::at(mem, self.node)
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
    let fs = match nix::sys::statfs::statfs(ngx_core::os::path(name)) {
        Ok(fs) => fs,
        Err(_) => return 512,
    };

    let bsize = fs.block_size() as usize;

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
    match nix::sys::statfs::statfs(ngx_core::os::path(name)) {
        Ok(fs) => fs.blocks_available() as i64 * fs.block_size() as i64,
        Err(_) => i64::MAX,
    }
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
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "read: {}, {:p}, {}, {}", fd, buf, buf.len(), offset);

    match ngx_core::os::pread(fd, buf, offset) {
        Ok(n) => n as isize,
        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pread() \"{}\" failed", B(name));
            NGX_ERROR as isize
        }
    }
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

        *cache.mem.borrow_mut() = ocache.mem.borrow().clone();
        cache.bsize.set(ocache.bsize.get());

        cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

        let mem = cache.mem();

        if cache.cold(&mem).load(Ordering::SeqCst) == 0 || cache.loading(&mem).load(Ordering::SeqCst) != 0 {
            *cache.path.loader.borrow_mut() = None;
        }

        return Ok(());
    }

    let mem = shm_zone.mem();
    let shpool = SlabPool::of(&mem);

    *cache.mem.borrow_mut() = Some(mem.clone());

    if shm_zone.shm.exists.get() {
        cache.sh.set(shpool.data());
        cache.bsize.set(fs_bsize(&cache.path.name));
        cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

        return Ok(());
    }

    let sh = shpool.alloc(FileCacheSh::SIZE);

    if sh == 0 {
        return Err(());
    }

    cache.sh.set(sh);

    shpool.set_data(sh);

    let shm = cache.sh(&mem);

    cache.rbtree(&mem).init(shm.field(FileCacheSh::sentinel_key));

    queue::init(&mem, cache.queue());

    shm.set(FileCacheSh::cold, 1);
    shm.set(FileCacheSh::loading, 0);
    shm.set(FileCacheSh::size, 0);
    shm.set(FileCacheSh::count, 0);
    shm.set(FileCacheSh::watermark, usize::MAX);

    cache.bsize.set(fs_bsize(&cache.path.name));

    cache.max_size.set(cache.max_size.get() / cache.bsize.get() as i64);

    let ctx = format!(" in cache keys zone \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(ctx.as_bytes())?;

    shpool.set_log_nomem(false);

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

    r.add_pool_cleanup(Box::new(move || {
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

    for key in c.keys.iter() {
        http_debug!(r, "http cache key: \"{}\"", B(key));
    }

    // the parts one after another
    let key = c.keys.bytes();
    let len = key.len();

    let mut crc = crc32fast::Hasher::new();
    let mut md5 = Md5::new();

    crc.update(key);
    md5.update(key);

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

    if c.node == 0 {
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

        test = cache.cold(&cache.mem()).load(Ordering::SeqCst) != 0;

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
    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let node = c.node(&mem);

    let timer = node.get(FileCacheNode::lock_time).wrapping_sub(now) as i64;

    if !node.updating() || timer <= 0 {
        node.set_updating(true);
        node.set(FileCacheNode::lock_time, now.wrapping_add(c.lock_age));
        c.updating = true;
        c.lock_time = node.get(FileCacheNode::lock_time);
    }

    shpool.unlock();

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
    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    let mut wait = false;

    shpool.lock();

    let node = c.node(&mem);

    let timer = node.get(FileCacheNode::lock_time).wrapping_sub(now) as i64;

    if node.updating() && timer > 0 {
        wait = true;
    }

    shpool.unlock();

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

    let n = read_file(c.fd, &c.file_name, &mut c.buf[..body_start], 0, &r.connection.log);

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

    // the parts of the key, one after another
    let p = FILE_CACHE_HEADER_SIZE + NGX_HTTP_FILE_CACHE_KEY.len();
    let key = c.keys.bytes();

    if &c.buf[p..p + key.len()] != key {
        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "cache file \"{}\" has md5 collision", B(&c.file_name));
        return NGX_DECLINED;
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
    c.etag.set(&h.etag[..h.etag_len as usize]);

    r.cached.set(true);

    let cache = c.cache();
    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    if cache.cold(&mem).load(Ordering::SeqCst) != 0 {
        shpool.lock();

        let node = c.node(&mem);

        if !node.exists() {
            node.set_uses(1);
            node.set(FileCacheNode::body_start, c.body_start);
            node.set_exists(true);
            node.set(FileCacheNode::uniq, c.uniq);
            node.set(FileCacheNode::fs_size, c.fs_size);

            sh_size_add(cache.sh(&mem), c.fs_size);
        }

        shpool.unlock();
    }

    let now = ngx_core::times::time();

    if c.valid_sec < now {
        c.stale_updating = c.valid_sec + c.updating_sec >= now;
        c.stale_error = c.valid_sec + c.error_sec >= now;

        shpool.lock();

        let rc;
        let node = c.node(&mem);

        if node.updating() {
            rc = NGX_HTTP_CACHE_UPDATING as i64;
        } else {
            node.set_updating(true);
            c.updating = true;
            c.lock_time = node.get(FileCacheNode::lock_time);
            rc = NGX_HTTP_CACHE_STALE as i64;
        }

        shpool.unlock();

        http_debug!(r, "http file cache expired: {} {} {}", rc, c.valid_sec, now);

        return rc;
    }

    NGX_OK
}

/// ngx_http_file_cache_exists: the node of the key, found or created; its
/// uses and the time it is inactive after.
fn file_cache_exists(cache: &FileCache, c: &mut HttpCache) -> i64 {
    let rc;

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let mut fcn = c.node;

    if fcn == 0 {
        fcn = file_cache_lookup(cache, &mem, &c.key);
    }

    'done: {
        'renew: {
            if fcn != 0 {
                let n = FileCacheNode::at(&mem, fcn);

                queue::remove(&mem, n.field(FileCacheNode::queue_prev));

                if c.node == 0 {
                    n.uses_inc();
                    n.count_inc();
                }

                if n.error() != 0 {
                    if n.get(FileCacheNode::valid_sec) < ngx_core::times::time() {
                        break 'renew;
                    }

                    rc = NGX_OK;

                    break 'done;
                }

                if n.exists() || n.uses() as usize >= c.min_uses {
                    c.exists = n.exists();

                    if n.get(FileCacheNode::body_start) != 0 && !c.update_variant {
                        c.body_start = n.get(FileCacheNode::body_start);
                    }

                    rc = NGX_OK;

                    break 'done;
                }

                rc = NGX_AGAIN;

                break 'done;
            }

            fcn = shpool.calloc_locked(FileCacheNode::SIZE);

            if fcn == 0 {
                file_cache_set_watermark(cache, &mem);

                shpool.unlock();

                let _ = file_cache_forced_expire(cache);

                shpool.lock();

                fcn = shpool.calloc_locked(FileCacheNode::SIZE);

                if fcn == 0 {
                    ngx_log_error!(NGX_LOG_ALERT, cycle_log(), None, "could not allocate node{}", B(&shpool.log_ctx()));

                    shpool.unlock();

                    return NGX_ERROR;
                }
            }

            sh_count_add(cache.sh(&mem), 1);

            let n = FileCacheNode::at(&mem, fcn);

            // ngx_memcpy((u_char *) &fcn->node.key, c->key, sizeof(ngx_rbtree_key_t))
            n.set(FileCacheNode::node_key, usize::from_ne_bytes(c.key[..RBTREE_KEY_SIZE].try_into().unwrap()));

            mem.write(n.field(FileCacheNode::key), &c.key[RBTREE_KEY_SIZE..]);

            rb::insert(&cache.rbtree(&mem), fcn, file_cache_rbtree_insert_value);

            n.set_uses(1);
            n.set_count(1);
        }

        // renew:

        rc = NGX_DECLINED;

        let n = FileCacheNode::at(&mem, fcn);

        n.set_valid_msec(0);
        n.set_error(0);
        n.set_exists(false);
        n.set(FileCacheNode::valid_sec, 0);
        n.set(FileCacheNode::uniq, 0);
        n.set(FileCacheNode::body_start, 0);
        n.set(FileCacheNode::fs_size, 0);
    }

    // done:

    let n = FileCacheNode::at(&mem, fcn);

    n.set(FileCacheNode::expire, ngx_core::times::time() + cache.inactive);

    queue::insert_head(&mem, cache.queue(), n.field(FileCacheNode::queue_prev));

    c.uniq = n.get(FileCacheNode::uniq);
    c.error = n.error() as usize;
    c.node = fcn;

    shpool.unlock();

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

    c.file_name = hashed_filename(path, &c.key);

    http_debug!(r, "cache file: \"{}\"", B(&c.file_name));

    NGX_OK
}

/// ngx_create_hashed_filename() of the md5 key in hex (as
/// PathConf::hashed_filename does), made in one buffer.
fn hashed_filename(path: &PathConf, key: &[u8; NGX_HTTP_CACHE_KEY_LEN]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut hex = [0u8; 2 * NGX_HTTP_CACHE_KEY_LEN];

    for (i, &b) in key.iter().enumerate() {
        hex[2 * i] = HEX[(b >> 4) as usize];
        hex[2 * i + 1] = HEX[(b & 0xf) as usize];
    }

    let mut out = Vec::with_capacity(path.name.len() + path.len + 1 + hex.len());

    out.extend_from_slice(&path.name);

    let mut pos = hex.len();

    for &lvl in path.level.iter() {
        if lvl == 0 {
            break;
        }

        out.push(b'/');
        pos -= lvl;
        out.extend_from_slice(&hex[pos..pos + lvl]);
    }

    out.push(b'/');
    out.extend_from_slice(&hex);

    out
}

/// ngx_http_file_cache_lookup: the node of the key, 0 if none (the zone is
/// locked)
fn file_cache_lookup(cache: &FileCache, mem: &ShmMem, key: &[u8; NGX_HTTP_CACHE_KEY_LEN]) -> usize {
    let node_key = usize::from_ne_bytes(key[..RBTREE_KEY_SIZE].try_into().unwrap());

    let tree = cache.rbtree(mem);

    let mut node = tree.root();
    let sentinel = tree.sentinel();

    while node != sentinel {
        let k = tree.key(node);

        if node_key < k {
            node = tree.left(node);
            continue;
        }

        if node_key > k {
            node = tree.right(node);
            continue;
        }

        // node_key == node->key

        let fcn = FileCacheNode::at(mem, node);

        // ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], fcn->key, ...)
        let rc = mem.cmp_bytes(fcn.field(FileCacheNode::key), &key[RBTREE_KEY_SIZE..]).reverse();

        if rc == std::cmp::Ordering::Equal {
            return node;
        }

        node = if rc == std::cmp::Ordering::Less { tree.left(node) } else { tree.right(node) };
    }

    // not found

    0
}

/// ngx_http_file_cache_rbtree_insert_value
fn file_cache_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    rb::insert_by(tree, temp, node, sentinel, |t, node, temp| {
        let (nk, tk) = (t.key(node), t.key(temp));

        if nk != tk {
            return nk < tk;
        }

        // node->key == temp->key: ngx_memcmp(cn->key, cnt->key, ...) < 0

        let cn = FileCacheNode::at(t.mem, node);
        let cnt = FileCacheNode::at(t.mem, temp);

        t.mem.cmp_bytes(cnt.field(FileCacheNode::key), &cn.key_bytes()) == std::cmp::Ordering::Greater
    });
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
    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    c.node(&mem).count_dec();
    c.node = 0;

    shpool.unlock();

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
    buf.extend_from_slice(c.keys.bytes());
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

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let node = c.node(&mem);

    node.count_dec();
    node.set_updating(false);
    c.node = 0;

    shpool.unlock();

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

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let node = c.node(&mem);

    node.count_dec();
    node.set_error(0);
    node.set(FileCacheNode::uniq, uniq);
    node.set(FileCacheNode::body_start, c.body_start);

    sh_size_add(cache.sh(&mem), fs_size - node.get(FileCacheNode::fs_size));
    node.set(FileCacheNode::fs_size, fs_size);

    if rc == NGX_OK {
        node.set_exists(true);
    }

    node.set_updating(false);

    shpool.unlock();
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

        match ngx_core::os::pwrite(fd, &bytes, 0) {
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "pwrite() \"{}\" failed", B(&name));
            }
            Ok(n) if n != bytes.len() => {
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, None, "pwrite() \"{}\" has written only {} of {}", B(&name), n, bytes.len());
            }
            Ok(_) => {}
        }
    }

    // done:

    if let Err(err) = ngx_core::os::close_fd(fd) {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, Some(err), "close() \"{}\" failed", B(&name));
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
    if c.updated || c.node == 0 {
        return;
    }

    let cache = c.cache();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http file cache free, fd: {}", c.fd);

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let fcn = c.node(&mem);

    fcn.count_dec();

    if c.updating && fcn.get(FileCacheNode::lock_time) == c.lock_time {
        fcn.set_updating(false);
    }

    if c.error != 0 {
        fcn.set_error(c.error as u32);

        if c.valid_sec != 0 {
            fcn.set(FileCacheNode::valid_sec, c.valid_sec);
            fcn.set_valid_msec(c.valid_msec as u32);
        }
    } else if !fcn.exists() && fcn.count() == 0 && c.min_uses == 1 {
        queue::remove(&mem, fcn.field(FileCacheNode::queue_prev));
        rb::delete(&cache.rbtree(&mem), fcn.off);
        shpool.free_locked(fcn.off);
        sh_count_add(cache.sh(&mem), -1);
        c.node = 0;
    }

    shpool.unlock();

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

        let mut n = ngx_core::file::next_temp_number(false);

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
                    n = ngx_core::file::next_temp_number(true);
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
            let n = match ngx_core::os::pwrite(self.fd, &data[off..], self.offset) {
                Ok(n) => n,
                Err(libc::EINTR) => continue,
                Err(err) => {
                    ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pwrite() \"{}\" failed", B(&self.name));
                    return Err(());
                }
            };

            off += n;
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
            if let Err(e) = ngx_core::os::chmod(src, access) {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "chmod() \"{}\" failed", B(src));
                err = 0;
                break 'failed;
            }
        }

        match ngx_core::os::rename(src, to) {
            Ok(()) => return NGX_OK,
            Err(e) => err = e,
        }

        if err == libc::ENOENT {
            if !create_path {
                break 'failed;
            }

            if let Err(e) = create_full_path(to, dir_access(path_access)) {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "mkdir() \"{}\" failed", B(to));
                err = 0;
                break 'failed;
            }

            match ngx_core::os::rename(src, to) {
                Ok(()) => return NGX_OK,
                Err(e) => err = e,
            }
        }

        if err == libc::EXDEV {
            // the copy of ngx_copy_file() to "to.NNNNNNNNNN", renamed
            let n = ngx_core::file::next_temp_number(false);

            let mut name = to.to_vec();
            name.push(b'.');
            name.extend_from_slice(format!("{:010}", n).as_bytes());

            if copy_file(src, &name, access, log).is_ok() {
                match ngx_core::os::rename(&name, to) {
                    Ok(()) => {
                        if let Err(e) = ngx_core::os::unlink(src) {
                            ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(src));
                            return NGX_ERROR;
                        }

                        return NGX_OK;
                    }
                    Err(e) => {
                        ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "rename() \"{}\" to \"{}\" failed", B(&name), B(to));
                    }
                }

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
fn node_file_name(path: &PathConf, fcn: FileCacheNode<'_>) -> Vec<u8> {
    path.hashed_filename(&fcn.key_hex())
}

/// ngx_http_file_cache_forced_expire: the least recently used node that is
/// not in use goes, when the zone or the cache is full.
fn file_cache_forced_expire(cache: &FileCache) -> i64 {
    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache forced expire");

    let mut wait = 10;
    let mut tries = 20;
    let mut sentinel: usize = 0;

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);
    let head = cache.queue();

    shpool.lock();

    loop {
        if queue::empty(&mem, head) {
            break;
        }

        let q = queue::last(&mem, head);

        if q == sentinel {
            break;
        }

        let fcn = queue_data(&mem, q);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache forced expire: #{} {} {}", fcn.count(), fcn.exists() as i32, B(&hex(&fcn.key_bytes()[..4])));

        if fcn.count() == 0 {
            file_cache_delete(cache, &mem, q);
            wait = 0;
            break;
        }

        if fcn.deleting() {
            wait = 1;
            break;
        }

        let key = fcn.key_hex();

        // abnormally exited workers may leave locked cache entries,
        // and although it may be safe to remove them completely,
        // we prefer to just move them to the top of the inactive queue

        queue::remove(&mem, q);
        fcn.set(FileCacheNode::expire, ngx_core::times::time() + cache.inactive);
        queue::insert_head(&mem, head, q);

        ngx_log_error!(NGX_LOG_ALERT, log, None, "ignore long locked inactive cache entry {}, count:{}", B(&key), fcn.count());

        if sentinel == 0 {
            sentinel = q;
        }

        tries -= 1;

        if tries != 0 {
            continue;
        }

        wait = 1;
        break;
    }

    shpool.unlock();

    wait
}

/// ngx_http_file_cache_expire: the nodes inactive for too long go.
fn file_cache_expire(cache: &FileCache) -> i64 {
    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache expire");

    let now = ngx_core::times::time();

    let mut wait;

    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);
    let head = cache.queue();

    shpool.lock();

    loop {
        if quitting() {
            wait = 1;
            break;
        }

        if queue::empty(&mem, head) {
            wait = 10;
            break;
        }

        let q = queue::last(&mem, head);

        let fcn = queue_data(&mem, q);

        wait = fcn.get(FileCacheNode::expire) - now;

        if wait > 0 {
            wait = if wait > 10 { 10 } else { wait };
            break;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache expire: #{} {} {}", fcn.count(), fcn.exists() as i32, B(&hex(&fcn.key_bytes()[..4])));

        'next: {
            if fcn.count() == 0 {
                file_cache_delete(cache, &mem, q);
                break 'next;
            }

            if fcn.deleting() {
                wait = 1;
                shpool.unlock();
                return wait;
            }

            let key = fcn.key_hex();

            // abnormally exited workers may leave locked cache entries,
            // and although it may be safe to remove them completely,
            // we prefer to just move them to the top of the inactive queue

            queue::remove(&mem, q);
            fcn.set(FileCacheNode::expire, ngx_core::times::time() + cache.inactive);
            queue::insert_head(&mem, head, q);

            ngx_log_error!(NGX_LOG_ALERT, log, None, "ignore long locked inactive cache entry {}, count:{}", B(&key), fcn.count());
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

    shpool.unlock();

    wait
}

/// ngx_http_file_cache_delete: the file of a node, and the node when it is
/// not used. The zone is locked on entry and on return.
fn file_cache_delete(cache: &FileCache, mem: &ShmMem, q: usize) {
    let fcn = queue_data(mem, q);
    let shpool = SlabPool::of(mem);

    if fcn.exists() {
        sh_size_add(cache.sh(mem), -fcn.get(FileCacheNode::fs_size));

        let name = node_file_name(&cache.path, fcn);

        fcn.count_inc();
        fcn.set_deleting(true);
        shpool.unlock();

        let log = cycle_log();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache expire: \"{}\"", B(&name));

        if let Err(err) = ngx_core::os::unlink(&name) {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "unlink() \"{}\" failed", B(&name));
        }

        shpool.lock();
        fcn.count_dec();
        fcn.set_deleting(false);
    }

    if fcn.count() == 0 {
        queue::remove(mem, q);
        rb::delete(&cache.rbtree(mem), fcn.off);
        shpool.free_locked(fcn.off);
        sh_count_add(cache.sh(mem), -1);
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

        let mem = cache.mem();
        let shpool = SlabPool::of(&mem);
        let sh = cache.sh(&mem);

        loop {
            shpool.lock();

            let size = sh.get(FileCacheSh::size);
            let count = sh.get(FileCacheSh::count);
            let watermark = sh.get(FileCacheSh::watermark);

            shpool.unlock();

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
    let mem = cache.mem();
    let cold = cache.cold(&mem);
    let loading = cache.loading(&mem);

    if cold.load(Ordering::SeqCst) == 0 || loading.load(Ordering::SeqCst) != 0 {
        return;
    }

    let pid = ngx_core::os::getpid() as usize;

    // ngx_atomic_cmp_set(&cache->sh->loading, 0, ngx_pid)
    if loading.compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }

    let log = cycle_log();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache loader");

    cache.last.set(ngx_core::times::current_msec());
    cache.files.set(0);

    if walk_tree(cache, &cache.path.name, &log) == NGX_ABORT {
        loading.store(0, Ordering::SeqCst);
        return;
    }

    cold.store(0, Ordering::SeqCst);
    loading.store(0, Ordering::SeqCst);

    ngx_log_error!(
        NGX_LOG_NOTICE,
        log,
        None,
        "http file cache: {} {:.3}M, bsize: {}",
        B(&cache.path.name),
        (cache.sh(&mem).get(FileCacheSh::size) as f64 * cache.bsize.get() as f64) / (1024.0 * 1024.0),
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
    let mem = cache.mem();
    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let mut fcn = file_cache_lookup(cache, &mem, key);

    if fcn == 0 {
        fcn = shpool.calloc_locked(FileCacheNode::SIZE);

        if fcn == 0 {
            file_cache_set_watermark(cache, &mem);

            if cache.fail_time.get() != ngx_core::times::time() {
                cache.fail_time.set(ngx_core::times::time());
                ngx_log_error!(NGX_LOG_ALERT, cycle_log(), None, "could not allocate node{}", B(&shpool.log_ctx()));
            }

            shpool.unlock();
            return NGX_ERROR;
        }

        let sh = cache.sh(&mem);

        sh_count_add(sh, 1);

        let n = FileCacheNode::at(&mem, fcn);

        // ngx_memcpy((u_char *) &fcn->node.key, key, sizeof(ngx_rbtree_key_t))
        n.set(FileCacheNode::node_key, usize::from_ne_bytes(key[..RBTREE_KEY_SIZE].try_into().unwrap()));

        mem.write(n.field(FileCacheNode::key), &key[RBTREE_KEY_SIZE..]);

        rb::insert(&cache.rbtree(&mem), fcn, file_cache_rbtree_insert_value);

        n.set_uses(1);
        n.set_exists(true);
        n.set(FileCacheNode::fs_size, fs_size);

        sh_size_add(sh, fs_size);
    } else {
        queue::remove(&mem, FileCacheNode::at(&mem, fcn).field(FileCacheNode::queue_prev));
    }

    let n = FileCacheNode::at(&mem, fcn);

    n.set(FileCacheNode::expire, ngx_core::times::time() + cache.inactive);

    queue::insert_head(&mem, cache.queue(), n.field(FileCacheNode::queue_prev));

    shpool.unlock();

    NGX_OK
}

/// ngx_http_file_cache_delete_file
fn file_cache_delete_file(path: &[u8], log: &Log) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http file cache delete: \"{}\"", B(path));

    if let Err(err) = ngx_core::os::unlink(path) {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "unlink() \"{}\" failed", B(path));
    }
}

/// ngx_http_file_cache_set_watermark (the zone is locked)
fn file_cache_set_watermark(cache: &FileCache, mem: &ShmMem) {
    let sh = cache.sh(mem);

    let count = sh.get(FileCacheSh::count);

    sh.set(FileCacheSh::watermark, count - count / 8);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, cycle_log(), "http file cache watermark: {}", sh.get(FileCacheSh::watermark));
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
        sh: Cell::new(0),
        mem: RefCell::new(None),
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
    fn cache_keys_parts() {
        let mut k = CacheKeys::new();
        assert!(k.is_empty());

        // the first part made for it is the buffer
        k.push_vec(b"http://backend".to_vec());
        k.data_mut().extend_from_slice(b"/uri?a=1");
        k.end();
        k.push(b"");

        assert_eq!(k.len(), 3);
        assert_eq!(k.bytes(), b"http://backend/uri?a=1");
        assert_eq!(k.iter().collect::<Vec<_>>(), [&b"http://backend"[..], b"/uri?a=1", b""]);

        // more than 4 parts
        for p in [&b"x"[..], b"yy", b"z"] {
            k.push_vec(p.to_vec());
        }

        assert_eq!(k.iter().collect::<Vec<_>>(), [&b"http://backend"[..], b"/uri?a=1", b"", b"x", b"yy", b"z"]);
        assert_eq!(k.bytes(), b"http://backend/uri?a=1xyyz");
    }

    #[test]
    fn hashed_filename_as_path_conf() {
        let key: [u8; NGX_HTTP_CACHE_KEY_LEN] = std::array::from_fn(|i| (i * 17 + 3) as u8);

        for level in [[0, 0, 0], [1, 0, 0], [1, 2, 0], [2, 2, 2]] {
            let path = PathConf::new(b"/var/cache/x".to_vec(), level);
            assert_eq!(hashed_filename(&path, &key), path.hashed_filename(&hex(&key)));
        }
    }

    #[test]
    fn cache_etag_kept() {
        let mut e = CacheEtag::new();
        assert!(e.is_empty());

        e.set(b"\"abc\"");
        assert_eq!(&*e, b"\"abc\"");

        let long = vec![b'e'; NGX_HTTP_CACHE_ETAG_LEN + 1];
        e.set(&long);
        assert_eq!(&*e, &long[..]);

        e.clear();
        assert_eq!(e.len(), 0);
    }

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
        let mem = ShmMem::private(4096).unwrap();
        let n = FileCacheNode::at(&mem, 128);

        n.set_uses(USES_MASK);
        n.uses_inc();
        assert_eq!(n.uses(), 0);
        n.count_dec();
        assert_eq!(n.count(), COUNT_MASK);
        n.count_inc();
        assert_eq!(n.count(), 0);

        // the fields of a unit do not overlap, and are cut to their widths
        n.set_count(5);
        n.set_uses(1023);
        assert_eq!((n.count(), n.uses()), (5, 1023));
        n.set_uses(1024);
        assert_eq!((n.count(), n.uses()), (5, 0));
        assert_eq!(n.get(FileCacheNode::bits0), 5);

        n.set_error(502);
        n.set_valid_msec(999);
        n.set_exists(true);
        n.set_deleting(true);
        assert_eq!(n.error(), 502);
        assert!(n.exists() && !n.updating() && n.deleting());
        n.set_updating(true);
        n.set_deleting(false);
        assert!(n.exists() && n.updating() && !n.deleting());
        assert_eq!(n.get(FileCacheNode::bits1), 999 | 502 << 10 | 1 << 20 | 1 << 21);
        assert_eq!(n.count(), 5, "the other unit is kept");

        // the key bytes, after the queue
        mem.write(n.field(FileCacheNode::key), b"\x01\x02\x03\x04\x05\x06\x07\x08");
        n.set(FileCacheNode::node_key, usize::from_ne_bytes([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]));
        assert_eq!(n.key_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(n.key_hex(), b"a0a1a2a3a4a5a6a70102030405060708");
        assert_eq!(n.get(FileCacheNode::bits0), 5);
    }

    #[test]
    fn test_zone_layout() {
        // sizeof(ngx_http_file_cache_node_t) and sizeof(ngx_http_file_cache_sh_t) on LP64
        assert_eq!(FileCacheNode::SIZE, 120);
        assert_eq!(FileCacheNode::queue_prev.off, 40);
        assert_eq!(FileCacheNode::key.off, 56);
        assert_eq!(FileCacheNode::bits0.off, 64);
        assert_eq!(FileCacheNode::bits1.off, 68);
        assert_eq!(FileCacheNode::uniq.off, 72);
        assert_eq!(FileCacheNode::expire.off, 80);
        assert_eq!(FileCacheNode::fs_size.off, 104);
        assert_eq!(FileCacheNode::lock_time.off, 112);
        assert_eq!(FileCacheNode::node_color.off, ngx_core::shmem::rbtree::RbNode::color.off);

        assert_eq!(FileCacheSh::SIZE, 120);
        assert_eq!(FileCacheSh::sentinel_key.off, 24);
        assert_eq!(FileCacheSh::queue_prev.off, 64);
        assert_eq!(FileCacheSh::cold.off, 80);
        assert_eq!(FileCacheSh::size.off, 96);
        assert_eq!(FileCacheSh::watermark.off, 112);
    }

    #[test]
    fn test_dir_access() {
        assert_eq!(dir_access(0o600), 0o700);
        assert_eq!(dir_access(0o644), 0o755);
    }

    /// ngx_cycle, for the messages of the cache (quiet: emerg only)
    fn test_cycle() {
        if ngx_core::cycle::try_cycle().is_none() {
            ngx_core::cycle::set_cycle(Rc::new(ngx_core::cycle::Cycle::init_cycle(Log::stderr(NGX_LOG_EMERG), Rc::new(Vec::new()))));
        }
    }

    /// A keys zone of `size` bytes and its cache, initialized by the zone
    /// init; the cache path does not exist.
    fn cache_of(size: usize) -> (Rc<ShmZone>, Rc<FileCache>) {
        test_cycle();

        let mem = Rc::new(ShmMem::private(size).unwrap());
        SlabPool::init_zone(&mem);

        let zone = ShmZone::new(b"one".to_vec(), mem.len(), "ngx_http_proxy_module");
        zone.shm.attach(mem);
        *zone.shm.log.borrow_mut() = Some(ngx_core::cycle::cycle().log.clone());

        let cache = Rc::new(FileCache {
            sh: Cell::new(0),
            mem: RefCell::new(None),
            path: Rc::new(PathConf::new(b"/nonexistent/rnginx/cache".to_vec(), [1, 2, 0])),
            min_free: 0,
            max_size: Cell::new(i64::MAX),
            bsize: Cell::new(512),
            inactive: 600,
            fail_time: Cell::new(0),
            files: Cell::new(0),
            loader_files: 100,
            last: Cell::new(0),
            loader_sleep: 50,
            loader_threshold: 200,
            manager_files: 100,
            manager_sleep: 50,
            manager_threshold: 200,
            name: b"one".to_vec(),
            shm_zone: Rc::downgrade(&zone),
            use_temp_path: true,
        });

        *zone.data.borrow_mut() = Some(cache.clone());

        file_cache_init(&zone, None).unwrap();

        (zone, cache)
    }

    /// The r->cache of a request for `key`.
    fn request_cache(cache: &Rc<FileCache>, key: [u8; NGX_HTTP_CACHE_KEY_LEN], min_uses: usize) -> HttpCache {
        let mut c = HttpCache::new(ngx_core::cycle::cycle().log.clone());
        c.file_cache = Some(cache.clone());
        c.key = key;
        c.main = key;
        c.min_uses = min_uses;
        c
    }

    /// A key: the rbtree key (the first 8 bytes) is `hash`, the rest `n`.
    fn key(hash: u64, n: u64) -> [u8; NGX_HTTP_CACHE_KEY_LEN] {
        let mut k = [0u8; NGX_HTTP_CACHE_KEY_LEN];
        k[..8].copy_from_slice(&hash.to_ne_bytes());
        k[8..].copy_from_slice(&n.to_be_bytes());
        k
    }

    /// The nodes of the LRU queue, the most recently used first.
    fn lru(cache: &FileCache) -> Vec<usize> {
        let mem = cache.mem();
        queue::walk(&mem, cache.queue()).into_iter().map(|q| queue_data(&mem, q).off).collect()
    }

    #[test]
    fn test_zone_init() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let sh = cache.sh(&mem);
        let shpool = SlabPool::of(&mem);

        assert_eq!(shpool.data(), cache.sh.get());
        assert_eq!(cache.cold(&mem).load(Ordering::SeqCst), 1);
        assert_eq!(cache.loading(&mem).load(Ordering::SeqCst), 0);
        assert_eq!(sh.get(FileCacheSh::size), 0);
        assert_eq!(sh.get(FileCacheSh::count), 0);
        assert_eq!(sh.get(FileCacheSh::watermark), usize::MAX);
        assert!(queue::empty(&mem, cache.queue()));
        assert_eq!(shpool.log_ctx(), b" in cache keys zone \"one\"");
        assert!(!shpool.log_nomem());
        // no such path: the default block size
        assert_eq!(cache.bsize.get(), 512);
    }

    #[test]
    fn test_exists_and_free() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let sh = cache.sh(&mem);
        let k = key(7, 1);

        let t0 = ngx_core::times::time();

        let mut c1 = request_cache(&cache, k, 1);
        assert_eq!(file_cache_exists(&cache, &mut c1), NGX_DECLINED);
        assert!(c1.node != 0);

        let n = FileCacheNode::at(&mem, c1.node);
        assert_eq!((n.count(), n.uses()), (1, 1));
        assert_eq!(n.key_bytes(), k[8..]);
        assert_eq!(cache.rbtree(&mem).key(c1.node), 7);
        assert_eq!(sh.get(FileCacheSh::count), 1);
        assert!((t0 + 600..=ngx_core::times::time() + 600).contains(&n.get(FileCacheNode::expire)));

        // another request: the node is found and used again
        let mut c2 = request_cache(&cache, k, 1);
        assert_eq!(file_cache_exists(&cache, &mut c2), NGX_OK);
        assert_eq!(c2.node, c1.node);
        assert_eq!((n.count(), n.uses()), (2, 2));
        assert!(!c2.exists);

        // min_uses not reached
        let mut c3 = request_cache(&cache, k, 5);
        assert_eq!(file_cache_exists(&cache, &mut c3), NGX_AGAIN);
        assert_eq!(n.count(), 3);

        // the same request again (c->node set): not counted again
        assert_eq!(file_cache_exists(&cache, &mut c3), NGX_AGAIN);
        assert_eq!((n.count(), n.uses()), (3, 3));

        file_cache_free(&mut c3, None);
        file_cache_free(&mut c2, None);
        assert_eq!(n.count(), 1);
        assert!(c2.updated);
        assert_eq!(c2.node, c1.node, "the node is kept while used");

        // the last user of a node never cached frees it
        file_cache_free(&mut c1, None);
        assert_eq!(c1.node, 0);
        assert_eq!(sh.get(FileCacheSh::count), 0);
        assert!(queue::empty(&mem, cache.queue()));
        let tree = cache.rbtree(&mem);
        assert_eq!(tree.root(), tree.sentinel());
    }

    #[test]
    fn test_cached_error_and_lock() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let k = key(9, 9);

        // a cached error: kept on free with its validity
        let mut c1 = request_cache(&cache, k, 1);
        assert_eq!(file_cache_exists(&cache, &mut c1), NGX_DECLINED);
        c1.error = 502;
        c1.valid_sec = ngx_core::times::time() + 60;
        c1.valid_msec = 5;
        file_cache_free(&mut c1, None);

        let n = FileCacheNode::at(&mem, c1.node);
        assert_eq!((n.count(), n.error()), (0, 502));
        assert_eq!(n.get(FileCacheNode::valid_sec), c1.valid_sec);

        let mut c2 = request_cache(&cache, k, 1);
        assert_eq!(file_cache_exists(&cache, &mut c2), NGX_OK);
        assert_eq!(c2.error, 502);

        // expired: renewed
        n.set(FileCacheNode::valid_sec, ngx_core::times::time() - 1);
        let mut c3 = request_cache(&cache, k, 1);
        assert_eq!(file_cache_exists(&cache, &mut c3), NGX_DECLINED);
        assert_eq!((c3.error, n.error()), (0, 0));
        assert_eq!(n.count(), 2);

        // the updating flag goes with the lock time of its owner
        c3.updating = true;
        c3.lock_time = 1234;
        n.set_updating(true);
        n.set(FileCacheNode::lock_time, 1234);
        file_cache_free(&mut c3, None);
        assert!(!n.updating());
    }

    #[test]
    fn test_colliding_keys() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let sh = cache.sh(&mem);

        // the same rbtree key for all: the rest of the key orders them
        let keys: Vec<[u8; 16]> = (0..200u64).map(|i| key(42, (i * 7919) % 200)).collect();

        for (i, k) in keys.iter().enumerate() {
            assert_eq!(file_cache_add(&cache, k, i as i64 + 1), NGX_OK);
        }

        assert_eq!(sh.get(FileCacheSh::count), 200);
        assert_eq!(sh.get(FileCacheSh::size), (1..=200).sum::<i64>());

        for (i, k) in keys.iter().enumerate() {
            let n = file_cache_lookup(&cache, &mem, k);
            assert!(n != 0);
            let n = FileCacheNode::at(&mem, n);
            assert_eq!(n.get(FileCacheNode::fs_size), i as i64 + 1);
            assert!(n.exists());
            assert_eq!((n.uses(), n.count()), (1, 0));
        }

        assert_eq!(file_cache_lookup(&cache, &mem, &key(42, 200)), 0);
        assert_eq!(file_cache_lookup(&cache, &mem, &key(43, 1)), 0);

        // in order of the key bytes
        let tree = cache.rbtree(&mem);
        let walked: Vec<[u8; 8]> = rb::walk(&tree).into_iter().map(|n| FileCacheNode::at(&mem, n).key_bytes()).collect();
        let mut sorted = walked.clone();
        sorted.sort();
        assert_eq!(walked, sorted);
        assert_eq!(walked.len(), 200);

        // added again (the loader meets a file twice): moved to the head,
        // nothing else changes
        let first = file_cache_lookup(&cache, &mem, &keys[0]);
        assert_eq!(*lru(&cache).last().unwrap(), first);
        assert_eq!(file_cache_add(&cache, &keys[0], 1000), NGX_OK);
        assert_eq!(lru(&cache)[0], first);
        assert_eq!(sh.get(FileCacheSh::count), 200);
        assert_eq!(sh.get(FileCacheSh::size), (1..=200).sum::<i64>());
    }

    #[test]
    fn test_forced_expire() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let sh = cache.sh(&mem);

        for i in 0..30u64 {
            assert_eq!(file_cache_add(&cache, &key(i, i), 2), NGX_OK);
        }

        // the least recently used node goes (its file is deleted: here
        // unlink() fails, as the path does not exist)
        let oldest = *lru(&cache).last().unwrap();
        assert_eq!(file_cache_forced_expire(&cache), 0);
        assert_eq!(sh.get(FileCacheSh::count), 29);
        assert_eq!(sh.get(FileCacheSh::size), 58);
        assert!(!lru(&cache).contains(&oldest));

        // a locked entry is moved to the head, the next one goes
        let locked = *lru(&cache).last().unwrap();
        FileCacheNode::at(&mem, locked).set_count(1);
        assert_eq!(file_cache_forced_expire(&cache), 0);
        assert_eq!(lru(&cache)[0], locked);
        assert_eq!(sh.get(FileCacheSh::count), 28);

        // a node being deleted stops it
        let deleting = *lru(&cache).last().unwrap();
        FileCacheNode::at(&mem, deleting).set_count(1);
        FileCacheNode::at(&mem, deleting).set_deleting(true);
        assert_eq!(file_cache_forced_expire(&cache), 1);
        assert_eq!(sh.get(FileCacheSh::count), 28);
        FileCacheNode::at(&mem, deleting).set_deleting(false);

        // all locked: 20 tries
        for n in lru(&cache) {
            FileCacheNode::at(&mem, n).set_count(1);
        }
        assert_eq!(file_cache_forced_expire(&cache), 1);
        assert_eq!(sh.get(FileCacheSh::count), 28);

        // fewer than 20, all locked: back to the first one moved
        let (_zone2, cache2) = cache_of(1 << 20);
        for i in 0..5u64 {
            assert_eq!(file_cache_add(&cache2, &key(i, i), 1), NGX_OK);
        }
        let mem2 = cache2.mem();
        let before = lru(&cache2);
        for &n in &before {
            FileCacheNode::at(&mem2, n).set_count(1);
        }
        assert_eq!(file_cache_forced_expire(&cache2), 10);
        assert_eq!(lru(&cache2), before, "each moved to the head once");
    }

    #[test]
    fn test_expire() {
        let (_zone, cache) = cache_of(1 << 20);
        let mem = cache.mem();
        let sh = cache.sh(&mem);

        // an empty queue: 10 seconds
        assert_eq!(file_cache_expire(&cache), 10);

        for i in 0..10u64 {
            assert_eq!(file_cache_add(&cache, &key(i, 0), 1), NGX_OK);
        }

        // not inactive yet: the time till the oldest is, at most 10s
        assert_eq!(file_cache_expire(&cache), 10);
        let oldest = *lru(&cache).last().unwrap();
        FileCacheNode::at(&mem, oldest).set(FileCacheNode::expire, ngx_core::times::time() + 3);
        let wait = file_cache_expire(&cache);
        assert!(wait == 3 || wait == 2, "{}", wait);

        // the inactive nodes go, up to the first one still active
        let nodes = lru(&cache);
        let now = ngx_core::times::time();
        for &n in &nodes[6..] {
            FileCacheNode::at(&mem, n).set(FileCacheNode::expire, now - 1);
        }
        // a locked inactive one is moved to the head
        FileCacheNode::at(&mem, nodes[7]).set_count(1);

        // as file_cache_manager() does
        cache.last.set(ngx_core::times::current_msec());
        cache.files.set(0);

        let wait = file_cache_expire(&cache);
        assert!(wait > 0 && wait <= 10, "{}", wait);
        assert_eq!(sh.get(FileCacheSh::count), 7);
        assert_eq!(lru(&cache)[0], nodes[7]);
        assert!(FileCacheNode::at(&mem, nodes[7]).get(FileCacheNode::expire) >= now + 600);
        assert_eq!(cache.files.get(), 4);

        // the manager's limits: manager_threshold since cache->last...
        for n in lru(&cache) {
            FileCacheNode::at(&mem, n).set_count(0);
            FileCacheNode::at(&mem, n).set(FileCacheNode::expire, now - 1);
        }
        cache.last.set(0);
        cache.files.set(0);
        assert_eq!(file_cache_expire(&cache), 0);
        assert_eq!(sh.get(FileCacheSh::count), 6);
        assert_eq!(cache.files.get(), 1);
    }

    #[test]
    fn test_no_memory() {
        // a small keys zone
        let (_zone, cache) = cache_of(8 * ngx_core::os::pagesize());
        let mem = cache.mem();
        let sh = cache.sh(&mem);

        let t0 = ngx_core::times::time();

        let mut n = 0u64;
        while file_cache_add(&cache, &key(n, n), 1) == NGX_OK {
            n += 1;
            assert!(n < 10000);
        }

        // "could not allocate node", once a second; the watermark is set
        let count = sh.get(FileCacheSh::count);
        assert_eq!(count as u64, n);
        assert!(n > 100, "{}", n);
        assert_eq!(sh.get(FileCacheSh::watermark), count - count / 8);
        assert!(cache.fail_time.get() >= t0);

        // a request for a new key: the least recently used node is expired
        // to make room
        let oldest = *lru(&cache).last().unwrap();
        let mut c = request_cache(&cache, key(n, n), 1);
        assert_eq!(file_cache_exists(&cache, &mut c), NGX_DECLINED);
        assert_eq!(c.node, oldest, "the freed chunk is reused");
        assert_eq!(sh.get(FileCacheSh::count), count);

        // all in use: "could not allocate node"
        for q in lru(&cache) {
            FileCacheNode::at(&mem, q).set_count(1);
        }
        let mut c = request_cache(&cache, key(n + 1, n + 1), 1);
        assert_eq!(file_cache_exists(&cache, &mut c), NGX_ERROR);
        assert_eq!(c.node, 0);
        assert_eq!(sh.get(FileCacheSh::count), count);
    }

    /// The tree, the queue and the counters agree: the number of nodes.
    fn check_zone(cache: &FileCache) -> usize {
        let mem = cache.mem();
        let sh = cache.sh(&mem);
        let tree = cache.rbtree(&mem);

        let mut in_tree = rb::walk(&tree);
        let mut in_queue = lru(cache);

        // ordered by the rbtree key, then by the rest of the key
        let keys: Vec<(usize, [u8; 8])> = in_tree.iter().map(|&n| (tree.key(n), FileCacheNode::at(&mem, n).key_bytes())).collect();
        for w in keys.windows(2) {
            assert!(w[0] < w[1], "{:?}", w);
        }

        in_tree.sort_unstable();
        in_queue.sort_unstable();
        assert_eq!(in_tree, in_queue);

        assert_eq!(sh.get(FileCacheSh::count), in_tree.len());

        let size: i64 = in_tree.iter().map(|&n| FileCacheNode::at(&mem, n)).filter(|n| n.exists()).map(|n| n.get(FileCacheNode::fs_size)).sum();
        assert_eq!(sh.get(FileCacheSh::size), size);

        in_tree.len()
    }

    #[test]
    fn test_random_operations() {
        let (_zone, cache) = cache_of(16 * ngx_core::os::pagesize());

        let mut seed: u32 = 4242;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            ((seed >> 16) & 0x7fff) as u64
        };

        // the requests holding a node
        let mut held: Vec<HttpCache> = Vec::new();
        let mut max = 0;

        for i in 0..20000 {
            // few rbtree keys: many collide
            let k = key(rnd() % 8, rnd() % 1000);

            match rnd() % 6 {
                // the loader
                0 => {
                    let _ = file_cache_add(&cache, &k, (rnd() % 10) as i64);
                }
                // the manager
                1 if i % 50 == 0 => {
                    let _ = file_cache_forced_expire(&cache);
                }
                // a request done
                2 | 3 if !held.is_empty() => {
                    let mut c = held.swap_remove((rnd() as usize) % held.len());
                    file_cache_free(&mut c, None);
                }
                // a request
                _ => {
                    let mut c = request_cache(&cache, k, 1 + (rnd() % 2) as usize);
                    match file_cache_exists(&cache, &mut c) {
                        NGX_ERROR => assert_eq!(c.node, 0),
                        _ if held.len() < 50 => held.push(c),
                        _ => file_cache_free(&mut c, None),
                    }
                }
            }

            if i % 100 == 0 {
                max = max.max(check_zone(&cache));
            }
        }

        for mut c in held.drain(..) {
            file_cache_free(&mut c, None);
        }

        assert!(max > 100, "{}", max);
        check_zone(&cache);

        // nothing is used any more: all can be expired
        while file_cache_forced_expire(&cache) == 0 {}
        assert_eq!(check_zone(&cache), 0);
    }
}
