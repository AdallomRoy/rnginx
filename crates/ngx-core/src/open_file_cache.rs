//! Open file cache, ported from ngx_open_file_cache.c.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use crate::log::{Log, NGX_LOG_ALERT, NGX_LOG_CRIT, NGX_LOG_DEBUG_CORE};
use crate::os;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

const NGX_INVALID_FILE: i32 = -1;
const NGX_MIN_READ_AHEAD: usize = 128 * 1024;

/// File information from stat, used by open_cached_file.
#[derive(Clone, Debug)]
pub struct OpenFileInfo {
    pub fd: i32,
    pub uniq: u64,
    pub mtime: i64,
    pub size: i64,
    pub fs_size: i64,
    pub directio: usize,
    pub read_ahead: usize,
    pub err: i32,
    pub failed: &'static str,
    pub valid: i64,
    pub min_uses: u32,
    pub disable_symlinks: u8,       // 0=off, 1=on, 2=if_not_owner
    pub disable_symlinks_from: usize,
    pub test_dir: bool,
    pub test_only: bool,
    pub log: bool,
    pub errors: bool,
    pub events: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_link: bool,
    pub is_exec: bool,
    pub is_directio: bool,
}

impl Default for OpenFileInfo {
    fn default() -> Self {
        OpenFileInfo {
            fd: NGX_INVALID_FILE,
            uniq: 0,
            mtime: 0,
            size: 0,
            fs_size: 0,
            directio: 0,
            read_ahead: 0,
            err: 0,
            failed: "",
            valid: 0,
            min_uses: 0,
            disable_symlinks: 0,
            disable_symlinks_from: 0,
            test_dir: false,
            test_only: false,
            log: false,
            errors: false,
            events: false,
            is_dir: false,
            is_file: false,
            is_link: false,
            is_exec: false,
            is_directio: false,
        }
    }
}

/// ngx_cached_open_file_t (without the vnode events of kqueue:
/// file->event is NULL and file->use_event is 0)
pub struct CachedFile {
    name: Vec<u8>,
    created: i64,
    accessed: i64,
    fd: i32,
    uniq: u64,
    mtime: i64,
    size: i64,
    err: i32,
    uses: u32,
    disable_symlinks: u8,
    disable_symlinks_from: usize,
    count: u32,
    close: bool,
    is_dir: bool,
    is_file: bool,
    is_link: bool,
    is_exec: bool,
    is_directio: bool,
}

type CachedFileRef = Rc<RefCell<CachedFile>>;

/// ngx_open_file_cache_t: the rbtree of the files by name and the expire
/// queue (the head is the most recently used file).
pub struct OpenFileCache {
    files: RefCell<BTreeMap<Vec<u8>, CachedFileRef>>,
    expire_queue: RefCell<VecDeque<CachedFileRef>>,
    current: RefCell<usize>,
    max: usize,
    inactive: i64,
}

impl OpenFileCache {
    /// ngx_open_file_cache_init
    pub fn new(max: usize, inactive_secs: i64) -> Rc<Self> {
        Rc::new(OpenFileCache {
            files: RefCell::new(BTreeMap::new()),
            expire_queue: RefCell::new(VecDeque::new()),
            current: RefCell::new(0),
            max,
            inactive: inactive_secs,
        })
    }

    pub fn len(&self) -> usize {
        *self.current.borrow()
    }

    /// Expires the inactive files, ngx_expire_old_cached_files() without the
    /// limit of two files.
    pub fn cleanup_expired(&self, log: &Log) {
        let now = current_time();

        loop {
            let file = match self.expire_queue.borrow().back() {
                Some(f) => f.clone(),
                None => return,
            };

            if now - file.borrow().accessed <= self.inactive {
                return;
            }

            self.expire(&file, log);
        }
    }

    /// ngx_open_file_lookup
    fn lookup(&self, name: &[u8]) -> Option<CachedFileRef> {
        self.files.borrow().get(name).cloned()
    }

    /// ngx_rbtree_insert(&cache->rbtree, &file->node)
    fn tree_insert(&self, file: &CachedFileRef) {
        let name = file.borrow().name.clone();
        self.files.borrow_mut().insert(name, file.clone());
    }

    /// ngx_rbtree_delete(&cache->rbtree, &file->node)
    fn tree_delete(&self, file: &CachedFileRef) {
        let name = file.borrow().name.clone();
        let mut files = self.files.borrow_mut();

        if files.get(&name).is_some_and(|f| Rc::ptr_eq(f, file)) {
            files.remove(&name);
        }
    }

    /// ngx_queue_remove(&file->queue)
    fn queue_remove(&self, file: &CachedFileRef) {
        let mut q = self.expire_queue.borrow_mut();

        if let Some(pos) = q.iter().position(|f| Rc::ptr_eq(f, file)) {
            q.remove(pos);
        }
    }

    /// ngx_queue_insert_head(&cache->expire_queue, &file->queue)
    fn queue_insert_head(&self, file: &CachedFileRef) {
        self.expire_queue.borrow_mut().push_front(file.clone());
    }

    /// The expiration of a file of ngx_expire_old_cached_files().
    fn expire(&self, file: &CachedFileRef, log: &Log) {
        self.queue_remove(file);

        self.tree_delete(file);

        *self.current.borrow_mut() -= 1;

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "expire cached open file: {}", B(&file.borrow().name));

        let (err, is_dir) = {
            let f = file.borrow();
            (f.err, f.is_dir)
        };

        if err == 0 && !is_dir {
            file.borrow_mut().close = true;
            close_cached_file(self, file, 0, log);
        }

        // ngx_free(file): the last reference goes with the handles
    }
}

/// ngx_expire_old_cached_files: n == 1 deletes one or two inactive files,
/// n == 0 deletes least recently used file by force and one or two
/// inactive files
fn expire_old_cached_files(cache: &OpenFileCache, mut n: u32, log: &Log) {
    let now = current_time();

    while n < 3 {
        let file = match cache.expire_queue.borrow().back() {
            Some(f) => f.clone(),
            None => return,
        };

        let forced = n == 0;

        n += 1;

        if !forced && now - file.borrow().accessed <= cache.inactive {
            return;
        }

        cache.expire(&file, log);
    }
}

/// ngx_close_cached_file
fn close_cached_file(cache: &OpenFileCache, file: &CachedFileRef, min_uses: u32, log: &Log) {
    {
        let f = file.borrow();

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "close cached open file: {}, fd:{}, c:{}, u:{}, {}", B(&f.name), f.fd, f.count, f.uses, f.close as u32);
    }

    if !file.borrow().close {
        file.borrow_mut().accessed = current_time();

        cache.queue_remove(file);

        cache.queue_insert_head(file);

        let f = file.borrow();

        if f.uses >= min_uses || f.count != 0 {
            return;
        }
    }

    // ngx_open_file_del_event(file): no events

    let mut f = file.borrow_mut();

    if f.count != 0 {
        return;
    }

    if f.fd != NGX_INVALID_FILE {
        if let Err(e) = close_file(f.fd) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(&f.name));
        }

        f.fd = NGX_INVALID_FILE;
    }

    // if (!file->close) return; else ngx_free(file): the memory goes with
    // the last reference
}

/// Guard for a file opened via `open_cached_file`: its drop is the pool
/// cleanup of C.
///
/// When cached (`Cached`), drop is ngx_open_file_cleanup: the file is
/// released and closed unless it is used often enough (min_uses) to stay
/// open, then one or two expired files are dropped. When uncached (`Owned`
/// — no `open_file_cache` configured), drop closes the fd unconditionally
/// (ngx_pool_cleanup_file), since nothing else owns it.
pub enum CachedFileHandle {
    Cached { cache: Rc<OpenFileCache>, name: Vec<u8>, file: CachedFileRef, min_uses: u32, log: Log },
    Owned { fd: i32 },
}

impl Drop for CachedFileHandle {
    fn drop(&mut self) {
        match self {
            CachedFileHandle::Cached { cache, file, min_uses, log, .. } => {
                // ngx_open_file_cleanup

                {
                    let mut f = file.borrow_mut();
                    f.count = f.count.saturating_sub(1);
                }

                close_cached_file(cache, file, *min_uses, log);

                // drop one or two expired open files
                expire_old_cached_files(cache, 1, log);
            }
            CachedFileHandle::Owned { fd } => {
                if *fd >= 0 {
                    os::close(*fd);
                    *fd = NGX_INVALID_FILE;
                }
            }
        }
    }
}

/// The labels of ngx_open_cached_file() after the lookup.
enum Next {
    Failed(Option<CachedFileRef>),
    Create,
    AddEvent(CachedFileRef),
    Update(CachedFileRef),
    Found(CachedFileRef),
}

/// ngx_open_cached_file: Ok(Some(handle)) for an open file, Ok(None) for a
/// directory or a test_only lookup without a cache (NGX_OK), Err(()) with
/// of.err (0 if the error is not to be reported) otherwise.
pub fn open_cached_file(
    cache: Option<&Rc<OpenFileCache>>,
    name: &[u8],
    of: &mut OpenFileInfo,
    log: &Log,
) -> Result<Option<Rc<CachedFileHandle>>, ()> {
    of.fd = NGX_INVALID_FILE;
    of.err = 0;

    let cache = match cache {
        Some(c) => c,

        None => {
            if of.test_only {
                match file_info_wrapper(name, of, log) {
                    Ok(st) => {
                        let _ = fill_info_from_stat(&st, of);
                        return Ok(None);
                    }
                    Err((err, failed)) => {
                        of.err = err;
                        of.failed = failed;
                        return Err(());
                    }
                }
            }

            open_and_stat_file(name, of, log)?;

            if of.is_dir || of.fd == NGX_INVALID_FILE {
                return Ok(None);
            }

            return Ok(Some(Rc::new(CachedFileHandle::Owned { fd: of.fd })));
        }
    };

    let now = current_time();

    let next = match cache.lookup(name) {
        Some(file) => lookup_found(cache, file, name, of, now, log),

        None => {
            // not found

            let rc = open_and_stat_file(name, of, log);

            if rc.is_err() && (of.err == 0 || !of.errors) {
                Next::Failed(None)
            } else {
                Next::Create
            }
        }
    };

    let file = match next {
        Next::Failed(file) => return open_failed(cache, file, name, of, log),

        Next::Create => {
            // create:

            if *cache.current.borrow() >= cache.max {
                expire_old_cached_files(cache, 0, log);
            }

            let file = Rc::new(RefCell::new(CachedFile {
                name: name.to_vec(),
                created: now,
                accessed: now,
                fd: NGX_INVALID_FILE,
                uniq: 0,
                mtime: 0,
                size: 0,
                err: 0,
                uses: 1,
                disable_symlinks: 0,
                disable_symlinks_from: 0,
                count: 0,
                close: false,
                is_dir: false,
                is_file: false,
                is_link: false,
                is_exec: false,
                is_directio: false,
            }));

            cache.tree_insert(&file);

            *cache.current.borrow_mut() += 1;

            update(&file, of, now);

            file
        }

        // add_event: ngx_open_file_add_event() does nothing without events
        Next::AddEvent(file) | Next::Update(file) => {
            update(&file, of, now);
            file
        }

        Next::Found(file) => file,
    };

    // found:

    file.borrow_mut().accessed = now;

    cache.queue_insert_head(&file);

    {
        let f = file.borrow();
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "cached open file: {}, fd:{}, c:{}, e:{}, u:{}", B(&f.name), f.fd, f.count, f.err, f.uses);
    }

    if of.err == 0 {
        if !of.is_dir {
            return Ok(Some(Rc::new(CachedFileHandle::Cached { cache: cache.clone(), name: name.to_vec(), file, min_uses: of.min_uses, log: log.clone() })));
        }

        return Ok(None);
    }

    Err(())
}

/// ngx_open_cached_file() for a file found in the cache.
fn lookup_found(cache: &OpenFileCache, file: CachedFileRef, name: &[u8], of: &mut OpenFileInfo, now: i64, log: &Log) -> Next {
    file.borrow_mut().uses += 1;

    cache.queue_remove(&file);

    let (fd, err, is_dir) = {
        let f = file.borrow();
        (f.fd, f.err, f.is_dir)
    };

    if fd == NGX_INVALID_FILE && err == 0 && !is_dir {
        // file was not used often enough to keep open

        let rc = open_and_stat_file(name, of, log);

        if rc.is_err() && (of.err == 0 || !of.errors) {
            return Next::Failed(Some(file));
        }

        return Next::AddEvent(file);
    }

    let valid = {
        let f = file.borrow();

        (of.uniq == 0 || of.uniq == f.uniq)
            && now - f.created < of.valid
            && of.disable_symlinks == f.disable_symlinks
            && of.disable_symlinks_from == f.disable_symlinks_from
    };

    if valid {
        let mut f = file.borrow_mut();

        if f.err == 0 {
            of.fd = f.fd;
            of.uniq = f.uniq;
            of.mtime = f.mtime;
            of.size = f.size;

            of.is_dir = f.is_dir;
            of.is_file = f.is_file;
            of.is_link = f.is_link;
            of.is_exec = f.is_exec;
            of.is_directio = f.is_directio;

            if !f.is_dir {
                f.count += 1;
            }
        } else {
            of.err = f.err;
            of.failed = if f.disable_symlinks != 0 { "openat()" } else { "open()" };
        }

        drop(f);

        return Next::Found(file);
    }

    {
        let f = file.borrow();

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "retest open file: {}, fd:{}, c:{}, e:{}", B(&f.name), f.fd, f.count, f.err);

        if f.is_dir {
            // chances that directory became file are very small
            // so test_dir flag allows to use a single syscall
            // in ngx_file_info() instead of three syscalls

            of.test_dir = true;
        }

        of.fd = f.fd;
        of.uniq = f.uniq;
    }

    let rc = open_and_stat_file(name, of, log);

    if rc.is_err() && (of.err == 0 || !of.errors) {
        return Next::Failed(Some(file));
    }

    let (f_is_dir, f_err, f_uniq, f_is_directio) = {
        let f = file.borrow();
        (f.is_dir, f.err, f.uniq, f.is_directio)
    };

    if of.is_dir {
        if f_is_dir || f_err != 0 {
            return Next::Update(file);
        }

        // file became directory
    } else if of.err == 0 {
        // file

        if f_is_dir || f_err != 0 {
            return Next::AddEvent(file);
        }

        if of.uniq == f_uniq {
            of.is_directio = f_is_directio;

            return Next::Update(file);
        }

        // file was changed
    } else {
        // error to cache

        if f_err != 0 || f_is_dir {
            return Next::Update(file);
        }

        // file was removed, etc.
    }

    if file.borrow().count == 0 {
        // ngx_open_file_del_event(file): no events

        let f = file.borrow();

        if let Err(e) = close_file(f.fd) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
        }

        drop(f);

        return Next::AddEvent(file);
    }

    cache.tree_delete(&file);

    *cache.current.borrow_mut() -= 1;

    file.borrow_mut().close = true;

    Next::Create
}

/// The update: label of ngx_open_cached_file().
fn update(file: &CachedFileRef, of: &OpenFileInfo, now: i64) {
    let mut f = file.borrow_mut();

    f.fd = of.fd;
    f.err = of.err;
    f.disable_symlinks = of.disable_symlinks;
    f.disable_symlinks_from = of.disable_symlinks_from;

    if of.err == 0 {
        f.uniq = of.uniq;
        f.mtime = of.mtime;
        f.size = of.size;

        f.close = false;

        f.is_dir = of.is_dir;
        f.is_file = of.is_file;
        f.is_link = of.is_link;
        f.is_exec = of.is_exec;
        f.is_directio = of.is_directio;

        if !of.is_dir {
            f.count += 1;
        }
    }

    f.created = now;
}

/// The failed: label of ngx_open_cached_file().
fn open_failed(cache: &OpenFileCache, file: Option<CachedFileRef>, name: &[u8], of: &mut OpenFileInfo, log: &Log) -> Result<Option<Rc<CachedFileHandle>>, ()> {
    if let Some(file) = file {
        cache.tree_delete(&file);

        *cache.current.borrow_mut() -= 1;

        let mut f = file.borrow_mut();

        if f.count == 0 {
            if f.fd != NGX_INVALID_FILE {
                if let Err(e) = close_file(f.fd) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(&f.name));
                }

                f.fd = NGX_INVALID_FILE;
            }

            // ngx_free(file)
        } else {
            f.close = true;
        }
    }

    if of.fd != NGX_INVALID_FILE {
        if let Err(e) = close_file(of.fd) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
        }
    }

    Err(())
}

/// ngx_open_and_stat_file
fn open_and_stat_file(name: &[u8], of: &mut OpenFileInfo, log: &Log) -> Result<(), ()> {
    if of.fd != NGX_INVALID_FILE {
        match file_info_wrapper(name, of, log) {
            Err((err, failed)) => {
                of.err = err;
                of.failed = failed;
                of.fd = NGX_INVALID_FILE;
                return Err(());
            }

            Ok(st) => {
                if of.uniq == stat_uniq(&st) {
                    return fill_info_from_stat(&st, of);
                }
            }
        }
    } else if of.test_dir {
        match file_info_wrapper(name, of, log) {
            Err((err, failed)) => {
                of.err = err;
                of.failed = failed;
                of.fd = NGX_INVALID_FILE;
                return Err(());
            }

            Ok(st) => {
                if os::is_dir(&st) {
                    return fill_info_from_stat(&st, of);
                }
            }
        }
    }

    let fd = if of.log {
        open_file_wrapper(name, of, libc::O_WRONLY | libc::O_APPEND, libc::O_CREAT, 0o644, log)
    } else {
        // Use non-blocking open() not to hang on FIFO files, etc.
        // This flag has no effect on a regular files.
        open_file_wrapper(name, of, libc::O_RDONLY | libc::O_NONBLOCK, 0, 0, log)
    };

    if fd < 0 {
        of.fd = NGX_INVALID_FILE;
        return Err(());
    }

    match os::fstat(fd) {
        Ok(st) => {
            if os::is_dir(&st) {
                if let Err(e) = close_file(fd) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
                }

                of.fd = NGX_INVALID_FILE;
            } else {
                of.fd = fd;

                if of.read_ahead > 0 && st.st_size as usize > NGX_MIN_READ_AHEAD {
                    let _ = posix_fadvise(fd, 0, st.st_size, libc::POSIX_FADV_SEQUENTIAL);
                }

                if of.directio > 0 && st.st_size as usize >= of.directio {
                    if directio_on(fd) == 0 {
                        of.is_directio = true;
                    }
                }
            }

            fill_info_from_stat(&st, of)
        }

        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "fstat() \"{}\" failed", B(name));

            if let Err(e) = close_file(fd) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
            }

            of.fd = NGX_INVALID_FILE;

            Err(())
        }
    }
}

/// NGX_FILE_SEARCH (O_PATH | O_RDONLY | NGX_FILE_DIRECTORY on Linux)
const FILE_SEARCH: i32 = libc::O_PATH | libc::O_RDONLY | libc::O_DIRECTORY;

/// NGX_DISABLE_SYMLINKS_NOTOWNER
const DISABLE_SYMLINKS_NOTOWNER: u8 = 2;

fn set_errno(err: i32) {
    unsafe { *libc::__errno_location() = err };
}

/// ngx_openat_file: openat(at_fd, name, mode | create, access)
fn openat_file(at_fd: i32, name: &[u8], mode: i32, create: i32, access: u32) -> i32 {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => {
            set_errno(libc::EINVAL);
            return NGX_INVALID_FILE;
        }
    };

    unsafe { libc::openat(at_fd, cname.as_ptr(), mode | create | libc::O_CLOEXEC, access as libc::c_uint) }
}

/// ngx_openat_file_owner: to allow symlinks with the same owner, openat()
/// (followed by fstat()) and fstatat(AT_SYMLINK_NOFOLLOW), and the uids
/// compared, even when fstatat() reports the component isn't a symlink
/// (there is a race between openat() and fstatat()).
fn openat_file_owner(at_fd: i32, name: &[u8], mode: i32, create: i32, access: u32, log: &Log) -> i32 {
    let fd = openat_file(at_fd, name, mode, create, access);

    if fd == NGX_INVALID_FILE {
        return NGX_INVALID_FILE;
    }

    let err = 'failed: {
        let cname = std::ffi::CString::new(name).expect("name");

        let mut atfi: libc::stat = unsafe { std::mem::zeroed() };

        if unsafe { libc::fstatat(at_fd, cname.as_ptr(), &mut atfi, libc::AT_SYMLINK_NOFOLLOW) } == -1 {
            break 'failed os::errno();
        }

        let mut fi: libc::stat = unsafe { std::mem::zeroed() };

        if file_o_path_info(fd, &mut fi, log).is_err() {
            break 'failed os::errno();
        }

        if fi.st_uid != atfi.st_uid {
            break 'failed libc::ELOOP;
        }

        return fd;
    };

    if let Err(e) = close_file(fd) {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
    }

    set_errno(err);

    NGX_INVALID_FILE
}

thread_local! {
    /// use_fstat of ngx_file_o_path_info
    static USE_FSTAT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// ngx_file_o_path_info: fstat() of an O_PATH descriptor, or fstatat()
/// with AT_EMPTY_PATH on kernels before 3.6
fn file_o_path_info(fd: i32, fi: &mut libc::stat, log: &Log) -> Result<(), ()> {
    if USE_FSTAT.with(|u| u.get()) {
        if unsafe { libc::fstat(fd, fi) } != -1 {
            return Ok(());
        }

        if os::errno() != libc::EBADF {
            return Err(());
        }

        ngx_log_error!(crate::log::NGX_LOG_NOTICE, log, None, "fstat(O_PATH) failed with EBADF, switching to fstatat(AT_EMPTY_PATH)");

        USE_FSTAT.with(|u| u.set(false));
    }

    if unsafe { libc::fstatat(fd, b"\0".as_ptr() as *const libc::c_char, fi, libc::AT_EMPTY_PATH) } != -1 {
        return Ok(());
    }

    Err(())
}

/// ngx_open_file_wrapper: without disable_symlinks, open(); with it, the
/// path walked component by component with openat(O_NOFOLLOW) from "/",
/// the current directory, or the disable_symlinks "from" part opened as a
/// whole; with if_not_owner, a symlink is followed when its owner is the
/// owner of what it points to.
fn open_file_wrapper(name: &[u8], of: &mut OpenFileInfo, mode: i32, create: i32, access: u32, log: &Log) -> i32 {
    if of.disable_symlinks == 0 {
        return match os::open(name, mode | create, access) {
            Ok(fd) => fd,
            Err(err) => {
                of.err = err;
                of.failed = "open()";
                NGX_INVALID_FILE
            }
        };
    }

    let end = name.len();
    let mut p: usize;
    let mut at_fd: i32;

    // at_name: the part of the name at_fd is, for the close() message
    let mut at_name_len: usize = name.len();

    if of.disable_symlinks_from != 0 {
        let cp = of.disable_symlinks_from;

        at_fd = match os::open(&name[..cp], FILE_SEARCH | libc::O_NONBLOCK, 0) {
            Ok(fd) => fd,
            Err(err) => {
                of.err = err;
                of.failed = "open()";
                return NGX_INVALID_FILE;
            }
        };

        at_name_len = of.disable_symlinks_from;
        p = cp + 1;
    } else if name.first() == Some(&b'/') {
        at_fd = match os::open(b"/", FILE_SEARCH | libc::O_NONBLOCK, 0) {
            Ok(fd) => fd,
            Err(err) => {
                of.err = err;
                of.failed = "openat()";
                return NGX_INVALID_FILE;
            }
        };

        at_name_len = 1;
        p = 1;
    } else {
        at_fd = libc::AT_FDCWD;
        p = 0;
    }

    let close_at = |at_fd: i32, at_name_len: usize| {
        if at_fd != libc::AT_FDCWD {
            if let Err(e) = close_file(at_fd) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(&name[..at_name_len.min(name.len())]));
            }
        }
    };

    loop {
        let cp = match memchr::memchr(b'/', &name[p.min(end)..end]) {
            Some(i) => p + i,
            None => break,
        };

        if cp == p {
            p += 1;
            continue;
        }

        let fd = if of.disable_symlinks == DISABLE_SYMLINKS_NOTOWNER {
            openat_file_owner(at_fd, &name[p..cp], FILE_SEARCH | libc::O_NONBLOCK, 0, 0, log)
        } else {
            openat_file(at_fd, &name[p..cp], FILE_SEARCH | libc::O_NONBLOCK | libc::O_NOFOLLOW, 0, 0)
        };

        if fd == NGX_INVALID_FILE {
            of.err = os::errno();
            of.failed = "openat()";
            close_at(at_fd, at_name_len);
            return NGX_INVALID_FILE;
        }

        close_at(at_fd, at_name_len);

        p = cp + 1;
        at_fd = fd;
        at_name_len = cp;
    }

    let fd = if p >= end {
        /*
         * If pathname ends with a trailing slash, assume the last path
         * component is a directory and reopen it with requested flags;
         * if not, fail with ENOTDIR as per POSIX.
         */

        openat_file(at_fd, b".", mode, create, access)
    } else if of.disable_symlinks == DISABLE_SYMLINKS_NOTOWNER && create & (libc::O_CREAT | libc::O_TRUNC) == 0 {
        openat_file_owner(at_fd, &name[p..end], mode, create, access, log)
    } else {
        openat_file(at_fd, &name[p..end], mode | libc::O_NOFOLLOW, create, access)
    };

    if fd == NGX_INVALID_FILE {
        of.err = os::errno();
        of.failed = "openat()";
    }

    close_at(at_fd, at_name_len);

    fd
}

/// ngx_file_info_wrapper: with disable_symlinks, the file is opened with
/// ngx_open_file_wrapper() and its information is taken with fstat()
fn file_info_wrapper(name: &[u8], of: &mut OpenFileInfo, log: &Log) -> Result<libc::stat, (i32, &'static str)> {
    if of.disable_symlinks == 0 {
        return os::stat(name).map_err(|e| (e, "stat()"));
    }

    let fd = open_file_wrapper(name, of, libc::O_RDONLY | libc::O_NONBLOCK, 0, 0, log);

    if fd == NGX_INVALID_FILE {
        return Err((of.err, of.failed));
    }

    let rc = os::fstat(fd).map_err(|e| (e, "fstat()"));

    if let Err(e) = close_file(fd) {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() \"{}\" failed", B(name));
    }

    rc
}

fn fill_info_from_stat(st: &libc::stat, of: &mut OpenFileInfo) -> Result<(), ()> {
    of.uniq = stat_uniq(st);
    of.mtime = st.st_mtime;
    of.size = st.st_size;
    of.fs_size = (st.st_blocks as i64) * 512;
    of.is_dir = os::is_dir(st);
    of.is_file = os::is_file(st);
    of.is_link = os::is_link(st);
    of.is_exec = os::is_exec(st);
    Ok(())
}

/// ngx_close_file
fn close_file(fd: i32) -> Result<(), i32> {
    // SAFETY: closing a descriptor owned by the cache or the caller.
    if unsafe { libc::close(fd) } == -1 {
        Err(os::errno())
    } else {
        Ok(())
    }
}

fn stat_uniq(st: &libc::stat) -> u64 {
    (((st.st_dev as u64) << 32) ^ (st.st_ino as u64)) as u64
}

fn current_time() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32 {
    unsafe { libc::posix_fadvise(fd, offset, len, advice) }
}

fn directio_on(fd: i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let flags = libc::O_DIRECT;
            if libc::fcntl(fd, libc::F_SETFL, flags) == -1 {
                return -1;
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = OpenFileCache::new(10, 60);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_open_file_info_default() {
        let info = OpenFileInfo::default();
        assert_eq!(info.fd, NGX_INVALID_FILE);
        assert_eq!(info.err, 0);
        assert!(!info.is_dir);
        assert!(!info.is_file);
    }

    #[test]
    fn test_cache_max_and_inactive() {
        let cache = OpenFileCache::new(5, 30);
        assert_eq!(cache.len(), 0);
    }

    fn test_dir(tag: &str) -> String {
        let d = format!("{}/ofc-{}-{}", std::env::temp_dir().display(), tag, std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn log_of(min_uses: u32) -> OpenFileInfo {
        OpenFileInfo { log: true, valid: 60, min_uses, directio: usize::MAX, ..Default::default() }
    }

    fn entry_fd(cache: &OpenFileCache, name: &str) -> Option<i32> {
        cache.lookup(name.as_bytes()).map(|f| f.borrow().fd)
    }

    #[test]
    fn min_uses_closes_and_reopens() {
        let d = test_dir("min-uses");
        let log = Log::stderr(0);
        let cache = OpenFileCache::new(10, 60);
        let name = format!("{}/a.log", d);

        // the first use: not used often enough to keep open
        let mut of = log_of(2);
        let h = open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap();
        assert!(h.is_some() && of.fd >= 0);
        drop(h);
        assert_eq!(entry_fd(&cache, &name), Some(NGX_INVALID_FILE));
        assert_eq!(cache.len(), 1);

        // the second use reopens the file and keeps it open
        let mut of = log_of(2);
        let h = open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap();
        let fd = of.fd;
        assert!(h.is_some() && fd >= 0);
        drop(h);
        assert_eq!(entry_fd(&cache, &name), Some(fd));

        // the third use is served from the cache
        let mut of = log_of(2);
        let _h = open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap();
        assert_eq!(of.fd, fd);

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn full_cache_forces_out_one_file() {
        let d = test_dir("full");
        let log = Log::stderr(0);
        let cache = OpenFileCache::new(3, 60);

        for n in ["a", "b", "c"] {
            let name = format!("{}/{}.log", d, n);
            let mut of = log_of(1);
            drop(open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap());
        }

        assert_eq!(cache.len(), 3);

        // "a" is the least recently used file, "b" and "c" are not inactive
        let name = format!("{}/d.log", d);
        let mut of = log_of(1);
        drop(open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap());

        assert_eq!(cache.len(), 3);
        assert!(entry_fd(&cache, &format!("{}/a.log", d)).is_none());
        for n in ["b", "c", "d"] {
            assert!(entry_fd(&cache, &format!("{}/{}.log", d, n)).unwrap() >= 0);
        }

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_open_drops_the_entry() {
        let d = test_dir("failed");
        let log = Log::stderr(0);
        let cache = OpenFileCache::new(10, 60);
        let name = format!("{}/sub/a.log", d);
        std::fs::create_dir(format!("{}/sub", d)).unwrap();

        let mut of = log_of(2);
        drop(open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).unwrap());
        assert_eq!(cache.len(), 1);

        std::fs::rename(format!("{}/sub", d), format!("{}/moved", d)).unwrap();

        // the file closed by min_uses cannot be reopened: the entry goes
        let mut of = log_of(2);
        assert!(open_cached_file(Some(&cache), name.as_bytes(), &mut of, &log).is_err());
        assert_eq!(of.err, libc::ENOENT);
        assert_eq!(of.failed, "open()");
        assert_eq!(cache.len(), 0);

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cached_directory_is_ok() {
        let d = test_dir("dir");
        let log = Log::stderr(0);
        let cache = OpenFileCache::new(10, 60);

        for _ in 0..2 {
            let mut of = OpenFileInfo { valid: 60, min_uses: 1, test_dir: true, test_only: true, ..Default::default() };
            let r = open_cached_file(Some(&cache), d.as_bytes(), &mut of, &log);
            assert!(matches!(r, Ok(None)));
            assert!(of.is_dir);
        }

        // without a cache, test_only only stats the name
        let file = format!("{}/f", d);
        std::fs::write(&file, b"x").unwrap();
        let mut of = OpenFileInfo { test_only: true, ..Default::default() };
        assert!(matches!(open_cached_file(None, file.as_bytes(), &mut of, &log), Ok(None)));
        assert!(of.is_file && of.fd == NGX_INVALID_FILE && of.size == 1);

        let _ = std::fs::remove_dir_all(&d);
    }
}
