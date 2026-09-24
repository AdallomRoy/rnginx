//! Open file cache, ported from ngx_open_file_cache.c.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::log::{Log, NGX_LOG_DEBUG_CORE};
use crate::os;
use crate::string::B;
use crate::ngx_log_debug;

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

#[derive(Clone)]
struct CachedFile {
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

/// LRU cache of open files.
pub struct OpenFileCache {
    files: RefCell<BTreeMap<Vec<u8>, Rc<RefCell<CachedFile>>>>,
    lru_queue: RefCell<Vec<Vec<u8>>>,
    current: RefCell<usize>,
    max: usize,
    inactive: i64,
}

impl OpenFileCache {
    pub fn new(max: usize, inactive_secs: i64) -> Rc<Self> {
        Rc::new(OpenFileCache {
            files: RefCell::new(BTreeMap::new()),
            lru_queue: RefCell::new(Vec::new()),
            current: RefCell::new(0),
            max,
            inactive: inactive_secs,
        })
    }

    pub fn len(&self) -> usize {
        *self.current.borrow()
    }

    pub fn cleanup_expired(&self, log: &Log) {
        let now = current_time();
        let mut to_remove = Vec::new();

        let files = self.files.borrow();
        for (name, file_rc) in files.iter() {
            let file = file_rc.borrow();
            if file.count == 0 && now - file.accessed > self.inactive {
                to_remove.push(name.clone());
            }
        }
        drop(files);

        for name in to_remove {
            if let Some(file_rc) = self.files.borrow_mut().remove(&name) {
                let file = file_rc.borrow();
                if file.fd >= 0 {
                    os::close(file.fd);
                }
                *self.current.borrow_mut() -= 1;
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "expire cached open file: {}", B(&name));
            }
        }

        let mut queue = self.lru_queue.borrow_mut();
        queue.retain(|n| self.files.borrow().contains_key(n));
    }

    fn lookup(&self, name: &[u8]) -> Option<Rc<RefCell<CachedFile>>> {
        self.files.borrow().get(name).cloned()
    }

    fn insert(&self, file: CachedFile) -> Rc<RefCell<CachedFile>> {
        let rc = Rc::new(RefCell::new(file.clone()));
        self.files.borrow_mut().insert(file.name.clone(), rc.clone());
        *self.current.borrow_mut() += 1;
        self.lru_queue.borrow_mut().insert(0, file.name.clone());
        rc
    }

    fn update_lru(&self, name: &[u8]) {
        let mut queue = self.lru_queue.borrow_mut();
        if let Some(pos) = queue.iter().position(|n| n == name) {
            queue.remove(pos);
        }
        queue.insert(0, name.to_vec());
    }

    fn expire_if_full(&self, log: &Log) {
        if *self.current.borrow() >= self.max {
            self.expire_lru(log);
        }
    }

    fn expire_lru(&self, log: &Log) {
        let mut queue = self.lru_queue.borrow_mut();
        let mut files = self.files.borrow_mut();

        let mut expired = 0;
        while expired < 3 && !queue.is_empty() {
            let name = queue.pop().unwrap();
            if let Some(file_rc) = files.remove(&name) {
                let file = file_rc.borrow();
                if file.fd >= 0 {
                    os::close(file.fd);
                }
                *self.current.borrow_mut() -= 1;
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "expire cached open file: {}", B(&name));
                expired += 1;
            }
        }
    }
}

/// Guard that decrements cache file count on drop.
pub struct CachedFileHandle {
    cache: Rc<OpenFileCache>,
    name: Vec<u8>,
}

impl Drop for CachedFileHandle {
    fn drop(&mut self) {
        if let Some(file_rc) = self.cache.files.borrow().get(&self.name) {
            let mut file = file_rc.borrow_mut();
            if file.count > 0 {
                file.count -= 1;
            }
            if file.close && file.count == 0 && file.fd >= 0 {
                os::close(file.fd);
                file.fd = NGX_INVALID_FILE;
            }
        }
    }
}

/// Open a file with optional caching. Returns a guard on success; errors set of.err/of.failed.
pub fn open_cached_file(
    cache: Option<&Rc<OpenFileCache>>,
    name: &[u8],
    of: &mut OpenFileInfo,
    log: &Log,
) -> Result<Option<Rc<CachedFileHandle>>, ()> {
    of.fd = NGX_INVALID_FILE;
    of.err = 0;

    if cache.is_none() {
        return open_and_stat_file(name, of, log).map(|_| None);
    }

    let cache = cache.unwrap();
    let now = current_time();

    if let Some(file_rc) = cache.lookup(name) {
        let mut file = file_rc.borrow_mut();
        file.uses += 1;

        if file.fd == NGX_INVALID_FILE && file.err == 0 && !file.is_dir {
            drop(file);
            open_and_stat_file(name, of, log)?;
            let mut file = file_rc.borrow_mut();
            file.fd = of.fd;
            file.uniq = of.uniq;
            file.mtime = of.mtime;
            file.size = of.size;
            file.close = false;
            file.is_dir = of.is_dir;
            file.is_file = of.is_file;
            file.is_link = of.is_link;
            file.is_exec = of.is_exec;
            file.is_directio = of.is_directio;
        } else if file.err == 0 || file.fd >= 0 {
            if now - file.created < of.valid {
                if file.err == 0 {
                    of.fd = file.fd;
                    of.uniq = file.uniq;
                    of.mtime = file.mtime;
                    of.size = file.size;
                    of.is_dir = file.is_dir;
                    of.is_file = file.is_file;
                    of.is_link = file.is_link;
                    of.is_exec = file.is_exec;
                    of.is_directio = file.is_directio;

                    if !file.is_dir {
                        file.count += 1;
                    }
                } else {
                    of.err = file.err;
                    of.failed = "open()";
                }

                file.accessed = now;
                cache.update_lru(name);
                ngx_log_debug!(
                    NGX_LOG_DEBUG_CORE,
                    log,
                    "cached open file: {}, fd:{}, c:{}, e:{}, u:{}",
                    B(name),
                    file.fd,
                    file.count,
                    file.err,
                    file.uses
                );

                if file.err == 0 && !file.is_dir {
                    return Ok(Some(Rc::new(CachedFileHandle {
                        cache: cache.clone(),
                        name: name.to_vec(),
                    })));
                } else {
                    return Err(());
                }
            }
        }

        ngx_log_debug!(
            NGX_LOG_DEBUG_CORE,
            log,
            "retest open file: {}, fd:{}, c:{}, e:{}",
            B(name),
            file.fd,
            file.count,
            file.err
        );

        if file.is_dir {
            of.test_dir = true;
        }
        of.fd = file.fd;
        of.uniq = file.uniq;

        drop(file);
        open_and_stat_file(name, of, log)?;

        let mut file = file_rc.borrow_mut();
        update_cache_entry(&mut file, of, now);
    } else {
        open_and_stat_file(name, of, log)?;

        cache.expire_if_full(log);

        let file = CachedFile {
            name: name.to_vec(),
            created: now,
            accessed: now,
            fd: of.fd,
            uniq: of.uniq,
            mtime: of.mtime,
            size: of.size,
            err: of.err,
            uses: 1,
            disable_symlinks: of.disable_symlinks,
            disable_symlinks_from: of.disable_symlinks_from,
            count: if !of.is_dir { 1 } else { 0 },
            close: false,
            is_dir: of.is_dir,
            is_file: of.is_file,
            is_link: of.is_link,
            is_exec: of.is_exec,
            is_directio: of.is_directio,
        };

        let file_rc = cache.insert(file);
        ngx_log_debug!(
            NGX_LOG_DEBUG_CORE,
            log,
            "cached open file: {}, fd:{}, c:{}, e:{}, u:{}",
            B(name),
            of.fd,
            if !of.is_dir { 1 } else { 0 },
            of.err,
            1
        );

        if of.err == 0 && !of.is_dir {
            return Ok(Some(Rc::new(CachedFileHandle {
                cache: cache.clone(),
                name: name.to_vec(),
            })));
        } else {
            return Err(());
        }
    }

    Err(())
}

fn update_cache_entry(file: &mut CachedFile, of: &OpenFileInfo, now: i64) {
    file.fd = of.fd;
    file.err = of.err;
    file.disable_symlinks = of.disable_symlinks;
    file.disable_symlinks_from = of.disable_symlinks_from;
    file.accessed = now;

    if of.err == 0 {
        file.uniq = of.uniq;
        file.mtime = of.mtime;
        file.size = of.size;
        file.close = false;
        file.is_dir = of.is_dir;
        file.is_file = of.is_file;
        file.is_link = of.is_link;
        file.is_exec = of.is_exec;
        file.is_directio = of.is_directio;

        if !of.is_dir {
            file.count += 1;
        }
    }
}

fn open_and_stat_file(name: &[u8], of: &mut OpenFileInfo, log: &Log) -> Result<(), ()> {
    if of.fd != NGX_INVALID_FILE {
        if let Ok(st) = os::fstat(of.fd) {
            if stat_uniq(&st) == of.uniq {
                return fill_info_from_stat(&st, of);
            }
        }
    } else if of.test_dir {
        if let Ok(st) = os::stat(name) {
            if os::is_dir(&st) {
                return fill_info_from_stat(&st, of);
            }
        }
    }

    if of.test_only {
        match file_info_wrapper(name, of) {
            Ok(st) => return fill_info_from_stat(&st, of),
            Err((err, failed)) => {
                of.err = err;
                of.failed = failed;
                return Err(());
            }
        }
    }

    let fd = if of.log {
        open_file_wrapper(name, of, libc::O_APPEND, libc::O_CREAT | libc::O_WRONLY, 0o644, log)
    } else {
        open_file_wrapper(name, of, libc::O_RDONLY | libc::O_NONBLOCK, 0, 0, log)
    };

    if fd < 0 {
        of.fd = NGX_INVALID_FILE;
        return Err(());
    }

    match os::fstat(fd) {
        Ok(st) => {
            if os::is_dir(&st) {
                os::close(fd);
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
            os::close(fd);
            of.fd = NGX_INVALID_FILE;
            of.err = err;
            of.failed = "fstat()";
            Err(())
        }
    }
}

fn open_file_wrapper(
    name: &[u8],
    of: &mut OpenFileInfo,
    flags: i32,
    create_flags: i32,
    mode: u32,
    _log: &Log,
) -> i32 {
    let mut open_flags = flags;

    if of.disable_symlinks != 0 {
        open_flags |= libc::O_NOFOLLOW;
    }

    match os::open(name, open_flags | create_flags, mode) {
        Ok(fd) => fd,
        Err(err) => {
            of.err = err;
            of.failed = "open()";
            NGX_INVALID_FILE
        }
    }
}

fn file_info_wrapper(name: &[u8], of: &OpenFileInfo) -> Result<libc::stat, (i32, &'static str)> {
    if of.disable_symlinks == 0 {
        os::stat(name).map_err(|e| (e, "stat()"))
    } else {
        os::lstat(name).map_err(|e| (e, "lstat()"))
    }
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
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let cache = OpenFileCache::new(10, 60);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_open_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"hello").unwrap();

        let log = Log::default();
        let mut of = OpenFileInfo::default();
        let name = file_path.to_str().unwrap().as_bytes();

        let result = open_cached_file(None, name, &mut of, &log);
        assert!(result.is_ok());
        assert_eq!(of.err, 0);
        assert!(of.is_file);
        assert!(!of.is_dir);
        assert_eq!(of.size, 5);
        if of.fd >= 0 {
            os::close(of.fd);
        }
    }

    #[test]
    fn test_open_directory() {
        let dir = TempDir::new().unwrap();
        let log = Log::default();
        let mut of = OpenFileInfo::default();
        let name = dir.path().to_str().unwrap().as_bytes();

        let result = open_cached_file(None, name, &mut of, &log);
        assert!(result.is_ok());
        assert_eq!(of.err, 0);
        assert!(of.is_dir);
        assert!(!of.is_file);
        assert_eq!(of.fd, NGX_INVALID_FILE);
    }

    #[test]
    fn test_file_caching() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("cached.txt");
        fs::write(&file_path, b"data").unwrap();

        let cache = OpenFileCache::new(10, 60);
        let log = Log::default();
        let mut of = OpenFileInfo::default();
        of.valid = 60;
        of.min_uses = 1;
        let name = file_path.to_str().unwrap().as_bytes();

        let result1 = open_cached_file(Some(&cache), name, &mut of, &log);
        assert!(result1.is_ok());
        let fd1 = of.fd;

        let mut of2 = OpenFileInfo::default();
        of2.valid = 60;
        let result2 = open_cached_file(Some(&cache), name, &mut of2, &log);
        assert!(result2.is_ok());
        assert_eq!(of2.fd, fd1);

        if of.fd >= 0 {
            os::close(of.fd);
        }
    }
}
