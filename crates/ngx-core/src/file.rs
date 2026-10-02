//! Temporary files, ported from ngx_file.c and ngx_files.c:
//! ngx_next_temp_number, ngx_create_temp_file, ngx_create_path,
//! ngx_write_chain_to_temp_file and ngx_write_chain_to_file.

use std::rc::Rc;

use crate::buf::{BufData, Chain};
use crate::conf::PathConf;
use crate::log::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, os};

/// ngx_random_number: the stride of ngx_next_temp_number(1)
const NGX_RANDOM_NUMBER: u64 = 123456;

/// NGX_MAX_PATH_LEVEL
const NGX_MAX_PATH_LEVEL: usize = 3;

/// NGX_IOVS_PREALLOCATE (IOV_MAX): the iovecs of one pwritev()
const NGX_IOVS_PREALLOCATE: usize = 64;

/// ngx_next_temp_number: the shared counter (ngx_temp_number) advanced by
/// one, or by ngx_random_number after a collision; the new value.
pub fn next_temp_number(collision: bool) -> u32 {
    let add = if collision { NGX_RANDOM_NUMBER } else { 1 };

    let n = crate::connection::stats().temp_number.fetch_add(add, std::sync::atomic::Ordering::Relaxed);

    n.wrapping_add(add) as u32
}

/// ngx_temp_file_t with its ngx_file_t: `name` preset (not empty) before
/// the file is created makes it "name.NNNNNNNNNN" next to that name,
/// otherwise the file is "NNNNNNNNNN" in `path` with its levels.
pub struct TempFile {
    pub name: Vec<u8>,
    /// NGX_INVALID_FILE (-1) until created
    pub fd: i32,
    pub offset: i64,
    pub path: Rc<PathConf>,
    pub persistent: bool,
    pub clean: bool,
    pub access: u32,
    /// tf->log_level and tf->warn: logged once the file is created
    pub log_level: u32,
    pub warn: &'static str,
    pub log: Log,
}

impl TempFile {
    pub fn new(path: Rc<PathConf>, log: &Log) -> TempFile {
        TempFile { name: Vec::new(), fd: -1, offset: 0, path, persistent: false, clean: false, access: 0, log_level: 0, warn: "", log: log.clone() }
    }

    /// ngx_create_temp_file: the file created with O_EXCL (unlinked at once
    /// unless persistent), the level directories created if missing.
    pub fn create(&mut self) -> Result<(), ()> {
        let prefix = !self.name.is_empty();

        let base = if prefix { std::mem::take(&mut self.name) } else { self.path.name.clone() };

        let mut n = next_temp_number(false);

        loop {
            let key = format!("{:010}", n);

            let name = if prefix {
                let mut name = base.clone();
                name.push(b'.');
                name.extend_from_slice(key.as_bytes());
                name
            } else {
                // ngx_create_hashed_filename
                self.path.hashed_filename(key.as_bytes())
            };

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log, "hashed path: {}", B(&name));

            let fd = open_tempfile(&name, self.persistent, self.access);

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log, "temp fd:{}", fd.unwrap_or(-1));

            match fd {
                Ok(fd) => {
                    self.name = name;
                    self.fd = fd;
                    return Ok(());
                }

                Err(err) if err == libc::EEXIST => {
                    n = next_temp_number(true);
                }

                Err(err) => {
                    if self.path.level[0] == 0 || err != libc::ENOENT {
                        ngx_log_error!(NGX_LOG_CRIT, self.log, Some(err), "open() \"{}\" failed", B(&name));
                        self.name = name;
                        return Err(());
                    }

                    create_path(&name, &self.path, &self.log)?;
                }
            }
        }
    }

    /// ngx_write_chain_to_temp_file: the file is created on the first write
    /// (and tf->warn logged at tf->log_level), then the memory buffers of
    /// the chain are written at tf->offset. Returns the bytes written; the
    /// caller advances the offset.
    pub fn write_chain(&mut self, chain: &Chain) -> Result<i64, ()> {
        if self.fd == -1 {
            self.create()?;

            if self.log_level != 0 {
                ngx_log_error!(self.log_level, self.log, None, "{} {}", self.warn, B(&self.name));
            }
        }

        write_chain_to_file(self.fd, &self.name, chain, self.offset, &self.log)
    }
}

impl TempFile {
    /// ngx_pool_run_cleanup_file(): the file closed (and deleted if
    /// clean) now, its name kept.
    pub fn close(&mut self) {
        self.cleanup();
    }

    /// ngx_pool_cleanup_file, or ngx_pool_delete_file for a clean file
    fn cleanup(&mut self) {
        if self.fd == -1 {
            return;
        }

        if self.clean {
            if let Err(err) = os::unlink(&self.name) {
                if err != libc::ENOENT {
                    ngx_log_error!(NGX_LOG_CRIT, self.log, Some(err), "unlink() \"{}\" failed", B(&self.name));
                }
            }
        }

        if let Err(err) = os::close_fd(self.fd) {
            ngx_log_error!(NGX_LOG_ALERT, self.log, Some(err), "close() \"{}\" failed", B(&self.name));
        }

        self.fd = -1;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// ngx_open_tempfile
fn open_tempfile(name: &[u8], persistent: bool, access: u32) -> Result<i32, i32> {
    let fd = os::open(name, libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, if access != 0 { access } else { 0o600 })?;

    if !persistent {
        let _ = os::unlink(name);
    }

    Ok(fd)
}

/// ngx_create_path: the level directories of a temporary file name.
pub fn create_path(name: &[u8], path: &PathConf, log: &Log) -> Result<(), ()> {
    let mut pos = path.name.len();

    for i in 0..NGX_MAX_PATH_LEVEL {
        if path.level[i] == 0 {
            break;
        }

        pos += path.level[i] + 1;

        let dir = &name[..pos.min(name.len())];

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "temp file: \"{}\"", B(dir));

        if let Err(err) = os::mkdir(dir, 0o700) {
            if err != libc::EEXIST {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "mkdir() \"{}\" failed", B(dir));
                return Err(());
            }
        }
    }

    Ok(())
}

/// The data of a memory buffer (not a special one).
fn buf_data(b: &crate::buf::Buf) -> Option<&[u8]> {
    match &b.data {
        BufData::Memory(v) if b.in_memory() => Some(&v[b.pos.min(v.len())..b.last.min(v.len())]),
        _ => None,
    }
}

/// ngx_write_chain_to_file: the memory buffers of the chain written at
/// `offset`, with pwrite() for one buffer or pwritev() for more.
pub fn write_chain_to_file(fd: i32, name: &[u8], chain: &Chain, offset: i64, log: &Log) -> Result<i64, ()> {
    let bufs: Vec<&[u8]> = chain.iter().filter_map(buf_data).collect();

    if bufs.len() == 1 {
        return write_file(fd, name, bufs[0], offset, log);
    }

    let mut total: i64 = 0;
    let mut offset = offset;

    for part in bufs.chunks(NGX_IOVS_PREALLOCATE) {
        if part.len() == 1 {
            let n = write_file(fd, name, part[0], offset, log)?;
            return Ok(total + n);
        }

        let n = writev_file(fd, name, part, offset, log)?;

        offset += n;
        total += n;
    }

    Ok(total)
}

/// ngx_write_file: pwrite() until all is written.
pub fn write_file(fd: i32, name: &[u8], data: &[u8], offset: i64, log: &Log) -> Result<i64, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "write: {}, {:p}, {}, {}", fd, data.as_ptr(), data.len(), offset);

    let mut written = 0usize;

    while written < data.len() {
        let n = match os::pwrite(fd, &data[written..], offset + written as i64) {
            Ok(n) => n,

            Err(err) if err == libc::EINTR => {
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "pwrite() was interrupted");
                continue;
            }

            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pwrite() \"{}\" failed", B(name));
                return Err(());
            }
        };

        written += n;
    }

    Ok(written as i64)
}

/// ngx_writev_file with pwritev()
fn writev_file(fd: i32, name: &[u8], bufs: &[&[u8]], offset: i64, log: &Log) -> Result<i64, ()> {
    let size: usize = bufs.iter().map(|b| b.len()).sum();

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "writev: {}, {}, {}", fd, size, offset);

    loop {
        let n = match os::pwritev(fd, bufs, offset) {
            Ok(n) => n,

            Err(err) if err == libc::EINTR => {
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "pwritev() was interrupted");
                continue;
            }

            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pwritev() \"{}\" failed", B(name));
                return Err(());
            }
        };

        if n != size {
            ngx_log_error!(NGX_LOG_CRIT, log, None, "pwritev() \"{}\" has written only {} of {}", B(name), n, size);
            return Err(());
        }

        return Ok(n as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::Buf;

    fn path(dir: &std::path::Path, levels: [usize; 3]) -> Rc<PathConf> {
        Rc::new(PathConf::new(dir.to_str().unwrap().as_bytes().to_vec(), levels))
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ngx-file-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn temp_number_advances() {
        let a = next_temp_number(false);
        let b = next_temp_number(false);
        assert_eq!(b, a.wrapping_add(1));
    }

    #[test]
    fn create_with_levels_and_write() {
        let d = tmpdir("levels");
        let log = Log::stderr(NGX_LOG_ERR);
        let mut tf = TempFile::new(path(&d, [1, 2, 0]), &log);
        tf.persistent = true;

        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(b"hello ".to_vec()));
        chain.push_back(Buf::from_vec(b"world".to_vec()));

        let n = tf.write_chain(&chain).unwrap();
        assert_eq!(n, 11);
        assert!(tf.fd >= 0);

        let data = std::fs::read(std::str::from_utf8(&tf.name).unwrap()).unwrap();
        assert_eq!(data, b"hello world");

        // "dir/X/YY/NNNNNNNNXYY"
        let rel = &tf.name[d.to_str().unwrap().len()..];
        assert_eq!(rel.len(), 1 + 1 + 1 + 2 + 1 + 10);

        drop(tf);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn non_persistent_is_unlinked_at_once() {
        let d = tmpdir("unlinked");
        let log = Log::stderr(NGX_LOG_ERR);
        let mut tf = TempFile::new(path(&d, [0, 0, 0]), &log);
        tf.create().unwrap();
        assert!(!std::path::Path::new(std::str::from_utf8(&tf.name).unwrap()).exists());
        drop(tf);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn prefixed_name() {
        let d = tmpdir("prefix");
        let log = Log::stderr(NGX_LOG_ERR);
        let mut tf = TempFile::new(path(&d, [0, 0, 0]), &log);
        let mut prefix = d.to_str().unwrap().as_bytes().to_vec();
        prefix.extend_from_slice(b"/cachefile");
        tf.name = prefix.clone();
        tf.persistent = true;
        tf.clean = true;
        tf.create().unwrap();
        assert!(tf.name.starts_with(&prefix));
        assert_eq!(tf.name[prefix.len()], b'.');
        assert_eq!(tf.name.len(), prefix.len() + 11);
        let name = tf.name.clone();
        drop(tf);
        assert!(!std::path::Path::new(std::str::from_utf8(&name).unwrap()).exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
