//! Buffer and chain structures, ported from ngx_buf.c/h.

use std::collections::VecDeque;
use std::rc::Rc;
use crate::conf::PathConf;
use crate::log::Log;
use crate::os;
use crate::ngx_log_error;

pub const NGX_MIN_READ_AHEAD: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub enum BufData {
    Memory(Vec<u8>),
    File(Rc<BufFile>),
    None,
}

#[derive(Clone, Debug)]
pub struct BufFile {
    pub fd: i32,
    pub name: Vec<u8>,
    pub directio: bool,
}

#[derive(Clone, Debug)]
pub struct Buf {
    pub pos: usize,
    pub last: usize,
    pub file_pos: i64,
    pub file_last: i64,
    pub tag: usize,
    pub num: i32,
    pub data: BufData,
    pub temporary: bool,
    pub memory: bool,
    pub mmap: bool,
    pub recycled: bool,
    pub in_file: bool,
    pub flush: bool,
    pub sync: bool,
    pub last_buf: bool,
    pub last_in_chain: bool,
    pub temp_file: bool,
}

impl Default for Buf {
    fn default() -> Self {
        Buf {
            pos: 0,
            last: 0,
            file_pos: 0,
            file_last: 0,
            tag: 0,
            num: 0,
            data: BufData::None,
            temporary: false,
            memory: false,
            mmap: false,
            recycled: false,
            in_file: false,
            flush: false,
            sync: false,
            last_buf: false,
            last_in_chain: false,
            temp_file: false,
        }
    }
}

impl Buf {
    pub fn temp(size: usize) -> Self {
        Buf {
            data: BufData::Memory(vec![0u8; size]),
            pos: 0,
            last: size,
            temporary: true,
            ..Default::default()
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let size = vec.len();
        Buf {
            data: BufData::Memory(vec),
            pos: 0,
            last: size,
            temporary: true,
            ..Default::default()
        }
    }

    pub fn from_static(data: &'static [u8]) -> Self {
        let size = data.len();
        Buf {
            data: BufData::Memory(data.to_vec()),
            pos: 0,
            last: size,
            memory: true,
            ..Default::default()
        }
    }

    pub fn file(file: Rc<BufFile>, pos: i64, last: i64) -> Self {
        Buf {
            data: BufData::File(file),
            file_pos: pos,
            file_last: last,
            in_file: true,
            ..Default::default()
        }
    }

    pub fn special() -> Self {
        Buf {
            sync: true,
            ..Default::default()
        }
    }

    pub fn in_memory(&self) -> bool {
        self.temporary || self.memory || self.mmap
    }

    pub fn in_memory_only(&self) -> bool {
        self.in_memory() && !self.in_file
    }

    pub fn special_buf(&self) -> bool {
        (self.flush || self.last_buf || self.sync) && !self.in_memory() && !self.in_file
    }

    pub fn sync_only(&self) -> bool {
        self.sync && !self.in_memory() && !self.in_file && !self.flush && !self.last_buf
    }

    pub fn buf_size(&self) -> i64 {
        if self.in_file {
            self.file_last - self.file_pos
        } else {
            (self.last - self.pos) as i64
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buf_size() == 0
    }
}

pub type Chain = VecDeque<Buf>;

pub fn chain_update_sent(chain: &mut Chain, mut sent: i64) {
    while !chain.is_empty() {
        let buf = &mut chain[0];

        if buf.special_buf() {
            chain.pop_front();
            continue;
        }

        if sent == 0 {
            break;
        }

        let size = buf.buf_size();

        if sent >= size {
            sent -= size;

            if buf.in_memory() {
                buf.pos = buf.last;
            }

            if buf.in_file {
                buf.file_pos = buf.file_last;
            }

            chain.pop_front();
            continue;
        }

        if buf.in_memory() {
            buf.pos += sent as usize;
        }

        if buf.in_file {
            buf.file_pos += sent;
        }

        break;
    }
}

pub fn chain_coalesce_file(chain: &mut Chain, limit: i64) -> i64 {
    if chain.is_empty() {
        return 0;
    }

    let mut total: i64 = 0;
    let first_fd = match &chain[0].data {
        BufData::File(f) => f.fd,
        _ => return 0,
    };

    let pagesize = os::pagesize() as i64;

    let mut idx = 0;
    loop {
        if idx >= chain.len() {
            break;
        }

        let buf = &chain[idx];

        if !buf.in_file {
            break;
        }

        let fd = match &buf.data {
            BufData::File(f) => f.fd,
            _ => break,
        };

        if fd != first_fd {
            break;
        }

        let mut size = buf.file_last - buf.file_pos;

        if size > limit - total {
            size = limit - total;

            let aligned = (buf.file_pos + size + pagesize - 1) & !(pagesize - 1);

            if aligned <= buf.file_last {
                size = aligned - buf.file_pos;
            }

            total += size;
            break;
        }

        total += size;

        if idx + 1 >= chain.len() {
            break;
        }

        let next_buf = &chain[idx + 1];
        if !next_buf.in_file {
            break;
        }

        let next_fd = match &next_buf.data {
            BufData::File(f) => f.fd,
            _ => break,
        };

        if next_fd != fd || buf.file_pos + size != next_buf.file_pos {
            break;
        }

        if total >= limit {
            break;
        }

        idx += 1;
    }

    total
}

pub fn chain_update_chains(busy: &mut Chain, mut out: Chain) {
    busy.append(&mut out);

    while !busy.is_empty() {
        if busy[0].tag != 0 {
            break;
        }

        if busy[0].buf_size() != 0 {
            break;
        }

        busy.pop_front();
    }
}

#[derive(Clone, Debug)]
pub struct TempFile {
    pub name: Vec<u8>,
    pub offset: i64,
    pub fd: i32,
    pub access: u32,
    pub clean: bool,
}

impl TempFile {
    pub fn new(name: Vec<u8>, fd: i32, access: u32, clean: bool) -> Self {
        TempFile {
            name,
            offset: 0,
            fd,
            access,
            clean,
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.clean && self.fd >= 0 {
            let _ = os::unlink(&self.name);
            os::close(self.fd);
        } else if self.fd >= 0 {
            os::close(self.fd);
        }
    }
}

pub fn create_temp_file(
    path: &PathConf,
    _persistent: bool,
    clean: bool,
    access: u32,
    log: &Log,
) -> Result<TempFile, i32> {
    use crate::connection;

    let stats = connection::stats();
    let num = stats.temp_number.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // ngx_create_temp_file uses a decimal 10-digit key; keep that so hashed
    // level paths line up (0000000001, 0000000002, ...). The old code left
    // NUL padding past 16 hex chars which leaked into the filename.
    let key_str = format!("{:010}", num);
    let filename = path.hashed_filename(key_str.as_bytes());

    // Match ngx_open_tempfile: `access ? access : 0600` — fall back to 0600
    // when the caller passed 0 so the owner can still read/write the temp
    // file (client_body_in_file_only tests read it back from Perl).
    let mode = if access == 0 { 0o600 } else { access };
    match os::open(&filename, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode) {
        Ok(fd) => Ok(TempFile::new(filename, fd, mode, clean)),
        Err(err) => {
            ngx_log_error!(crate::log::NGX_LOG_CRIT, log, Some(err), "open temp file failed");
            Err(err)
        }
    }
}

pub fn write_chain_to_temp_file(
    tf: &mut TempFile,
    chain: &Chain,
    _log: &Log,
) -> Result<i64, i32> {
    let mut written: i64 = 0;

    for buf in chain {
        if buf.in_memory() {
            let data = match &buf.data {
                BufData::Memory(v) => &v[buf.pos..buf.last],
                _ => continue,
            };

            if data.is_empty() {
                continue;
            }

            let n = unsafe {
                libc::pwrite(tf.fd, data.as_ptr() as *const libc::c_void, data.len(), tf.offset)
            };

            if n < 0 {
                return Err(crate::os::errno());
            }

            tf.offset += n as i64;
            written += n as i64;
        }
    }

    Ok(written)
}

pub fn ngx_write_chain_to_file(dst_fd: i32, chain: &Chain) -> Result<i64, i32> {
    let mut written: i64 = 0;

    for buf in chain {
        if buf.in_memory() {
            let data = match &buf.data {
                BufData::Memory(v) => &v[buf.pos..buf.last],
                _ => continue,
            };

            if data.is_empty() {
                continue;
            }

            let n = unsafe {
                libc::write(dst_fd, data.as_ptr() as *const libc::c_void, data.len())
            };

            if n < 0 {
                return Err(crate::os::errno());
            }

            written += n as i64;
        } else if buf.in_file {
            if let BufData::File(f) = &buf.data {
                let mut pos = buf.file_pos;
                let last = buf.file_last;

                while pos < last {
                    let size = (last - pos) as usize;
                    let n = unsafe {
                        libc::sendfile(dst_fd, f.fd, &mut pos, size)
                    };

                    if n <= 0 {
                        if n < 0 {
                            return Err(crate::os::errno());
                        }
                        break;
                    }

                    written += n as i64;
                }
            }
        }
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf_temp() {
        let buf = Buf::temp(1024);
        assert_eq!(buf.buf_size(), 1024);
        assert!(buf.temporary);
        assert!(buf.in_memory_only());
    }

    #[test]
    fn test_buf_from_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let buf = Buf::from_vec(data);
        assert_eq!(buf.buf_size(), 5);
        assert!(buf.temporary);
    }

    #[test]
    fn test_buf_special() {
        let buf = Buf::special();
        assert!(buf.sync);
        assert!(buf.special_buf());
    }

    #[test]
    fn test_chain_update_sent_memory() {
        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(vec![1, 2, 3, 4, 5]));
        chain.push_back(Buf::from_vec(vec![6, 7, 8, 9]));

        chain_update_sent(&mut chain, 3);
        assert_eq!(chain[0].pos, 3);
        assert_eq!(chain[0].buf_size(), 2);

        chain_update_sent(&mut chain, 2);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pos, 0);
        assert_eq!(chain[0].buf_size(), 4);
    }

    #[test]
    fn test_chain_update_sent_special_skip() {
        let mut chain = Chain::new();
        chain.push_back(Buf::special());
        chain.push_back(Buf::from_vec(vec![1, 2, 3]));

        chain_update_sent(&mut chain, 0);
        assert_eq!(chain.len(), 1);
        assert!(!chain[0].special_buf());
    }

    #[test]
    fn test_chain_coalesce_file() {
        let file = Rc::new(BufFile {
            fd: -1,
            name: b"test".to_vec(),
            directio: false,
        });

        let mut chain = Chain::new();
        chain.push_back(Buf::file(file.clone(), 0, 100));
        chain.push_back(Buf::file(file.clone(), 100, 200));
        chain.push_back(Buf::from_vec(vec![1, 2, 3]));

        let size = chain_coalesce_file(&mut chain, 500);
        assert_eq!(size, 200);
    }

    #[test]
    fn test_chain_update_chains() {
        let mut busy = Chain::new();
        busy.push_back(Buf::from_vec(vec![1, 2, 3]));

        let mut out = Chain::new();
        out.push_back(Buf::from_vec(vec![4, 5, 6]));

        chain_update_chains(&mut busy, out);
        assert_eq!(busy.len(), 2);
    }
}
