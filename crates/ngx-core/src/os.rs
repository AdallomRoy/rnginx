//! OS helpers (Unix): glob, fork, signals, file operations.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;

pub fn cstr(s: &[u8]) -> CString {
    CString::new(s.iter().copied().filter(|&c| c != 0).collect::<Vec<u8>>()).unwrap()
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// glob(3) with default flags; no match returns empty vec.
pub fn glob(pattern: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    let c = cstr(pattern);
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    let n = unsafe { libc::glob(c.as_ptr(), 0, None, &mut g) };
    if n != 0 {
        unsafe { libc::globfree(&mut g) };
        if n == libc::GLOB_NOMATCH {
            return Ok(Vec::new());
        }
        return Err(errno());
    }
    let mut out = Vec::new();
    for i in 0..g.gl_pathc as isize {
        let p = unsafe { *g.gl_pathv.offset(i) };
        if p.is_null() {
            continue;
        }
        let s = unsafe { CStr::from_ptr(p) };
        out.push(s.to_bytes().to_vec());
    }
    unsafe { libc::globfree(&mut g) };
    Ok(out)
}

pub fn path(s: &[u8]) -> &std::path::Path {
    std::path::Path::new(std::ffi::OsStr::from_bytes(s))
}

/// Get lowercase hostname (ngx_init_cycle behaviour).
pub fn hostname() -> Vec<u8> {
    let mut buf = [0u8; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == -1 {
            return b"localhost".to_vec();
        }
    }
    buf[255] = 0;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
    crate::string::to_lower_vec(&buf[..len])
}

pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

pub fn getppid() -> i32 {
    unsafe { libc::getppid() }
}

/// open() wrapper returning raw fd or errno.
pub fn open(name: &[u8], flags: i32, mode: u32) -> Result<i32, i32> {
    let c = cstr(name);
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

pub fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

pub fn write_fd(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(errno())
    } else {
        Ok(n as usize)
    }
}

pub fn unlink(name: &[u8]) -> Result<(), i32> {
    let c = cstr(name);
    if unsafe { libc::unlink(c.as_ptr()) } == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn mkdir(name: &[u8], mode: u32) -> Result<(), i32> {
    let c = cstr(name);
    if unsafe { libc::mkdir(c.as_ptr(), mode) } == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn chown(name: &[u8], uid: u32, gid: u32) -> Result<(), i32> {
    let c = cstr(name);
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn stat(name: &[u8]) -> Result<libc::stat, i32> {
    let c = cstr(name);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } == -1 {
        Err(errno())
    } else {
        Ok(st)
    }
}

pub fn fstat(fd: i32) -> Result<libc::stat, i32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == -1 {
        Err(errno())
    } else {
        Ok(st)
    }
}

pub fn lstat(name: &[u8]) -> Result<libc::stat, i32> {
    let c = cstr(name);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } == -1 {
        Err(errno())
    } else {
        Ok(st)
    }
}

pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub fn is_file(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

pub fn is_link(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

pub fn is_exec(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IXUSR != 0
}

/// ngx_create_full_path: create all directories with `access` mode.
pub fn create_full_path(dir: &[u8], access: u32) -> Result<(), i32> {
    let mut i = 1;
    while i < dir.len() {
        if dir[i] == b'/' {
            let part = &dir[..i];
            if let Err(e) = mkdir(part, access) {
                if e != libc::EEXIST {
                    return Err(e);
                }
            }
        }
        i += 1;
    }
    Ok(())
}

/// Lookup user by name: returns (uid, primary gid).
pub fn getpwnam(name: &[u8]) -> Option<(u32, u32)> {
    let c = cstr(name);
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some(((*pw).pw_uid, (*pw).pw_gid))
        }
    }
}

pub fn getgrnam(name: &[u8]) -> Option<u32> {
    let c = cstr(name);
    unsafe {
        let gr = libc::getgrnam(c.as_ptr());
        if gr.is_null() {
            None
        } else {
            Some((*gr).gr_gid)
        }
    }
}

pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn set_nonblocking(fd: i32) -> Result<(), i32> {
    unsafe {
        let mut nb: libc::c_int = 1;
        if libc::ioctl(fd, libc::FIONBIO, &mut nb) == -1 {
            return Err(errno());
        }
    }
    Ok(())
}

pub fn set_blocking(fd: i32) -> Result<(), i32> {
    unsafe {
        let mut nb: libc::c_int = 0;
        if libc::ioctl(fd, libc::FIONBIO, &mut nb) == -1 {
            return Err(errno());
        }
    }
    Ok(())
}

/// ngx_directio_on_n
pub const DIRECTIO_ON_N: &str = "fcntl(O_DIRECT)";

/// ngx_directio_on: O_DIRECT added to the file status flags, -1 on error
pub fn directio_on(fd: i32) -> i32 {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

    if flags == -1 {
        return -1;
    }

    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_DIRECT) }
}

/// ngx_directio_off_n
pub const DIRECTIO_OFF_N: &str = "fcntl(!O_DIRECT)";

/// ngx_directio_off: O_DIRECT taken off the file status flags, -1 on error
pub fn directio_off(fd: i32) -> i32 {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

    if flags == -1 {
        return -1;
    }

    unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_DIRECT) }
}

pub fn set_cloexec(fd: i32) -> Result<(), i32> {
    unsafe {
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == -1 {
            return Err(errno());
        }
    }
    Ok(())
}

pub fn kill(pid: i32, sig: i32) -> Result<(), i32> {
    if unsafe { libc::kill(pid, sig) } == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn pagesize() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

pub fn ncpu() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n < 1 {
        1
    } else {
        n as usize
    }
}

pub fn cacheline_size() -> usize {
    64
}

/// ngx_dir_t: opendir()/readdir()/closedir() as ngx_open_dir, ngx_read_dir
/// and ngx_close_dir use them.
pub struct Dir {
    dir: *mut libc::DIR,
}

impl Dir {
    /// ngx_open_dir; Err(errno) on failure
    pub fn open(name: &[u8]) -> Result<Dir, i32> {
        let c = cstr(name);

        // SAFETY: c is a NUL-terminated string that outlives the call
        let dir = unsafe { libc::opendir(c.as_ptr()) };

        if dir.is_null() {
            return Err(errno());
        }

        Ok(Dir { dir })
    }

    /// ngx_read_dir: the next entry name, "." and ".." included; Err(errno)
    /// when readdir() returns NULL, the errno being 0 (NGX_ENOMOREFILES)
    /// at the end of the directory
    pub fn read(&mut self) -> Result<Vec<u8>, i32> {
        // SAFETY: errno is thread-local; self.dir is an open DIR stream
        // (it is set to NULL only by close(), which consumes self), and the
        // dirent returned stays valid until the next readdir() on it
        unsafe {
            *libc::__errno_location() = 0;

            let de = libc::readdir(self.dir);

            if de.is_null() {
                return Err(errno());
            }

            Ok(CStr::from_ptr((*de).d_name.as_ptr()).to_bytes().to_vec())
        }
    }

    /// ngx_close_dir; Err(errno) on failure
    pub fn close(mut self) -> Result<(), i32> {
        let dir = std::mem::replace(&mut self.dir, std::ptr::null_mut());

        // SAFETY: dir is the open stream, closed exactly once
        if unsafe { libc::closedir(dir) } == -1 {
            return Err(errno());
        }

        Ok(())
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        if !self.dir.is_null() {
            // SAFETY: the stream was not closed (close() nulls the pointer)
            unsafe { libc::closedir(self.dir) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_entries() {
        let d = std::env::temp_dir().join(format!("ngx-os-dir-{}", std::process::id()));
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("file"), b"x").unwrap();
        let name = d.as_os_str().as_bytes().to_vec();

        let mut dir = Dir::open(&name).unwrap();
        let mut names = Vec::new();
        loop {
            match dir.read() {
                Ok(n) => names.push(n),
                Err(e) => {
                    assert_eq!(e, 0, "the end of the directory is errno 0");
                    break;
                }
            }
        }
        dir.close().unwrap();
        names.sort();
        assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"file".to_vec(), b"sub".to_vec()]);

        let mut file = name.clone();
        file.extend_from_slice(b"/file");
        assert_eq!(Dir::open(&file).err(), Some(libc::ENOTDIR));
        file.extend_from_slice(b"/x");
        assert_eq!(Dir::open(&file).err(), Some(libc::ENOTDIR));
        let mut missing = name.clone();
        missing.extend_from_slice(b"/missing");
        assert_eq!(Dir::open(&missing).err(), Some(libc::ENOENT));

        std::fs::remove_dir_all(&d).unwrap();
    }
}
