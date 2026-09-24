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
