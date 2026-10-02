//! OS helpers (Unix): glob, files, directories, users, processes.
//!
//! Errors are errno values, as nginx reports them. Descriptors are the
//! numbers of the process's table (fd.rs): what opens one registers it,
//! close() closes it.

use std::ffi::{CString, OsStr};
use std::io::IoSlice;
use std::os::unix::ffi::OsStrExt;

use nix::fcntl::{FcntlArg, FdFlag, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{Gid, Group, Pid, Uid, User};

use crate::fd;

pub fn cstr(s: &[u8]) -> CString {
    CString::new(s.iter().copied().filter(|&c| c != 0).collect::<Vec<u8>>()).unwrap()
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

// The errors of rustix and of the descriptor table are returned, not left
// in errno as libc does: they are set in errno too, so that the callers
// logging os::errno() after a failed call report the right one.

fn io_errno(e: std::io::Error) -> i32 {
    let err = e.raw_os_error().unwrap_or(libc::EIO);
    nix::errno::Errno::set_raw(err);
    err
}

fn rustix_errno(e: rustix::io::Errno) -> i32 {
    let err = e.raw_os_error();
    nix::errno::Errno::set_raw(err);
    err
}

/// The text of an errno value, strerror() as glibc words it
/// ("No such file or directory").
pub fn strerror(err: i32) -> String {
    let s = std::io::Error::from_raw_os_error(err).to_string();

    // std appends " (os error N)" to strerror_r()'s text
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// glob(3) with default flags; no match returns empty vec.
///
/// The pattern's '*', '?' and '[...]' (with '!' or '^', ranges and the
/// [:class:] names) are matched per path component as fnmatch() does with
/// FNM_PERIOD (a leading dot is matched by a dot only); a backslash quotes
/// the next character; unreadable directories are skipped; the paths are
/// sorted bytewise, as glob() does in the C locale.
pub fn glob(pattern: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    let absolute = pattern.first() == Some(&b'/');
    let comps: Vec<&[u8]> = pattern.split(|&c| c == b'/').filter(|c| !c.is_empty()).collect();

    let mut paths: Vec<Vec<u8>> = vec![if absolute { b"/".to_vec() } else { Vec::new() }];

    for (i, comp) in comps.iter().enumerate() {
        let last = i == comps.len() - 1;
        let mut next = Vec::new();

        for base in &paths {
            if !glob_magic(comp) {
                let mut p = base.clone();
                p.extend_from_slice(&glob_unquote(comp));
                if last {
                    if std::fs::symlink_metadata(path(&p)).is_ok() {
                        next.push(p);
                    }
                } else {
                    next.push(p);
                }
                continue;
            }

            let dir = if base.is_empty() { b".".to_vec() } else { base.clone() };
            let entries = match std::fs::read_dir(path(&dir)) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.as_bytes();

                if !fnmatch(comp, name) {
                    continue;
                }

                let mut p = base.clone();
                p.extend_from_slice(name);

                if !last {
                    // a directory to go on with
                    match std::fs::metadata(path(&p)) {
                        Ok(m) if m.is_dir() => {}
                        _ => continue,
                    }
                }

                next.push(p);
            }
        }

        if !last {
            for p in next.iter_mut() {
                p.push(b'/');
            }
        }

        paths = next;

        if paths.is_empty() {
            break;
        }
    }

    if comps.is_empty() {
        paths.retain(|p| !p.is_empty() && std::fs::symlink_metadata(path(p)).is_ok());
    }

    paths.sort();
    paths.dedup();

    Ok(paths)
}

/// The component has an unquoted '*', '?' or '['.
fn glob_magic(comp: &[u8]) -> bool {
    let mut i = 0;
    while i < comp.len() {
        match comp[i] {
            b'\\' => i += 1,
            b'*' | b'?' | b'[' => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn glob_unquote(comp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(comp.len());
    let mut i = 0;
    while i < comp.len() {
        if comp[i] == b'\\' && i + 1 < comp.len() {
            i += 1;
        }
        out.push(comp[i]);
        i += 1;
    }
    out
}

/// fnmatch(pattern, name, FNM_PERIOD) for a path component.
fn fnmatch(pat: &[u8], name: &[u8]) -> bool {
    if name.first() == Some(&b'.') && pat.first() != Some(&b'.') {
        return false;
    }
    fnmatch_at(pat, name)
}

fn fnmatch_at(pat: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // the position after the last '*' and the name position it matched up to
    let mut star: Option<(usize, usize)> = None;

    loop {
        if p < pat.len() {
            match pat[p] {
                b'*' => {
                    while p < pat.len() && pat[p] == b'*' {
                        p += 1;
                    }
                    star = Some((p, n));
                    continue;
                }
                b'?' if n < name.len() => {
                    p += 1;
                    n += 1;
                    continue;
                }
                b'[' if n < name.len() => {
                    if let Some((matched, len)) = bracket(&pat[p..], name[n]) {
                        if matched {
                            p += len;
                            n += 1;
                            continue;
                        }
                    } else if name[n] == b'[' {
                        // no closing bracket: a literal '['
                        p += 1;
                        n += 1;
                        continue;
                    }
                }
                b'\\' if p + 1 < pat.len() && n < name.len() && pat[p + 1] == name[n] => {
                    p += 2;
                    n += 1;
                    continue;
                }
                c if c != b'\\' && c != b'*' && c != b'?' && c != b'[' && n < name.len() && c == name[n] => {
                    p += 1;
                    n += 1;
                    continue;
                }
                _ => {}
            }
        } else if n == name.len() {
            return true;
        }

        // backtrack: the last '*' takes one more character
        match star {
            Some((sp, sn)) if sn < name.len() => {
                star = Some((sp, sn + 1));
                p = sp;
                n = sn + 1;
            }
            _ => return false,
        }
    }
}

/// A bracket expression at the start of `pat` against `c`: whether it
/// matches and its length; None if it has no closing ']'.
fn bracket(pat: &[u8], c: u8) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(pat.get(i), Some(b'!') | Some(b'^'));
    if negate {
        i += 1;
    }

    let mut matched = false;
    let mut first = true;

    loop {
        let ch = *pat.get(i)?;

        if ch == b']' && !first {
            i += 1;
            break;
        }
        first = false;

        if ch == b'[' && pat.get(i + 1) == Some(&b':') {
            if let Some(end) = pat[i + 2..].windows(2).position(|w| w == b":]") {
                let class = &pat[i + 2..i + 2 + end];
                matched |= match class {
                    b"alpha" => c.is_ascii_alphabetic(),
                    b"digit" => c.is_ascii_digit(),
                    b"alnum" => c.is_ascii_alphanumeric(),
                    b"upper" => c.is_ascii_uppercase(),
                    b"lower" => c.is_ascii_lowercase(),
                    b"space" => matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c),
                    b"blank" => c == b' ' || c == b'\t',
                    b"punct" => c.is_ascii_punctuation(),
                    b"xdigit" => c.is_ascii_hexdigit(),
                    b"print" => (0x20..0x7f).contains(&c),
                    b"graph" => c.is_ascii_graphic(),
                    b"cntrl" => c.is_ascii_control(),
                    _ => false,
                };
                i += 2 + end + 2;
                continue;
            }
        }

        let lo = if ch == b'\\' {
            i += 1;
            *pat.get(i)?
        } else {
            ch
        };
        i += 1;

        if pat.get(i) == Some(&b'-') && pat.get(i + 1).is_some_and(|&e| e != b']') {
            let mut hi = pat[i + 1];
            i += 2;
            if hi == b'\\' {
                hi = *pat.get(i)?;
                i += 1;
            }
            matched |= lo <= c && c <= hi;
        } else {
            matched |= lo == c;
        }
    }

    Some((matched != negate, i))
}

pub fn path(s: &[u8]) -> &std::path::Path {
    std::path::Path::new(OsStr::from_bytes(s))
}

/// Get lowercase hostname (ngx_init_cycle behaviour).
pub fn hostname() -> Vec<u8> {
    // gethostname() is the nodename of uname() on Linux
    crate::string::to_lower_vec(rustix::system::uname().nodename().to_bytes())
}

pub fn getpid() -> i32 {
    nix::unistd::getpid().as_raw()
}

pub fn getppid() -> i32 {
    nix::unistd::getppid().as_raw()
}

fn oflags(flags: i32) -> rustix::fs::OFlags {
    rustix::fs::OFlags::from_bits_retain(flags as u32)
}

/// open(), close-on-exec: the registered descriptor or errno.
pub fn open(name: &[u8], flags: i32, mode: u32) -> Result<i32, i32> {
    rustix::fs::open(path(name), oflags(flags | libc::O_CLOEXEC), rustix::fs::Mode::from_raw_mode(mode))
        .map(fd::register)
        .map_err(rustix_errno)
}

/// openat() relative to the open directory `dir`, close-on-exec: the
/// registered descriptor or errno.
pub fn openat(dir: i32, name: &[u8], flags: i32, mode: u32) -> Result<i32, i32> {
    let d = fd::get(dir).map_err(io_errno)?;
    rustix::fs::openat(&d, path(name), oflags(flags | libc::O_CLOEXEC), rustix::fs::Mode::from_raw_mode(mode))
        .map(fd::register)
        .map_err(rustix_errno)
}

/// close() of a registered descriptor (fd.rs), or of a number opened
/// otherwise.
pub fn close(fd: i32) {
    let _ = close_fd(fd);
}

/// close(), with its error.
pub fn close_fd(fd: i32) -> Result<(), i32> {
    match fd::close_registered(fd) {
        Some(r) => r.map_err(io_errno),
        None => nix::unistd::close(fd).map_err(|e| e as i32),
    }
}

/// dup(), close-on-exec: the registered duplicate or errno.
pub fn dup(fd: i32) -> Result<i32, i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    rustix::io::fcntl_dupfd_cloexec(&f, 0).map(fd::register).map_err(rustix_errno)
}

pub fn write_fd(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    nix::unistd::write(&f, buf).map_err(|e| e as i32)
}

pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    nix::unistd::read(fd, buf).map_err(|e| e as i32)
}

pub fn pread(fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    nix::sys::uio::pread(&f, buf, offset).map_err(|e| e as i32)
}

pub fn pwrite(fd: i32, buf: &[u8], offset: i64) -> Result<usize, i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    nix::sys::uio::pwrite(&f, buf, offset).map_err(|e| e as i32)
}

pub fn pwritev(fd: i32, bufs: &[&[u8]], offset: i64) -> Result<usize, i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    let iov: Vec<IoSlice<'_>> = bufs.iter().map(|b| IoSlice::new(b)).collect();
    nix::sys::uio::pwritev(&f, &iov, offset).map_err(|e| e as i32)
}

pub fn ftruncate(fd: i32, len: i64) -> Result<(), i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    nix::unistd::ftruncate(&f, len).map_err(|e| e as i32)
}

pub fn unlink(name: &[u8]) -> Result<(), i32> {
    nix::unistd::unlink(path(name)).map_err(|e| e as i32)
}

pub fn mkdir(name: &[u8], mode: u32) -> Result<(), i32> {
    nix::unistd::mkdir(path(name), Mode::from_bits_retain(mode)).map_err(|e| e as i32)
}

pub fn rmdir(name: &[u8]) -> Result<(), i32> {
    rustix::fs::unlinkat(rustix::fs::CWD, path(name), rustix::fs::AtFlags::REMOVEDIR).map_err(rustix_errno)
}

pub fn rename(from: &[u8], to: &[u8]) -> Result<(), i32> {
    rustix::fs::rename(path(from), path(to)).map_err(rustix_errno)
}

pub fn chmod(name: &[u8], mode: u32) -> Result<(), i32> {
    rustix::fs::chmod(path(name), rustix::fs::Mode::from_raw_mode(mode)).map_err(rustix_errno)
}

pub fn fchmod(fd: i32, mode: u32) -> Result<(), i32> {
    nix::sys::stat::fchmod(fd, Mode::from_bits_retain(mode)).map_err(|e| e as i32)
}

fn owner(uid: u32, gid: u32) -> (Option<Uid>, Option<Gid>) {
    // (uid_t) -1 and (gid_t) -1 leave the id as it is
    ((uid != u32::MAX).then(|| Uid::from_raw(uid)), (gid != u32::MAX).then(|| Gid::from_raw(gid)))
}

pub fn chown(name: &[u8], uid: u32, gid: u32) -> Result<(), i32> {
    let (u, g) = owner(uid, gid);
    nix::unistd::chown(path(name), u, g).map_err(|e| e as i32)
}

pub fn fchown(fd: i32, uid: u32, gid: u32) -> Result<(), i32> {
    let (u, g) = owner(uid, gid);
    nix::unistd::fchown(fd, u, g).map_err(|e| e as i32)
}

/// utimes(): the access and modification times of a file set to `sec`.
pub fn utimes(name: &[u8], sec: i64) -> Result<(), i32> {
    let t = nix::sys::time::TimeVal::new(sec, 0);
    nix::sys::stat::utimes(path(name), &t, &t).map_err(|e| e as i32)
}

/// futimes(): the access and modification times of an open file set to
/// `sec`.
pub fn futimes(fd: i32, sec: i64) -> Result<(), i32> {
    let t = nix::sys::time::TimeSpec::new(sec, 0);
    nix::sys::stat::futimens(fd, &t, &t).map_err(|e| e as i32)
}

pub fn stat(name: &[u8]) -> Result<libc::stat, i32> {
    nix::sys::stat::stat(path(name)).map_err(|e| e as i32)
}

pub fn fstat(fd: i32) -> Result<libc::stat, i32> {
    nix::sys::stat::fstat(fd).map_err(|e| e as i32)
}

pub fn lstat(name: &[u8]) -> Result<libc::stat, i32> {
    nix::sys::stat::lstat(path(name)).map_err(|e| e as i32)
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
    let name = std::str::from_utf8(name).ok()?;
    User::from_name(name).ok().flatten().map(|u| (u.uid.as_raw(), u.gid.as_raw()))
}

pub fn getgrnam(name: &[u8]) -> Option<u32> {
    let name = std::str::from_utf8(name).ok()?;
    Group::from_name(name).ok().flatten().map(|g| g.gid.as_raw())
}

pub fn geteuid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

pub fn set_nonblocking(fd: i32) -> Result<(), i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    rustix::io::ioctl_fionbio(&f, true).map_err(rustix_errno)
}

pub fn set_blocking(fd: i32) -> Result<(), i32> {
    let f = fd::get(fd).map_err(io_errno)?;
    rustix::io::ioctl_fionbio(&f, false).map_err(rustix_errno)
}

/// ngx_directio_on_n
pub const DIRECTIO_ON_N: &str = "fcntl(O_DIRECT)";

/// The file status flags with `set` added and `clear` taken off; -1 on
/// error, with errno set by the failed fcntl().
fn change_flags(fd: i32, set: OFlag, clear: OFlag) -> i32 {
    let flags = match nix::fcntl::fcntl(fd, FcntlArg::F_GETFL) {
        Ok(f) => OFlag::from_bits_retain(f),
        Err(_) => return -1,
    };

    match nix::fcntl::fcntl(fd, FcntlArg::F_SETFL((flags | set) & !clear)) {
        Ok(rc) => rc,
        Err(_) => -1,
    }
}

/// ngx_directio_on: O_DIRECT added to the file status flags, -1 on error
pub fn directio_on(fd: i32) -> i32 {
    change_flags(fd, OFlag::O_DIRECT, OFlag::empty())
}

/// ngx_directio_off_n
pub const DIRECTIO_OFF_N: &str = "fcntl(!O_DIRECT)";

/// ngx_directio_off: O_DIRECT taken off the file status flags, -1 on error
pub fn directio_off(fd: i32) -> i32 {
    change_flags(fd, OFlag::empty(), OFlag::O_DIRECT)
}

pub fn set_cloexec(fd: i32) -> Result<(), i32> {
    nix::fcntl::fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map(|_| ()).map_err(|e| e as i32)
}

pub fn kill(pid: i32, sig: i32) -> Result<(), i32> {
    let sig = if sig == 0 { None } else { Some(nix::sys::signal::Signal::try_from(sig).map_err(|e| e as i32)?) };
    nix::sys::signal::kill(Pid::from_raw(pid), sig).map_err(|e| e as i32)
}

pub fn pagesize() -> usize {
    rustix::param::page_size()
}

pub fn ncpu() -> usize {
    match nix::unistd::sysconf(nix::unistd::SysconfVar::_NPROCESSORS_ONLN) {
        Ok(Some(n)) if n >= 1 => n as usize,
        _ => 1,
    }
}

pub fn cacheline_size() -> usize {
    64
}

/// ngx_dir_t: opendir()/readdir()/closedir() as ngx_open_dir, ngx_read_dir
/// and ngx_close_dir use them.
pub struct Dir {
    dir: rustix::fs::Dir,
}

impl Dir {
    /// ngx_open_dir; Err(errno) on failure
    pub fn open(name: &[u8]) -> Result<Dir, i32> {
        use rustix::fs::OFlags;

        // the flags of opendir()
        let fd = rustix::fs::open(path(name), OFlags::RDONLY | OFlags::NONBLOCK | OFlags::DIRECTORY | OFlags::CLOEXEC, rustix::fs::Mode::empty())
            .map_err(rustix_errno)?;

        let dir = rustix::fs::Dir::new(fd).map_err(rustix_errno)?;

        Ok(Dir { dir })
    }

    /// ngx_read_dir: the next entry name, "." and ".." included; Err(errno)
    /// when readdir() returns NULL, the errno being 0 (NGX_ENOMOREFILES)
    /// at the end of the directory
    pub fn read(&mut self) -> Result<Vec<u8>, i32> {
        match self.dir.read() {
            Some(Ok(entry)) => Ok(entry.file_name().to_bytes().to_vec()),
            Some(Err(e)) => Err(rustix_errno(e)),
            None => Err(0),
        }
    }

    /// ngx_close_dir; Err(errno) on failure
    pub fn close(self) -> Result<(), i32> {
        drop(self.dir);
        Ok(())
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

    #[test]
    fn fnmatch_patterns() {
        assert!(fnmatch(b"*.conf", b"a.conf"));
        assert!(!fnmatch(b"*.conf", b".a.conf"), "a leading dot is matched by a dot only");
        assert!(fnmatch(b".*", b".a"));
        assert!(fnmatch(b"a?c", b"abc"));
        assert!(!fnmatch(b"a?c", b"ac"));
        assert!(fnmatch(b"[a-c]x", b"bx"));
        assert!(!fnmatch(b"[!a-c]x", b"bx"));
        assert!(fnmatch(b"[^a-c]x", b"dx"));
        assert!(fnmatch(b"[]]", b"]"));
        assert!(fnmatch(b"[[:digit:]]*", b"1abc"));
        assert!(fnmatch(b"\\*", b"*"));
        assert!(!fnmatch(b"\\*", b"a"));
        assert!(fnmatch(b"a*b*c", b"aXXbYYc"));
        assert!(!fnmatch(b"a*b*c", b"aXXbYY"));
        assert!(fnmatch(b"[ab", b"[ab"), "no closing bracket: literal");
        assert!(fnmatch(b"*", b"x"));
        assert!(!fnmatch(b"*", b"."));
    }

    #[test]
    fn glob_paths() {
        let d = std::env::temp_dir().join(format!("ngx-os-glob-{}", std::process::id()));
        std::fs::create_dir_all(d.join("a1/x")).unwrap();
        std::fs::create_dir_all(d.join("a2/x")).unwrap();
        std::fs::write(d.join("a1/x/one.conf"), b"").unwrap();
        std::fs::write(d.join("a2/x/two.conf"), b"").unwrap();
        std::fs::write(d.join("a2/x/.hidden.conf"), b"").unwrap();
        std::fs::write(d.join("b.conf"), b"").unwrap();
        let base = d.as_os_str().as_bytes().to_vec();
        let p = |s: &str| {
            let mut v = base.clone();
            v.extend_from_slice(s.as_bytes());
            v
        };

        assert_eq!(glob(&p("/a*/x/*.conf")).unwrap(), vec![p("/a1/x/one.conf"), p("/a2/x/two.conf")]);
        assert_eq!(glob(&p("/*.conf")).unwrap(), vec![p("/b.conf")]);
        assert_eq!(glob(&p("/a2/x/.*.conf")).unwrap(), vec![p("/a2/x/.hidden.conf")]);
        assert!(glob(&p("/nothing*")).unwrap().is_empty());
        assert_eq!(glob(&p("/b.con[f]")).unwrap(), vec![p("/b.conf")]);

        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failures_set_errno() {
        assert_eq!(rename(b"/nonexistent/a", b"/nonexistent/b"), Err(libc::ENOENT));
        assert_eq!(errno(), libc::ENOENT);
        assert_eq!(set_nonblocking(1 << 20), Err(libc::EBADF));
        assert_eq!(errno(), libc::EBADF);
    }

    #[test]
    fn errno_text() {
        assert_eq!(strerror(libc::ENOENT), "No such file or directory");
        assert_eq!(strerror(libc::EACCES), "Permission denied");
    }

    #[test]
    fn files() {
        let d = std::env::temp_dir().join(format!("ngx-os-files-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mut name = d.as_os_str().as_bytes().to_vec();
        name.extend_from_slice(b"/f");

        let fd = open(&name, libc::O_RDWR | libc::O_CREAT, 0o644).unwrap();
        assert!(crate::fd::contains(fd));
        assert_eq!(pwritev(fd, &[b"ab", b"cd"], 0).unwrap(), 4);
        assert_eq!(pwrite(fd, b"X", 1).unwrap(), 1);
        let mut buf = [0u8; 8];
        assert_eq!(pread(fd, &mut buf, 0).unwrap(), 4);
        assert_eq!(&buf[..4], b"aXcd");
        assert_eq!(fstat(fd).unwrap().st_size, 4);
        ftruncate(fd, 2).unwrap();
        futimes(fd, 1000).unwrap();
        assert_eq!(fstat(fd).unwrap().st_mtime, 1000);
        assert_eq!(directio_off(fd) == -1, false);
        let d2 = dup(fd).unwrap();
        assert_ne!(d2, fd);
        close_fd(d2).unwrap();
        close_fd(fd).unwrap();
        assert!(!crate::fd::contains(fd));

        let mut to = name.clone();
        to.push(b'2');
        rename(&name, &to).unwrap();
        utimes(&to, 2000).unwrap();
        assert_eq!(stat(&to).unwrap().st_mtime, 2000);
        chmod(&to, 0o600).unwrap();
        assert_eq!(stat(&to).unwrap().st_mode & 0o777, 0o600);
        unlink(&to).unwrap();
        assert_eq!(stat(&to).err(), Some(libc::ENOENT));

        let mut sub = d.as_os_str().as_bytes().to_vec();
        sub.extend_from_slice(b"/sub");
        mkdir(&sub, 0o755).unwrap();
        rmdir(&sub).unwrap();

        std::fs::remove_dir_all(&d).unwrap();
    }
}
