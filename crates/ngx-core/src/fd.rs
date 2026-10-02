//! The descriptors of the process, owned by their numbers.
//!
//! nginx passes descriptors around as numbers (c->fd, file->fd, the
//! channels, ...) and so does the port. The safe system call wrappers
//! (nix, rustix, socket2) want a borrowed descriptor (AsFd), which only an
//! owner can lend: this table is that owner. Every descriptor the process
//! opens is registered here, by its number, as the kernel's table holds
//! it: register() takes an OwnedFd (made by rustix, nix or std) and
//! returns the number, get() lends the descriptor of a number (the handle
//! keeps it open while it lives), close() takes it out of the table and
//! closes it, reporting close() errors as nginx does.
//!
//! Descriptors are closed by close() only; a number closed behind the
//! table's back (a nix close() of a registered descriptor) leaves a stale
//! entry, which register() leaks when the kernel hands the number out
//! again rather than closing the new descriptor with it.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, MutexGuard};

static TABLE: Mutex<Vec<Option<Arc<OwnedFd>>>> = Mutex::new(Vec::new());

fn table() -> MutexGuard<'static, Vec<Option<Arc<OwnedFd>>>> {
    TABLE.lock().unwrap_or_else(|e| e.into_inner())
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

/// A descriptor of the table, kept open as long as a handle lives.
#[derive(Debug)]
pub struct Fd(Inner);

#[derive(Debug)]
enum Inner {
    Owned(Arc<OwnedFd>),
    /// the standard descriptors, which std owns
    Stdin(std::io::Stdin),
    Stdout(std::io::Stdout),
    Stderr(std::io::Stderr),
}

impl Clone for Fd {
    fn clone(&self) -> Fd {
        Fd(match &self.0 {
            Inner::Owned(o) => Inner::Owned(o.clone()),
            Inner::Stdin(_) => Inner::Stdin(std::io::stdin()),
            Inner::Stdout(_) => Inner::Stdout(std::io::stdout()),
            Inner::Stderr(_) => Inner::Stderr(std::io::stderr()),
        })
    }
}

impl AsFd for Fd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.0 {
            Inner::Owned(o) => o.as_fd(),
            Inner::Stdin(s) => s.as_fd(),
            Inner::Stdout(s) => s.as_fd(),
            Inner::Stderr(s) => s.as_fd(),
        }
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

/// Takes the ownership of a descriptor; its number is returned.
pub fn register(fd: OwnedFd) -> RawFd {
    let n = fd.as_raw_fd();
    let i = n as usize;
    let mut t = table();

    if t.len() <= i {
        t.resize(i + 1, None);
    }

    if let Some(stale) = t[i].replace(Arc::new(fd)) {
        // the number was closed behind the table's back and handed out
        // again: dropping the stale owner would close the new descriptor
        std::mem::forget(stale);
    }

    n
}

/// The descriptor of the number `fd`: the table's, or std's for the
/// standard descriptors 0, 1 and 2 when not registered; EBADF for a
/// number the table does not have, as for a closed descriptor.
pub fn get(fd: RawFd) -> io::Result<Fd> {
    if fd < 0 {
        return Err(ebadf());
    }

    if let Some(owner) = table().get(fd as usize).and_then(|e| e.clone()) {
        return Ok(Fd(Inner::Owned(owner)));
    }

    match fd {
        0 => Ok(Fd(Inner::Stdin(std::io::stdin()))),
        1 => Ok(Fd(Inner::Stdout(std::io::stdout()))),
        2 => Ok(Fd(Inner::Stderr(std::io::stderr()))),
        _ => Err(ebadf()),
    }
}

/// An owned duplicate of the open descriptor `fd` of the process (one it
/// does not own, e.g. the reactor's epoll instance).
pub fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    let pidfd = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())?;

    match rustix::process::pidfd_getfd(&pidfd, fd, rustix::process::PidfdGetfdFlags::empty()) {
        Ok(d) => Ok(d),
        Err(e) if e == rustix::io::Errno::BADF => Err(ebadf()),
        Err(e) => Err(e.into()),
    }
}

/// Whether the table has the descriptor `fd`.
pub fn contains(fd: RawFd) -> bool {
    fd >= 0 && table().get(fd as usize).is_some_and(|e| e.is_some())
}

/// close(): the descriptor is taken out of the table and closed, or, if a
/// handle of it still lives, closed when the last one is dropped.
pub fn close(fd: RawFd) -> io::Result<()> {
    if fd < 0 {
        return Err(ebadf());
    }

    let owner = table().get_mut(fd as usize).and_then(|e| e.take()).ok_or_else(ebadf)?;

    match Arc::try_unwrap(owner) {
        // nix's close() reports the error OwnedFd's drop ignores
        Ok(owned) => nix::unistd::close(owned.into_raw_fd()).map_err(io::Error::from),
        Err(_) => Ok(()),
    }
}

/// Takes the descriptor `fd` out of the table, to make a File or a socket
/// of it; EBUSY while a handle of it lives (it is left in the table then).
pub fn take(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(ebadf());
    }

    let mut t = table();
    let entry = t.get_mut(fd as usize).ok_or_else(ebadf)?;
    let owner = entry.take().ok_or_else(ebadf)?;

    match Arc::try_unwrap(owner) {
        Ok(owned) => Ok(owned),
        Err(owner) => {
            *entry = Some(owner);
            Err(io::Error::from_raw_os_error(libc::EBUSY))
        }
    }
}

/// A descriptor the process did not open itself but inherited across
/// exec() (the listening sockets of a binary upgrade): pidfd_getfd() makes
/// an owned duplicate of it (close-on-exec), the inherited number is
/// closed, and the duplicate registered; its number is returned.
pub fn adopt(fd: RawFd) -> io::Result<RawFd> {
    let dup = duplicate(fd)?;

    // the number is not in the table: nobody else owns it
    if !contains(fd) {
        let _ = nix::unistd::close(fd);
    }

    Ok(register(dup))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_get_close() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        let wn = register(w);

        assert!(contains(rn));
        let h = get(wn).unwrap();
        assert_eq!(nix::unistd::write(&h, b"x").unwrap(), 1);

        // closed when the last handle goes
        close(wn).unwrap();
        assert!(!contains(wn));
        assert_eq!(nix::unistd::write(&h, b"y").unwrap(), 1);
        drop(h);

        let mut buf = [0u8; 4];
        assert_eq!(nix::unistd::read(rn, &mut buf).unwrap(), 2);
        assert_eq!(nix::unistd::read(rn, &mut buf).unwrap(), 0, "the write end is closed");

        close(rn).unwrap();
        assert_eq!(close(1 << 20).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
        assert!(get(-1).is_err());
    }

    #[test]
    fn take_while_lent() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        drop(w);

        let h = get(rn).unwrap();
        assert_eq!(take(rn).err().and_then(|e| e.raw_os_error()), Some(libc::EBUSY));
        drop(h);

        let owned = take(rn).unwrap();
        assert!(!contains(rn));
        drop(owned);
    }

    #[test]
    fn standard_and_unregistered() {
        assert_eq!(get(2).unwrap().as_raw_fd(), 2);

        // a descriptor the table does not own is not lent
        let (_r, w) = nix::unistd::pipe().unwrap();
        let raw = w.into_raw_fd();
        assert_eq!(get(raw).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
        let _ = nix::unistd::close(raw);

        assert_eq!(get(1 << 20).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
    }

    #[test]
    fn adopt_inherited() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let raw = l.into_raw_fd();

        let n = adopt(raw).unwrap();
        assert!(contains(n));
        let s = std::net::TcpStream::connect(addr);
        assert!(s.is_ok(), "the adopted socket still listens");
        close(n).unwrap();
    }
}
