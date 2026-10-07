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
//! The processes run a single thread (fork() refuses to fork any other),
//! so the table is the thread's: a lookup is an index into a vector, and a
//! handle a reference count, with no lock or atomic operation. A
//! connection keeps the handle of its socket (its AsyncFd's), so its I/O
//! does not look the number up at all. The owners of closed descriptors
//! are kept for the next ones registered, so a descriptor opened and
//! closed again (a connection, a file) allocates nothing. The table is
//! never dropped: at exit, the kernel closes what is left, as for C's
//! processes.
//!
//! Descriptors are closed by close() only; a number closed behind the
//! table's back (a nix close() of a registered descriptor) leaves a stale
//! entry, which register() leaks when the kernel hands the number out
//! again rather than closing the new descriptor with it.

use std::cell::RefCell;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::rc::Rc;

/// The owner of a descriptor, shared with the handles lent of it. None
/// only in an owner kept for reuse, which nobody else holds: an owner is
/// emptied only when nobody else holds it.
type Owner = Rc<Option<OwnedFd>>;

struct Table {
    /// the descriptors by number
    fds: Vec<Option<Owner>>,
    /// the owners of closed descriptors, for the next ones registered
    free: Vec<Owner>,
}

/// The owners kept for reuse at most.
const FREE_MAX: usize = 256;

thread_local! {
    /// ManuallyDrop: the thread-local has no destructor, which exit() would
    /// run, closing every descriptor.
    static TABLE: ManuallyDrop<RefCell<Table>> = const { ManuallyDrop::new(RefCell::new(Table { fds: Vec::new(), free: Vec::new() })) };
}

fn with_table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    TABLE.with(|t| f(&mut t.borrow_mut()))
}

/// An owner of `fd`: one kept for reuse, or a new one.
fn new_owner(t: &mut Table, fd: OwnedFd) -> Owner {
    if let Some(mut owner) = t.free.pop() {
        if let Some(slot) = Rc::get_mut(&mut owner) {
            *slot = Some(fd);
            return owner;
        }
    }

    Rc::new(Some(fd))
}

/// The descriptor of an owner nobody else holds, taken out of it (the
/// owner is kept for reuse); the owner back if handles of it live.
fn unique_fd(mut owner: Owner) -> Result<OwnedFd, Owner> {
    let fd = Rc::get_mut(&mut owner).and_then(|slot| slot.take());

    match fd {
        Some(fd) => {
            with_table(|t| {
                if t.free.len() < FREE_MAX {
                    t.free.push(owner);
                }
            });

            Ok(fd)
        }
        None => Err(owner),
    }
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

/// A descriptor of the table, kept open as long as a handle lives.
#[derive(Debug)]
pub struct Fd(Inner);

#[derive(Debug)]
enum Inner {
    /// never empty: an owner is emptied only when no handle holds it
    Owned(Owner),
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
            Inner::Owned(o) => o.as_ref().as_ref().expect("the descriptor of a handle is open").as_fd(),
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

    let stale = with_table(|t| {
        if t.fds.len() <= i {
            t.fds.resize(i + 1, None);
        }

        let owner = new_owner(t, fd);

        t.fds[i].replace(owner)
    });

    if let Some(stale) = stale {
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

    if let Some(owner) = with_table(|t| t.fds.get(fd as usize).and_then(|e| e.clone())) {
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
    fd >= 0 && with_table(|t| t.fds.get(fd as usize).is_some_and(|e| e.is_some()))
}

/// The table's owner of `fd`, taken out of it.
fn take_owner(fd: RawFd) -> Option<Owner> {
    if fd < 0 {
        return None;
    }

    with_table(|t| t.fds.get_mut(fd as usize).and_then(|e| e.take()))
}

/// close() of the owner taken out of the table: now, or, if a handle of it
/// still lives, when the last one is dropped.
fn close_owner(owner: Owner) -> io::Result<()> {
    match unique_fd(owner) {
        // nix's close() reports the error OwnedFd's drop ignores
        Ok(owned) => nix::unistd::close(owned.into_raw_fd()).map_err(io::Error::from),
        Err(_) => Ok(()),
    }
}

/// close(): the descriptor is taken out of the table and closed, or, if a
/// handle of it still lives, closed when the last one is dropped.
pub fn close(fd: RawFd) -> io::Result<()> {
    close_owner(take_owner(fd).ok_or_else(ebadf)?)
}

/// close() of the number `fd` in one lookup: the table's descriptor as
/// close() closes it, None if the table does not have the number.
pub fn close_registered(fd: RawFd) -> Option<io::Result<()>> {
    take_owner(fd).map(close_owner)
}

/// Takes the descriptor `fd` out of the table, to make a File or a socket
/// of it; EBUSY while a handle of it lives (it is left in the table then).
pub fn take(fd: RawFd) -> io::Result<OwnedFd> {
    let owner = take_owner(fd).ok_or_else(ebadf)?;

    match unique_fd(owner) {
        Ok(owned) => Ok(owned),
        Err(owner) => {
            with_table(|t| t.fds[fd as usize] = Some(owner));
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
        let h2 = h.clone();
        drop(h);
        assert_eq!(nix::unistd::write(&h2, b"z").unwrap(), 1, "a clone keeps it open too");
        drop(h2);

        let mut buf = [0u8; 4];
        assert_eq!(nix::unistd::read(get(rn).unwrap(), &mut buf).unwrap(), 3);
        assert_eq!(nix::unistd::read(get(rn).unwrap(), &mut buf).unwrap(), 0, "the write end is closed");

        close(rn).unwrap();
        assert_eq!(close(1 << 20).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
        assert_eq!(close(-1).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
        assert!(get(-1).is_err());
    }

    #[test]
    fn close_registered_once() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        let wn = register(w);

        assert!(close_registered(wn).unwrap().is_ok());
        assert!(close_registered(wn).is_none(), "not in the table any more");
        assert!(close_registered(-1).is_none());
        assert!(close_registered(1 << 20).is_none());

        // the descriptor was closed: the read end sees the end
        let mut buf = [0u8; 1];
        assert_eq!(nix::unistd::read(get(rn).unwrap(), &mut buf).unwrap(), 0);

        // with a handle alive, closed when it goes
        let h = get(rn).unwrap();
        assert!(close_registered(rn).unwrap().is_ok());
        assert!(!contains(rn));
        assert_eq!(nix::unistd::read(&h, &mut buf).unwrap(), 0, "still open");
    }

    #[test]
    fn take_while_lent() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        drop(w);

        let h = get(rn).unwrap();
        assert_eq!(take(rn).err().and_then(|e| e.raw_os_error()), Some(libc::EBUSY));
        assert!(contains(rn), "left in the table");
        drop(h);

        let owned = take(rn).unwrap();
        assert!(!contains(rn));
        drop(owned);
        assert_eq!(take(rn).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
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
    fn stale_entry_left_open() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        drop(w);

        // closed behind the table's back, the number handed out again
        let raw = get(rn).unwrap().as_raw_fd();
        nix::unistd::close(raw).unwrap();
        let (r2, w2) = nix::unistd::pipe().unwrap();
        let (n2, wn2) = (register(r2), register(w2));
        if n2 == rn {
            // the new descriptor replaced the stale entry, which was not
            // closed with it
            assert_eq!(nix::unistd::write(get(wn2).unwrap(), b"x").unwrap(), 1);
            let mut buf = [0u8; 1];
            assert_eq!(nix::unistd::read(get(rn).unwrap(), &mut buf).unwrap(), 1);
        }
        close(n2).unwrap();
        close(wn2).unwrap();
    }

    #[test]
    fn owners_reused() {
        let free = || with_table(|t| t.free.len());
        let before = free();

        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        let wn = register(w);
        let kept = free();

        // closed: the owner is kept, and given to the next descriptor
        close(wn).unwrap();
        assert_eq!(free(), kept + 1);
        let (r2, w2) = nix::unistd::pipe().unwrap();
        let rn2 = register(r2);
        assert_eq!(free(), kept);
        let wn2 = register(w2);
        assert_eq!(nix::unistd::write(get(wn2).unwrap(), b"x").unwrap(), 1);
        let mut buf = [0u8; 1];
        assert_eq!(nix::unistd::read(get(rn2).unwrap(), &mut buf).unwrap(), 1);

        // lent when closed: not kept, closed with the last handle
        let f = free();
        let h = get(rn).unwrap();
        let h2 = h.clone();
        close(rn).unwrap();
        assert_eq!(free(), f);
        drop(h);
        assert_eq!(h2.as_fd().as_raw_fd(), rn, "still open");
        drop(h2);

        // taken: the owner is kept, the descriptor given back
        let owned = take(rn2).unwrap();
        assert_eq!(free(), f + 1);
        drop(owned);

        close(wn2).unwrap();
        assert_eq!(free(), f + 2);
        assert!(before <= FREE_MAX);
    }

    #[test]
    fn the_threads_table() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let rn = register(r);
        let wn = register(w);

        // another thread has a table of its own
        std::thread::spawn(move || {
            assert!(!contains(rn));
            assert_eq!(get(wn).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));
        })
        .join()
        .unwrap();

        assert!(contains(rn) && contains(wn));
        close(rn).unwrap();
        close(wn).unwrap();
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
