#![forbid(unsafe_code)]
//! The read event of a listening socket in a worker process: added by
//! ngx_event_process_init with ngx_add_event(rev, NGX_READ_EVENT, 0) or,
//! with several worker processes and no accept mutex, with
//! NGX_EXCLUSIVE_EVENT (EPOLLEXCLUSIVE, so that a new connection or
//! datagram wakes one worker instead of all of them); deleted and added
//! again by the accept mutex, after EMFILE / ENFILE, and by
//! ngx_reorder_accept_events.
//!
//! The reactor (tokio, over mio's epoll) registers descriptors
//! edge-triggered, and has no EPOLLEXCLUSIVE; nor would an epoll instance
//! of the socket's own, waited for by the reactor, do: the kernel counts an
//! exclusive wakeup as taken only by an epoll instance a thread is blocked
//! on, and goes on waking the others. So the event is a dup() of the
//! socket registered in the reactor, which is then deleted from and added
//! to the reactor's epoll instance with epoll_ctl() directly, with the
//! token of the registration, as ngx_epoll_add_event() adds it:
//! level-triggered, EPOLLEXCLUSIVE if asked. The reactor's epoll instance
//! and the token are found in /proc/self/fdinfo; without them the event
//! stays as the reactor registered it (edge-triggered, never exclusive,
//! deleted by not waiting for it). The epoll_ctl() calls are made on a
//! duplicate of the reactor's descriptor (the same epoll instance), which
//! the process owns.
//!
//! The dup() also lets the event of a socket inherited by a new cycle be
//! added before the reactor has deleted the previous one, and keeps the
//! socket open until the reactor has deleted it: the registration of a
//! socket closed while other processes hold it would stay in the epoll
//! instance otherwise.

use std::cell::{Cell, RefCell};
use std::io;
use std::os::fd::{AsRawFd, RawFd};

use rustix::event::epoll;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

/// The dup() of the listening socket registered in the reactor: a
/// descriptor of the table, closed with the event.
pub struct EventFd(RawFd);

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        let _ = crate::fd::close(self.0);
    }
}

/// The reactor's epoll instance in a process: the duplicate of its
/// descriptor which epoll_ctl() is called with (a descriptor of the table,
/// open as long as the process lives).
struct Reactor {
    pid: i32,
    dup: RawFd,
}

thread_local! {
    /// The reactor's epoll instance, once found, in the process.
    static REACTOR: RefCell<Option<Reactor>> = const { RefCell::new(None) };
}

/// The read event of a listening socket.
pub struct ListenEvent {
    afd: AsyncFd<EventFd>,
    /// the reactor's epoll instance (the duplicate of its descriptor) and
    /// the token of the registration
    reactor: Option<(RawFd, u64)>,
    /// rev->active
    active: Cell<bool>,
    exclusive: Cell<bool>,
    /// wakes the handler waiting for the event to be added
    added: tokio::sync::Notify,
}

impl ListenEvent {
    /// The read event of the listening socket `fd`, not added.
    pub fn new(fd: RawFd) -> io::Result<ListenEvent> {
        let s = crate::fd::register(rustix::io::fcntl_dupfd_cloexec(crate::fd::get(fd)?, 0)?);

        let afd = AsyncFd::with_interest(EventFd(s), Interest::READABLE)?;

        let reactor = reactor_registration(s);

        let ev = ListenEvent { afd, reactor, active: Cell::new(true), exclusive: Cell::new(false), added: tokio::sync::Notify::new() };

        ev.del()?;

        Ok(ev)
    }

    /// ngx_add_event(rev, NGX_READ_EVENT, 0), or with NGX_EXCLUSIVE_EVENT:
    /// EPOLLIN | EPOLLRDHUP, level-triggered, or EPOLLIN | EPOLLEXCLUSIVE
    /// (ngx_epoll_add_event drops EPOLLRDHUP for an exclusive event).
    pub fn add(&self, exclusive: bool) -> io::Result<()> {
        if let Some((epfd, token)) = self.reactor {
            let events = if exclusive { epoll::EventFlags::IN | epoll::EventFlags::EXCLUSIVE } else { epoll::EventFlags::IN | epoll::EventFlags::RDHUP };

            epoll::add(crate::fd::get(epfd)?, crate::fd::get(self.afd.get_ref().0)?, epoll::EventData::new_u64(token), events)?;

            self.exclusive.set(exclusive);
        }

        self.active.set(true);
        self.added.notify_one();

        Ok(())
    }

    /// ngx_del_event(rev, NGX_READ_EVENT, NGX_DISABLE_EVENT)
    pub fn del(&self) -> io::Result<()> {
        if let Some((epfd, _)) = self.reactor {
            epoll::delete(crate::fd::get(epfd)?, crate::fd::get(self.afd.get_ref().0)?)?;
        }

        self.active.set(false);
        self.exclusive.set(false);

        Ok(())
    }

    /// rev->active
    pub fn is_active(&self) -> bool {
        self.active.get()
    }

    /// The event was added with EPOLLEXCLUSIVE.
    pub fn is_exclusive(&self) -> bool {
        self.exclusive.get()
    }

    /// The event was added to the reactor's epoll instance by epoll_ctl(),
    /// level-triggered, as in C.
    pub fn is_level(&self) -> bool {
        self.reactor.is_some()
    }

    /// Wait for the event: added, and reported.
    pub async fn wait(&self) -> io::Result<AsyncFdReadyGuard<'_, EventFd>> {
        loop {
            if !self.active.get() {
                self.added.notified().await;
                continue;
            }

            let guard = self.afd.readable().await?;

            if !self.active.get() {
                // deleted while waiting (the reactor's registration, which
                // keeps reporting): the readiness stays for the next add
                continue;
            }

            return Ok(guard);
        }
    }

    /// The handler returned, after EAGAIN if `again`: a level-triggered
    /// event is reported again while connections or datagrams are
    /// pending; the reactor's edge-triggered one is not until EAGAIN.
    pub fn handled(&self, guard: &mut AsyncFdReadyGuard<'_, EventFd>, again: bool) {
        if again || self.reactor.is_some() {
            guard.clear_ready();
        }
    }
}

/// The reactor's epoll instance holding `fd` (the duplicate of its
/// descriptor the process owns), and the token of the registration
/// (epoll_event.data), from /proc/self/fdinfo.
fn reactor_registration(fd: RawFd) -> Option<(RawFd, u64)> {
    let pid = crate::os::getpid();

    let cached = REACTOR.with(|r| r.borrow().as_ref().filter(|r| r.pid == pid).map(|r| r.dup));

    // the registration is looked for in the instance the duplicate is of
    if let Some(dup) = cached {
        if let Some(token) = registration_token(dup, fd) {
            return Some((dup, token));
        }
    }

    let dir = std::fs::read_dir("/proc/self/fd").ok()?;

    for entry in dir.flatten() {
        let epfd: RawFd = match entry.file_name().to_str().and_then(|n| n.parse().ok()) {
            Some(n) => n,
            None => continue,
        };

        match std::fs::read_link(entry.path()) {
            Ok(l) if l.as_os_str() == "anon_inode:[eventpoll]" => {}
            _ => continue,
        }

        if let Some(token) = registration_token(epfd, fd) {
            // the descriptor is the reactor's: the process owns a duplicate
            let dup = crate::fd::register(crate::fd::duplicate(epfd).ok()?);
            let old = REACTOR.with(|r| r.borrow_mut().replace(Reactor { pid, dup }));

            // the duplicate of a parent's reactor, inherited across fork()
            // (that of this process stays: events may use it)
            if let Some(old) = old.filter(|old| old.pid != pid) {
                let _ = crate::fd::close(old.dup);
            }

            return Some((dup, token));
        }
    }

    None
}

/// The token of the registration of `fd` in the epoll instance `epfd`:
/// the lines of its fdinfo are
/// "tfd: %8d events: %8x data: %16llx pos:%lli ino:%lx sdev:%x".
fn registration_token(epfd: RawFd, fd: RawFd) -> Option<u64> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", epfd)).ok()?;

    for line in info.lines() {
        let mut words = line.split_whitespace();

        if words.next() != Some("tfd:") {
            continue;
        }

        if words.next().and_then(|w| w.parse::<RawFd>().ok()) != Some(fd) {
            continue;
        }

        while let Some(w) = words.next() {
            if w == "data:" {
                return words.next().and_then(|d| u64::from_str_radix(d, 16).ok());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    fn run<F: std::future::Future<Output = ()>>(f: F) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(f);
    }

    /// accept4() of a connection, closed at once
    fn accept(fd: RawFd) -> bool {
        let l = crate::fd::get(fd).unwrap();
        rustix::net::accept_with(&l, rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC).is_ok()
    }

    /// A listening socket in the descriptor table.
    fn listener() -> (RawFd, std::net::SocketAddr) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        (crate::fd::register(OwnedFd::from(l)), addr)
    }

    #[test]
    fn level_triggered_event() {
        run(async {
            let (fd, addr) = listener();

            let ev = ListenEvent::new(fd).unwrap();
            assert!(ev.is_level());
            assert!(!ev.is_active());

            let _c1 = std::net::TcpStream::connect(addr).unwrap();
            let _c2 = std::net::TcpStream::connect(addr).unwrap();

            // not reported before it is added
            assert!(tokio::time::timeout(Duration::from_millis(50), ev.wait()).await.is_err());

            ev.add(false).unwrap();
            assert!(ev.is_active() && !ev.is_exclusive());

            // one connection per event: reported again for the second one
            for _ in 0..2 {
                let mut guard = tokio::time::timeout(Duration::from_secs(2), ev.wait()).await.expect("event").unwrap();
                assert!(accept(fd));
                ev.handled(&mut guard, false);
            }

            // nothing pending: not reported
            assert!(tokio::time::timeout(Duration::from_millis(50), ev.wait()).await.is_err());
            assert!(!accept(fd));

            // ngx_reorder_accept_events
            ev.del().unwrap();
            ev.add(true).unwrap();
            assert!(ev.is_exclusive());

            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(b"x").unwrap();

            let mut guard = tokio::time::timeout(Duration::from_secs(2), ev.wait()).await.expect("event").unwrap();
            assert!(accept(fd));
            ev.handled(&mut guard, false);

            drop(guard);
            drop(ev);
            crate::fd::close(fd).unwrap();
        });
    }

    #[test]
    fn events_of_one_socket() {
        run(async {
            let (fd, addr) = listener();

            // the event of a previous cycle is not deleted yet
            let old = ListenEvent::new(fd).unwrap();
            old.add(false).unwrap();

            let ev = ListenEvent::new(fd).unwrap();
            ev.add(false).unwrap();
            drop(old);

            let _client = std::net::TcpStream::connect(addr).unwrap();

            let mut guard = tokio::time::timeout(Duration::from_secs(2), ev.wait()).await.expect("event").unwrap();
            assert!(accept(fd));
            ev.handled(&mut guard, false);
            drop(guard);

            drop(ev);
            crate::fd::close(fd).unwrap();
        });
    }
}
