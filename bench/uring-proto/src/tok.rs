// tokio-hosted variants, shaped like rnginx: a current-thread runtime, a LocalSet,
// one spawned task per connection, accept on the listening socket's readiness.
//
//   tokio-epoll   readiness through tokio's reactor (AsyncFd), recv/send syscalls;
//                 the readiness is cleared after a short read, as rnginx does
//   tokio-uring   the tokio-uring crate as designed: its runtime, owned buffers,
//                 SQEs flushed when the thread parks
//   tokio-ring    an own minimal ring driver inside tokio: RECV with buffer select
//                 submitted only when the task wants data, flushed and reaped at the
//                 end of every LocalSet tick; the ring fd in tokio's reactor wakes a
//                 parked thread. SYNCSEND=1: the response with a send() syscall.

use super::{feed, pipe_resp, set_nodelay, BufRing, RESP};
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::task::LocalSet;

struct Fd(RawFd);

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_park(flush)
        .build()
        .unwrap()
}

/// The accept loop on the listening socket's readiness, as rnginx's.
async fn accept_loop(lfd: RawFd, conn: fn(RawFd)) {
    let afd = AsyncFd::with_interest(Fd(lfd), Interest::READABLE).unwrap();
    loop {
        let mut g = afd.readable().await.unwrap();
        loop {
            let c = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if c < 0 {
                g.clear_ready();
                break;
            }
            set_nodelay(c);
            conn(c);
        }
    }
}

/// LocalSet::block_on() with the ring flushed after every LocalSet tick, as
/// rnginx's block_on_events() updates the time.
fn block_on_local<F: Future>(rt: &tokio::runtime::Runtime, local: &LocalSet, f: F) -> F::Output {
    let mut run = std::pin::pin!(local.run_until(f));
    rt.block_on(std::future::poll_fn(move |cx| {
        let r = run.as_mut().poll(cx);
        flush();
        r
    }))
}

// ---------------------------------------------------------------------------
// tokio-epoll

pub fn run_tokio_epoll(lfd: RawFd) {
    let rt = runtime();
    let local = LocalSet::new();
    block_on_local(&rt, &local, async move {
        spin();
        accept_loop(lfd, |c| {
            tokio::task::spawn_local(conn_epoll(c));
        })
        .await
    });
}

async fn conn_epoll(fd: RawFd) {
    let resps = resps();
    let afd = AsyncFd::with_interest(Fd(fd), Interest::READABLE | Interest::WRITABLE).unwrap();
    let mut buf = [0u8; 1024];
    let mut pending = Vec::new();
    'conn: loop {
        let mut g = afd.readable().await.unwrap();
        let n = match g.try_io(|_| cvt(unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) })) {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                if n < buf.len() {
                    g.clear_ready();
                }
                n
            }
            Err(_) => continue,
        };
        drop(g);
        let reqs = feed(&mut pending, &buf[..n]).min(super::MAX_PIPE);
        if reqs == 0 {
            continue;
        }
        let out = &resps[..reqs * RESP.len()];
        // the sync-first write: one attempt while write-ready, else wait
        loop {
            match afd.try_io(Interest::WRITABLE, |_| cvt(unsafe { libc::send(fd, out.as_ptr() as *const _, out.len(), libc::MSG_NOSIGNAL) })) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if afd.writable().await.is_err() {
                        break 'conn;
                    }
                }
                Err(_) => break 'conn,
            }
        }
    }
    drop(afd);
    unsafe { libc::close(fd) };
}

fn cvt(r: isize) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

fn resps() -> &'static [u8] {
    thread_local!(static R: &'static [u8] = pipe_resp());
    R.with(|r| *r)
}

// ---------------------------------------------------------------------------
// tokio-uring

/// SPIN=1: one task that stays runnable (a long response produced in chunks,
/// yielding between them), so the runtime never parks.
fn spin() {
    if std::env::var_os("SPIN").is_some() {
        tokio::task::spawn_local(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
    }
}

pub fn run_tokio_uring(lfd: RawFd) {
    tokio_uring::builder().entries(4096).start(async move {
        spin();
        use std::os::fd::FromRawFd;
        let listener = tokio_uring::net::TcpListener::from_std(unsafe { std::net::TcpListener::from_raw_fd(lfd) });
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = stream.set_nodelay(true);
            tokio_uring::spawn(async move {
                let resps = resps();
                let mut buf = vec![0u8; 1024];
                let mut pending = Vec::new();
                loop {
                    let (res, b) = stream.read(buf).await;
                    buf = b;
                    let n = match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let reqs = feed(&mut pending, &buf[..n]).min(super::MAX_PIPE);
                    if reqs > 0 {
                        let (res, _) = stream.write(&resps[..reqs * RESP.len()]).submit().await;
                        if res.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// tokio-ring: an own driver

enum State {
    Free,
    Waiting(Option<Waker>),
    Done(i32, u32),
    /// The future went away: the CQE frees the slot (and its buffer).
    Ignored,
}

struct Driver {
    ring: IoUring,
    br: BufRing,
    slots: Vec<(u32, State)>,
    free: Vec<u32>,
    unsubmitted: u32,
    recycled: bool,
    enters: u64,
}

thread_local! {
    static DRIVER: RefCell<Option<Driver>> = const { RefCell::new(None) };
}

const CANCEL: u64 = u64::MAX;

fn init_driver() -> RawFd {
    let mut b = IoUring::builder();
    if std::env::var("DEFER").is_ok() {
        b.setup_single_issuer().setup_defer_taskrun();
    } else {
        b.setup_single_issuer().setup_coop_taskrun().setup_taskrun_flag();
    }
    let ring: IoUring = b.build(4096).expect("io_uring");
    let br = BufRing::new(&ring.submitter());
    let fd = ring.as_raw_fd();
    DRIVER.with(|d| {
        *d.borrow_mut() = Some(Driver { ring, br, slots: Vec::new(), free: Vec::new(), unsubmitted: 0, recycled: false, enters: 0 })
    });
    fd
}

impl Driver {
    fn alloc(&mut self, waker: &Waker) -> (u32, u32) {
        let idx = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push((0, State::Free));
                (self.slots.len() - 1) as u32
            }
        };
        let s = &mut self.slots[idx as usize];
        s.0 = s.0.wrapping_add(1);
        s.1 = State::Waiting(Some(waker.clone()));
        (idx, s.0)
    }

    fn push(&mut self, sqe: squeue::Entry) {
        while unsafe { self.ring.submission().push(&sqe) }.is_err() {
            self.enter();
        }
        self.unsubmitted += 1;
    }

    fn enter(&mut self) {
        self.enters += 1;
        let n = self.ring.submission().len() as u32;
        // GETEVENTS: with DEFER_TASKRUN the completions are only produced here
        let _ = unsafe { self.ring.submitter().enter::<libc::sigset_t>(n, 0, 1 /* IORING_ENTER_GETEVENTS */, None) };
        self.unsubmitted = 0;
    }

    fn reap(&mut self) {
        let mut wake: Vec<Waker> = Vec::new();
        {
            let (_, _, mut cq) = self.ring.split();
            cq.sync();
            for cqe in &mut cq {
                let ud = cqe.user_data();
                if ud == CANCEL {
                    continue;
                }
                let (idx, gen) = (ud as u32, (ud >> 32) as u32);
                let slot = &mut self.slots[idx as usize];
                if slot.0 != gen {
                    continue;
                }
                match std::mem::replace(&mut slot.1, State::Free) {
                    State::Waiting(w) => {
                        slot.1 = State::Done(cqe.result(), cqe.flags());
                        if let Some(w) = w {
                            wake.push(w);
                        }
                    }
                    State::Ignored => {
                        if let Some(bid) = cqueue::buffer_select(cqe.flags()) {
                            self.br.add(bid);
                            self.recycled = true;
                        }
                        self.free.push(idx);
                    }
                    s => slot.1 = s,
                }
            }
        }
        if self.recycled {
            self.br.publish();
            self.recycled = false;
        }
        for w in wake {
            w.wake();
        }
    }
}

/// Submit what the tick queued and reap what completed.
fn flush() {
    DRIVER.with(|d| {
        let mut d = d.borrow_mut();
        let Some(d) = d.as_mut() else { return };
        if d.unsubmitted > 0 || d.ring.submission().taskrun() || std::env::var_os("DEFER").is_some() {
            d.enter();
        }
        d.reap();
    })
}

/// recv(2) through the ring into a kernel-chosen buffer, copied out when polled.
struct Recv<'a> {
    fd: RawFd,
    buf: &'a mut [u8],
    key: Option<(u32, u32)>,
}

impl Future for Recv<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        DRIVER.with(|d| {
            let mut d = d.borrow_mut();
            let d = d.as_mut().unwrap();
            loop {
                let Some((idx, gen)) = this.key else {
                    let (idx, gen) = d.alloc(cx.waker());
                    let sqe = opcode::Recv::new(types::Fd(this.fd), std::ptr::null_mut(), this.buf.len() as u32)
                        .buf_group(0)
                        .build()
                        .flags(squeue::Flags::BUFFER_SELECT)
                        .user_data(((gen as u64) << 32) | idx as u64);
                    d.push(sqe);
                    this.key = Some((idx, gen));
                    return Poll::Pending;
                };
                let slot = &mut d.slots[idx as usize];
                match &mut slot.1 {
                    State::Waiting(w) => {
                        if !w.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                            *w = Some(cx.waker().clone());
                        }
                        return Poll::Pending;
                    }
                    State::Done(res, flags) => {
                        let (res, flags) = (*res, *flags);
                        slot.1 = State::Free;
                        d.free.push(idx);
                        this.key = None;
                        if res == -libc::ENOBUFS {
                            continue;
                        }
                        if res < 0 {
                            return Poll::Ready(Err(io::Error::from_raw_os_error(-res)));
                        }
                        if let Some(bid) = cqueue::buffer_select(flags) {
                            let n = res as usize;
                            this.buf[..n].copy_from_slice(d.br.data(bid, n));
                            d.br.add(bid);
                            d.br.publish();
                        }
                        return Poll::Ready(Ok(res as usize));
                    }
                    _ => unreachable!(),
                }
            }
        })
    }
}

impl Drop for Recv<'_> {
    fn drop(&mut self) {
        if let Some((idx, gen)) = self.key {
            DRIVER.with(|d| {
                let mut d = d.borrow_mut();
                let d = d.as_mut().unwrap();
                if let State::Waiting(_) = d.slots[idx as usize].1 {
                    d.slots[idx as usize].1 = State::Ignored;
                    d.push(opcode::AsyncCancel::new(((gen as u64) << 32) | idx as u64).build().user_data(CANCEL));
                }
            })
        }
    }
}

/// send(2) of static bytes through the ring.
struct Send {
    fd: RawFd,
    data: &'static [u8],
    key: Option<(u32, u32)>,
}

impl Future for Send {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        DRIVER.with(|d| {
            let mut d = d.borrow_mut();
            let d = d.as_mut().unwrap();
            let Some((idx, _gen)) = this.key else {
                let (idx, gen) = d.alloc(cx.waker());
                let sqe = opcode::Send::new(types::Fd(this.fd), this.data.as_ptr(), this.data.len() as u32)
                    .flags(libc::MSG_NOSIGNAL)
                    .build()
                    .user_data(((gen as u64) << 32) | idx as u64);
                d.push(sqe);
                this.key = Some((idx, gen));
                return Poll::Pending;
            };
            let slot = &mut d.slots[idx as usize];
            match slot.1 {
                State::Waiting(ref mut w) => {
                    *w = Some(cx.waker().clone());
                    Poll::Pending
                }
                State::Done(res, _) => {
                    slot.1 = State::Free;
                    d.free.push(idx);
                    this.key = None;
                    Poll::Ready(if res < 0 { Err(io::Error::from_raw_os_error(-res)) } else { Ok(res as usize) })
                }
                _ => unreachable!(),
            }
        })
    }
}

pub fn run_tokio_ring(lfd: RawFd) {
    let rt = runtime();
    let local = LocalSet::new();
    let ring_fd = {
        let _g = rt.enter();
        init_driver()
    };
    block_on_local(&rt, &local, async move {
        spin();
        // a parked thread wakes up for completions through the ring's fd
        tokio::task::spawn_local(async move {
            let afd = AsyncFd::with_interest(Fd(ring_fd), Interest::READABLE).unwrap();
            loop {
                let mut g = afd.readable().await.unwrap();
                flush();
                g.clear_ready();
            }
        });
        accept_loop(lfd, |c| {
            tokio::task::spawn_local(conn_ring(c));
        })
        .await
    });
}

async fn conn_ring(fd: RawFd) {
    let resps = resps();
    let sync = std::env::var_os("SYNCSEND").is_some();
    let mut buf = [0u8; 1024];
    let mut pending = Vec::new();
    loop {
        let n = match (Recv { fd, buf: &mut buf, key: None }).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let reqs = feed(&mut pending, &buf[..n]).min(super::MAX_PIPE);
        if reqs == 0 {
            continue;
        }
        let out = &resps[..reqs * RESP.len()];
        if sync {
            let r = unsafe { libc::send(fd, out.as_ptr() as *const _, out.len(), libc::MSG_NOSIGNAL) };
            if r != out.len() as isize {
                break;
            }
        } else if (Send { fd, data: out, key: None }).await.is_err() {
            break;
        }
    }
    unsafe { libc::close(fd) };
}
