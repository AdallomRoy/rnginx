//! The worker's io_uring (docs/IO_URING_PLAN.md): the ring of
//! ngx_sys::uring driven by the event loop, its operations as futures.
//!
//! - flush() submits what the tasks queued and reaps the completions,
//!   waking their tasks. It runs at the end of every run of the tasks
//!   (event::block_on_events) and before the thread parks (events_park),
//!   and makes no system call when nothing is queued and the kernel has no
//!   task work for the ring. Submitting only when the thread parks would
//!   starve every operation while some task stays runnable (tokio parks
//!   only when idle).
//! - While the thread is parked in the reactor, a duplicate of the ring's
//!   descriptor, registered there, wakes the driver task, which flushes.
//! - A future dropped before its operation completed cancels it; what the
//!   operation lent stays with the ring until the completion, and is
//!   dropped once the driver is not borrowed.
//! - Operations name their socket by a handle of the descriptor table
//!   (fd::Fd): fd::close() of the number closes the socket only once the
//!   last operation naming it has completed, so the number cannot be given
//!   to another descriptor meanwhile.

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use ngx_sys::uring::{BufGroup, BufToken, OpId, RecvTarget, SendSource};

use crate::fd::{self, Fd};

/// The ring of a worker: its operations name sockets by handles of the
/// descriptor table.
type Ring = ngx_sys::uring::Ring<Fd>;
type Completion = ngx_sys::uring::Completion<Fd>;

/// The submission queue's entries (the completion queue has twice as many).
const RING_ENTRIES: u32 = 4096;

/// The provided buffers of receives of at most SMALL.1 bytes (request heads,
/// frames), and of the larger ones (bodies): count, size, and how many are
/// in the kernel's ring at first (more once receives find it empty). The
/// buffers used are those given back last: as many are touched (resident)
/// as are in use at a time, not all of them.
const SMALL: (u16, usize, u16) = (1024, 2048, 64);
const LARGE: (u16, usize, u16) = (256, 16384, 16);

thread_local! {
    static DRIVER: RefCell<Option<Driver>> = const { RefCell::new(None) };
}

/// What the driver did, for the debug log and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// io_uring_enter() calls
    pub submits: u64,
    /// completions reaped
    pub completions: u64,
    /// receives retried for want of a provided buffer (ENOBUFS)
    pub no_buffers: u64,
}

enum State {
    Free,
    /// in flight; `flushed`: submitted, and not complete after the flush
    /// that submitted it (it waits in the kernel); `settle`: its future
    /// wants to know that (poll_settled)
    Waiting { op: OpId, waker: Option<Waker>, flushed: bool, settle: bool },
    /// complete: the completion is `done[i]`, a slot being as small as an
    /// operation in flight (one for each idle connection)
    Done(u32),
    /// the future went away before the completion
    Ignored,
}

struct Slot {
    gen: u32,
    state: State,
}

struct Driver {
    ring: Ring,
    small: BufGroup,
    large: BufGroup,
    slots: Vec<Slot>,
    free: Vec<u32>,
    /// the completions their futures have not taken yet (few at a time)
    done: Vec<Option<Completion>>,
    done_free: Vec<u32>,
    stats: Stats,
    /// the wakers of a flush, woken once the driver is not borrowed (kept
    /// for their capacity)
    wake: Vec<Waker>,
    /// what abandoned operations lent, dropped once the driver is not
    /// borrowed (dropping it may run any code)
    graveyard: Vec<Completion>,
    /// the completions of a reap (kept for its capacity)
    reaped: Vec<Completion>,
    /// the operations started since the last flush
    pushed: Vec<u64>,
}

fn tag(index: u32, gen: u32) -> u64 {
    ((gen as u64) << 32) | index as u64
}

impl Driver {
    fn alloc(&mut self) -> (u32, u32) {
        let index = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push(Slot { gen: 0, state: State::Free });
                (self.slots.len() - 1) as u32
            }
        };

        let slot = &mut self.slots[index as usize];
        slot.gen = slot.gen.wrapping_add(1);

        (index, slot.gen)
    }

    /// The slot of a tag, if the tag is its current operation's.
    fn slot(&mut self, tag: u64) -> Option<&mut Slot> {
        let (index, gen) = (tag as u32 as usize, (tag >> 32) as u32);

        self.slots.get_mut(index).filter(|s| s.gen == gen)
    }

    fn release(&mut self, tag: u64) {
        if let Some(s) = self.slot(tag) {
            s.state = State::Free;
            self.free.push(tag as u32);
        }
    }

    /// Keeps a completion until its future takes it: its index in `done`.
    fn keep(&mut self, c: Completion) -> u32 {
        match self.done_free.pop() {
            Some(i) => {
                self.done[i as usize] = Some(c);
                i
            }
            None => {
                self.done.push(Some(c));
                (self.done.len() - 1) as u32
            }
        }
    }

    /// The completion kept at `i`, taken.
    fn take_done(&mut self, i: u32) -> Completion {
        self.done_free.push(i);
        self.done[i as usize].take().expect("a completion kept")
    }

    /// Starts an operation: `push` queues it with the tag given.
    fn start<E>(&mut self, push: impl FnOnce(&mut Ring, u64) -> Result<OpId, E>) -> Result<u64, E> {
        let (index, gen) = self.alloc();
        let tag = tag(index, gen);

        match push(&mut self.ring, tag) {
            Ok(op) => {
                self.slots[index as usize].state = State::Waiting { op, waker: None, flushed: false, settle: false };
                self.pushed.push(tag);
                Ok(tag)
            }
            Err(e) => {
                self.free.push(index);
                Err(e)
            }
        }
    }

    fn poll(&mut self, tag: u64, cx: &mut Context<'_>) -> Poll<Completion> {
        match self.poll_settled(tag, cx, false) {
            Poll::Ready(Some(c)) => Poll::Ready(c),
            _ => Poll::Pending,
        }
    }

    /// The completion, or, with `settle`, None once the operation is known
    /// to wait in the kernel (not complete after the flush that submitted
    /// it).
    fn poll_settled(&mut self, tag: u64, cx: &mut Context<'_>, settle: bool) -> Poll<Option<Completion>> {
        let slot = self.slot(tag).expect("the slot of an operation");

        let i = match &mut slot.state {
            State::Waiting { flushed: true, .. } if settle => return Poll::Ready(None),
            State::Waiting { waker, settle: s, .. } => {
                *s |= settle;
                match waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => *waker = Some(cx.waker().clone()),
                }
                return Poll::Pending;
            }
            State::Done(i) => *i,
            _ => unreachable!("an operation polled after its end"),
        };

        slot.state = State::Free;
        self.free.push(tag as u32);

        Poll::Ready(Some(self.take_done(i)))
    }

    /// The completion if the operation has completed, taken; no waker is
    /// registered (the caller waits with poll_ready()).
    fn try_take(&mut self, tag: u64) -> Option<Completion> {
        let slot = self.slot(tag)?;

        let State::Done(i) = slot.state else { return None };

        slot.state = State::Free;
        self.free.push(tag as u32);

        Some(self.take_done(i))
    }

    /// Ready once the operation has completed, its completion left for
    /// the next poll or try_take().
    fn poll_ready(&mut self, tag: u64, cx: &mut Context<'_>) -> Poll<()> {
        let slot = self.slot(tag).expect("the slot of an operation");

        match &mut slot.state {
            State::Done(_) => Poll::Ready(()),
            State::Waiting { waker, .. } => {
                match waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => *waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            _ => unreachable!("an operation polled after its end"),
        }
    }

    /// Ready(true) once the operation has completed (its completion left
    /// for the next poll or try_take()), Ready(false) once it is known to
    /// wait in the kernel (not complete after the flush that submitted it).
    fn poll_settled_ready(&mut self, tag: u64, cx: &mut Context<'_>) -> Poll<bool> {
        let slot = self.slot(tag).expect("the slot of an operation");

        match &mut slot.state {
            State::Done(_) => Poll::Ready(true),
            State::Waiting { flushed: true, .. } => Poll::Ready(false),
            State::Waiting { waker, settle, .. } => {
                *settle = true;
                match waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => *waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            _ => unreachable!("an operation polled after its end"),
        }
    }

    /// The future of an operation went away: the operation is cancelled,
    /// or its completion (what it lent) returned to be dropped.
    fn abandon(&mut self, tag: u64) -> Option<Completion> {
        let slot = self.slot(tag)?;

        match std::mem::replace(&mut slot.state, State::Ignored) {
            State::Waiting { op, .. } => {
                let _ = self.ring.push_cancel(op);
                None
            }
            State::Done(i) => {
                self.release(tag);
                Some(self.take_done(i))
            }
            s => {
                slot.state = s;
                None
            }
        }
    }

    fn flush(&mut self) {
        let submitted = self.ring.needs_submit();

        if submitted {
            self.stats.submits += 1;

            if let Err(e) = self.ring.submit() {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    // completions overflowed: reaped first
                    self.reap();
                    self.stats.submits += 1;
                    let _ = self.ring.submit();
                }
            }
        }

        self.reap();

        // what was submitted (by this submit, or by a push that found the
        // queue full) and did not complete waits in the kernel
        let mut pushed = std::mem::take(&mut self.pushed);

        for tag in pushed.drain(..) {
            let mut settled = None;

            if let Some(Slot { state: State::Waiting { waker, flushed, settle, .. }, .. }) = self.slot(tag) {
                *flushed = true;

                if *settle {
                    settled = waker.clone();
                }
            }

            if let Some(w) = settled {
                self.wake.push(w);
            }
        }

        self.pushed = pushed;
    }

    fn reap(&mut self) {
        let mut done = std::mem::take(&mut self.reaped);

        self.stats.completions += self.ring.reap(|c| done.push(c)) as u64;

        for c in done.drain(..) {
            let tag = c.tag;

            match self.slot(tag).map(|s| std::mem::replace(&mut s.state, State::Free)) {
                Some(State::Waiting { waker, .. }) => {
                    let i = self.keep(c);
                    if let Some(s) = self.slot(tag) {
                        s.state = State::Done(i);
                    }
                    if let Some(w) = waker {
                        self.wake.push(w);
                    }
                }
                Some(State::Ignored) => {
                    self.free.push(tag as u32);
                    self.graveyard.push(c);
                }
                Some(s) => {
                    if let Some(slot) = self.slot(tag) {
                        slot.state = s;
                    }
                    self.graveyard.push(c);
                }
                None => self.graveyard.push(c),
            }
        }

        self.reaped = done;
    }
}

/// Whether this process runs its sockets' I/O through io_uring.
pub fn enabled() -> bool {
    DRIVER.try_with(|d| d.borrow().is_some()).unwrap_or(false)
}

/// How the output chains of connections in io_uring mode are written
/// (RNGINX_URING_WRITES, an experiment, read by the master with the
/// configuration, as the workers' environment is cleared): 0 sent by the
/// ring (ring), 1 by writev() at once (sync), 2 by writev() at once and the
/// ring for what the socket does not take (hybrid)
static WRITES: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Reads RNGINX_URING_WRITES (the master, with the configuration).
pub fn read_env() {
    let mode = match std::env::var_os("RNGINX_URING_WRITES") {
        Some(v) if v == "sync" => 1,
        Some(v) if v == "hybrid" => 2,
        _ => 0,
    };

    WRITES.store(mode, std::sync::atomic::Ordering::Relaxed);
}

/// The output of connections in io_uring mode is written by system calls
/// (RNGINX_URING_WRITES=sync), not sent by the ring.
pub fn sync_writes() -> bool {
    WRITES.load(std::sync::atomic::Ordering::Relaxed) == 1
}

/// A writev() at once first, the ring for what the socket does not take
/// (RNGINX_URING_WRITES=hybrid).
pub fn hybrid_writes() -> bool {
    WRITES.load(std::sync::atomic::Ordering::Relaxed) == 2
}

/// What the driver did so far.
pub fn stats() -> Stats {
    DRIVER.try_with(|d| d.borrow().as_ref().map(|d| d.stats).unwrap_or_default()).unwrap_or_default()
}

/// Whether the kernel lets this process do its sockets' I/O through
/// io_uring: a small ring with what the driver uses (the opcodes, a group
/// of provided buffers) is made and dropped. io_uring is then the default
/// event method, as ngx_event_init_conf takes the best method available.
pub fn available() -> bool {
    match Ring::new(8) {
        Ok(mut ring) => ring.add_buffer_group(1, 64, 1).is_ok(),
        Err(_) => false,
    }
}

/// Creates the process's ring and starts its driver task (in the event
/// loop's LocalSet). Fails where io_uring cannot be used (seccomp, the
/// kernel.io_uring_disabled sysctl, an older kernel, RLIMIT_MEMLOCK).
pub fn init() -> io::Result<()> {
    let mut ring = Ring::new(RING_ENTRIES)?;
    let small = ring.add_buffer_group(SMALL.0, SMALL.1, SMALL.2)?;
    let large = ring.add_buffer_group(LARGE.0, LARGE.1, LARGE.2)?;

    let dup = rustix::io::fcntl_dupfd_cloexec(ring.as_fd(), 0)?;
    let afd = tokio::io::unix::AsyncFd::with_interest(fd::get(fd::register(dup))?, tokio::io::Interest::READABLE)?;

    DRIVER.with(|d| {
        *d.borrow_mut() = Some(Driver {
            ring,
            small,
            large,
            slots: Vec::new(),
            free: Vec::new(),
            done: Vec::new(),
            done_free: Vec::new(),
            stats: Stats::default(),
            wake: Vec::new(),
            graveyard: Vec::new(),
            reaped: Vec::new(),
            pushed: Vec::new(),
        })
    });

    crate::event::spawn(wake_task(afd));

    Ok(())
}

/// The completions that came while the thread was parked: the ring's
/// descriptor turns readable.
async fn wake_task(afd: tokio::io::unix::AsyncFd<Fd>) {
    loop {
        let mut guard = match afd.readable().await {
            Ok(g) => g,
            Err(_) => return,
        };

        flush();

        guard.clear_ready();
    }
}

/// Drops the ring: what is in flight is cancelled and waited for.
pub fn shutdown() {
    let driver = DRIVER.try_with(|d| d.borrow_mut().take()).ok().flatten();

    drop(driver);
}

/// Submits what the tasks queued, reaps the completions and wakes their
/// tasks.
pub fn flush() {
    let taken = DRIVER.try_with(|d| {
        let mut d = d.try_borrow_mut().ok()?;
        let d = d.as_mut()?;

        d.flush();

        Some((std::mem::take(&mut d.wake), std::mem::take(&mut d.graveyard)))
    });

    let Ok(Some((mut wake, mut graveyard))) = taken else { return };

    for w in wake.drain(..) {
        w.wake();
    }

    graveyard.clear();

    // the vectors back, for their capacity
    let _ = DRIVER.try_with(|d| {
        if let Ok(mut d) = d.try_borrow_mut() {
            if let Some(d) = d.as_mut() {
                if d.wake.is_empty() {
                    d.wake = wake;
                }
                if d.graveyard.is_empty() {
                    d.graveyard = graveyard;
                }
            }
        }
    });
}

fn no_ring() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "no io_uring in this process")
}

/// An operation in flight, by its tag: cancelled if dropped before its
/// completion.
struct Op {
    tag: u64,
    done: bool,
}

impl Op {
    fn poll_completion(&mut self, cx: &mut Context<'_>) -> Poll<Completion> {
        let r = DRIVER.with(|d| d.borrow_mut().as_mut().expect("the io_uring driver").poll(self.tag, cx));

        if r.is_ready() {
            self.done = true;
        }

        r
    }

    fn poll_settled(&mut self, cx: &mut Context<'_>) -> Poll<Option<Completion>> {
        let r = DRIVER.with(|d| d.borrow_mut().as_mut().expect("the io_uring driver").poll_settled(self.tag, cx, true));

        if let Poll::Ready(Some(_)) = r {
            self.done = true;
        }

        r
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        if self.done {
            return;
        }

        let lent = DRIVER.try_with(|d| d.try_borrow_mut().ok().and_then(|mut d| d.as_mut().and_then(|d| d.abandon(self.tag))));

        // dropped outside the borrow of the driver
        drop(lent);
    }
}

/// recv(2) of at most `len` bytes into a provided buffer: the future of
/// [`recv`].
pub struct Recv {
    op: Op,
    fd: Fd,
    len: usize,
}

/// The bytes a receive got (none: the end of the stream), in a provided
/// buffer, which goes back to the ring when this is dropped.
#[derive(Debug)]
pub struct Received {
    token: Option<BufToken>,
}

impl Received {
    pub fn len(&self) -> usize {
        self.token.as_ref().map(|t| t.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `f` of the bytes received.
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        match &self.token {
            Some(t) => DRIVER.with(|d| f(d.borrow().as_ref().expect("the io_uring driver").ring.buffer(t))),
            None => f(&[]),
        }
    }

    /// Copies the bytes from `from` on into `out`; returns how many.
    pub fn copy_to(&self, from: usize, out: &mut [u8]) -> usize {
        self.with(|b| {
            let src = b.get(from..).unwrap_or(&[]);
            let n = src.len().min(out.len());
            out[..n].copy_from_slice(&src[..n]);
            n
        })
    }
}

fn push_recv(fd: &Fd, len: usize) -> io::Result<u64> {
    DRIVER.with(|d| {
        let mut d = d.borrow_mut();
        let d = d.as_mut().ok_or_else(no_ring)?;
        let group = if len <= SMALL.1 { d.small } else { d.large };

        d.start(|ring, tag| ring.push_recv(fd.clone(), len, group, tag))
    })
}

/// recv(2) of at most `len` bytes (at most the large buffers' size) from
/// the socket, into a provided buffer.
pub fn recv(fd: &Fd, len: usize) -> io::Result<Recv> {
    let tag = push_recv(fd, len)?;

    Ok(Recv { op: Op { tag, done: false }, fd: fd.clone(), len })
}

impl Future for Recv {
    type Output = io::Result<Received>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<Received>> {
        let this = self.get_mut();

        loop {
            let mut c = match this.op.poll_completion(cx) {
                Poll::Ready(c) => c,
                Poll::Pending => return Poll::Pending,
            };

            if c.result == -libc::ENOBUFS {
                // no provided buffer was free: again, at the next flush,
                // once the buffers dropped meanwhile are back
                DRIVER.with(|d| {
                    if let Some(d) = d.borrow_mut().as_mut() {
                        d.stats.no_buffers += 1;
                    }
                });

                match push_recv(&this.fd, this.len) {
                    Ok(tag) => {
                        this.op = Op { tag, done: false };
                        continue;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            return Poll::Ready(c.res().map(|_| Received { token: c.take_buffer() }));
        }
    }
}

/// sendmsg(2) of what a [`SendSource`] lends: the future of [`send`],
/// which gives the source back with the result.
pub struct Send<S> {
    op: Op,
    _source: PhantomData<fn() -> S>,
}

/// sendmsg(2) with MSG_NOSIGNAL of what `src` lends; on failure to queue
/// the operation, `src` comes back with the error.
pub fn send<S: SendSource>(fd: &Fd, src: S) -> Result<Send<S>, (io::Error, S)> {
    let r = DRIVER.with(|d| {
        let mut d = d.borrow_mut();
        let Some(d) = d.as_mut() else { return Err((no_ring(), src)) };

        d.start(|ring, tag| ring.push_send(fd.clone(), src, libc::MSG_NOSIGNAL, tag))
    });

    r.map(|tag| Send { op: Op { tag, done: false }, _source: PhantomData })
}

impl<S: SendSource> Send<S> {
    /// The send's output if it has completed, without waiting or
    /// registering a waker (poll_ready() waits).
    pub fn try_take(&mut self) -> Option<(io::Result<usize>, S)> {
        let mut c = DRIVER.with(|d| d.borrow_mut().as_mut().and_then(|d| d.try_take(self.op.tag)))?;

        self.op.done = true;

        let src = c.take_payload::<S>().expect("the source of a send");

        Some((c.res(), src))
    }

    /// Ready(true) once the send has completed (its output stays for
    /// try_take() or the future), Ready(false) once it is known to wait in
    /// the kernel for room in the socket (as C's NGX_AGAIN).
    pub fn poll_settled_ready(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.op.done {
            return Poll::Ready(true);
        }

        DRIVER.with(|d| d.borrow_mut().as_mut().expect("the io_uring driver").poll_settled_ready(self.op.tag, cx))
    }

    /// Ready once the send has completed; its output stays for try_take()
    /// or the future.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.op.done {
            return Poll::Ready(());
        }

        DRIVER.with(|d| d.borrow_mut().as_mut().expect("the io_uring driver").poll_ready(self.op.tag, cx))
    }

    /// The send's output if it completed in the flush that submitted it,
    /// or None once it is known to wait in the kernel for room in the
    /// socket (as C's NGX_AGAIN): the caller then awaits the future.
    pub fn poll_settled(&mut self, cx: &mut Context<'_>) -> Poll<Option<(io::Result<usize>, S)>> {
        match std::task::ready!(self.op.poll_settled(cx)) {
            Some(mut c) => {
                let src = c.take_payload::<S>().expect("the source of a send");
                Poll::Ready(Some((c.res(), src)))
            }
            None => Poll::Ready(None),
        }
    }
}

impl<S: SendSource> Future for Send<S> {
    type Output = (io::Result<usize>, S);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<(io::Result<usize>, S)> {
        let this = self.get_mut();
        let mut c = std::task::ready!(this.op.poll_completion(cx));
        let src = c.take_payload::<S>().expect("the source of a send");

        Poll::Ready((c.res(), src))
    }
}

/// recvmsg(2) into what a [`RecvTarget`] lends: the future of
/// [`recv_into`], which gives the target back with the result.
pub struct RecvInto<T> {
    op: Op,
    _target: PhantomData<fn() -> T>,
}

/// recvmsg(2) into what `dst` lends; on failure to queue the operation,
/// `dst` comes back with the error.
pub fn recv_into<T: RecvTarget>(fd: &Fd, dst: T) -> Result<RecvInto<T>, (io::Error, T)> {
    let r = DRIVER.with(|d| {
        let mut d = d.borrow_mut();
        let Some(d) = d.as_mut() else { return Err((no_ring(), dst)) };

        d.start(|ring, tag| ring.push_recv_into(fd.clone(), dst, 0, tag))
    });

    r.map(|tag| RecvInto { op: Op { tag, done: false }, _target: PhantomData })
}

impl<T: RecvTarget> Future for RecvInto<T> {
    type Output = (io::Result<usize>, T);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<(io::Result<usize>, T)> {
        let this = self.get_mut();
        let mut c = std::task::ready!(this.op.poll_completion(cx));
        let dst = c.take_payload::<T>().expect("the target of a receive");

        Poll::Ready((c.res(), dst))
    }
}

/// poll(2) of the socket for `events`, once: the future of [`poll_fd`],
/// whose output is the events that came.
pub struct PollFd {
    op: Op,
}

/// Waits for `events` (POLLIN, POLLOUT, POLLRDHUP, ...) on the socket.
pub fn poll_fd(fd: &Fd, events: u32) -> io::Result<PollFd> {
    let tag = DRIVER.with(|d| {
        let mut d = d.borrow_mut();
        let d = d.as_mut().ok_or_else(no_ring)?;

        d.start(|ring, tag| ring.push_poll(fd.clone(), events, tag))
    })?;

    Ok(PollFd { op: Op { tag, done: false } })
}

impl Future for PollFd {
    type Output = io::Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        let c = std::task::ready!(self.get_mut().op.poll_completion(cx));

        Poll::Ready(c.res().map(|n| n as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// Runs `f` in a LocalSet with the ring flushed after every run of the
    /// tasks, as event::block_on_events does; None where io_uring is not
    /// available (the test is skipped).
    fn run<F: Future + 'static>(f: impl FnOnce() -> F) -> Option<F::Output> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().on_thread_park(flush).build().unwrap();
        let local = tokio::task::LocalSet::new();
        let ok = local.block_on(&rt, async { init() });

        if let Err(e) = ok {
            eprintln!("io_uring not available, test skipped: {e}");
            return None;
        }

        let fut = f();
        let mut run = std::pin::pin!(local.run_until(fut));
        let out = rt.block_on(std::future::poll_fn(move |cx| {
            let r = run.as_mut().poll(cx);
            flush();
            r
        }));

        shutdown();

        Some(out)
    }

    /// A socket pair, the second end in the descriptor table.
    fn pair() -> (UnixStream, i32) {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        (a, fd::register(OwnedFd::from(b)))
    }

    #[test]
    fn send_and_recv() {
        run(|| async {
            let (mut a, n) = pair();
            let b = fd::get(n).unwrap();

            let (r, v) = send(&b, b"ping".to_vec()).map_err(|(e, _)| e).unwrap().await;
            assert_eq!(r.unwrap(), 4);
            assert_eq!(v, b"ping");
            let mut got = [0u8; 8];
            a.set_nonblocking(false).unwrap();
            assert_eq!(a.read(&mut got).unwrap(), 4);

            a.write_all(b"pong").unwrap();
            let rcv = recv(&b, 1024).unwrap().await.unwrap();
            let mut out = [0u8; 8];
            assert_eq!(rcv.copy_to(0, &mut out), 4);
            assert_eq!(&out[..4], b"pong");
            assert_eq!(rcv.copy_to(2, &mut out), 2);

            drop(b);
            fd::close(n).unwrap();
        });
    }

    #[test]
    fn recv_into_and_poll() {
        run(|| async {
            let (mut a, n) = pair();
            let b = fd::get(n).unwrap();

            let p = poll_fd(&b, libc::POLLIN as u32).unwrap();
            a.write_all(b"xyz").unwrap();
            assert!(p.await.unwrap() & libc::POLLIN as u32 != 0);

            let (r, v) = recv_into(&b, vec![0u8; 8]).map_err(|(e, _)| e).unwrap().await;
            assert_eq!(r.unwrap(), 3);
            assert_eq!(&v[..3], b"xyz");

            drop(b);
            fd::close(n).unwrap();
        });
    }

    #[test]
    fn end_of_stream() {
        run(|| async {
            let (a, n) = pair();
            let b = fd::get(n).unwrap();

            drop(a);
            let rcv = recv(&b, 64).unwrap().await.unwrap();
            assert!(rcv.is_empty());

            drop(b);
            fd::close(n).unwrap();
        });
    }

    /// A receive given up (a timeout) is cancelled, and the socket closed by
    /// fd::close() is closed for real at once: the peer sees the end.
    #[test]
    fn abandoned_recv_does_not_hold_the_socket() {
        run(|| async {
            let (mut a, n) = pair();
            let b = fd::get(n).unwrap();

            let r = tokio::time::timeout(Duration::from_millis(20), recv(&b, 64).unwrap()).await;
            assert!(r.is_err());

            drop(b);
            fd::close(n).unwrap();

            // the cancellation completes at the next flush
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(20)).await;

            a.set_nonblocking(false).unwrap();
            a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut got = [0u8; 1];
            assert_eq!(a.read(&mut got).unwrap(), 0);
        });
    }

    /// A completion while the thread is parked wakes it through the ring's
    /// descriptor.
    #[test]
    fn wakes_a_parked_thread() {
        run(|| async {
            let (a, n) = pair();
            let b = fd::get(n).unwrap();

            let writer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                let mut a = a;
                a.set_nonblocking(false).unwrap();
                a.write_all(b"late").unwrap();
                a
            });

            let rcv = recv(&b, 64).unwrap().await.unwrap();
            assert_eq!(rcv.len(), 4);
            drop(writer.join().unwrap());

            drop(b);
            fd::close(n).unwrap();
        });
    }

    #[test]
    fn flush_with_nothing_queued_makes_no_system_call() {
        run(|| async {
            flush();
            let before = stats().submits;
            for _ in 0..100 {
                flush();
            }
            assert_eq!(stats().submits, before);
        });
    }

    #[test]
    fn the_number_stays_reserved_until_the_completion() {
        run(|| async {
            let (mut a, n) = pair();
            let b = fd::get(n).unwrap();

            let rcv = recv(&b, 64).unwrap();
            flush();
            drop(b);
            fd::close(n).unwrap();

            // the descriptor stays open while the receive names it
            let (c, d) = UnixStream::pair().unwrap();
            assert_ne!(c.as_raw_fd(), n);
            assert_ne!(d.as_raw_fd(), n);

            a.write_all(b"ok").unwrap();
            assert_eq!(rcv.await.unwrap().len(), 2);
        });
    }
}
