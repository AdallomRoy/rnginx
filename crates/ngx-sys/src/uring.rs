//! io_uring for socket I/O (docs/IO_URING_PLAN.md): a ring whose
//! operations own everything the kernel may touch while they are in flight,
//! so that pushing them is safe.
//!
//! - An operation is pushed with its descriptor by value: any `AsFd` owner,
//!   which keeps the number open, naming the same file, until the
//!   completion. A send or a receive into the caller's memory also takes a
//!   [`SendSource`] or [`RecvTarget`] by value: the ring boxes it and asks
//!   it once, boxed, for the memory it lends.
//! - The ring keeps all that until the operation's completion is reaped,
//!   which hands it back ([`Completion`]). An operation that is cancelled
//!   still completes; its payload is freed then, never earlier.
//! - A receive into a provided buffer (buffer select) lends that buffer
//!   through a [`BufToken`]: its bytes can be read only while the token
//!   lives, and the buffer goes back to the kernel only after the token is
//!   dropped.
//! - Dropping the ring cancels what is in flight and waits for it; what the
//!   kernel might still touch after the wait is leaked, never freed.
//!
//! Memory the kernel reads or writes while an operation is in flight (the
//! payload, the iovecs, the msghdr, the provided buffers) is held through
//! raw pointers from Box::into_raw or an allocation, never through a Box or
//! a reference, which would claim it unshared.

use std::alloc::Layout;
use std::any::Any;
use std::cell::RefCell;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use io_uring::{cqueue, opcode, squeue, types, IoUring, Probe};

/// The user_data of the operations without a slot (cancellations).
const NO_SLOT: u64 = u64::MAX;

/// The iovecs of one send or receive, at most (IOV_MAX).
pub const MAX_IOVECS: usize = 1024;

/// What a send sends: memory that the object owns, or 'static memory.
pub trait SendSource: 'static {
    /// The bytes to send, in order. Called once, on the boxed object, which
    /// is not touched again until the send's completion returns it.
    fn slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>);
}

/// What a receive fills: memory that the object owns.
pub trait RecvTarget: 'static {
    /// The memory to receive into, in order. Called once, on the boxed
    /// object, which is not touched again until the receive's completion
    /// returns it.
    fn slices_mut<'a>(&'a mut self, out: &mut Vec<IoSliceMut<'a>>);
}

impl SendSource for Vec<u8> {
    fn slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>) {
        out.push(IoSlice::new(self));
    }
}

impl SendSource for Box<[u8]> {
    fn slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>) {
        out.push(IoSlice::new(self));
    }
}

impl SendSource for &'static [u8] {
    fn slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>) {
        out.push(IoSlice::new(self));
    }
}

impl RecvTarget for Vec<u8> {
    fn slices_mut<'a>(&'a mut self, out: &mut Vec<IoSliceMut<'a>>) {
        out.push(IoSliceMut::new(self));
    }
}

/// An operation in flight: its user_data (slot index and generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId(u64);

impl OpId {
    fn new(index: u32, gen: u32) -> OpId {
        OpId(((gen as u64) << 32) | index as u64)
    }

    fn index(self) -> usize {
        self.0 as u32 as usize
    }

    fn gen(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// A group of provided buffers, as returned by [`Ring::add_buffer_group`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufGroup(u16);

/// What the kernel may touch while an operation is in flight, and the
/// descriptor it names.
struct InFlight {
    /// the caller's tag, handed back with the completion
    tag: u64,
    /// the owner of the descriptor
    keeper: Box<dyn Any>,
    /// Box::into_raw() of the send source or receive target
    payload: Option<*mut dyn Any>,
    /// Box::into_raw() of the iovecs of the payload
    iov: Option<*mut [libc::iovec]>,
    /// Box::into_raw() of the msghdr pointing at the iovecs
    msg: Option<*mut libc::msghdr>,
    /// the group of a buffer-select receive
    group: Option<u16>,
}

impl InFlight {
    /// The payload back, the iovecs and the msghdr freed: once the kernel
    /// is done with them (a final completion, or never submitted).
    fn release(self) -> (Box<dyn Any>, Option<Box<dyn Any>>) {
        // SAFETY: each pointer comes from Box::into_raw() of this
        // operation's own allocation, and the kernel is done with it.
        unsafe {
            if let Some(msg) = self.msg {
                drop(Box::from_raw(msg));
            }
            if let Some(iov) = self.iov {
                drop(Box::from_raw(iov));
            }
            (self.keeper, self.payload.map(|p| Box::from_raw(p)))
        }
    }
}

struct Slot {
    gen: u32,
    op: Option<InFlight>,
}

/// The completion of an operation.
pub struct Completion {
    /// the tag the operation was pushed with
    pub tag: u64,
    /// the operation
    pub op: OpId,
    /// the result: what the system call would have returned, or -errno
    pub result: i32,
    /// the completion's flags (IORING_CQE_F_*)
    pub flags: u32,
    keeper: Option<Box<dyn Any>>,
    payload: Option<Box<dyn Any>>,
    buffer: Option<BufToken>,
}

impl Completion {
    /// The result as io::Result.
    pub fn res(&self) -> io::Result<usize> {
        if self.result < 0 {
            return Err(io::Error::from_raw_os_error(-self.result));
        }

        Ok(self.result as usize)
    }

    /// The send source or receive target the operation was pushed with.
    pub fn take_payload<T: 'static>(&mut self) -> Option<T> {
        self.payload.take()?.downcast::<T>().ok().map(|b| *b)
    }

    /// The provided buffer a receive filled.
    pub fn take_buffer(&mut self) -> Option<BufToken> {
        self.buffer.take()
    }

    /// The descriptor owner the operation was pushed with.
    pub fn take_keeper(&mut self) -> Option<Box<dyn Any>> {
        self.keeper.take()
    }

    /// More completions of the operation follow (a multishot operation).
    pub fn more(&self) -> bool {
        cqueue::more(self.flags)
    }
}

/// A provided buffer lent by a receive's completion: read it with
/// [`Ring::buffer`]; dropping the token gives it back to its ring, which
/// gives it back to the kernel at its next submit or reap.
pub struct BufToken {
    ring: u64,
    group: u16,
    bid: u16,
    len: u32,
    returned: Rc<RefCell<Vec<(u16, u16)>>>,
}

impl BufToken {
    /// The bytes received.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for BufToken {
    fn drop(&mut self) {
        self.returned.borrow_mut().push((self.group, self.bid));
    }
}

impl std::fmt::Debug for BufToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BufToken({}:{}, {} bytes)", self.group, self.bid, self.len)
    }
}

/// A group of provided buffers: a buffer ring registered with the kernel
/// (entries the kernel reads up to the tail we publish) and the buffers.
struct Group {
    bgid: u16,
    /// the ring's entries (page aligned, zeroed), `entries` of them
    ring: *mut u8,
    ring_layout: Layout,
    entries: u16,
    tail: u16,
    /// the buffers, `entries` of `size` bytes
    mem: *mut u8,
    mem_layout: Layout,
    size: usize,
}

impl Group {
    /// Hands buffer `bid` to the kernel (seen once the tail is published).
    fn add(&mut self, bid: u16) {
        let idx = (self.tail & (self.entries - 1)) as usize;

        // SAFETY: idx < entries, so the entry (struct io_uring_buf: u64
        // addr, u32 len, u16 bid, u16 resv) is inside the ring's allocation,
        // its fields aligned (the ring is page aligned, entries 16 bytes);
        // the kernel does not read entries past the published tail, so
        // nothing reads this one now. Only the three fields are written:
        // the first entry's resv is the tail, which the kernel reads. The
        // address is inside the buffers' allocation (bid < entries).
        unsafe {
            let e = self.ring.add(idx * std::mem::size_of::<types::BufRingEntry>());
            ptr::write(e as *mut u64, self.mem.add(bid as usize * self.size) as u64);
            ptr::write(e.add(8) as *mut u32, self.size as u32);
            ptr::write(e.add(12) as *mut u16, bid);
        }

        self.tail = self.tail.wrapping_add(1);
    }

    /// The tail published: the entries added are the kernel's.
    fn publish(&self) {
        // SAFETY: the tail is the u16 at offset 14 of the ring's first
        // entry (struct io_uring_buf_ring), inside the allocation, 2-aligned
        // (the ring is page aligned); the kernel reads it concurrently, so
        // it is written as an atomic, with release ordering for the entries.
        unsafe { (*(self.ring.add(14) as *const AtomicU16)).store(self.tail, Ordering::Release) };
    }
}

static RING_IDS: AtomicU64 = AtomicU64::new(1);

/// An io_uring instance of the calling thread.
pub struct Ring {
    ring: IoUring,
    id: u64,
    slots: Vec<Slot>,
    free: Vec<u32>,
    in_flight: usize,
    groups: Vec<Group>,
    /// the provided buffers given back (group index, bid), not yet the
    /// kernel's again
    returned: Rc<RefCell<Vec<(u16, u16)>>>,
}

impl Ring {
    /// A ring of `entries` submission entries (completion queue twice
    /// that), set up for one thread (SINGLE_ISSUER, COOP_TASKRUN with the
    /// TASKRUN flag, SUBMIT_ALL). Fails unless the kernel has everything
    /// the plan uses: RECV, SENDMSG, RECVMSG, POLL_ADD and ASYNC_CANCEL.
    pub fn new(entries: u32) -> io::Result<Ring> {
        let ring: IoUring = IoUring::builder()
            .setup_single_issuer()
            .setup_coop_taskrun()
            .setup_taskrun_flag()
            .setup_submit_all()
            .build(entries)?;

        let mut probe = Probe::new();
        ring.submitter().register_probe(&mut probe)?;

        for code in [opcode::Recv::CODE, opcode::SendMsg::CODE, opcode::RecvMsg::CODE, opcode::PollAdd::CODE, opcode::AsyncCancel::CODE] {
            if !probe.is_supported(code) {
                return Err(io::Error::new(io::ErrorKind::Unsupported, format!("io_uring opcode {} is not supported", code)));
            }
        }

        Ok(Ring {
            ring,
            id: RING_IDS.fetch_add(1, Ordering::Relaxed),
            slots: Vec::new(),
            free: Vec::new(),
            in_flight: 0,
            groups: Vec::new(),
            returned: Rc::new(RefCell::new(Vec::new())),
        })
    }

    /// The ring's descriptor, readable when completions wait to be reaped
    /// (for a reactor to wake the thread).
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.ring.as_fd()
    }

    /// The operations in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Registers `count` provided buffers of `size` bytes (count a power of
    /// two, at most 32768) for buffer-select receives (5.19).
    pub fn add_buffer_group(&mut self, count: u16, size: usize) -> io::Result<BufGroup> {
        if !count.is_power_of_two() || count > 32768 || size == 0 || size > u32::MAX as usize {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        let bgid = self.groups.len() as u16;
        let ring_layout = Layout::from_size_align(count as usize * std::mem::size_of::<types::BufRingEntry>(), 4096).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let mem_layout = Layout::from_size_align(count as usize * size, 64).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        // SAFETY: both layouts have a non-zero size (count and size > 0).
        let (ring, mem) = unsafe { (std::alloc::alloc_zeroed(ring_layout), std::alloc::alloc(mem_layout)) };

        if ring.is_null() || mem.is_null() {
            // SAFETY: what was allocated, with its layout
            unsafe {
                if !ring.is_null() {
                    std::alloc::dealloc(ring, ring_layout);
                }
                if !mem.is_null() {
                    std::alloc::dealloc(mem, mem_layout);
                }
            }
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }

        // SAFETY: the ring's memory is page aligned, zeroed, for `count`
        // entries, and stays allocated until the group is unregistered (in
        // drop(), or leaked); the kernel reads only the entries we publish.
        if let Err(e) = unsafe { self.ring.submitter().register_buf_ring_with_flags(ring as u64, count, bgid, 0) } {
            // SAFETY: never registered: nothing else uses the memory
            unsafe {
                std::alloc::dealloc(ring, ring_layout);
                std::alloc::dealloc(mem, mem_layout);
            }
            return Err(e);
        }

        let mut g = Group { bgid, ring, ring_layout, entries: count, tail: 0, mem, mem_layout, size };

        for bid in 0..count {
            g.add(bid);
        }

        g.publish();
        self.groups.push(g);

        Ok(BufGroup(bgid))
    }

    /// The buffer size of a group.
    pub fn buffer_size(&self, group: BufGroup) -> usize {
        self.groups[group.0 as usize].size
    }

    /// The bytes a receive put in a provided buffer.
    pub fn buffer<'a>(&'a self, token: &'a BufToken) -> &'a [u8] {
        assert_eq!(token.ring, self.id, "a provided buffer of another ring");

        let g = &self.groups[token.group as usize];

        // SAFETY: the buffer is inside the group's allocation (bid <
        // entries, len <= size); while the token lives, the buffer is not
        // the kernel's (it goes back only once the token is dropped, and
        // only by a call borrowing the ring mutably, which this borrow
        // excludes), so nothing writes it while the slice lives.
        unsafe { std::slice::from_raw_parts(g.mem.add(token.bid as usize * g.size), token.len as usize) }
    }

    fn alloc(&mut self) -> OpId {
        let index = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push(Slot { gen: 0, op: None });
                (self.slots.len() - 1) as u32
            }
        };

        let slot = &mut self.slots[index as usize];

        slot.gen = slot.gen.wrapping_add(1);

        // u64::MAX is NO_SLOT
        if slot.gen == u32::MAX && index == u32::MAX {
            slot.gen = 0;
        }

        OpId::new(index, slot.gen)
    }

    /// Queues the entry of an operation whose slot holds what it
    /// references; on failure the slot is emptied and what it held handed
    /// back.
    fn push_op(&mut self, op: OpId, sqe: squeue::Entry, inflight: InFlight) -> Result<OpId, InFlight> {
        self.slots[op.index()].op = Some(inflight);

        if self.push_entry(&sqe.user_data(op.0)).is_err() {
            self.free.push(op.index() as u32);
            return Err(self.slots[op.index()].op.take().expect("the slot of an operation"));
        }

        self.in_flight += 1;

        Ok(op)
    }

    /// Queues an entry, submitting the queued ones if the queue is full.
    fn push_entry(&mut self, sqe: &squeue::Entry) -> io::Result<()> {
        for _ in 0..2 {
            // SAFETY: the memory an entry references (iovecs, msghdr,
            // payload, provided buffers) is held by its slot, or the ring,
            // until its final completion is reaped, and drop() waits for
            // every operation (or leaks what is left); its descriptor is
            // kept open by the slot's keeper.
            if unsafe { self.ring.submission().push(sqe) }.is_ok() {
                return Ok(());
            }

            self.submit()?;
        }

        Err(io::Error::new(io::ErrorKind::WouldBlock, "io_uring submission queue full"))
    }

    /// recv(2) of at most `len` bytes (at most the group's buffer size)
    /// into a provided buffer of `group`, lent by the completion.
    pub fn push_recv<K: AsFd + 'static>(&mut self, fd: K, len: usize, group: BufGroup, tag: u64) -> io::Result<OpId> {
        let g = &self.groups[group.0 as usize];
        let len = len.min(g.size) as u32;
        let bgid = g.bgid;
        let raw = fd.as_fd().as_raw_fd();
        let op = self.alloc();

        let sqe = opcode::Recv::new(types::Fd(raw), ptr::null_mut(), len).buf_group(bgid).build().flags(squeue::Flags::BUFFER_SELECT);

        let inflight = InFlight { tag, keeper: Box::new(fd), payload: None, iov: None, msg: None, group: Some(group.0) };

        self.push_op(op, sqe, inflight).map_err(|f| {
            drop(f.release());
            io::Error::new(io::ErrorKind::WouldBlock, "io_uring submission queue full")
        })
    }

    /// The iovecs and msghdr of a payload's slices.
    fn msghdr(slices: &[(*mut libc::c_void, usize)]) -> (*mut [libc::iovec], *mut libc::msghdr) {
        let iov: Box<[libc::iovec]> = slices.iter().take(MAX_IOVECS).map(|&(base, len)| libc::iovec { iov_base: base, iov_len: len }).collect();
        let n = iov.len();
        let iov = Box::into_raw(iov);

        // SAFETY: msghdr is plain data, all zeros valid (no name, no
        // control); the iovecs pointer is that of the allocation just made.
        let msg = unsafe {
            let mut m: libc::msghdr = std::mem::zeroed();
            m.msg_iov = iov as *mut libc::iovec;
            m.msg_iovlen = n as _;
            m
        };

        (iov, Box::into_raw(Box::new(msg)))
    }

    /// sendmsg(2) of what `src` lends, with `flags` (MSG_NOSIGNAL, ...);
    /// the completion hands `src` back. On failure to queue, `src` comes
    /// back with the error.
    pub fn push_send<K: AsFd + 'static, S: SendSource>(&mut self, fd: K, src: S, flags: i32, tag: u64) -> Result<OpId, (io::Error, S)> {
        let raw = fd.as_fd().as_raw_fd();
        let p: *mut S = Box::into_raw(Box::new(src));

        let mut slices: Vec<(*mut libc::c_void, usize)> = Vec::new();

        {
            // SAFETY: p comes from Box::into_raw() and nothing else refers
            // to it; this borrow ends with the block.
            let s: &S = unsafe { &*p };
            let mut v: Vec<IoSlice<'_>> = Vec::new();
            s.slices(&mut v);
            slices.extend(v.iter().map(|sl| (sl.as_ptr() as *mut libc::c_void, sl.len())));
        }

        // The slices lent are memory the boxed object owns (or 'static):
        // safe code can lend nothing else for as long as the borrow of the
        // object, and the object is not touched until the completion, so
        // the memory stays valid and unwritten while the kernel reads it.
        let (iov, msg) = Self::msghdr(&slices);
        let op = self.alloc();

        let sqe = opcode::SendMsg::new(types::Fd(raw), msg).flags(flags as u32).build();

        let inflight = InFlight { tag, keeper: Box::new(fd), payload: Some(p as *mut dyn Any), iov: Some(iov), msg: Some(msg), group: None };

        self.push_op(op, sqe, inflight).map_err(|f| {
            let (_, payload) = f.release();
            let src = *payload.expect("the payload of a send").downcast::<S>().expect("the payload's type");
            (io::Error::new(io::ErrorKind::WouldBlock, "io_uring submission queue full"), src)
        })
    }

    /// recvmsg(2) into what `dst` lends, with `flags`; the completion hands
    /// `dst` back. On failure to queue, `dst` comes back with the error.
    pub fn push_recv_into<K: AsFd + 'static, T: RecvTarget>(&mut self, fd: K, dst: T, flags: i32, tag: u64) -> Result<OpId, (io::Error, T)> {
        let raw = fd.as_fd().as_raw_fd();
        let p: *mut T = Box::into_raw(Box::new(dst));

        let mut slices: Vec<(*mut libc::c_void, usize)> = Vec::new();

        {
            // SAFETY: p comes from Box::into_raw() and nothing else refers
            // to it; this borrow ends with the block.
            let t: &mut T = unsafe { &mut *p };
            let mut v: Vec<IoSliceMut<'_>> = Vec::new();
            t.slices_mut(&mut v);
            slices.extend(v.iter_mut().map(|sl| (sl.as_mut_ptr() as *mut libc::c_void, sl.len())));
        }

        // The slices lent are memory only the boxed object reaches (safe
        // code can lend nothing else mutably for as long as the borrow of
        // the object), and the object is not touched until the completion,
        // so only the kernel writes the memory meanwhile.
        let (iov, msg) = Self::msghdr(&slices);
        let op = self.alloc();

        let sqe = opcode::RecvMsg::new(types::Fd(raw), msg).flags(flags as u32).build();

        let inflight = InFlight { tag, keeper: Box::new(fd), payload: Some(p as *mut dyn Any), iov: Some(iov), msg: Some(msg), group: None };

        self.push_op(op, sqe, inflight).map_err(|f| {
            let (_, payload) = f.release();
            let dst = *payload.expect("the payload of a receive").downcast::<T>().expect("the payload's type");
            (io::Error::new(io::ErrorKind::WouldBlock, "io_uring submission queue full"), dst)
        })
    }

    /// poll(2) of the descriptor for `events` (POLLIN, POLLOUT, POLLRDHUP,
    /// ...), once: the completion's result is the events that came.
    pub fn push_poll<K: AsFd + 'static>(&mut self, fd: K, events: u32, tag: u64) -> io::Result<OpId> {
        let raw = fd.as_fd().as_raw_fd();
        let op = self.alloc();

        let sqe = opcode::PollAdd::new(types::Fd(raw), events).build();

        let inflight = InFlight { tag, keeper: Box::new(fd), payload: None, iov: None, msg: None, group: None };

        self.push_op(op, sqe, inflight).map_err(|f| {
            drop(f.release());
            io::Error::new(io::ErrorKind::WouldBlock, "io_uring submission queue full")
        })
    }

    /// Cancels an operation: it completes soon, with -ECANCELED unless it
    /// had completed already. Nothing to do for an operation reaped.
    pub fn push_cancel(&mut self, op: OpId) -> io::Result<()> {
        match self.slots.get(op.index()) {
            Some(s) if s.gen == op.gen() && s.op.is_some() => {}
            _ => return Ok(()),
        }

        self.push_entry(&opcode::AsyncCancel::new(op.0).build().user_data(NO_SLOT))
    }

    /// Whether submit() has anything to do: entries queued, task work of
    /// the kernel waiting to run, or completions that overflowed.
    pub fn needs_submit(&mut self) -> bool {
        let sq = self.ring.submission();

        !sq.is_empty() || sq.taskrun() || sq.cq_overflow()
    }

    /// Submits the queued entries, running the kernel's task work (which
    /// posts the completions of what became ready); the provided buffers
    /// given back go to the kernel first.
    pub fn submit(&mut self) -> io::Result<usize> {
        self.publish_returned();

        loop {
            match self.ring.submitter().submit() {
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                r => return r,
            }
        }
    }

    /// Submits, then waits up to `timeout` for a completion.
    fn submit_and_wait(&mut self, timeout: Duration) -> io::Result<usize> {
        self.publish_returned();

        let ts = types::Timespec::from(timeout);
        let args = types::SubmitArgs::new().timespec(&ts);

        self.ring.submitter().submit_with_args(1, &args)
    }

    /// The provided buffers given back, the kernel's again.
    fn publish_returned(&mut self) {
        let mut returned = self.returned.borrow_mut();

        if returned.is_empty() {
            return;
        }

        let mut touched = 0u64;

        for (group, bid) in returned.drain(..) {
            self.groups[group as usize].add(bid);
            touched |= 1 << (group % 64);
        }

        for (i, g) in self.groups.iter().enumerate() {
            if touched & (1 << (i % 64)) != 0 {
                g.publish();
            }
        }
    }

    /// Reaps the completions waiting, giving each to `f`; returns how many.
    pub fn reap(&mut self, mut f: impl FnMut(Completion)) -> usize {
        let mut n = 0;

        let id = self.id;
        let returned = self.returned.clone();
        let mut cq = self.ring.completion();

        cq.sync();

        for cqe in &mut cq {
            let user_data = cqe.user_data();

            if user_data == NO_SLOT {
                continue;
            }

            let op = OpId(user_data);

            let slot = match self.slots.get_mut(op.index()) {
                Some(s) if s.gen == op.gen() && s.op.is_some() => s,
                _ => continue,
            };

            let flags = cqe.flags();
            let result = cqe.result();

            let group = slot.op.as_ref().and_then(|f| f.group);

            let buffer = match (group, cqueue::buffer_select(flags)) {
                (Some(group), Some(bid)) => Some(BufToken { ring: id, group, bid, len: result.max(0) as u32, returned: returned.clone() }),
                _ => None,
            };

            let tag = slot.op.as_ref().map(|f| f.tag).unwrap_or(0);

            if cqueue::more(flags) {
                // a multishot operation goes on: its payload stays
                f(Completion { tag, op, result, flags, keeper: None, payload: None, buffer });
                n += 1;
                continue;
            }

            let (keeper, payload) = slot.op.take().expect("the slot of an operation").release();

            self.free.push(op.index() as u32);
            self.in_flight -= 1;

            f(Completion { tag, op, result, flags, keeper: Some(keeper), payload, buffer });
            n += 1;
        }

        drop(cq);

        self.publish_returned();

        n
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if self.in_flight > 0 {
            let cancel = opcode::AsyncCancel2::new(types::CancelBuilder::any()).build().user_data(NO_SLOT);

            let _ = self.push_entry(&cancel);

            let deadline = Instant::now() + Duration::from_secs(5);

            while self.in_flight > 0 && Instant::now() < deadline {
                let _ = self.submit_and_wait(Duration::from_millis(100));
                self.reap(drop);
            }

            if self.in_flight > 0 {
                // the kernel may still touch the payloads and the buffers:
                // leaked, never freed
                for slot in self.slots.drain(..) {
                    std::mem::forget(slot);
                }
                for g in self.groups.drain(..) {
                    std::mem::forget(g);
                }
                return;
            }
        }

        for g in self.groups.drain(..) {
            let _ = self.ring.submitter().unregister_buf_ring(g.bgid);

            // SAFETY: unregistered, and no operation is in flight: the
            // kernel no longer reads the ring or writes the buffers.
            unsafe {
                std::alloc::dealloc(g.ring, g.ring_layout);
                std::alloc::dealloc(g.mem, g.mem_layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::io::{Read, Write};

    /// A ring, or None (the test is skipped) where io_uring is not
    /// available (seccomp, sysctl, old kernel).
    fn ring() -> Option<Ring> {
        match Ring::new(64) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("io_uring not available, test skipped: {e}");
                None
            }
        }
    }

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        (a, b)
    }

    fn owned(s: &UnixStream) -> OwnedFd {
        s.as_fd().try_clone_to_owned().unwrap()
    }

    /// Submits and reaps until `n` completions came.
    fn wait(r: &mut Ring, n: usize) -> Vec<Completion> {
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while out.len() < n {
            assert!(Instant::now() < deadline, "no completion");
            r.submit_and_wait(Duration::from_millis(10)).ok();
            r.reap(|c| out.push(c));
        }
        out
    }

    #[test]
    fn recv_into_provided_buffer() {
        let Some(mut r) = ring() else { return };
        let g = r.add_buffer_group(4, 64).unwrap();
        let (mut a, b) = pair();

        a.write_all(b"hello").unwrap();
        r.push_recv(owned(&b), 1024, g, 7).unwrap();

        let mut c = wait(&mut r, 1);
        let mut c = c.remove(0);
        assert_eq!(c.tag, 7);
        assert_eq!(c.res().unwrap(), 5);
        let t = c.take_buffer().unwrap();
        assert_eq!(r.buffer(&t), b"hello");
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn recv_waits_and_capped_length() {
        let Some(mut r) = ring() else { return };
        let g = r.add_buffer_group(2, 8).unwrap();
        let (mut a, b) = pair();

        r.push_recv(owned(&b), 4, g, 1).unwrap();
        r.submit().unwrap();
        assert_eq!(r.reap(drop), 0);

        a.write_all(b"0123456789").unwrap();
        let mut c = wait(&mut r, 1).remove(0);
        let t = c.take_buffer().unwrap();
        assert_eq!(r.buffer(&t), b"0123");
    }

    #[test]
    fn buffers_come_back_once_dropped() {
        let Some(mut r) = ring() else { return };
        let g = r.add_buffer_group(1, 16).unwrap();
        let (mut a, b) = pair();

        a.write_all(b"one").unwrap();
        r.push_recv(owned(&b), 16, g, 1).unwrap();
        let mut c = wait(&mut r, 1).remove(0);
        let t = c.take_buffer().unwrap();

        // the only buffer is lent: the next receive finds none
        a.write_all(b"two").unwrap();
        r.push_recv(owned(&b), 16, g, 2).unwrap();
        let c2 = wait(&mut r, 1).remove(0);
        assert_eq!(c2.result, -libc::ENOBUFS);

        drop(t);
        drop(c);
        r.push_recv(owned(&b), 16, g, 3).unwrap();
        let mut c3 = wait(&mut r, 1).remove(0);
        let t3 = c3.take_buffer().unwrap();
        assert_eq!(r.buffer(&t3), b"two");
    }

    #[test]
    fn send_hands_the_source_back() {
        let Some(mut r) = ring() else { return };
        let (a, mut b) = pair();

        struct Two(Vec<u8>, Vec<u8>);
        impl SendSource for Two {
            fn slices<'a>(&'a self, out: &mut Vec<IoSlice<'a>>) {
                out.push(IoSlice::new(&self.0));
                out.push(IoSlice::new(&self.1));
            }
        }

        r.push_send(owned(&a), Two(b"head".to_vec(), b"-body".to_vec()), libc::MSG_NOSIGNAL, 9).map_err(|(e, _)| e).unwrap();
        let mut c = wait(&mut r, 1).remove(0);
        assert_eq!(c.res().unwrap(), 9);
        let two = c.take_payload::<Two>().unwrap();
        assert_eq!(two.1, b"-body");

        let mut got = [0u8; 16];
        let n = b.read(&mut got).unwrap();
        assert_eq!(&got[..n], b"head-body");
    }

    #[test]
    fn recv_into_hands_the_target_back() {
        let Some(mut r) = ring() else { return };
        let (mut a, b) = pair();

        a.write_all(b"abc").unwrap();
        r.push_recv_into(owned(&b), vec![0u8; 8], 0, 4).map_err(|(e, _)| e).unwrap();
        let mut c = wait(&mut r, 1).remove(0);
        assert_eq!(c.res().unwrap(), 3);
        let v = c.take_payload::<Vec<u8>>().unwrap();
        assert_eq!(&v[..3], b"abc");
    }

    #[test]
    fn poll_reports_the_events() {
        let Some(mut r) = ring() else { return };
        let (mut a, b) = pair();

        r.push_poll(owned(&b), libc::POLLIN as u32, 5).unwrap();
        r.submit().unwrap();
        assert_eq!(r.reap(drop), 0);

        a.write_all(b"x").unwrap();
        let c = wait(&mut r, 1).remove(0);
        assert!(c.result as i16 & libc::POLLIN != 0);
    }

    #[test]
    fn cancel_completes_the_operation() {
        let Some(mut r) = ring() else { return };
        let g = r.add_buffer_group(2, 16).unwrap();
        let (_a, b) = pair();

        let op = r.push_recv(owned(&b), 16, g, 1).unwrap();
        r.submit().unwrap();
        r.push_cancel(op).unwrap();
        let c = wait(&mut r, 1).remove(0);
        assert_eq!(c.result, -libc::ECANCELED);
        assert_eq!(r.in_flight(), 0);

        // a reaped operation: nothing to cancel
        r.push_cancel(op).unwrap();
    }

    #[test]
    fn keeper_holds_the_descriptor_until_the_completion() {
        let Some(mut r) = ring() else { return };
        let (mut a, b) = pair();

        let fd = owned(&b);
        let raw = fd.as_raw_fd();
        r.push_recv_into(fd, vec![0u8; 4], 0, 1).map_err(|(e, _)| e).unwrap();
        r.submit().unwrap();
        drop(b);

        // the number still names the socket: a new descriptor gets another
        let other = UnixStream::pair().unwrap();
        assert_ne!(other.0.as_raw_fd(), raw);
        assert_ne!(other.1.as_raw_fd(), raw);

        a.write_all(b"ok").unwrap();
        let mut c = wait(&mut r, 1).remove(0);
        assert_eq!(c.res().unwrap(), 2);
        assert!(c.take_keeper().is_some());
    }

    #[test]
    fn drop_with_operations_in_flight() {
        let Some(mut r) = ring() else { return };
        let g = r.add_buffer_group(2, 16).unwrap();
        let (_a, b) = pair();

        r.push_recv(owned(&b), 16, g, 1).unwrap();
        r.push_recv_into(owned(&b), vec![0u8; 4], 0, 2).map_err(|(e, _)| e).unwrap();
        r.submit().unwrap();

        let start = Instant::now();
        drop(r);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
