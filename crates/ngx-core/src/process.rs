#![forbid(unsafe_code)]
//! Process management: master/worker cycle, signals, channels (ngx_process*.c).

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::ffi::{CString, OsStr};
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, LazyLock};

use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use signal_hook::iterator::backend::SignalDelivery;
use signal_hook::iterator::exfiltrator::WithOrigin;

use crate::core_module::{core_conf, delete_pidfile};
use crate::cycle::*;
use crate::log::*;
use crate::string::B;
use crate::{fd, ngx_log_debug, ngx_log_error, os};

pub const NGX_MAX_PROCESSES: usize = 1024;
pub const NGX_PROCESS_NORESPAWN: i64 = -1;
pub const NGX_PROCESS_JUST_SPAWN: i64 = -2;
pub const NGX_PROCESS_RESPAWN: i64 = -3;
pub const NGX_PROCESS_JUST_RESPAWN: i64 = -4;
pub const NGX_PROCESS_DETACHED: i64 = -5;

pub const NGX_CMD_OPEN_CHANNEL: u32 = 1;
pub const NGX_CMD_CLOSE_CHANNEL: u32 = 2;
pub const NGX_CMD_QUIT: u32 = 3;
pub const NGX_CMD_TERMINATE: u32 = 4;
pub const NGX_CMD_REOPEN: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Channel {
    pub command: u32,
    pub pid: i32,
    pub slot: i32,
    pub fd: i32,
}

/// The size of a channel message: the four fields, as the repr(C)
/// structure lays them out
const CHANNEL_SIZE: usize = std::mem::size_of::<Channel>();

impl Channel {
    /// The message as sent: the fields in their order, native endian.
    fn to_bytes(self) -> [u8; CHANNEL_SIZE] {
        let mut b = [0u8; CHANNEL_SIZE];

        b[0..4].copy_from_slice(&self.command.to_ne_bytes());
        b[4..8].copy_from_slice(&self.pid.to_ne_bytes());
        b[8..12].copy_from_slice(&self.slot.to_ne_bytes());
        b[12..16].copy_from_slice(&self.fd.to_ne_bytes());

        b
    }

    fn from_bytes(b: &[u8; CHANNEL_SIZE]) -> Channel {
        let field = |i: usize| [b[i], b[i + 1], b[i + 2], b[i + 3]];

        Channel {
            command: u32::from_ne_bytes(field(0)),
            pid: i32::from_ne_bytes(field(4)),
            slot: i32::from_ne_bytes(field(8)),
            fd: i32::from_ne_bytes(field(12)),
        }
    }
}

pub type ProcFn = fn(Rc<Cycle>, i64) -> !;

#[derive(Clone)]
pub struct Process {
    pub pid: i32,
    pub status: i32,
    pub channel: [i32; 2],
    pub proc_fn: Option<ProcFn>,
    pub data: i64,
    pub name: &'static str,
    pub respawn: bool,
    pub just_spawn: bool,
    pub detached: bool,
    pub exiting: bool,
    pub exited: bool,
}

thread_local! {
    pub static PROCESSES: RefCell<Vec<Process>> = RefCell::new(Vec::new());
    pub static PROCESS_SLOT: Cell<usize> = const { Cell::new(0) };
    pub static CHANNEL: Cell<i32> = const { Cell::new(-1) };
    static ARGV: RefCell<Vec<CString>> = RefCell::new(Vec::new());
}

// --- signal flags ---

/// A flag the signal handler sets itself.
type HandlerFlag = LazyLock<Arc<AtomicBool>>;

const fn handler_flag() -> HandlerFlag {
    LazyLock::new(|| Arc::new(AtomicBool::new(false)))
}

/// ngx_quit, ngx_terminate and ngx_reopen, which SIGQUIT, SIGTERM (and
/// SIGINT) and SIGUSR1 set in every kind of process: set by the signal
/// handler, as in C. The other flags are set when the signals are
/// processed (process_signals()).
pub static SIG_QUIT: HandlerFlag = handler_flag();
pub static SIG_TERMINATE: HandlerFlag = handler_flag();
pub static SIG_REOPEN: HandlerFlag = handler_flag();
pub static SIG_RECONFIGURE: AtomicBool = AtomicBool::new(false);
pub static SIG_NOACCEPT: AtomicBool = AtomicBool::new(false);
pub static SIG_CHANGE_BINARY: AtomicBool = AtomicBool::new(false);
pub static SIG_ALRM: AtomicBool = AtomicBool::new(false);
pub static SIG_IO: AtomicBool = AtomicBool::new(false);
pub static SIG_REAP: AtomicBool = AtomicBool::new(false);
pub static DEBUG_QUIT: AtomicBool = AtomicBool::new(false);
pub static DAEMONIZED: AtomicBool = AtomicBool::new(false);
pub static NEW_BINARY: AtomicI32 = AtomicI32::new(0);

/// the handler ran: there are signals to process
static SIGNALED: HandlerFlag = handler_flag();
/// a signal but SIGALRM (ngx_event_timer_alarm) came since the event loop
/// blocked in epoll_wait(): it interrupted the wait (EINTR in
/// ngx_epoll_process_events())
static INTERRUPTED: HandlerFlag = handler_flag();

static PROCESS_KIND: AtomicI32 = AtomicI32::new(0); // 0 single, 1 master, 3 worker, 4 helper

/// ngx_signals[]: the signals of ngx_signal_handler() and their names
const SIGNALS: [(i32, &str); 10] = [
    (libc::SIGHUP, "SIGHUP"),
    (libc::SIGUSR1, "SIGUSR1"),
    (libc::SIGWINCH, "SIGWINCH"),
    (libc::SIGTERM, "SIGTERM"),
    (libc::SIGQUIT, "SIGQUIT"),
    (libc::SIGUSR2, "SIGUSR2"),
    (libc::SIGALRM, "SIGALRM"),
    (libc::SIGINT, "SIGINT"),
    (libc::SIGIO, "SIGIO"),
    (libc::SIGCHLD, "SIGCHLD"),
];

/// The handler of the signals: it records each signal with the pid of its
/// sender (si_pid) and wakes the process through a pipe of its own.
type Delivery = SignalDelivery<UnixStream, WithOrigin>;

thread_local! {
    /// the signal handler's records of this process
    static DELIVERY: RefCell<Option<Delivery>> = const { RefCell::new(None) };
    /// the timer of the master's SIGALRM (setitimer(ITIMER_REAL))
    static ALARM: RefCell<Option<nix::sys::timer::Timer>> = const { RefCell::new(None) };
}

pub fn set_process_kind(pt: ProcessType) {
    let k = match pt {
        ProcessType::Single => 0,
        ProcessType::Master => 1,
        ProcessType::Signaller => 2,
        ProcessType::Worker => 3,
        ProcessType::Helper => 4,
    };
    PROCESS_KIND.store(k, Ordering::Relaxed);
    globals_mut(|g| g.process = pt);
}

pub fn save_argv(args: &[String]) {
    ARGV.with(|a| *a.borrow_mut() = args.iter().map(|s| CString::new(s.as_bytes()).unwrap()).collect());
}

pub fn argv() -> Vec<CString> {
    ARGV.with(|a| a.borrow().clone())
}

/// The errno of an error of std or ngx-sys.
fn io_errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn signame(signo: i32) -> &'static str {
    SIGNALS.iter().find(|&&(s, _)| s == signo).map_or("unknown", |&(_, name)| name)
}

/// ngx_parent
static PARENT_PID: AtomicI32 = AtomicI32::new(0);

/// A new handler record of the signals, with a pipe of its own.
fn new_delivery() -> std::io::Result<Delivery> {
    let (read, write) = UnixStream::pair()?;

    SignalDelivery::with_pipe(read, write, WithOrigin::default(), std::iter::empty::<i32>())
}

/// ngx_init_signals: the handler of the signals nginx handles (signal-hook
/// registers its own handler, which runs the actions registered for the
/// signal: the flags of ngx_signal_handler() set in every kind of process,
/// the flags telling there are signals to process, and the record of the
/// signal with its sender, written to the pipe of the process). SIGSYS
/// gets a handler doing nothing instead of SIG_IGN; std ignores SIGPIPE
/// already.
pub fn init_signals(log: &Log) -> Result<(), ()> {
    PARENT_PID.store(os::getppid(), Ordering::Relaxed);

    register_signals(log)
}

/// The actions of a signal: its record (registered first, so that it is
/// there once a flag is seen), the flag the handler sets in every kind of
/// process, and the flags telling there are signals to process.
fn register_signal(delivery: &Delivery, signo: i32) -> std::io::Result<()> {
    delivery.handle().add_signal(signo)?;

    let flag: Option<&HandlerFlag> = match signo {
        libc::SIGQUIT => Some(&SIG_QUIT),
        libc::SIGTERM | libc::SIGINT => Some(&SIG_TERMINATE),
        libc::SIGUSR1 => Some(&SIG_REOPEN),
        _ => None,
    };

    if let Some(flag) = flag {
        signal_hook::flag::register(signo, Arc::clone(flag))?;
    }

    signal_hook::flag::register(signo, Arc::clone(&SIGNALED))?;

    if signo != libc::SIGALRM {
        signal_hook::flag::register(signo, Arc::clone(&INTERRUPTED))?;
    }

    Ok(())
}

fn register_signals(log: &Log) -> Result<(), ()> {
    let delivery = match new_delivery() {
        Ok(d) => d,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(io_errno(&e)), "socketpair() failed");
            return Err(());
        }
    };

    for &(signo, name) in SIGNALS.iter() {
        if let Err(e) = register_signal(&delivery, signo) {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(io_errno(&e)), "sigaction({}) failed", name);
            return Err(());
        }
    }

    // SIGSYS, SIG_IGN: a handler doing nothing
    if let Err(e) = signal_hook::flag::register(libc::SIGSYS, Arc::new(AtomicBool::new(false))) {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(io_errno(&e)), "sigaction(SIGSYS, SIG_IGN) failed");
        return Err(());
    }

    DELIVERY.with(|d| *d.borrow_mut() = Some(delivery));

    Ok(())
}

/// After fork(), in the child: a record of the signals of its own, as the
/// pipe of its parent's would wake both processes (the signals are still
/// blocked here: those coming meanwhile are delivered to the new one);
/// the parent's alarm timer is not inherited.
fn init_child_signals(log: &Log) {
    ALARM.with(|a| {
        if let Some(t) = a.borrow_mut().take() {
            // no timer_delete() of the parent's timer
            std::mem::forget(t);
        }
    });

    if DELIVERY.with(|d| d.borrow().is_none()) {
        return;
    }

    // the flags registered by the parent are the child's too
    let new = new_delivery().and_then(|d| {
        let handle = d.handle();

        for &(signo, _) in SIGNALS.iter() {
            handle.add_signal(signo)?;
        }

        Ok(d)
    });

    let new = match new {
        Ok(d) => Some(d),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(io_errno(&e)), "sigaction() failed");
            None
        }
    };

    // the parent's: its pipe closed here, its actions unregistered here
    let old = DELIVERY.with(|d| std::mem::replace(&mut *d.borrow_mut(), new));
    drop(old);
}

/// The signals the handler recorded, as ngx_signal_handler() handles them:
/// the flags it sets (but those the handler set), and the notice of each
/// "signal N (SIGX) received from PID, action". Only if the handler ran
/// since the last call, unless `force`. Whether signals were processed: the
/// pipe of the records is drained then, and an event loop waiting for it
/// to be readable is to be woken.
pub fn process_signals(log: &Log, force: bool) -> bool {
    if !SIGNALED.swap(false, Ordering::SeqCst) && !force {
        return false;
    }

    let received: Vec<(i32, i32)> = DELIVERY.with(|d| match d.borrow_mut().as_mut() {
        Some(d) => d.pending().map(|o| (o.signal, o.process.map_or(0, |p| p.pid))).collect(),
        None => Vec::new(),
    });

    for (signo, pid) in received {
        signal_handler(signo, pid, log);
    }

    true
}

/// ngx_signal_handler() of a signal received from `pid` (0 if not sent by
/// a process).
fn signal_handler(signo: i32, pid: i32, log: &Log) {
    let mut action = "";
    let mut ignore = false;

    match PROCESS_KIND.load(Ordering::Relaxed) {
        0 | 1 => match signo {
            libc::SIGQUIT => action = ", shutting down",
            libc::SIGTERM | libc::SIGINT => action = ", exiting",
            libc::SIGWINCH => {
                if DAEMONIZED.load(Ordering::Relaxed) {
                    SIG_NOACCEPT.store(true, Ordering::SeqCst);
                    action = ", stop accepting connections";
                }
            }
            libc::SIGHUP => {
                SIG_RECONFIGURE.store(true, Ordering::SeqCst);
                action = ", reconfiguring";
            }
            libc::SIGUSR1 => action = ", reopening logs",
            libc::SIGUSR2 => {
                // ignored in the new binary while the old binary's process
                // (its parent) runs, or in the old binary's process while
                // the new binary's process runs
                if os::getppid() == PARENT_PID.load(Ordering::Relaxed) || NEW_BINARY.load(Ordering::Relaxed) > 0 {
                    action = ", ignoring";
                    ignore = true;
                } else {
                    SIG_CHANGE_BINARY.store(true, Ordering::SeqCst);
                    action = ", changing binary";
                }
            }
            libc::SIGALRM => SIG_ALRM.store(true, Ordering::SeqCst),
            libc::SIGIO => SIG_IO.store(true, Ordering::SeqCst),
            libc::SIGCHLD => SIG_REAP.store(true, Ordering::SeqCst),
            _ => {}
        },
        3 | 4 => match signo {
            libc::SIGWINCH => {
                if DAEMONIZED.load(Ordering::Relaxed) {
                    DEBUG_QUIT.store(true, Ordering::SeqCst);
                    SIG_QUIT.store(true, Ordering::SeqCst);
                    action = ", shutting down";
                }
            }
            libc::SIGQUIT => action = ", shutting down",
            libc::SIGTERM | libc::SIGINT => action = ", exiting",
            libc::SIGUSR1 => action = ", reopening logs",
            libc::SIGHUP | libc::SIGUSR2 | libc::SIGIO => action = ", ignoring",
            _ => {}
        },
        _ => {}
    }

    if pid != 0 {
        ngx_log_error!(NGX_LOG_NOTICE, log, None, "signal {} ({}) received from {}{}", signo, signame(signo), pid, action);
    } else {
        ngx_log_error!(NGX_LOG_NOTICE, log, None, "signal {} ({}) received{}", signo, signame(signo), action);
    }

    if ignore {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "the changing binary signal is ignored: you should shutdown or terminate before either old or new binary's process");
    }
}

/// The event loop blocks in epoll_wait().
pub fn events_park() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

/// epoll_wait() returned: whether a signal (but SIGALRM) interrupted it.
pub fn events_interrupted() -> bool {
    INTERRUPTED.swap(false, Ordering::SeqCst)
}

/// The read end of the signal pipe of the process, readable once the
/// handler ran (for the event loop of a worker, helper or single process):
/// the descriptor stays open as long as the process lives, a child
/// replacing the pipe before it runs an event loop.
pub fn signal_fd() -> Option<RawFd> {
    DELIVERY.with(|d| d.borrow().as_ref().map(|d| d.get_read().as_raw_fd()))
}

/// setitimer(ITIMER_REAL): SIGALRM after `delay` milliseconds.
fn set_alarm(delay: u64) -> Result<(), i32> {
    use nix::sys::signal::{SigEvent, SigevNotify};
    use nix::sys::timer::{Expiration, Timer, TimerSetTimeFlags};

    ALARM.with(|a| {
        let mut a = a.borrow_mut();

        if a.is_none() {
            let ev = SigEvent::new(SigevNotify::SigevSignal { signal: Signal::SIGALRM, si_value: 0 });
            *a = Some(Timer::new(nix::time::ClockId::CLOCK_MONOTONIC, ev).map_err(|e| e as i32)?);
        }

        let value = nix::sys::time::TimeSpec::from(std::time::Duration::from_millis(delay));

        match a.as_mut() {
            Some(timer) => timer.set(Expiration::OneShot(value), TimerSetTimeFlags::empty()).map_err(|e| e as i32),
            None => Ok(()),
        }
    })
}

// ---------------------------------------------------------------------------
// channels

pub fn write_channel(s: i32, ch: &Channel, log: &Log) -> Result<(), bool> {
    let bytes = ch.to_bytes();
    let iov = [IoSlice::new(&bytes)];

    let rc = fd::get(s).map_err(|e| io_errno(&e)).and_then(|sock| {
        if ch.fd == -1 {
            return rustix::net::sendmsg(&sock, &iov, &mut SendAncillaryBuffer::default(), SendFlags::empty()).map_err(|e| e.raw_os_error());
        }

        let passed = fd::get(ch.fd).map_err(|e| io_errno(&e))?;
        let fds = [passed.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);

        cmsg.push(SendAncillaryMessage::ScmRights(&fds));

        rustix::net::sendmsg(&sock, &iov, &mut cmsg, SendFlags::empty()).map_err(|e| e.raw_os_error())
    });

    match rc {
        Ok(_) => Ok(()),
        Err(e) if e == libc::EAGAIN => Err(true),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "sendmsg() failed");
            Err(false)
        }
    }
}

/// Returns Ok(Some(ch)), Ok(None) for EAGAIN, Err(()) for error/EOF.
pub fn read_channel(s: i32, log: &Log) -> Result<Option<Channel>, ()> {
    let mut bytes = [0u8; CHANNEL_SIZE];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg = RecvAncillaryBuffer::new(&mut space);

    let rc = fd::get(s).map_err(|e| io_errno(&e)).and_then(|sock| {
        let mut iov = [IoSliceMut::new(&mut bytes)];
        rustix::net::recvmsg(&sock, &mut iov, &mut cmsg, RecvFlags::empty()).map_err(|e| e.raw_os_error())
    });

    let msg = match rc {
        Ok(msg) => msg,
        Err(e) if e == libc::EAGAIN => return Ok(None),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "recvmsg() failed");

            if e == libc::EMSGSIZE || e == libc::EMFILE {
                // file descriptor table is full
                return Ok(Some(Channel::default()));
            }

            return Err(());
        }
    };

    let n = msg.bytes;

    if n == 0 {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "recvmsg() returned zero");
        return Err(());
    }

    if n < CHANNEL_SIZE {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned not enough data: {}", n);
        return Err(());
    }

    let mut ch = Channel::from_bytes(&bytes);

    if ch.command == NGX_CMD_OPEN_CHANNEL {
        // the first control message: the descriptors of SCM_RIGHTS, of which
        // the first is the channel (the others, if any, are closed)
        let first = cmsg.drain().next();

        match first {
            Some(RecvAncillaryMessage::ScmRights(mut fds)) => match fds.next() {
                Some(owned) => ch.fd = fd::register(owned),
                None => {
                    ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned too small ancillary data");
                    ch.fd = -1;
                }
            },
            Some(RecvAncillaryMessage::ScmCredentials(_)) => {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned invalid ancillary data level {} or type {}", libc::SOL_SOCKET, libc::SCM_CREDENTIALS);
                return Err(());
            }
            _ => {
                // nothing, or no descriptor the file table had room for
                ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned too small ancillary data");
                ch.fd = -1;
            }
        }
    }

    // not MSG_CTRUNC: a descriptor which could not be received (EMFILE)
    // is the "too small ancillary data" above
    if msg.flags.contains(ReturnFlags::TRUNC) {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() truncated data");
    }

    Ok(Some(ch))
}

pub fn close_channel(ch: &[i32; 2], log: &Log) {
    for &fd in ch {
        if fd != -1 {
            if let Err(e) = os::close_fd(fd) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "close() channel failed");
            }
        }
    }
}

/// ioctl(FIOASYNC) on the channel: SIGIO when it is readable or closed.
fn channel_async(fd: i32) -> Result<(), i32> {
    let f = fd::get(fd).map_err(|e| io_errno(&e))?;
    ngx_sys::os::ioctl_fioasync(f.as_fd(), true).map_err(|e| io_errno(&e))
}

/// fcntl(F_SETOWN): the SIGIO of the descriptor to `pid`.
pub fn set_owner(fd: i32, pid: i32) -> Result<(), i32> {
    let f = fd::get(fd).map_err(|e| io_errno(&e))?;
    ngx_sys::os::fcntl_setown(f.as_fd(), pid).map_err(|e| io_errno(&e))
}

// ---------------------------------------------------------------------------
// spawning

/// ngx_spawn_process
pub fn spawn_process(cycle: &Rc<Cycle>, proc_fn: ProcFn, data: i64, name: &'static str, respawn: i64) -> i32 {
    let log = cycle.log.clone();
    let s = if respawn >= 0 {
        respawn as usize
    } else {
        let s = PROCESSES.with(|p| {
            let p = p.borrow();
            p.iter().position(|x| x.pid == -1).unwrap_or(p.len())
        });
        if s == NGX_MAX_PROCESSES {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "no more than {} processes can be spawned", NGX_MAX_PROCESSES);
            return -1;
        }
        s
    };
    PROCESSES.with(|p| {
        let mut p = p.borrow_mut();
        while p.len() <= s {
            p.push(Process { pid: -1, status: 0, channel: [-1, -1], proc_fn: None, data: 0, name: "", respawn: false, just_spawn: false, detached: false, exiting: false, exited: false });
        }
    });

    let mut channel = [-1i32, -1];
    if respawn != NGX_PROCESS_DETACHED {
        use rustix::net::{AddressFamily, SocketFlags, SocketType};

        match rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None) {
            Ok((a, b)) => channel = [fd::register(a), fd::register(b)],
            Err(e) => {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e.raw_os_error()), "socketpair() failed while spawning \"{}\"", name);
                return -1;
            }
        }
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "channel {}:{}", channel[0], channel[1]);
        for &fd in &channel {
            if let Err(e) = os::set_nonblocking(fd) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "ioctl(FIONBIO) failed while spawning \"{}\"", name);
                close_channel(&channel, &log);
                return -1;
            }
        }
        if let Err(e) = channel_async(channel[0]) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "ioctl(FIOASYNC) failed while spawning \"{}\"", name);
            close_channel(&channel, &log);
            return -1;
        }
        if let Err(e) = set_owner(channel[0], os::getpid()) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "fcntl(F_SETOWN) failed while spawning \"{}\"", name);
            close_channel(&channel, &log);
            return -1;
        }
        CHANNEL.with(|c| c.set(channel[1]));
    }
    PROCESSES.with(|p| p.borrow_mut()[s].channel = channel);
    PROCESS_SLOT.with(|p| p.set(s));

    let pid = match ngx_sys::os::fork() {
        Err(e) => {
            // EAGAIN as well for a process with threads, which cannot fork
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e.raw_os_error().unwrap_or(libc::EAGAIN)), "fork() failed while spawning \"{}\"", name);
            close_channel(&channel, &log);
            return -1;
        }
        Ok(ngx_sys::os::Fork::Child) => {
            PARENT_PID.store(os::getppid(), Ordering::Relaxed);
            update_pid();
            init_child_signals(&log);
            proc_fn(cycle.clone(), data);
        }
        Ok(ngx_sys::os::Fork::Parent(pid)) => pid,
    };
    ngx_log_error!(NGX_LOG_NOTICE, log, None, "start {} {}", name, pid);
    PROCESSES.with(|p| {
        let mut p = p.borrow_mut();
        let pr = &mut p[s];
        pr.pid = pid;
        pr.exited = false;
        if respawn >= 0 {
            return;
        }
        pr.proc_fn = Some(proc_fn);
        pr.data = data;
        pr.name = name;
        pr.exiting = false;
        let (r, j, d) = match respawn {
            NGX_PROCESS_NORESPAWN => (false, false, false),
            NGX_PROCESS_JUST_SPAWN => (false, true, false),
            NGX_PROCESS_RESPAWN => (true, false, false),
            NGX_PROCESS_JUST_RESPAWN => (true, true, false),
            NGX_PROCESS_DETACHED => (false, false, true),
            _ => (false, false, false),
        };
        pr.respawn = r;
        pr.just_spawn = j;
        pr.detached = d;
    });
    pid
}

/// ngx_pass_open_channel
fn pass_open_channel(cycle: &Rc<Cycle>) {
    let slot = PROCESS_SLOT.with(|p| p.get());
    let (pid, fd) = PROCESSES.with(|p| {
        let p = p.borrow();
        (p[slot].pid, p[slot].channel[0])
    });
    let ch = Channel { command: NGX_CMD_OPEN_CHANNEL, pid, slot: slot as i32, fd };
    let procs = PROCESSES.with(|p| p.borrow().clone());
    for (i, pr) in procs.iter().enumerate() {
        if i == slot || pr.pid == -1 || pr.channel[0] == -1 {
            continue;
        }
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "pass channel s:{} pid:{} fd:{} to s:{} pid:{} fd:{}", ch.slot, ch.pid, ch.fd, i, pr.pid, pr.channel[0]);
        let _ = write_channel(pr.channel[0], &ch, &cycle.log);
    }
}

fn start_worker_processes(cycle: &Rc<Cycle>, n: i64, ty: i64) {
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "start worker processes");
    for i in 0..n {
        spawn_process(cycle, crate::event::worker_process_cycle, i, "worker process", ty);
        pass_open_channel(cycle);
    }
}

fn start_cache_manager_processes(cycle: &Rc<Cycle>, respawn: bool) {
    let manager = cycle.paths.iter().any(|p| p.manager.borrow().is_some());
    let loader = cycle.paths.iter().any(|p| p.loader.borrow().is_some());
    if !manager {
        return;
    }
    spawn_process(cycle, crate::event::cache_manager_process_cycle, 0, "cache manager process", if respawn { NGX_PROCESS_JUST_RESPAWN } else { NGX_PROCESS_RESPAWN });
    pass_open_channel(cycle);
    if !loader {
        return;
    }
    spawn_process(cycle, crate::event::cache_manager_process_cycle, 1, "cache loader process", if respawn { NGX_PROCESS_JUST_SPAWN } else { NGX_PROCESS_NORESPAWN });
    pass_open_channel(cycle);
}

fn signal_worker_processes(cycle: &Rc<Cycle>, signo: i32) {
    let command = match signo {
        libc::SIGQUIT => NGX_CMD_QUIT,
        libc::SIGTERM => NGX_CMD_TERMINATE,
        libc::SIGUSR1 => NGX_CMD_REOPEN,
        _ => 0,
    };
    let ch = Channel { command, pid: 0, slot: 0, fd: -1 };
    let n = PROCESSES.with(|p| p.borrow().len());
    for i in 0..n {
        let pr = PROCESSES.with(|p| p.borrow()[i].clone());
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "child: {} {} e:{} t:{} d:{} r:{} j:{}", i, pr.pid, pr.exiting as i32, pr.exited as i32, pr.detached as i32, pr.respawn as i32, pr.just_spawn as i32);
        if pr.detached || pr.pid == -1 {
            continue;
        }
        if pr.just_spawn {
            PROCESSES.with(|p| p.borrow_mut()[i].just_spawn = false);
            continue;
        }
        if pr.exiting && signo == libc::SIGQUIT {
            continue;
        }
        if command != 0 && write_channel(pr.channel[0], &ch, &cycle.log).is_ok() {
            if signo != libc::SIGUSR1 {
                PROCESSES.with(|p| p.borrow_mut()[i].exiting = true);
            }
            continue;
        }
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "kill ({}, {})", pr.pid, signo);
        if let Err(e) = os::kill(pr.pid, signo) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "kill({}, {}) failed", pr.pid, signo);
            if e == libc::ESRCH {
                PROCESSES.with(|p| {
                    let mut p = p.borrow_mut();
                    p[i].exited = true;
                    p[i].exiting = false;
                });
                SIG_REAP.store(true, Ordering::SeqCst);
            }
            continue;
        }
        if signo != libc::SIGUSR1 {
            PROCESSES.with(|p| p.borrow_mut()[i].exiting = true);
        }
    }
}

/// ngx_process_get_status: waitpid loop.
fn process_get_status(log: &Log) {
    let mut one = false;
    loop {
        let (pid, status) = match rustix::process::wait(rustix::process::WaitOptions::NOHANG) {
            Ok(None) => return,
            Ok(Some((pid, status))) => (pid.as_raw_nonzero().get(), status.as_raw()),
            Err(e) => {
                let e = e.raw_os_error();
                if e == libc::EINTR {
                    continue;
                }
                if e == libc::ECHILD && one {
                    return;
                }
                if e == libc::ECHILD {
                    ngx_log_error!(NGX_LOG_INFO, log, Some(e), "waitpid() failed");
                    return;
                }
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "waitpid() failed");
                return;
            }
        };
        one = true;
        // ngx_shmtx_force_unlock(&ngx_accept_mutex, pid)
        let _ = crate::connection::stats().accept_mutex.compare_exchange(pid as i64, 0, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire);
        let mut process = "unknown process";
        let mut idx = None;
        PROCESSES.with(|p| {
            let mut p = p.borrow_mut();
            for (i, pr) in p.iter_mut().enumerate() {
                if pr.pid == pid {
                    pr.status = status;
                    pr.exited = true;
                    process = pr.name;
                    idx = Some(i);
                    break;
                }
            }
        });

        // WTERMSIG(), WCOREDUMP() and WEXITSTATUS() of the status
        let termsig = status & 0x7f;
        let exitcode = (status >> 8) & 0xff;

        if termsig != 0 {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "{} {} exited on signal {}{}", process, pid, termsig, if status & 0x80 != 0 { " (core dumped)" } else { "" });
        } else {
            ngx_log_error!(NGX_LOG_NOTICE, log, None, "{} {} exited with code {}", process, pid, exitcode);
        }
        if exitcode == 2 {
            if let Some(i) = idx {
                let respawn = PROCESSES.with(|p| p.borrow()[i].respawn);
                if respawn {
                    ngx_log_error!(NGX_LOG_ALERT, log, None, "{} {} exited with fatal code {} and cannot be respawned", process, pid, exitcode);
                    PROCESSES.with(|p| p.borrow_mut()[i].respawn = false);
                }
            }
        }
    }
}

/// ngx_reap_children
fn reap_children(cycle: &Rc<Cycle>) -> bool {
    let mut live = false;
    let n = PROCESSES.with(|p| p.borrow().len());
    let mut i = 0;
    while i < n {
        let pr = PROCESSES.with(|p| p.borrow().get(i).cloned());
        let pr = match pr {
            Some(p) => p,
            None => break,
        };
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "child: {} {} e:{} t:{} d:{} r:{} j:{}", i, pr.pid, pr.exiting as i32, pr.exited as i32, pr.detached as i32, pr.respawn as i32, pr.just_spawn as i32);
        if pr.pid == -1 {
            i += 1;
            continue;
        }
        if pr.exited {
            if !pr.detached {
                close_channel(&pr.channel, &cycle.log);
                PROCESSES.with(|p| p.borrow_mut()[i].channel = [-1, -1]);
                let ch = Channel { command: NGX_CMD_CLOSE_CHANNEL, pid: pr.pid, slot: i as i32, fd: -1 };
                let procs = PROCESSES.with(|p| p.borrow().clone());
                for other in procs.iter() {
                    if other.exited || other.pid == -1 || other.channel[0] == -1 {
                        continue;
                    }
                    ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "pass close channel s:{} pid:{} to:{}", ch.slot, ch.pid, other.pid);
                    let _ = write_channel(other.channel[0], &ch, &cycle.log);
                }
            }
            if pr.respawn && !pr.exiting && !SIG_TERMINATE.load(Ordering::SeqCst) && !SIG_QUIT.load(Ordering::SeqCst) {
                if spawn_process(cycle, pr.proc_fn.unwrap(), pr.data, pr.name, i as i64) == -1 {
                    ngx_log_error!(NGX_LOG_ALERT, cycle.log, None, "could not respawn {}", pr.name);
                    i += 1;
                    continue;
                }
                pass_open_channel(cycle);
                live = true;
                i += 1;
                continue;
            }
            if pr.pid == NEW_BINARY.load(Ordering::Relaxed) {
                let ccf = core_conf(cycle);
                let (oldpid, pid) = {
                    let c = ccf.borrow();
                    (c.oldpid.clone(), c.pid.clone())
                };
                if let Err(e) = std::fs::rename(os::path(&oldpid), os::path(&pid)) {
                    ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(io_errno(&e)), "rename() {} back to {} failed after the new binary process \"{}\" exited", B(&oldpid), B(&pid), B(argv()[0].as_bytes()));
                }
                crate::control::reown(&cycle.log);
                NEW_BINARY.store(0, Ordering::Relaxed);
                globals_mut(|g| g.new_binary = 0);
                if globals(|g| g.noaccepting) {
                    globals_mut(|g| {
                        g.restart = true;
                        g.noaccepting = false;
                    });
                }
            }
            PROCESSES.with(|p| {
                let mut p = p.borrow_mut();
                if i == p.len() - 1 {
                    p.pop();
                } else {
                    p[i].pid = -1;
                }
            });
        } else if pr.exiting || !pr.detached {
            live = true;
        }
        i += 1;
    }
    live
}

/// ngx_master_process_exit
fn master_process_exit(cycle: &Rc<Cycle>) -> ! {
    delete_pidfile(cycle);
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exit");
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.exit_master {
            f(cycle);
        }
    }
    crate::connection::close_listening_sockets(cycle);
    crate::control::uninit(&cycle.log);
    std::process::exit(0);
}

/// ngx_master_process_cycle
pub fn master_process_cycle(mut cycle: Rc<Cycle>) -> ! {
    set_process_kind(ProcessType::Master);

    let mut set = SigSet::empty();
    for s in [Signal::SIGCHLD, Signal::SIGALRM, Signal::SIGIO, Signal::SIGINT, Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGWINCH, Signal::SIGTERM, Signal::SIGQUIT, Signal::SIGUSR2] {
        set.add(s);
    }
    if let Err(e) = nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), None) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "sigprocmask() failed");
    }

    let mut title = b"master process".to_vec();
    for a in argv() {
        title.push(b' ');
        title.extend_from_slice(a.as_bytes());
    }
    setproctitle(&title);

    let ccf = core_conf(&cycle);
    let mut worker_processes = *ccf.borrow().worker_processes;
    start_worker_processes(&cycle, worker_processes, NGX_PROCESS_RESPAWN);
    start_cache_manager_processes(&cycle, false);

    NEW_BINARY.store(0, Ordering::Relaxed);
    let mut delay: u64 = 0;
    let mut sigio: i64 = 0;
    let mut live = true;

    loop {
        if delay != 0 {
            if SIG_ALRM.swap(false, Ordering::SeqCst) {
                sigio = 0;
                delay *= 2;
            }
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "termination cycle: {}", delay);
            if let Err(e) = set_alarm(delay) {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "setitimer() failed");
            }
        }
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "sigsuspend");

        // returns once the handler of a signal ran (EINTR)
        let _ = SigSet::empty().suspend();

        crate::times::update();
        process_signals(&cycle.log, true);
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "wake up, sigio {}", sigio);

        if SIG_REAP.swap(false, Ordering::SeqCst) {
            process_get_status(&cycle.log);
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "reap children");
            live = reap_children(&cycle);
        }

        if SIG_IO.swap(false, Ordering::SeqCst) && crate::control::handle_events(&mut cycle) == crate::rc::NGX_DONE {
            // the control API reloaded the configuration
            let ccf = core_conf(&cycle);
            worker_processes = *ccf.borrow().worker_processes;
            start_worker_processes(&cycle, worker_processes, NGX_PROCESS_JUST_RESPAWN);
            start_cache_manager_processes(&cycle, true);

            // allow new processes to start
            std::thread::sleep(std::time::Duration::from_millis(100));

            live = true;
            signal_worker_processes(&cycle, libc::SIGQUIT);
        }

        let terminate = SIG_TERMINATE.load(Ordering::SeqCst);
        let quit = SIG_QUIT.load(Ordering::SeqCst);
        if !live && (terminate || quit) {
            master_process_exit(&cycle);
        }
        if terminate {
            if delay == 0 {
                delay = 50;
            }
            if sigio > 0 {
                sigio -= 1;
                continue;
            }
            sigio = worker_processes + 2;
            if delay > 1000 {
                signal_worker_processes(&cycle, libc::SIGKILL);
            } else {
                signal_worker_processes(&cycle, libc::SIGTERM);
            }
            continue;
        }
        if quit {
            signal_worker_processes(&cycle, libc::SIGQUIT);
            crate::connection::close_listening_sockets(&cycle);
            continue;
        }
        if SIG_RECONFIGURE.swap(false, Ordering::SeqCst) {
            if NEW_BINARY.load(Ordering::Relaxed) != 0 {
                start_worker_processes(&cycle, worker_processes, NGX_PROCESS_RESPAWN);
                start_cache_manager_processes(&cycle, false);
                globals_mut(|g| g.noaccepting = false);
                continue;
            }
            ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "reconfiguring");
            match init_cycle(cycle.clone(), &crate::connection::init_hooks()) {
                Ok(c) => {
                    cycle = c;
                    set_cycle(cycle.clone());
                }
                Err(()) => continue,
            }
            let ccf = core_conf(&cycle);
            worker_processes = *ccf.borrow().worker_processes;
            start_worker_processes(&cycle, worker_processes, NGX_PROCESS_JUST_RESPAWN);
            start_cache_manager_processes(&cycle, true);
            std::thread::sleep(std::time::Duration::from_millis(100));
            live = true;
            signal_worker_processes(&cycle, libc::SIGQUIT);
        }
        if globals(|g| g.restart) {
            globals_mut(|g| g.restart = false);
            start_worker_processes(&cycle, worker_processes, NGX_PROCESS_RESPAWN);
            start_cache_manager_processes(&cycle, false);
            live = true;
        }
        if SIG_REOPEN.swap(false, Ordering::SeqCst) {
            ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "reopening logs");
            let user = core_conf(&cycle).borrow().user;
            cycle.reopen_files(user);
            signal_worker_processes(&cycle, libc::SIGUSR1);
        }
        if SIG_CHANGE_BINARY.swap(false, Ordering::SeqCst) {
            ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "changing binary");
            let pid = exec_new_binary(&cycle);
            NEW_BINARY.store(pid, Ordering::Relaxed);
            globals_mut(|g| g.new_binary = pid);
        }
        if SIG_NOACCEPT.swap(false, Ordering::SeqCst) {
            globals_mut(|g| g.noaccepting = true);
            signal_worker_processes(&cycle, libc::SIGQUIT);
        }
    }
}

/// ngx_single_process_cycle: run everything in one process.
pub fn single_process_cycle(cycle: Rc<Cycle>) -> ! {
    set_process_kind(ProcessType::Single);
    set_environment(&cycle);
    crate::event::single_process_run(cycle)
}

/// FD_CLOEXEC of a descriptor set or cleared.
fn set_cloexec(fd: i32, on: bool) {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = if on { FdFlag::FD_CLOEXEC } else { FdFlag::empty() };
    let _ = fcntl(fd, FcntlArg::F_SETFD(flags));
}

/// ngx_exec_new_binary: start a new binary with inherited listening sockets.
pub fn exec_new_binary(cycle: &Rc<Cycle>) -> i32 {
    let mut env = environment(cycle);

    let mut var = b"NGINX=".to_vec();
    for ls in cycle.listening.iter() {
        if ls.ignore.get() || ls.fd.get() == -1 {
            continue;
        }
        var.extend_from_slice(format!("{};", ls.fd.get()).as_bytes());
    }

    env.push(var);

    // NGX_SETPROCTITLE_USES_ENV: allocate the spare 300 bytes for the new
    // binary process title
    let mut spare = b"SPARE=".to_vec();
    spare.resize(300, b'X');
    env.push(spare);

    if let Some(e) = crate::control::handoff() {
        env.push(e);
    }

    for e in &env {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "env: {}", B(e));
    }

    let ccf = core_conf(cycle);
    let (pid, oldpid) = {
        let c = ccf.borrow();
        (c.pid.clone(), c.oldpid.clone())
    };
    if let Err(e) = std::fs::rename(os::path(&pid), os::path(&oldpid)) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, e.raw_os_error(), "rename() {} to {} failed before executing new binary process \"{}\"", B(&pid), B(&oldpid), B(argv()[0].as_bytes()));
        return -1;
    }
    let args = argv();
    // the listening sockets are passed to the new binary: no close-on-exec
    for ls in cycle.listening.iter() {
        let fd = ls.fd.get();
        if fd != -1 {
            set_cloexec(fd, false);
        }
    }
    PENDING_EXEC_ENV.with(|e| *e.borrow_mut() = Some(env));
    let child = spawn_process(cycle, exec_proc, 0, "new binary process", NGX_PROCESS_DETACHED);
    if child == -1 {
        if let Err(e) = std::fs::rename(os::path(&oldpid), os::path(&pid)) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, e.raw_os_error(), "rename() {} back to {} failed after an attempt to execute new binary process \"{}\"", B(&oldpid), B(&pid), B(args[0].as_bytes()));
        }
    }
    for ls in cycle.listening.iter() {
        let fd = ls.fd.get();
        if fd != -1 {
            set_cloexec(fd, true);
        }
    }
    PENDING_EXEC_ENV.with(|e| *e.borrow_mut() = None);
    child
}

thread_local! {
    /// ctx.envp of the new binary process
    static PENDING_EXEC_ENV: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
}

/// ngx_execute_proc: execve() of argv[0] with the arguments of this binary
/// and the environment of exec_new_binary().
fn exec_proc(cycle: Rc<Cycle>, _data: i64) -> ! {
    let args = argv();
    let path = args[0].as_bytes();
    let env = PENDING_EXEC_ENV.with(|e| e.borrow().clone().unwrap_or_default());

    // execve() takes a path without a slash in the current directory,
    // where Command would look for it in PATH
    let program = if path.contains(&b'/') { path.to_vec() } else { [&b"./"[..], path].concat() };

    let mut cmd = std::process::Command::new(OsStr::from_bytes(&program));

    cmd.arg0(OsStr::from_bytes(path));
    cmd.args(args[1..].iter().map(|a| OsStr::from_bytes(a.as_bytes())));
    cmd.env_clear();

    let mut names: HashSet<&[u8]> = HashSet::new();

    for e in &env {
        let i = match memchr::memchr(b'=', e) {
            Some(i) => i,
            None => continue,
        };

        // the first of a name, which getenv() finds
        if names.insert(&e[..i]) {
            cmd.env(OsStr::from_bytes(&e[..i]), OsStr::from_bytes(&e[i + 1..]));
        }
    }

    let err = cmd.exec();

    ngx_log_error!(NGX_LOG_ALERT, cycle.log, err.raw_os_error(), "execve() failed while executing new binary process \"{}\"", B(path));
    std::process::exit(1);
}

/// ngx_daemon
pub fn daemon(log: &Log) -> Result<(), ()> {
    let pid = os::getpid();
    match ngx_sys::os::fork() {
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error().unwrap_or(libc::EAGAIN)), "fork() failed");
            return Err(());
        }
        Ok(ngx_sys::os::Fork::Child) => {}
        Ok(ngx_sys::os::Fork::Parent(_)) => std::process::exit(0),
    }
    update_pid();
    // ngx_parent = ngx_pid
    PARENT_PID.store(pid, Ordering::Relaxed);
    if let Err(e) = nix::unistd::setsid() {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(e as i32), "setsid() failed");
        return Err(());
    }
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    let fd = match rustix::fs::open("/dev/null", rustix::fs::OFlags::RDWR, rustix::fs::Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "open(\"/dev/null\") failed");
            return Err(());
        }
    };
    if let Err(e) = rustix::stdio::dup2_stdin(&fd) {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "dup2(STDIN) failed");
        return Err(());
    }
    if let Err(e) = rustix::stdio::dup2_stdout(&fd) {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "dup2(STDOUT) failed");
        return Err(());
    }
    if fd.as_raw_fd() <= libc::STDERR_FILENO {
        // it is a standard descriptor itself now: left open
        let _ = fd.into_raw_fd();
    }
    Ok(())
}

/// ngx_set_environment(cycle, &last): the variables of the "env" directives
/// and TZ as "NAME=value", the environment is not changed.
fn environment(cycle: &Rc<Cycle>) -> Vec<Vec<u8>> {
    let ccf = core_conf(cycle);
    let mut vars = ccf.borrow().env.clone();

    if !vars.iter().any(|(name, _)| name == b"TZ") {
        vars.push((b"TZ".to_vec(), None));
    }

    let mut env = Vec::new();

    for (name, full) in vars {
        match full {
            Some(f) => env.push(f),
            None => {
                if let Some(v) = std::env::var_os(OsStr::from_bytes(&name)) {
                    let mut var = name;
                    var.push(b'=');
                    var.extend_from_slice(v.as_bytes());
                    env.push(var);
                }
            }
        }
    }

    env
}

/// ngx_set_environment: restrict the environment to "env" directives (+TZ).
pub fn set_environment(cycle: &Rc<Cycle>) {
    let ccf = core_conf(cycle);
    let env = ccf.borrow().env.clone();
    let mut vars: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut has_tz = false;
    for (name, full) in &env {
        if name == b"TZ" {
            has_tz = true;
        }
        match full {
            Some(f) => {
                let i = memchr::memchr(b'=', f).unwrap();
                vars.push((f[..i].to_vec(), f[i + 1..].to_vec()));
            }
            None => {
                if let Some(v) = std::env::var_os(OsStr::from_bytes(name)) {
                    vars.push((name.clone(), v.as_bytes().to_vec()));
                }
            }
        }
    }
    if !has_tz {
        if let Some(v) = std::env::var_os("TZ") {
            vars.push((b"TZ".to_vec(), v.as_bytes().to_vec()));
        }
    }
    // environ = the variables only: the others removed (those whose names
    // unsetenv() refuses cannot be)
    let names: Vec<std::ffi::OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    for k in names {
        if !k.is_empty() && !k.as_bytes().contains(&b'=') {
            std::env::remove_var(&k);
        }
    }
    for (k, v) in vars {
        std::env::set_var(OsStr::from_bytes(&k), OsStr::from_bytes(&v));
    }
}

// --- the process title ---

/// ngx_init_setproctitle() was called
static PROCTITLE: AtomicBool = AtomicBool::new(false);

/// ngx_init_setproctitle: the environment moved out of the argument and
/// environment strings the title is written over (glibc copies a variable
/// that setenv() sets).
pub fn init_setproctitle() {
    let mut names = HashSet::new();

    for (k, v) in std::env::vars_os() {
        // the first of a name, which getenv() finds
        if k.is_empty() || k.as_bytes().contains(&b'=') || !names.insert(k.clone()) {
            continue;
        }

        std::env::set_var(&k, &v);
    }

    PROCTITLE.store(true, Ordering::Relaxed);
}

/// ngx_setproctitle: "nginx: <title>"
pub fn setproctitle(title: &[u8]) {
    if !PROCTITLE.load(Ordering::Relaxed) {
        return;
    }

    let mut buf = b"nginx: ".to_vec();
    buf.extend_from_slice(title);

    let _ = ngx_sys::os::setproctitle(&buf);
}

/// A descriptor inherited across execve() (by the number the old binary
/// passed) taken into the table under the same number; left as it is if
/// it is not open, so that the calls on it fail as in C.
pub fn adopt_inherited(n: RawFd) -> RawFd {
    if n <= libc::STDERR_FILENO || fd::contains(n) {
        return n;
    }

    let dup = match fd::duplicate(n) {
        Ok(d) => d,
        Err(_) => return n,
    };

    os::close(n);

    match rustix::io::fcntl_dupfd_cloexec(&dup, n) {
        Ok(owned) => fd::register(owned),
        Err(_) => fd::register(dup),
    }
}

/// ngx_add_inherited_sockets: the listening sockets passed by
/// ngx_exec_new_binary in the NGINX environment variable.
pub fn add_inherited_sockets(cycle: &mut Cycle) -> Result<(), ()> {
    let inherited = match std::env::var_os("NGINX") {
        Some(v) => v.as_bytes().to_vec(),
        None => return Ok(()),
    };

    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "using inherited sockets from \"{}\"", B(&inherited));

    for s in inherited_sockets(&inherited, &cycle.log) {
        // the address is set by ngx_set_inherited_sockets
        let mut ls = crate::listening::Listening::new(crate::inet::SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, 0), cycle.log.clone());
        ls.addr_text = Vec::new();
        ls.fd.set(adopt_inherited(s));
        ls.inherited.set(true);
        cycle.listening.push(Rc::new(ls));
    }

    globals_mut(|g| g.inherited = true);

    crate::connection::set_inherited_sockets(cycle)
}

/// The socket numbers of the NGINX variable, as the ngx_add_inherited_sockets
/// loop parses them.
fn inherited_sockets(inherited: &[u8], log: &Log) -> Vec<i32> {
    let mut fds = Vec::new();
    let mut v = 0;
    let mut p = 0;

    while p < inherited.len() {
        if inherited[p] == b':' || inherited[p] == b';' {
            let s = match crate::string::atoi(&inherited[v..p]) {
                Some(s) => s,
                None => {
                    ngx_log_error!(NGX_LOG_EMERG, log, None, "invalid socket number \"{}\" in NGINX environment variable, ignoring the rest of the variable", B(&inherited[v..]));
                    break;
                }
            };

            v = p + 1;

            fds.push(s as i32);
        }

        p += 1;
    }

    if v != p {
        ngx_log_error!(NGX_LOG_EMERG, log, None, "invalid socket number \"{}\" in NGINX environment variable, ignoring", B(&inherited[v..]));
    }

    fds
}

/// ngx_parent
pub fn parent_pid() -> i32 {
    PARENT_PID.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inet::SockAddr;
    use crate::listening::Listening;
    use std::os::fd::{BorrowedFd, OwnedFd};

    fn capture() -> (Log, Rc<RefCell<Vec<u8>>>) {
        let logged: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let lg = logged.clone();
        let chain = LogChain::new();
        chain.insert(LogEntry::new(NGX_LOG_INFO, LogWriter::Custom(Rc::new(move |_, line: &[u8]| lg.borrow_mut().extend_from_slice(line)))));
        (Log::new(chain), logged)
    }

    /// the messages without the time and pid
    fn messages(l: &RefCell<Vec<u8>>) -> Vec<String> {
        String::from_utf8_lossy(&l.borrow())
            .lines()
            .map(|line| {
                let level = &line[line.find(" [").unwrap() + 1..];
                let (level, rest) = level.split_at(level.find(' ').unwrap());
                format!("{} {}", level, &rest[rest.find(": ").unwrap() + 2..])
            })
            .collect()
    }

    #[test]
    fn nginx_variable() {
        let invalid = "in NGINX environment variable";
        let cases: Vec<(&str, Vec<i32>, Vec<String>)> = vec![
            ("", vec![], vec![]),
            ("6;", vec![6], vec![]),
            ("6;7:8;", vec![6, 7, 8], vec![]),
            ("6;7", vec![6], vec![format!("[emerg] invalid socket number \"7\" {}, ignoring", invalid)]),
            (";", vec![], vec![format!("[emerg] invalid socket number \";\" {}, ignoring the rest of the variable", invalid)]),
            (
                "6;x;7;",
                vec![6],
                vec![
                    format!("[emerg] invalid socket number \"x;7;\" {}, ignoring the rest of the variable", invalid),
                    format!("[emerg] invalid socket number \"x;7;\" {}, ignoring", invalid),
                ],
            ),
            (
                "0x5;",
                vec![],
                vec![
                    format!("[emerg] invalid socket number \"0x5;\" {}, ignoring the rest of the variable", invalid),
                    format!("[emerg] invalid socket number \"0x5;\" {}, ignoring", invalid),
                ],
            ),
        ];

        for (var, fds, msgs) in cases {
            let (log, l) = capture();
            assert_eq!(inherited_sockets(var.as_bytes(), &log), fds, "{:?}", var);
            assert_eq!(messages(&l), msgs, "{:?}", var);
        }
    }

    /// ngx_close_listening_sockets deletes a unix socket file only in the
    /// master (or single) process, unless a new binary uses it: the one it
    /// has started, or the old binary it has inherited it from and which is
    /// still running.
    #[test]
    fn unix_socket_file_on_close() {
        let path = std::env::temp_dir().join(format!("ngx-close-listening-{}.sock", std::process::id()));
        let name = path.to_str().unwrap().as_bytes().to_vec();
        let ppid = os::getppid();

        let cases = [
            // process, new binary, inherited, ngx_parent, deleted
            (ProcessType::Master, 0, false, ppid, true),
            (ProcessType::Single, 0, false, ppid, true),
            (ProcessType::Worker, 0, false, ppid, false),
            (ProcessType::Helper, 0, false, ppid, false),
            (ProcessType::Master, 1234, false, ppid, false),
            (ProcessType::Master, 0, true, ppid, false),
            (ProcessType::Master, 0, true, ppid + 1, true),
            (ProcessType::Master, 1234, true, ppid + 1, false),
        ];

        for (process, new_binary, inherited, parent, deleted) in cases {
            let _ = std::fs::remove_file(&path);
            let fd = fd::register(OwnedFd::from(std::os::unix::net::UnixListener::bind(&path).unwrap()));

            let (log, _l) = capture();
            let mut cycle = Cycle::init_cycle(log.clone(), Rc::new(Vec::new()));
            let ls = Listening::new(SockAddr::Unix(name.clone()), log.clone());
            ls.fd.set(fd);
            ls.inherited.set(inherited);
            cycle.listening.push(Rc::new(ls));

            globals_mut(|g| {
                g.process = process;
                g.new_binary = new_binary;
            });
            PARENT_PID.store(parent, Ordering::Relaxed);

            crate::connection::close_listening_sockets(&cycle);

            assert_eq!(cycle.listening[0].fd.get(), -1);
            assert_eq!(!path.exists(), deleted, "{:?} {} {} {}", process, new_binary, inherited, parent);
        }

        globals_mut(|g| {
            g.process = ProcessType::Single;
            g.new_binary = 0;
        });
        PARENT_PID.store(0, Ordering::Relaxed);
        let _ = std::fs::remove_file(&path);
    }

    /// sendmsg() of a channel message with SCM_RIGHTS descriptors
    fn send_channel(s: i32, ch: &Channel, fds: &[i32]) {
        let handles: Vec<fd::Fd> = fds.iter().map(|&f| fd::get(f).unwrap()).collect();
        let borrowed: Vec<BorrowedFd<'_>> = handles.iter().map(|h| h.as_fd()).collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);

        if !borrowed.is_empty() {
            assert!(cmsg.push(SendAncillaryMessage::ScmRights(&borrowed)));
        }

        let bytes = ch.to_bytes();
        let n = rustix::net::sendmsg(fd::get(s).unwrap(), &[IoSlice::new(&bytes)], &mut cmsg, SendFlags::empty()).unwrap();
        assert_eq!(n, CHANNEL_SIZE);
    }

    fn inode(fd: i32) -> Option<(u64, u64)> {
        let st = os::fstat(fd).ok()?;
        Some((st.st_dev, st.st_ino))
    }

    #[test]
    fn channel_bytes() {
        let ch = Channel { command: NGX_CMD_OPEN_CHANNEL, pid: 1234, slot: 7, fd: -1 };
        let b = ch.to_bytes();
        assert_eq!(&b[0..4], &1u32.to_ne_bytes());
        assert_eq!(&b[12..16], &(-1i32).to_ne_bytes());
        let back = Channel::from_bytes(&b);
        assert_eq!((back.command, back.pid, back.slot, back.fd), (NGX_CMD_OPEN_CHANNEL, 1234, 7, -1));
    }

    /// ngx_read_channel: the descriptor of NGX_CMD_OPEN_CHANNEL; a message
    /// whose descriptors did not all fit (MSG_CTRUNC, as when the file
    /// table is full) is not "truncated data"
    #[test]
    fn channel_ancillary_data() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType};

        let (a, b) = rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None).unwrap();
        let sp = [fd::register(a), fd::register(b)];
        os::set_nonblocking(sp[1]).unwrap();
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let pipe = [fd::register(r), fd::register(w)];
        let pipe_inode = inode(pipe[0]);

        let (log, l) = capture();
        let open = Channel { command: NGX_CMD_OPEN_CHANNEL, pid: 1, slot: 2, fd: -1 };

        send_channel(sp[0], &Channel { command: NGX_CMD_QUIT, pid: 0, slot: 0, fd: -1 }, &[]);
        let ch = read_channel(sp[1], &log).unwrap().unwrap();
        assert_eq!((ch.command, ch.fd), (NGX_CMD_QUIT, -1));

        send_channel(sp[0], &open, &[pipe[0]]);
        let ch = read_channel(sp[1], &log).unwrap().unwrap();
        assert_eq!((ch.command, ch.pid, ch.slot), (NGX_CMD_OPEN_CHANNEL, 1, 2));
        assert!(ch.fd != -1 && ch.fd != pipe[0] && inode(ch.fd) == pipe_inode);
        assert!(fd::contains(ch.fd), "the descriptor received is in the table");
        os::close(ch.fd);

        // more descriptors than the channel's: the first one is taken, the
        // others are closed
        send_channel(sp[0], &open, &[pipe[0], pipe[0], pipe[0]]);
        let ch = read_channel(sp[1], &log).unwrap().unwrap();
        assert!(ch.fd != -1 && inode(ch.fd) == pipe_inode);
        os::close(ch.fd);

        send_channel(sp[0], &open, &[]);
        let ch = read_channel(sp[1], &log).unwrap().unwrap();
        assert_eq!(ch.fd, -1);

        assert!(read_channel(sp[1], &log).unwrap().is_none());

        assert_eq!(messages(&l), vec!["[alert] recvmsg() returned too small ancillary data"]);

        // write_channel() passes the descriptor
        write_channel(sp[0], &Channel { command: NGX_CMD_OPEN_CHANNEL, pid: 3, slot: 4, fd: pipe[1] }, &log).unwrap();
        let ch = read_channel(sp[1], &log).unwrap().unwrap();
        assert_eq!((ch.command, ch.pid, ch.slot), (NGX_CMD_OPEN_CHANNEL, 3, 4));
        assert_eq!(inode(ch.fd), inode(pipe[1]));
        os::close(ch.fd);

        // EOF
        os::close(sp[0]);
        assert!(read_channel(sp[1], &log).is_err());

        for fd in [sp[1], pipe[0], pipe[1]] {
            os::close(fd);
        }
    }

    /// A descriptor inherited across execve() is taken into the table (under
    /// its number, but for another thread of the test opening a file at the
    /// same moment); a number not open is left as it is.
    #[test]
    fn inherited_descriptor() {
        use std::os::fd::IntoRawFd;

        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let n = l.into_raw_fd();
        assert!(!fd::contains(n));

        let m = adopt_inherited(n);
        assert!(fd::contains(m));
        assert!(std::net::TcpStream::connect(addr).is_ok(), "the adopted socket still listens");
        assert_eq!(adopt_inherited(m), m, "a descriptor of the table is left as it is");
        os::close(m);

        let unused = 1 << 20;
        assert_eq!(adopt_inherited(unused), unused);
        assert!(!fd::contains(unused));
        assert_eq!(adopt_inherited(2), 2, "the standard descriptors are std's");
    }

    /// The signals recorded by the handler, with the pid of their sender,
    /// and the notices of ngx_signal_handler()
    #[test]
    fn signal_notices() {
        let (log, l) = capture();

        // not init_signals(): ngx_parent is the one of another test
        PROCESS_KIND.store(3, Ordering::Relaxed);
        register_signals(&log).unwrap();

        // a worker: SIGUSR1 sets ngx_reopen in the handler (which may run in
        // another thread of the test)
        SIG_REOPEN.store(false, Ordering::SeqCst);
        nix::sys::signal::kill(nix::unistd::getpid(), Signal::SIGUSR1).unwrap();

        for _ in 0..100 {
            if SIG_REOPEN.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(SIG_REOPEN.swap(false, Ordering::SeqCst), "the handler sets the flag");
        process_signals(&log, true);

        let pid = os::getpid();
        assert_eq!(messages(&l), vec![format!("[notice] signal 10 (SIGUSR1) received from {}, reopening logs", pid)]);

        // the kind-dependent flags are set when processed
        assert!(!SIG_RECONFIGURE.load(Ordering::SeqCst));
        signal_handler(libc::SIGHUP, 0, &log);
        assert!(!SIG_RECONFIGURE.load(Ordering::SeqCst), "SIGHUP is ignored by a worker");
        PROCESS_KIND.store(1, Ordering::Relaxed);
        signal_handler(libc::SIGHUP, 0, &log);
        assert!(SIG_RECONFIGURE.swap(false, Ordering::SeqCst), "SIGHUP reconfigures the master");
        signal_handler(libc::SIGALRM, 0, &log);
        assert!(SIG_ALRM.swap(false, Ordering::SeqCst));

        assert_eq!(
            messages(&l)[1..],
            ["[notice] signal 1 (SIGHUP) received, ignoring", "[notice] signal 1 (SIGHUP) received, reconfiguring", "[notice] signal 14 (SIGALRM) received"]
        );

        PROCESS_KIND.store(0, Ordering::Relaxed);
    }
}
