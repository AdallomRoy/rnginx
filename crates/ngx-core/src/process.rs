//! Process management: master/worker cycle, signals, channels (ngx_process*.c).

use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use crate::core_module::{core_conf, delete_pidfile};
use crate::cycle::*;
use crate::log::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, os};

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

// --- signal flags (set from the async-signal handler) ---
pub static SIG_QUIT: AtomicBool = AtomicBool::new(false);
pub static SIG_TERMINATE: AtomicBool = AtomicBool::new(false);
pub static SIG_REOPEN: AtomicBool = AtomicBool::new(false);
pub static SIG_RECONFIGURE: AtomicBool = AtomicBool::new(false);
pub static SIG_NOACCEPT: AtomicBool = AtomicBool::new(false);
pub static SIG_CHANGE_BINARY: AtomicBool = AtomicBool::new(false);
pub static SIG_ALRM: AtomicBool = AtomicBool::new(false);
pub static SIG_IO: AtomicBool = AtomicBool::new(false);
pub static SIG_REAP: AtomicBool = AtomicBool::new(false);
pub static DEBUG_QUIT: AtomicBool = AtomicBool::new(false);
pub static DAEMONIZED: AtomicBool = AtomicBool::new(false);
pub static NEW_BINARY: AtomicI32 = AtomicI32::new(0);
static PROCESS_KIND: AtomicI32 = AtomicI32::new(0); // 0 single, 1 master, 3 worker, 4 helper
static WAKE_PIPE: [AtomicI32; 2] = [AtomicI32::new(-1), AtomicI32::new(-1)];

// ring of received signals for logging outside the handler: (signo, pid)
const SIGRING: usize = 64;
static SIGRING_SIGNO: [AtomicI32; SIGRING] = [const { AtomicI32::new(0) }; SIGRING];
static SIGRING_PID: [AtomicI32; SIGRING] = [const { AtomicI32::new(0) }; SIGRING];
static SIGRING_HEAD: AtomicUsize = AtomicUsize::new(0);
static SIGRING_TAIL: AtomicUsize = AtomicUsize::new(0);

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

pub fn wake_fd() -> i32 {
    WAKE_PIPE[0].load(Ordering::Relaxed)
}

fn signame(signo: i32) -> &'static str {
    match signo {
        libc::SIGHUP => "SIGHUP",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGWINCH => "SIGWINCH",
        libc::SIGTERM => "SIGTERM",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGALRM => "SIGALRM",
        libc::SIGINT => "SIGINT",
        libc::SIGIO => "SIGIO",
        libc::SIGCHLD => "SIGCHLD",
        _ => "unknown",
    }
}

extern "C" fn signal_handler(signo: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let saved = unsafe { *libc::__errno_location() };
    let kind = PROCESS_KIND.load(Ordering::Relaxed);
    let mut ignore = false;
    match kind {
        0 | 1 => match signo {
            libc::SIGQUIT => SIG_QUIT.store(true, Ordering::SeqCst),
            libc::SIGTERM | libc::SIGINT => SIG_TERMINATE.store(true, Ordering::SeqCst),
            libc::SIGWINCH => {
                if DAEMONIZED.load(Ordering::Relaxed) {
                    SIG_NOACCEPT.store(true, Ordering::SeqCst);
                }
            }
            libc::SIGHUP => SIG_RECONFIGURE.store(true, Ordering::SeqCst),
            libc::SIGUSR1 => SIG_REOPEN.store(true, Ordering::SeqCst),
            libc::SIGUSR2 => {
                let ppid = unsafe { libc::getppid() };
                if ppid == PARENT_PID.load(Ordering::Relaxed) || NEW_BINARY.load(Ordering::Relaxed) > 0 {
                    ignore = true;
                } else {
                    SIG_CHANGE_BINARY.store(true, Ordering::SeqCst);
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
                }
            }
            libc::SIGQUIT => SIG_QUIT.store(true, Ordering::SeqCst),
            libc::SIGTERM | libc::SIGINT => SIG_TERMINATE.store(true, Ordering::SeqCst),
            libc::SIGUSR1 => SIG_REOPEN.store(true, Ordering::SeqCst),
            _ => {}
        },
        _ => {}
    }
    // record for logging
    let pid = if info.is_null() { 0 } else { unsafe { (*info).si_pid() } };
    let h = SIGRING_HEAD.load(Ordering::Relaxed);
    let next = (h + 1) % SIGRING;
    if next != SIGRING_TAIL.load(Ordering::Relaxed) {
        SIGRING_SIGNO[h].store(if ignore { -signo } else { signo }, Ordering::Relaxed);
        SIGRING_PID[h].store(pid, Ordering::Relaxed);
        SIGRING_HEAD.store(next, Ordering::Release);
    }
    // wake the event loop
    let w = WAKE_PIPE[1].load(Ordering::Relaxed);
    if w >= 0 {
        let b = [1u8];
        unsafe {
            libc::write(w, b.as_ptr() as *const libc::c_void, 1);
        }
    }
    unsafe { *libc::__errno_location() = saved };
}

/// ngx_parent
static PARENT_PID: AtomicI32 = AtomicI32::new(0);

/// Log queued "signal received" notices (called outside the handler).
pub fn drain_signal_log(log: &Log) {
    loop {
        let t = SIGRING_TAIL.load(Ordering::Relaxed);
        if t == SIGRING_HEAD.load(Ordering::Acquire) {
            break;
        }
        let signo = SIGRING_SIGNO[t].load(Ordering::Relaxed);
        let pid = SIGRING_PID[t].load(Ordering::Relaxed);
        SIGRING_TAIL.store((t + 1) % SIGRING, Ordering::Release);
        let ignored = signo < 0;
        let signo = signo.abs();
        let kind = PROCESS_KIND.load(Ordering::Relaxed);
        let action = match (kind, signo) {
            (0 | 1, libc::SIGQUIT) => ", shutting down",
            (0 | 1, libc::SIGTERM) | (0 | 1, libc::SIGINT) => ", exiting",
            (0 | 1, libc::SIGWINCH) => {
                if DAEMONIZED.load(Ordering::Relaxed) {
                    ", stop accepting connections"
                } else {
                    ""
                }
            }
            (0 | 1, libc::SIGHUP) => ", reconfiguring",
            (0 | 1, libc::SIGUSR1) => ", reopening logs",
            (0 | 1, libc::SIGUSR2) => {
                if ignored {
                    ", ignoring"
                } else {
                    ", changing binary"
                }
            }
            (3 | 4, libc::SIGWINCH) | (3 | 4, libc::SIGQUIT) => ", shutting down",
            (3 | 4, libc::SIGTERM) | (3 | 4, libc::SIGINT) => ", exiting",
            (3 | 4, libc::SIGUSR1) => ", reopening logs",
            (3 | 4, libc::SIGHUP) | (3 | 4, libc::SIGUSR2) | (3 | 4, libc::SIGIO) => ", ignoring",
            _ => "",
        };
        if pid != 0 {
            ngx_log_error!(NGX_LOG_NOTICE, log, None, "signal {} ({}) received from {}{}", signo, signame(signo), pid, action);
        } else {
            ngx_log_error!(NGX_LOG_NOTICE, log, None, "signal {} ({}) received{}", signo, signame(signo), action);
        }
        if ignored {
            ngx_log_error!(NGX_LOG_CRIT, log, None, "the changing binary signal is ignored: you should shutdown or terminate before either old or new binary's process");
        }
    }
}

/// ngx_init_signals
pub fn init_signals(log: &Log) -> Result<(), ()> {
    PARENT_PID.store(unsafe { libc::getppid() }, Ordering::Relaxed);
    // wake pipe
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } == 0 {
        WAKE_PIPE[0].store(fds[0], Ordering::Relaxed);
        WAKE_PIPE[1].store(fds[1], Ordering::Relaxed);
    }
    for &signo in &[libc::SIGHUP, libc::SIGUSR1, libc::SIGWINCH, libc::SIGTERM, libc::SIGQUIT, libc::SIGUSR2, libc::SIGALRM, libc::SIGINT, libc::SIGIO, libc::SIGCHLD] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = signal_handler as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(signo, &sa, std::ptr::null_mut()) == -1 {
                ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "sigaction({}) failed", signame(signo));
                return Err(());
            }
        }
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut());
    }
    Ok(())
}

/// Drain the wake pipe.
pub fn drain_wake_pipe() {
    let fd = WAKE_PIPE[0].load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// channels

pub fn write_channel(s: i32, ch: &Channel, log: &Log) -> Result<(), bool> {
    unsafe {
        let mut iov = libc::iovec { iov_base: ch as *const Channel as *mut libc::c_void, iov_len: std::mem::size_of::<Channel>() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        let mut cmsg_buf = [0u8; 32];
        if ch.fd == -1 {
            msg.msg_control = std::ptr::null_mut();
            msg.msg_controllen = 0;
        } else {
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
            let cm = libc::CMSG_FIRSTHDR(&msg);
            (*cm).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
            (*cm).cmsg_level = libc::SOL_SOCKET;
            (*cm).cmsg_type = libc::SCM_RIGHTS;
            std::ptr::copy_nonoverlapping(&ch.fd as *const i32 as *const u8, libc::CMSG_DATA(cm), std::mem::size_of::<i32>());
        }
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let n = libc::sendmsg(s, &msg, 0);
        if n == -1 {
            let e = os::errno();
            if e == libc::EAGAIN {
                return Err(true);
            }
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "sendmsg() failed");
            return Err(false);
        }
    }
    Ok(())
}

/// Returns Ok(Some(ch)), Ok(None) for EAGAIN, Err(()) for error/EOF.
pub fn read_channel(s: i32, log: &Log) -> Result<Option<Channel>, ()> {
    unsafe {
        let mut ch = Channel::default();
        let mut iov = libc::iovec { iov_base: &mut ch as *mut Channel as *mut libc::c_void, iov_len: std::mem::size_of::<Channel>() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        let mut cmsg_buf = [0u8; 32];
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
        let n = libc::recvmsg(s, &mut msg, 0);
        if n == -1 {
            let e = os::errno();
            if e == libc::EAGAIN {
                return Ok(None);
            }
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "recvmsg() failed");
            if e == libc::EMSGSIZE || e == libc::EMFILE {
                return Ok(Some(Channel::default()));
            }
            return Err(());
        }
        if n == 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "recvmsg() returned zero");
            return Err(());
        }
        if (n as usize) < std::mem::size_of::<Channel>() {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned not enough data: {}", n);
            return Err(());
        }
        if ch.command == NGX_CMD_OPEN_CHANNEL {
            if msg.msg_controllen < libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned too small ancillary data");
                ch.fd = -1;
            } else {
                let cm = libc::CMSG_FIRSTHDR(&msg);
                if (*cm).cmsg_level != libc::SOL_SOCKET || (*cm).cmsg_type != libc::SCM_RIGHTS {
                    ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned invalid ancillary data level {} or type {}", (*cm).cmsg_level, (*cm).cmsg_type);
                    return Err(());
                } else {
                    let mut fd: i32 = -1;
                    std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cm), &mut fd as *mut i32 as *mut u8, std::mem::size_of::<i32>());
                    ch.fd = fd;
                }
            }
        }
        // not MSG_CTRUNC: a descriptor which could not be received (EMFILE)
        // is the "too small ancillary data" above
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() truncated data");
        }
        Ok(Some(ch))
    }
}

pub fn close_channel(ch: &[i32; 2], log: &Log) {
    for &fd in ch {
        if fd != -1 && unsafe { libc::close(fd) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "close() channel failed");
        }
    }
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
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, channel.as_mut_ptr()) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "socketpair() failed while spawning \"{}\"", name);
            return -1;
        }
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "channel {}:{}", channel[0], channel[1]);
        for &fd in &channel {
            if let Err(e) = os::set_nonblocking(fd) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "ioctl(FIONBIO) failed while spawning \"{}\"", name);
                close_channel(&channel, &log);
                return -1;
            }
        }
        unsafe {
            let on: libc::c_int = 1;
            if libc::ioctl(channel[0], libc::FIOASYNC, &on) == -1 {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "ioctl(FIOASYNC) failed while spawning \"{}\"", name);
                close_channel(&channel, &log);
                return -1;
            }
            if libc::fcntl(channel[0], libc::F_SETOWN, libc::getpid()) == -1 {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "fcntl(F_SETOWN) failed while spawning \"{}\"", name);
                close_channel(&channel, &log);
                return -1;
            }
        }
        CHANNEL.with(|c| c.set(channel[1]));
    }
    PROCESSES.with(|p| p.borrow_mut()[s].channel = channel);
    PROCESS_SLOT.with(|p| p.set(s));

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "fork() failed while spawning \"{}\"", name);
            close_channel(&channel, &log);
            return -1;
        }
        0 => {
            PARENT_PID.store(os::getppid(), Ordering::Relaxed);
            update_pid();
            proc_fn(cycle.clone(), data);
        }
        _ => {}
    }
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
        let mut status: i32 = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            return;
        }
        if pid == -1 {
            let e = os::errno();
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
        if libc::WIFSIGNALED(status) {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "{} {} exited on signal {}{}", process, pid, libc::WTERMSIG(status), if libc::WCOREDUMP(status) { " (core dumped)" } else { "" });
        } else {
            ngx_log_error!(NGX_LOG_NOTICE, log, None, "{} {} exited with code {}", process, pid, libc::WEXITSTATUS(status));
        }
        if libc::WEXITSTATUS(status) == 2 {
            if let Some(i) = idx {
                let respawn = PROCESSES.with(|p| p.borrow()[i].respawn);
                if respawn {
                    ngx_log_error!(NGX_LOG_ALERT, log, None, "{} {} exited with fatal code {} and cannot be respawned", process, pid, libc::WEXITSTATUS(status));
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
                for (n2, other) in procs.iter().enumerate() {
                    if other.exited || other.pid == -1 || other.channel[0] == -1 {
                        continue;
                    }
                    ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "pass close channel s:{} pid:{} to:{}", ch.slot, ch.pid, other.pid);
                    let _ = n2;
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
                if std::fs::rename(os::path(&oldpid), os::path(&pid)).is_err() {
                    ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "rename() {} back to {} failed after the new binary process \"{}\" exited", B(&oldpid), B(&pid), B(argv()[0].as_bytes()));
                }
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
    std::process::exit(0);
}

/// ngx_master_process_cycle
pub fn master_process_cycle(mut cycle: Rc<Cycle>) -> ! {
    set_process_kind(ProcessType::Master);
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in &[libc::SIGCHLD, libc::SIGALRM, libc::SIGIO, libc::SIGINT, libc::SIGHUP, libc::SIGUSR1, libc::SIGWINCH, libc::SIGTERM, libc::SIGQUIT, libc::SIGUSR2] {
            libc::sigaddset(&mut set, s);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "sigprocmask() failed");
        }
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
            let itv = libc::itimerval {
                it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
                it_value: libc::timeval { tv_sec: (delay / 1000) as libc::time_t, tv_usec: ((delay % 1000) * 1000) as libc::suseconds_t },
            };
            if unsafe { libc::setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) } == -1 {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "setitimer() failed");
            }
        }
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "sigsuspend");
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigsuspend(&set);
        }
        crate::times::update();
        drain_wake_pipe();
        drain_signal_log(&cycle.log);
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "wake up, sigio {}", sigio);

        if SIG_REAP.swap(false, Ordering::SeqCst) {
            process_get_status(&cycle.log);
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "reap children");
            live = reap_children(&cycle);
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
    // clear close-on-exec on listening sockets
    for ls in cycle.listening.iter() {
        let fd = ls.fd.get();
        if fd != -1 {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
        }
    }
    PENDING_EXEC_ENV.with(|e| *e.borrow_mut() = Some(env));
    let child = spawn_process(cycle, exec_proc_stub, 0, "new binary process", NGX_PROCESS_DETACHED);
    if child == -1 {
        if let Err(e) = std::fs::rename(os::path(&oldpid), os::path(&pid)) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, e.raw_os_error(), "rename() {} back to {} failed after an attempt to execute new binary process \"{}\"", B(&oldpid), B(&pid), B(args[0].as_bytes()));
        }
    }
    for ls in cycle.listening.iter() {
        let fd = ls.fd.get();
        if fd != -1 {
            let _ = os::set_cloexec(fd);
        }
    }
    PENDING_EXEC_ENV.with(|e| *e.borrow_mut() = None);
    child
}

thread_local! {
    /// ctx.envp of the new binary process
    static PENDING_EXEC_ENV: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
}

/// ngx_execute_proc
fn exec_proc_stub(cycle: Rc<Cycle>, _data: i64) -> ! {
    let args = argv();
    let argv_ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    let envs: Vec<CString> = PENDING_EXEC_ENV.with(|e| e.borrow().iter().flatten().map(|v| os::cstr(v)).collect());
    let env_ptrs: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    unsafe {
        libc::execve(args[0].as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "execve() failed while executing new binary process \"{}\"", B(args[0].as_bytes()));
    std::process::exit(1);
}

/// ngx_daemon
pub fn daemon(log: &Log) -> Result<(), ()> {
    let pid = os::getpid();
    match unsafe { libc::fork() } {
        -1 => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "fork() failed");
            return Err(());
        }
        0 => {}
        _ => std::process::exit(0),
    }
    update_pid();
    // ngx_parent = ngx_pid
    PARENT_PID.store(pid, Ordering::Relaxed);
    if unsafe { libc::setsid() } == -1 {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "setsid() failed");
        return Err(());
    }
    unsafe { libc::umask(0) };
    let fd = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if fd == -1 {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "open(\"/dev/null\") failed");
        return Err(());
    }
    unsafe {
        if libc::dup2(fd, libc::STDIN_FILENO) == -1 {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "dup2(STDIN) failed");
            return Err(());
        }
        if libc::dup2(fd, libc::STDOUT_FILENO) == -1 {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "dup2(STDOUT) failed");
            return Err(());
        }
        if fd > libc::STDERR_FILENO {
            libc::close(fd);
        }
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
                if let Some(v) = std::env::var_os(std::ffi::OsStr::from_bytes(&name)) {
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
                if let Some(v) = std::env::var_os(std::ffi::OsStr::from_bytes(name)) {
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
    // keep NGINX var handling out; clear and set
    let keep_nginx = std::env::var_os("NGINX");
    unsafe {
        libc::clearenv();
    }
    for (k, v) in vars {
        std::env::set_var(std::ffi::OsStr::from_bytes(&k), std::ffi::OsStr::from_bytes(&v));
    }
    let _ = keep_nginx;
}

use std::os::unix::ffi::OsStrExt;

// --- setproctitle via argv area captured at startup ---

static mut OS_ARGV: *mut *mut libc::c_char = std::ptr::null_mut();
static mut OS_ARGC: libc::c_int = 0;
static mut OS_ENVP: *mut *mut libc::c_char = std::ptr::null_mut();
static mut ARGV_LAST: *mut libc::c_char = std::ptr::null_mut();

#[used]
#[link_section = ".init_array"]
static CAPTURE_ARGS: extern "C" fn(libc::c_int, *mut *mut libc::c_char, *mut *mut libc::c_char) = capture_args;

extern "C" fn capture_args(argc: libc::c_int, argv: *mut *mut libc::c_char, envp: *mut *mut libc::c_char) {
    unsafe {
        OS_ARGC = argc;
        OS_ARGV = argv;
        OS_ENVP = envp;
    }
}

/// ngx_init_setproctitle: move environment strings so argv+environ area can hold the title.
pub fn init_setproctitle() {
    unsafe {
        if OS_ARGV.is_null() {
            return;
        }
        let mut last: *mut libc::c_char = std::ptr::null_mut();
        for i in 0..OS_ARGC as isize {
            let a = *OS_ARGV.offset(i);
            if last.is_null() || a == last {
                last = a.add(libc::strlen(a) + 1);
            }
        }
        let mut i = 0;
        loop {
            let e = *OS_ENVP.offset(i);
            if e.is_null() {
                break;
            }
            if e == last {
                let len = libc::strlen(e) + 1;
                last = e.add(len);
                let copy = libc::malloc(len) as *mut libc::c_char;
                if copy.is_null() {
                    return;
                }
                std::ptr::copy_nonoverlapping(e, copy, len);
                *OS_ENVP.offset(i) = copy;
            }
            i += 1;
        }
        ARGV_LAST = last.sub(1);
    }
}

/// ngx_setproctitle: "nginx: <title>"
pub fn setproctitle(title: &[u8]) {
    unsafe {
        if OS_ARGV.is_null() || ARGV_LAST.is_null() {
            return;
        }
        let start = *OS_ARGV;
        *OS_ARGV.offset(1) = std::ptr::null_mut();
        let cap = ARGV_LAST as usize - start as usize;
        let mut buf = b"nginx: ".to_vec();
        buf.extend_from_slice(title);
        if buf.len() > cap {
            buf.truncate(cap);
        }
        std::ptr::copy_nonoverlapping(buf.as_ptr(), start as *mut u8, buf.len());
        let pad = cap - buf.len();
        if pad > 0 {
            std::ptr::write_bytes((start as *mut u8).add(buf.len()), 0, pad);
        }
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
        ls.fd.set(s);
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
    use std::os::unix::io::IntoRawFd;

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
            let fd = std::os::unix::net::UnixListener::bind(&path).unwrap().into_raw_fd();

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
}
