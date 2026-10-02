//! Event module (events {} block) and the per-worker tokio runtime.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use tokio::io::unix::AsyncFd;
use tokio::task::LocalSet;

use crate::conf::*;
use crate::connection::*;
use crate::core_module::core_conf;
use crate::cycle::*;
use crate::inet::{ptocidr, Cidr, CidrParse};
use crate::listen_event::ListenEvent;
use crate::listening::Listening;
use crate::log::*;
use crate::module::*;
use crate::process::*;
use crate::string::B;
use crate::{cmd, cmd_fn, ngx_log_debug, ngx_log_error, os};

pub const DEFAULT_CONNECTIONS: u64 = 512;

/// The read event of a listening socket in this worker, and the task of
/// its handler.
struct ListenSlot {
    ls: Rc<Listening>,
    ev: Rc<ListenEvent>,
    task: tokio::task::AbortHandle,
}

pub struct EventConf {
    pub connections: Val<u64>,
    pub use_: Val<Vec<u8>>,
    pub multi_accept: Val<bool>,
    pub accept_mutex: Val<bool>,
    pub accept_mutex_delay: Val<u64>,
    pub debug_connection: Vec<Cidr>,
}

thread_local! {
    static EVENT_CONF: RefCell<Option<Rc<RefCell<EventConf>>>> = const { RefCell::new(None) };
    /// The read events of the listening sockets of this worker
    /// (ls->connection->read), by socket, and the tasks of their handlers.
    static LISTEN_EVENTS: RefCell<HashMap<i32, ListenSlot>> = RefCell::new(HashMap::new());
    /// ngx_accept_mutex_held
    static ACCEPT_MUTEX_HELD: Cell<bool> = const { Cell::new(false) };
    /// ngx_accept_disabled: accepting is skipped while the worker has less
    /// than 1/8 of its connections free
    static ACCEPT_DISABLED: Cell<i64> = const { Cell::new(0) };
    /// ngx_use_exclusive_accept
    static USE_EXCLUSIVE_ACCEPT: Cell<bool> = const { Cell::new(false) };
    /// ngx_use_accept_mutex
    static USE_ACCEPT_MUTEX: Cell<bool> = const { Cell::new(false) };
    /// an accept event was handled (the end of an event loop iteration of
    /// the accept mutex holder)
    static ACCEPTED: Rc<tokio::sync::Notify> = Rc::new(tokio::sync::Notify::new());
    static EXITING: Cell<bool> = const { Cell::new(false) };
    static FLAGS_NOTIFY: Rc<tokio::sync::Notify> = Rc::new(tokio::sync::Notify::new());
    static WORKER: Cell<i64> = const { Cell::new(0) };
}

pub fn event_conf() -> Option<Rc<RefCell<EventConf>>> {
    EVENT_CONF.with(|e| e.borrow().clone())
}

pub fn is_exiting() -> bool {
    EXITING.with(|e| e.get())
}

pub fn worker_index() -> i64 {
    WORKER.with(|w| w.get())
}

pub fn debug_connection_cidrs() -> Vec<Cidr> {
    event_conf().map(|c| c.borrow().debug_connection.clone()).unwrap_or_default()
}

/// The test of a debug_connection cidr in ngx_debug_accepted_connection:
/// the family of the address must be the one of the cidr, an IPv4-mapped
/// IPv6 address is AF_INET6 there (unlike in ngx_cidr_match).
pub fn debug_connection_match(cidr: &Cidr, sa: &crate::inet::SockAddr) -> bool {
    use crate::inet::SockAddr;

    match (cidr, sa) {
        (Cidr::V6 { addr, mask }, SockAddr::V6(a)) => {
            let s6_addr = a.ip().octets();
            (0..16).all(|n| (s6_addr[n] & mask[n]) == addr[n])
        }
        (Cidr::Unix, SockAddr::Unix(_)) => true,
        // AF_INET
        (Cidr::V4 { addr, mask }, SockAddr::V4(a)) => (u32::from(*a.ip()) & mask) == *addr,
        _ => false,
    }
}

// --- events {} block -------------------------------------------------------

fn events_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let idx = cf.module_index;
    if cf.cycle.conf_ctx[idx].is_some() {
        return Err(msg("is duplicate"));
    }
    let n = count_modules(&cf.cycle.modules, NGX_EVENT_MODULE);
    let slots = new_slots(n);
    // create confs
    let modules = cf.cycle.modules.clone();
    for m in modules.iter().filter(|m| m.def.ty == NGX_EVENT_MODULE) {
        if let Some(ctx) = m.ctx::<EventModuleCtx>() {
            if let Some(create) = ctx.create_conf {
                slots.borrow_mut()[m.ctx_index] = Some(create(cf.cycle));
            }
        }
    }
    let holder: Rc<dyn Any> = Rc::new(slots.clone());
    cf.cycle.conf_ctx[idx] = Some(holder);

    let saved_ctx = std::mem::take(&mut cf.ctx);
    let saved_mt = cf.module_type;
    let saved_ct = cf.cmd_type;
    cf.ctx = ConfCtx { main: Some(slots.clone()), srv: None, loc: None };
    cf.module_type = NGX_EVENT_MODULE;
    cf.cmd_type = NGX_EVENT_CONF;
    let rv = cf.parse_block();
    cf.ctx = saved_ctx;
    cf.module_type = saved_mt;
    cf.cmd_type = saved_ct;
    rv?;

    for m in modules.iter().filter(|m| m.def.ty == NGX_EVENT_MODULE) {
        if let Some(ctx) = m.ctx::<EventModuleCtx>() {
            if let Some(init) = ctx.init_conf {
                let c = slots.borrow()[m.ctx_index].clone().expect("event conf");
                init(cf, &c)?;
            }
        }
    }
    Ok(())
}

pub const NGX_EVENT_CONF: u32 = 0x02000000;

pub struct EventModuleCtx {
    pub name: &'static str,
    pub create_conf: Option<fn(&mut Cycle) -> Rc<dyn Any>>,
    pub init_conf: Option<fn(&mut Conf, &Rc<dyn Any>) -> ConfResult>,
}

pub fn events_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_events_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "events", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("events", NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, events_block)];
    m.init_module = Some(event_module_init);
    m
}

fn create_event_conf(_cycle: &mut Cycle) -> Rc<dyn Any> {
    make_slot(EventConf {
        connections: Val::unset(),
        use_: Val::unset(),
        multi_accept: Val::unset(),
        accept_mutex: Val::unset(),
        accept_mutex_delay: Val::unset(),
        debug_connection: Vec::new(),
    })
}

fn init_event_conf(cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let cell = conf_cell::<EventConf>(conf);
    let mut ecf = cell.borrow_mut();
    ecf.connections.init(DEFAULT_CONNECTIONS);
    ecf.use_.init(b"epoll".to_vec());
    ecf.multi_accept.init(false);
    ecf.accept_mutex.init(false);
    ecf.accept_mutex_delay.init(500);
    // Propagate to the cycle so the process init sets the per-worker connection cap.
    cf.cycle.connection_n = *ecf.connections as usize;
    Ok(())
}

fn set_connections(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<EventConf>(&conf);
    let mut ecf = cell.borrow_mut();
    if ecf.connections.is_set() {
        return Err(msg("is duplicate"));
    }
    match crate::string::atoi(&cf.args[1]) {
        Some(n) => {
            ecf.connections = Val::set(n as u64);
        }
        None => return Err(cf.emerg(format_args!("invalid number \"{}\"", B(&cf.args[1])))),
    }
    cf.cycle.connection_n = *ecf.connections as usize;
    Ok(())
}

fn set_use(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<EventConf>(&conf);
    let mut ecf = cell.borrow_mut();
    if ecf.use_.is_set() {
        return Err(msg("is duplicate"));
    }
    if cf.args[1] != b"epoll" {
        return Err(cf.emerg(format_args!("invalid event type \"{}\"", B(&cf.args[1]))));
    }
    ecf.use_ = Val::set(cf.args[1].clone());
    Ok(())
}

fn debug_connection(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<EventConf>(&conf);
    let mut ecf = cell.borrow_mut();
    let v = cf.args[1].clone();
    if v == b"unix:" {
        ecf.debug_connection.push(Cidr::Unix);
        return Ok(());
    }
    match ptocidr(&v) {
        CidrParse::Ok(c) => ecf.debug_connection.push(c),
        CidrParse::Done(c) => {
            cf.warn(format_args!("low address bits of {} are meaningless", B(&v)));
            ecf.debug_connection.push(c);
        }
        CidrParse::Error => {
            // try resolving as a host name
            let mut u = crate::inet::Url::new(&v);
            u.no_port = true;
            if crate::inet::parse_url(&mut u).is_err() {
                if let Some(e) = u.err {
                    return Err(cf.emerg(format_args!("{} in debug_connection \"{}\"", e, B(&v))));
                }
                return Err(ConfError::Logged);
            }
            for a in u.addrs {
                match a.sockaddr {
                    crate::inet::SockAddr::V4(s) => ecf.debug_connection.push(Cidr::V4 { addr: u32::from(*s.ip()), mask: 0xffffffff }),
                    crate::inet::SockAddr::V6(s) => ecf.debug_connection.push(Cidr::V6 { addr: s.ip().octets(), mask: [0xff; 16] }),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

pub fn event_core_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_event_core_module", NGX_EVENT_MODULE);
    m.ctx = Some(Rc::new(EventModuleCtx { name: "event_core", create_conf: Some(create_event_conf), init_conf: Some(init_event_conf) }));
    m.commands = vec![
        cmd_fn!("worker_connections", NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::Main, set_connections),
        cmd_fn!("use", NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::Main, set_use),
        cmd!("multi_accept", NGX_EVENT_CONF | NGX_CONF_FLAG, ConfLevel::Main, EventConf, multi_accept, set_flag),
        cmd!("accept_mutex", NGX_EVENT_CONF | NGX_CONF_FLAG, ConfLevel::Main, EventConf, accept_mutex, set_flag),
        cmd!("accept_mutex_delay", NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::Main, EventConf, accept_mutex_delay, set_msec),
        cmd_fn!("debug_connection", NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::Main, debug_connection),
    ];
    m.init_process = Some(event_process_init);
    m
}

/// Get the event core conf from a cycle.
pub fn get_event_conf(cycle: &Cycle) -> Option<Rc<RefCell<EventConf>>> {
    let m = find_module(&cycle.modules, "ngx_events_module")?;
    let holder = cycle.conf_ctx[m.index].as_ref()?;
    let slots = holder.downcast_ref::<Rc<ConfSlots>>()?;
    let core = find_module(&cycle.modules, "ngx_event_core_module")?;
    let c = slots.borrow()[core.ctx_index].clone()?;
    Some(conf_rc::<EventConf>(&c))
}

/// ngx_event_module_init: validate events section, log OS info, init shared stats.
fn event_module_init(cycle: &mut Cycle) -> Result<(), ()> {
    let ecf = match get_event_conf(cycle) {
        Some(e) => e,
        None => {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, None, "no \"events\" section in configuration");
            return Err(());
        }
    };
    if is_test_config() {
        return Ok(());
    }
    let connections = *ecf.borrow().connections;
    cycle.connection_n = connections as usize;
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "using the \"{}\" event method", B(&ecf.borrow().use_));
    let ccf = core_conf(cycle);
    let _ = ccf;
    init_shared_stats(&cycle.log);
    EVENT_CONF.with(|e| *e.borrow_mut() = Some(ecf));
    Ok(())
}

fn event_process_init(cycle: &Rc<Cycle>) -> Result<(), ()> {
    set_connection_n(cycle.connection_n.max(1));

    // a connection for each listening socket, but those of the other
    // workers with reuseport
    let worker = worker_index();
    let n = cycle.listening.iter().filter(|ls| ls.fd.get() != -1 && !(ls.reuseport.get() && ls.worker.get() as i64 != worker)).count();

    crate::connection::reserve_connections(n);

    if let Some(e) = get_event_conf(cycle) {
        EVENT_CONF.with(|c| *c.borrow_mut() = Some(e));
    }
    Ok(())
}

// --- worker runtime --------------------------------------------------------

pub fn spawn<F: std::future::Future<Output = ()> + 'static>(f: F) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(f)
}

thread_local! {
    static POSTED_TASKS: RefCell<Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>>> = const { RefCell::new(Vec::new()) };
}

/// spawn(), or, before the event loop runs, once it starts: init_process
/// handlers add timers, as ngx_add_timer() works before
/// ngx_process_events_and_timers() in C.
pub fn spawn_posted<F: std::future::Future<Output = ()> + 'static>(f: F) {
    if tokio::runtime::Handle::try_current().is_ok() {
        spawn(f);
        return;
    }
    POSTED_TASKS.with(|p| p.borrow_mut().push(Box::pin(f)));
}

fn spawn_posted_tasks() {
    let tasks = POSTED_TASKS.with(|p| std::mem::take(&mut *p.borrow_mut()));
    for f in tasks {
        spawn(f);
    }
}

/// NGX_TIMER_LAZY_DELAY: ngx_add_timer() leaves a set timer as it is when
/// the new expiry is less than this many milliseconds from the old one.
pub const NGX_TIMER_LAZY_DELAY: u64 = 300;

/// The timer of an event (ev->timer.key, ev->timer_set, ev->timedout) for
/// the task that handles the event: ngx_add_timer() and ngx_del_timer()
/// over one tokio Sleep, pinned once and reset, instead of a timeout future
/// made, registered with the timer wheel and cancelled for each wait.
///
/// - add(msec) / add_at(deadline): ngx_add_timer(); a set timer is moved
///   only by NGX_TIMER_LAZY_DELAY or more (C saves rbtree operations that
///   way; here the wheel's). Moving a timer later is lock-free in tokio
///   (the entry's expiry is extended in place; the wheel re-files it when
///   the old expiry comes); moving it earlier re-registers it.
/// - del(): ngx_del_timer(): no longer set. The Sleep is left as it is, so
///   the next add() is usually a move later; a deleted timer whose old
///   expiry passes may wake its waiter once, which finds it not set.
/// - expired().await / poll_expired(): the event handler's wait for
///   ev->timedout. Never ready while the timer is not set; once expired,
///   the timer is not set any more and timedout() is true, as
///   ngx_event_expire_timers() leaves it before calling the handler.
///
/// The methods take &self, so the timer can be shared (Rc) between the
/// code that sets it and the task waiting for it; one task waits at a time
/// (the Sleep keeps the waker of the last poll), as an event has one
/// handler. Made in a runtime (a Sleep is bound to the timer driver); the
/// Sleep is boxed once per timer, and registered only once polled.
pub struct EventTimer {
    sleep: RefCell<std::pin::Pin<Box<tokio::time::Sleep>>>,
    key: Cell<Option<tokio::time::Instant>>,
    timedout: Cell<bool>,
}

impl EventTimer {
    pub fn new() -> EventTimer {
        // a Sleep that is never polled is never registered: the deadline
        // is only that of a Sleep not set yet
        let far = tokio::time::Instant::now() + std::time::Duration::from_secs(86400 * 365 * 30);

        EventTimer { sleep: RefCell::new(Box::pin(tokio::time::sleep_until(far))), key: Cell::new(None), timedout: Cell::new(false) }
    }

    /// ev->timer_set
    pub fn is_set(&self) -> bool {
        self.key.get().is_some()
    }

    /// ev->timer.key: when the timer expires, if set
    pub fn deadline(&self) -> Option<tokio::time::Instant> {
        self.key.get()
    }

    /// ev->timedout: set when the timer expired, until the handler clears it
    pub fn timedout(&self) -> bool {
        self.timedout.get()
    }

    pub fn set_timedout(&self, timedout: bool) {
        self.timedout.set(timedout);
    }

    /// ngx_add_timer(ev, msec)
    pub fn add(&self, msec: u64) {
        self.add_at(tokio::time::Instant::now() + std::time::Duration::from_millis(msec));
    }

    /// ngx_add_timer() with the expiry given: a set timer is moved only if
    /// by NGX_TIMER_LAZY_DELAY or more
    pub fn add_at(&self, key: tokio::time::Instant) {
        if let Some(old) = self.key.get() {
            let diff = if key > old { key - old } else { old - key };

            if diff < std::time::Duration::from_millis(NGX_TIMER_LAZY_DELAY) {
                return;
            }
        }

        self.key.set(Some(key));
        self.sleep.borrow_mut().as_mut().reset(key);
    }

    /// ngx_del_timer(ev)
    pub fn del(&self) {
        self.key.set(None);
    }

    /// Ready once the timer, while set, expires: it is not set any more,
    /// and timedout() is true.
    pub fn poll_expired(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        use std::future::Future;

        if self.key.get().is_none() {
            return std::task::Poll::Pending;
        }

        match self.sleep.borrow_mut().as_mut().poll(cx) {
            std::task::Poll::Ready(()) => {
                self.key.set(None);
                self.timedout.set(true);
                std::task::Poll::Ready(())
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Wait until the timer expires (see poll_expired()); never, while it
    /// is not set.
    pub async fn expired(&self) {
        std::future::poll_fn(|cx| self.poll_expired(cx)).await
    }
}

impl Default for EventTimer {
    fn default() -> EventTimer {
        EventTimer::new()
    }
}

fn flags_notify() -> Rc<tokio::sync::Notify> {
    FLAGS_NOTIFY.with(|n| n.clone())
}

/// Called after fork in a worker (ngx_worker_process_init).
fn worker_process_init(cycle: &Rc<Cycle>, worker: i64) {
    crate::control::close_sockets();

    set_environment(cycle);
    let ccf = core_conf(cycle);
    let (priority, rlimit_nofile, rlimit_core, user, group, username, workdir, cpu_affinity, cpu_auto) = {
        let c = ccf.borrow();
        (c.priority, c.rlimit_nofile.clone(), c.rlimit_core.clone(), c.user, c.group, c.username.clone(), c.working_directory.clone(), c.cpu_affinity.clone(), c.cpu_affinity_auto)
    };
    if worker >= 0 && priority != 0 {
        if let Err(e) = rustix::process::setpriority_process(None, priority as i32) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e.raw_os_error()), "setpriority({}) failed", priority);
        }
    }
    if let Some(n) = rlimit_nofile.as_option() {
        if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, *n as libc::rlim_t, *n as libc::rlim_t) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "setrlimit(RLIMIT_NOFILE, {}) failed", n);
        }
    }
    if let Some(n) = rlimit_core.as_option() {
        if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, *n as libc::rlim_t, *n as libc::rlim_t) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "setrlimit(RLIMIT_CORE, {}) failed", n);
        }
    }
    if os::geteuid() == 0 {
        if let (Some(uid), Some(gid)) = (user, group) {
            if let Err(e) = nix::unistd::setgid(nix::unistd::Gid::from_raw(gid)) {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e as i32), "setgid({}) failed", gid);
                std::process::exit(2);
            }
            let uname = os::cstr(&username);
            if let Err(e) = nix::unistd::initgroups(&uname, nix::unistd::Gid::from_raw(gid)) {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e as i32), "initgroups({}, {}) failed", B(&username), gid);
            }
            if let Err(e) = nix::unistd::setuid(nix::unistd::Uid::from_raw(uid)) {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e as i32), "setuid({}) failed", uid);
                std::process::exit(2);
            }
        }
    }
    if worker >= 0 && !cpu_affinity.is_empty() {
        let mask = if cpu_auto {
            None
        } else {
            let idx = (worker as usize).min(cpu_affinity.len() - 1);
            Some(&cpu_affinity[idx])
        };
        if let Some(mask) = mask {
            let mut set = nix::sched::CpuSet::new();
            for (i, &on) in mask.iter().enumerate() {
                if on && i < nix::sched::CpuSet::count() {
                    let _ = set.set(i);
                }
            }
            if let Err(e) = nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set) {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "sched_setaffinity() failed");
            }
        }
    }
    // allow coredump after setuid()
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable);
    if !workdir.is_empty() {
        if let Err(e) = nix::unistd::chdir(os::path(&workdir)) {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "chdir(\"{}\") failed", B(&workdir));
            std::process::exit(2);
        }
    }
    if let Err(e) = nix::sys::signal::sigprocmask(nix::sys::signal::SigmaskHow::SIG_SETMASK, Some(&nix::sys::signal::SigSet::empty()), None) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e as i32), "sigprocmask() failed");
    }
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.init_process {
            if f(cycle).is_err() {
                std::process::exit(2);
            }
        }
    }
    // the connection of the channel (ngx_add_channel_event)
    crate::connection::reserve_connections(1);
    // close other workers' channel[1] and our channel[0]
    let slot = PROCESS_SLOT.with(|p| p.get());
    PROCESSES.with(|p| {
        let p = p.borrow();
        for (n, pr) in p.iter().enumerate() {
            if pr.pid == -1 || n == slot || pr.channel[1] == -1 {
                continue;
            }
            if let Err(e) = os::close_fd(pr.channel[1]) {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "close() channel failed");
            }
        }
        if slot < p.len() && p[slot].channel[0] != -1 {
            if let Err(e) = os::close_fd(p[slot].channel[0]) {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "close() channel failed");
            }
        }
    });
}

fn worker_process_exit(cycle: &Rc<Cycle>) -> ! {
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.exit_process {
            f(cycle);
        }
    }
    if is_exiting() && !SIG_TERMINATE.load(Ordering::SeqCst) {
        for_each_connection(|c| {
            if !c.is_closed() {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, None, "*{} open socket #{} left in connection", c.number, c.fd.get());
                DEBUG_QUIT.store(true, Ordering::SeqCst);
            }
        });
    }
    if DEBUG_QUIT.load(Ordering::SeqCst) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, None, "aborting");
    }
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exit");
    std::process::exit(0);
}

/// ngx_worker_process_cycle
pub fn worker_process_cycle(cycle: Rc<Cycle>, worker: i64) -> ! {
    set_process_kind(ProcessType::Worker);
    globals_mut(|g| g.worker = worker as usize);
    WORKER.with(|w| w.set(worker));
    set_cycle(cycle.clone());
    worker_process_init(&cycle, worker);
    setproctitle(b"worker process");
    run_event_loop(cycle, false)
}

/// ngx_single_process_cycle body.
pub fn single_process_run(cycle: Rc<Cycle>) -> ! {
    set_cycle(cycle.clone());
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.init_process {
            if f(&cycle).is_err() {
                std::process::exit(2);
            }
        }
    }
    run_event_loop(cycle, true)
}

/// Cache manager / loader helper processes (data: 0 manager, 1 loader).
pub fn cache_manager_process_cycle(cycle: Rc<Cycle>, data: i64) -> ! {
    set_process_kind(ProcessType::Helper);
    set_cycle(cycle.clone());
    close_listening_sockets(&cycle);
    set_connection_n(512);
    worker_process_init(&cycle, -1);
    let name: &[u8] = if data == 0 { b"cache manager process" } else { b"cache loader process" };
    setproctitle(name);
    let rt = event_runtime();
    let local = LocalSet::new();
    let c2 = cycle.clone();
    block_on_events(&rt, &local, async move {
        spawn(control_task(c2.clone(), false));
        let notify = flags_notify();
        // ngx_add_timer(&ev, ctx->delay): the manager at once, the loader
        // after a minute
        let timer = EventTimer::new();
        timer.add(if data == 0 { 0 } else { 60000 });
        loop {
            if SIG_TERMINATE.load(Ordering::SeqCst) || SIG_QUIT.load(Ordering::SeqCst) {
                ngx_log_error!(NGX_LOG_NOTICE, c2.log, None, "exiting");
                std::process::exit(0);
            }
            if SIG_REOPEN.swap(false, Ordering::SeqCst) {
                ngx_log_error!(NGX_LOG_NOTICE, c2.log, None, "reopening logs");
                c2.reopen_files(None);
            }
            // ngx_process_events_and_timers
            tokio::select! {
                _ = notify.notified() => continue,
                _ = timer.expired() => {}
            }
            if data == 0 {
                // ngx_cache_manager_process_handler: every path manager
                let mut next: u64 = 60 * 60 * 1000;
                for p in c2.paths.iter() {
                    let m = p.manager.borrow().clone();
                    if let Some(m) = m {
                        let d = p.data.borrow().clone();
                        if let Some(d) = d {
                            let n = m(&d);
                            if n <= next {
                                next = n;
                            }
                        }
                        crate::times::update();
                    }
                }
                if next == 0 {
                    next = 1;
                }
                timer.add(next);
            } else {
                // ngx_cache_loader_process_handler: every path loader, once
                for p in c2.paths.iter() {
                    if SIG_TERMINATE.load(Ordering::SeqCst) || SIG_QUIT.load(Ordering::SeqCst) {
                        break;
                    }
                    let l = p.loader.borrow().clone();
                    if let Some(l) = l {
                        if let Some(d) = p.data.borrow().clone() {
                            l(&d);
                        }
                        crate::times::update();
                    }
                }
                std::process::exit(0);
            }
        }
    });
    std::process::exit(0);
}

/// The read end of the signal pipe, which the process owns as long as it
/// lives (process::signal_fd()), registered in the reactor by its number.
struct SignalFd(i32);

impl std::os::fd::AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

/// Task that watches signal wakeups and the master channel, setting flags.
async fn control_task(cycle: Rc<Cycle>, _single: bool) {
    let chan = CHANNEL.with(|c| c.get());
    // the read end of the signal pipe, readable once the signal handler ran
    let wake_afd = signal_fd().and_then(|fd| AsyncFd::with_interest(SignalFd(fd), tokio::io::Interest::READABLE).ok());
    let mut chan_afd = if chan >= 0 && process_type() != ProcessType::Single {
        crate::fd::get(chan).ok().and_then(|f| AsyncFd::with_interest(f, tokio::io::Interest::READABLE).ok())
    } else {
        None
    };
    let notify = flags_notify();
    loop {
        tokio::select! {
            r = async { match &wake_afd { Some(a) => a.readable().await.map(|mut g| { g.clear_ready(); }), None => std::future::pending().await } } => {
                let _ = r;
                process_signals(&cycle.log, true);
                notify.notify_waiters();
                notify.notify_one();
            }
            r = async { match &chan_afd { Some(a) => a.readable().await.map(|mut g| { g.clear_ready(); }), None => std::future::pending().await } } => {
                if r.is_err() { break; }
                loop {
                    match read_channel(chan, &cycle.log) {
                        Err(()) => {
                            // ngx_close_connection() of the channel: signals
                            // are still handled
                            chan_afd = None;
                            if let Err(e) = os::close_fd(chan) {
                                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "close() socket {} failed", chan);
                            }
                            break;
                        }
                        Ok(None) => break,
                        Ok(Some(ch)) => {
                            ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "channel command: {}", ch.command);
                            match ch.command {
                                NGX_CMD_QUIT => SIG_QUIT.store(true, Ordering::SeqCst),
                                NGX_CMD_TERMINATE => SIG_TERMINATE.store(true, Ordering::SeqCst),
                                NGX_CMD_REOPEN => SIG_REOPEN.store(true, Ordering::SeqCst),
                                NGX_CMD_OPEN_CHANNEL => {
                                    ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "get channel s:{} pid:{} fd:{}", ch.slot, ch.pid, ch.fd);
                                    PROCESSES.with(|p| {
                                        let mut p = p.borrow_mut();
                                        let s = ch.slot as usize;
                                        while p.len() <= s {
                                            p.push(Process { pid: -1, status: 0, channel: [-1, -1], proc_fn: None, data: 0, name: "", respawn: false, just_spawn: false, detached: false, exiting: false, exited: false });
                                        }
                                        p[s].pid = ch.pid;
                                        p[s].channel[0] = ch.fd;
                                    });
                                }
                                NGX_CMD_CLOSE_CHANNEL => {
                                    PROCESSES.with(|p| {
                                        let mut p = p.borrow_mut();
                                        let s = ch.slot as usize;
                                        if s < p.len() && p[s].channel[0] != -1 && p[s].pid == ch.pid {
                                            if let Err(e) = os::close_fd(p[s].channel[0]) {
                                                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "close() channel failed");
                                            }
                                            p[s].channel[0] = -1;
                                        }
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }
                notify.notify_waiters();
                notify.notify_one();
            }
        }
    }
}

/// ngx_accept_disabled after an accept: connection_n / 8 minus the free
/// connections
pub(crate) fn update_accept_disabled() {
    ACCEPT_DISABLED.with(|d| d.set(connection_n() as i64 / 8 - free_connections() as i64));
}

pub fn accept_disabled() -> i64 {
    ACCEPT_DISABLED.with(|d| d.get())
}

/// The peer address accept4() returned for the connection `s`; None for a
/// family other than AF_INET, AF_INET6 and AF_UNIX. A unix address is the
/// one getpeername() gives: rustix's conversion of it panics on a path
/// filling sun_path, which a client can bind.
fn accepted_sockaddr(addr: rustix::net::SocketAddrAny, s: i32) -> Option<crate::inet::SockAddr> {
    use crate::inet::SockAddr;
    use rustix::net::AddressFamily;

    match addr.address_family() {
        AddressFamily::INET => std::net::SocketAddrV4::try_from(addr).ok().map(SockAddr::V4),
        AddressFamily::INET6 => std::net::SocketAddrV6::try_from(addr).ok().map(SockAddr::V6),
        AddressFamily::UNIX => {
            let ss = nix::sys::socket::getpeername::<nix::sys::socket::SockaddrStorage>(s).ok();

            // an unnamed peer otherwise, as most are
            Some(ss.and_then(|ss| SockAddr::from_nix(&ss)).unwrap_or(SockAddr::Unix(Vec::new())))
        }
        _ => None,
    }
}

/// ngx_event_accept: the read handler of a TCP listening socket, as the
/// task waiting for its read event.
async fn accept_loop(ls: Rc<Listening>, ev: Rc<ListenEvent>) {
    let fd = ls.fd.get();

    let log = ls.log.borrow().clone();

    let handler = ls.handler.borrow().clone();
    let handler = match handler {
        Some(h) => h,
        None => return,
    };

    // ls->connection->requests of ngx_reorder_accept_events
    let mut requests: u64 = 0;

    loop {
        let mut guard = match ev.wait().await {
            Ok(g) => g,
            Err(_) => return,
        };

        let multi_accept = event_conf().map(|c| *c.borrow().multi_accept).unwrap_or(false);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "accept on {}, ready: {}", B(&ls.addr_text), multi_accept as i32);

        // ev->available = multi_accept: one connection per event without it

        let mut again = false;
        let mut emfile = false;
        let mut reorder = false;

        loop {
            let accepted = crate::fd::get(fd)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))
                .and_then(|lfd| rustix::net::acceptfrom_with(&lfd, rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC).map_err(|e| e.raw_os_error()));
            let (s, addr) = match accepted {
                Ok((owned, addr)) => (crate::fd::register(owned), addr),
                Err(err) => {
                    if err == libc::EAGAIN {
                        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "accept() not ready");
                        again = true;
                        break;
                    }
                    let level = if err == libc::ECONNABORTED { NGX_LOG_ERR } else if err == libc::EMFILE || err == libc::ENFILE { NGX_LOG_CRIT } else { NGX_LOG_ALERT };
                    ngx_log_error!(level, log, Some(err), "accept4() failed");
                    if err == libc::ECONNABORTED && multi_accept {
                        continue;
                    }
                    if err == libc::EMFILE || err == libc::ENFILE {
                        emfile = true;
                    }
                    break;
                }
            };
            stats().accepted.fetch_add(1, Ordering::Relaxed);
            update_accept_disabled();
            let sa = match addr.and_then(|a| accepted_sockaddr(a, s)) {
                Some(sa) => sa,
                None => {
                    os::close(s);
                    continue;
                }
            };
            let c = match Connection::accepted(s, &ls, sa, &log) {
                Some(c) => c,
                None => {
                    os::close(s);
                    break;
                }
            };
            stats().handled.fetch_add(1, Ordering::Relaxed);
            stats().active.fetch_add(1, Ordering::Relaxed);
            // debug_connection
            if log.level() & NGX_LOG_DEBUG_CONNECTION == 0 {
                let cidrs = debug_connection_cidrs();
                if !cidrs.is_empty() {
                    let peer = c.sockaddr.borrow().clone();
                    if cidrs.iter().any(|ci| debug_connection_match(ci, &peer)) {
                        c.log.set_level(NGX_LOG_DEBUG_CONNECTION | NGX_LOG_DEBUG_ALL);
                    }
                }
            }
            if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
                // c->log is a copy of ls->log until the handler sets the
                // connection number in it
                let addr = c.sockaddr.borrow().to_text(true);
                c.log.set_connection(0);
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "*{} accept: {} fd:{}", c.number, B(&addr), s);
                c.log.set_connection(c.number);
            }
            handler(c);

            if !multi_accept {
                // the do-while loop ends
                reorder = true;
                break;
            }
        }

        ev.handled(&mut guard, again);
        drop(guard);

        ACCEPTED.with(|a| a.notify_one());

        if emfile {
            if disable_accept_events(true).is_ok() {
                if USE_ACCEPT_MUTEX.with(|m| m.get()) {
                    if ACCEPT_MUTEX_HELD.with(|h| h.replace(false)) {
                        accept_mutex_unlock();
                    }

                    ACCEPT_DISABLED.with(|d| d.set(1));
                } else {
                    // the timer of the event, which then enables the
                    // accept events (ev->timedout)
                    let delay = event_conf().map(|c| *c.borrow().accept_mutex_delay).unwrap_or(500);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

                    let _ = enable_accept_events();
                }
            }

            continue;
        }

        if reorder {
            reorder_accept_events(&ls, &ev, &mut requests);
        }

        if is_exiting() {
            return;
        }

        // back to the event loop between events
        tokio::task::yield_now().await;
    }
}

/// ngx_reorder_accept_events: Linux with EPOLLEXCLUSIVE usually notifies
/// only the process which was first to add the listening socket to the
/// epoll instance, so the socket is added again periodically, and other
/// workers get a chance to accept connections.
fn reorder_accept_events(ls: &Listening, ev: &ListenEvent, requests: &mut u64) {
    if !use_exclusive_accept() {
        return;
    }

    if ls.reuseport.get() {
        return;
    }

    let n = *requests;
    *requests += 1;

    if n % 16 != 0 && accept_disabled() <= 0 {
        return;
    }

    if del_listen_event(ls, ev).is_err() {
        return;
    }

    let _ = add_listen_event(ls, ev, true);
}

/// ngx_add_event(ls->connection->read, NGX_READ_EVENT, 0), or with
/// NGX_EXCLUSIVE_EVENT, logging as ngx_epoll_add_event.
fn add_listen_event(ls: &Listening, ev: &ListenEvent, exclusive: bool) -> Result<(), ()> {
    let fd = ls.fd.get();
    let log = ls.log.borrow();

    let events = if exclusive { libc::EPOLLIN | libc::EPOLLEXCLUSIVE } else { libc::EPOLLIN | libc::EPOLLRDHUP };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "epoll add event: fd:{} op:{} ev:{:08X}", fd, libc::EPOLL_CTL_ADD, events as u32);

    if let Err(e) = ev.add(exclusive) {
        ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "epoll_ctl({}, {}) failed", libc::EPOLL_CTL_ADD, fd);
        return Err(());
    }

    Ok(())
}

/// ngx_del_event(ls->connection->read, NGX_READ_EVENT, NGX_DISABLE_EVENT),
/// logging as ngx_epoll_del_event.
fn del_listen_event(ls: &Listening, ev: &ListenEvent) -> Result<(), ()> {
    let fd = ls.fd.get();
    let log = ls.log.borrow();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "epoll del event: fd:{} op:{} ev:{:08X}", fd, libc::EPOLL_CTL_DEL, 0);

    if let Err(e) = ev.del() {
        ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "epoll_ctl({}, {}) failed", libc::EPOLL_CTL_DEL, fd);
        return Err(());
    }

    Ok(())
}

/// The read event of a listening socket being closed: deleted, as C does
/// explicitly (ngx_close_listening_sockets), and its handler stopped.
pub fn stop_accepting(ls: &Listening) {
    let fd = ls.fd.get();

    let slot = LISTEN_EVENTS.with(|m| {
        let mut m = m.borrow_mut();
        match m.get(&fd) {
            Some(slot) if std::ptr::eq(Rc::as_ptr(&slot.ls), ls) => m.remove(&fd),
            _ => None,
        }
    });

    if let Some(slot) = slot {
        slot.task.abort();

        if slot.ev.is_active() {
            let _ = del_listen_event(&slot.ls, &slot.ev);
        }
    }

    crate::event_udp::stop_recvmsg(ls);
}

/// The listening sockets are closed: no accept mutex any more
/// (ngx_close_listening_sockets).
pub fn close_accept_mutex() {
    ACCEPT_MUTEX_HELD.with(|h| h.set(false));
    USE_ACCEPT_MUTEX.with(|m| m.set(false));
}

/// The read events of the listening sockets are exclusive
/// (ngx_use_exclusive_accept).
pub fn use_exclusive_accept() -> bool {
    USE_EXCLUSIVE_ACCEPT.with(|e| e.get())
}

/// The listening sockets of this worker: not the reuseport sockets of the
/// other workers.
fn worker_listenings(cycle: &Rc<Cycle>) -> Vec<Rc<Listening>> {
    let worker = worker_index();

    cycle
        .listening
        .iter()
        .filter(|ls| !(ls.ignore.get() || ls.fd.get() == -1))
        .filter(|ls| !(ls.reuseport.get() && ls.worker.get() as i64 != worker && process_type() == ProcessType::Worker))
        .cloned()
        .collect()
}

/// The listening sockets of the cycle with read events in this worker
/// (ls->connection), and their events.
fn listen_events() -> Vec<(Rc<Listening>, Rc<ListenEvent>)> {
    let cycle = crate::cycle::cycle();

    LISTEN_EVENTS.with(|m| {
        let m = m.borrow();

        cycle
            .listening
            .iter()
            .filter_map(|ls| match m.get(&ls.fd.get()) {
                Some(slot) if Rc::ptr_eq(&slot.ls, ls) => Some((slot.ls.clone(), slot.ev.clone())),
                _ => None,
            })
            .collect()
    })
}

/// ngx_enable_accept_events
fn enable_accept_events() -> Result<(), ()> {
    for (ls, ev) in listen_events() {
        if ev.is_active() {
            continue;
        }

        add_listen_event(&ls, &ev, false)?;
    }

    Ok(())
}

/// ngx_disable_accept_events: not the worker's own reuseport sockets when
/// disabling accept events due to accept mutex
fn disable_accept_events(all: bool) -> Result<(), ()> {
    for (ls, ev) in listen_events() {
        if !ev.is_active() {
            continue;
        }

        if ls.reuseport.get() && !all {
            continue;
        }

        del_listen_event(&ls, &ev)?;
    }

    Ok(())
}

/// ngx_shmtx_trylock(&ngx_accept_mutex)
fn accept_mutex_trylock() -> bool {
    let pid = os::getpid() as i64;
    stats().accept_mutex.load(Ordering::Acquire) == 0 && stats().accept_mutex.compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// ngx_shmtx_unlock(&ngx_accept_mutex)
fn accept_mutex_unlock() {
    let pid = os::getpid() as i64;
    let _ = stats().accept_mutex.compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// ngx_trylock_accept_mutex
fn trylock_accept_mutex(cycle: &Cycle) -> Result<(), ()> {
    if accept_mutex_trylock() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "accept mutex locked");

        if ACCEPT_MUTEX_HELD.with(|h| h.get()) {
            return Ok(());
        }

        if enable_accept_events().is_err() {
            accept_mutex_unlock();
            return Err(());
        }

        ACCEPT_MUTEX_HELD.with(|h| h.set(true));

        return Ok(());
    }

    let held = ACCEPT_MUTEX_HELD.with(|h| h.get());

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "accept mutex lock failed: {}", held as u32);

    if held {
        disable_accept_events(false)?;

        ACCEPT_MUTEX_HELD.with(|h| h.set(false));
    }

    Ok(())
}

/// The accept mutex part of ngx_process_events_and_timers: in each
/// iteration the worker tries the mutex (unless ngx_accept_disabled);
/// holding it, the accept events are enabled and handled, and the mutex is
/// released at the end of the iteration; otherwise the accept events are
/// disabled and the iteration waits at most accept_mutex_delay.
async fn accept_mutex_loop(cycle: Rc<Cycle>) {
    let delay = event_conf().map(|c| *c.borrow().accept_mutex_delay).unwrap_or(500);
    let delay = std::time::Duration::from_millis(delay);

    let accepted = ACCEPTED.with(|a| a.clone());

    // the timer of an iteration (epoll_wait() for accept_mutex_delay)
    let timer = EventTimer::new();

    let iteration = |timer: &EventTimer| {
        timer.del();
        timer.add_at(tokio::time::Instant::now() + delay);
    };

    loop {
        if is_exiting() || !USE_ACCEPT_MUTEX.with(|m| m.get()) {
            return;
        }

        let disabled = accept_disabled();

        if disabled > 0 {
            ACCEPT_DISABLED.with(|d| d.set(disabled - 1));

            // an iteration of a busy worker
            tokio::task::yield_now().await;
            continue;
        }

        if trylock_accept_mutex(&cycle).is_err() {
            iteration(&timer);
            timer.expired().await;
            continue;
        }

        if !ACCEPT_MUTEX_HELD.with(|h| h.get()) {
            // the timer of the iteration
            iteration(&timer);
            timer.expired().await;
            continue;
        }

        // the iteration: until an accept event is handled, then the mutex
        // is released
        iteration(&timer);
        tokio::select! {
            _ = accepted.notified() => {}
            _ = timer.expired() => {}
        }

        if ACCEPT_MUTEX_HELD.with(|h| h.get()) {
            accept_mutex_unlock();
        }

        tokio::task::yield_now().await;
    }
}

/// The read events of the listening sockets (ngx_event_process_init), and
/// the tasks of their handlers.
fn start_accepting(cycle: &Rc<Cycle>) {
    let ccf = core_conf(cycle);
    let (master, worker_processes) = {
        let c = ccf.borrow();
        (*c.master, *c.worker_processes)
    };

    let accept_mutex = event_conf().map(|c| *c.borrow().accept_mutex).unwrap_or(false);

    // the master is the process that runs the workers
    let use_accept_mutex = master && worker_processes > 1 && accept_mutex && process_type() == ProcessType::Worker;

    USE_ACCEPT_MUTEX.with(|m| m.set(use_accept_mutex));
    ACCEPT_MUTEX_HELD.with(|h| h.set(false));

    for ls in worker_listenings(cycle) {
        let fd = ls.fd.get();

        let ev = match ListenEvent::new(fd) {
            Ok(e) => Rc::new(e),
            Err(e) => {
                ngx_log_error!(NGX_LOG_ALERT, ls.log.borrow(), e.raw_os_error(), "epoll_ctl({}, {}) failed", libc::EPOLL_CTL_ADD, fd);
                continue;
            }
        };

        // rev->handler: ngx_event_accept, or ngx_event_recvmsg for UDP
        let task = if ls.ty == libc::SOCK_DGRAM { spawn(crate::event_udp::recvmsg_loop(ls.clone(), ev.clone())) } else { spawn(accept_loop(ls.clone(), ev.clone())) };

        let slot = ListenSlot { ls: ls.clone(), ev: ev.clone(), task: task.abort_handle() };

        // the event of a previous cycle's listening on the socket
        if let Some(old) = LISTEN_EVENTS.with(|m| m.borrow_mut().insert(fd, slot)) {
            old.task.abort();

            if old.ev.is_active() {
                let _ = del_listen_event(&old.ls, &old.ev);
            }
        }

        if ls.reuseport.get() {
            let _ = add_listen_event(&ls, &ev, false);
            continue;
        }

        if use_accept_mutex {
            continue;
        }

        if worker_processes > 1 {
            USE_EXCLUSIVE_ACCEPT.with(|e| e.set(true));

            let _ = add_listen_event(&ls, &ev, true);
            continue;
        }

        let _ = add_listen_event(&ls, &ev, false);
    }

    if use_accept_mutex {
        spawn(accept_mutex_loop(cycle.clone()));
    }
}

thread_local! {
    /// The cached time was updated by the driver's park (events_unparked)
    /// since the tasks last ran.
    static TIME_UPDATED: Cell<bool> = const { Cell::new(false) };
}

/// LocalSet::block_on() with ngx_time_update() before each run of the
/// tasks: the cached time is that of the event loop's iteration (the
/// driver's turn which woke the tasks), as C updates it once epoll_wait()
/// returns, and the clock is read once per iteration rather than by each
/// reader. A park of the driver updates it already (events_unparked); the
/// driver's turns without a park (when tasks yielded) do not.
fn block_on_events<F: std::future::Future>(rt: &tokio::runtime::Runtime, local: &LocalSet, f: F) -> F::Output {
    use std::future::Future;

    let mut run = std::pin::pin!(local.run_until(f));

    rt.block_on(std::future::poll_fn(move |cx| {
        if !TIME_UPDATED.with(|t| t.replace(false)) {
            crate::times::update();
        }

        run.as_mut().poll(cx)
    }))
}

/// The runtime of a process running ngx_process_events_and_timers(): its
/// park is the epoll_wait() of ngx_epoll_process_events()
fn event_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_park(events_park)
        .on_thread_unpark(events_unparked)
        .build()
        .expect("tokio runtime")
}

/// epoll_wait() returned: a signal which interrupted it is logged as
/// ngx_signal_handler() and ngx_epoll_process_events() do, and the process
/// ends on ngx_terminate (ngx_quit for a single or helper process) before
/// any event is handled, as the cycles check it after
/// ngx_process_events_and_timers()
fn events_unparked() {
    let interrupted = events_interrupted();

    // ngx_time_update()
    crate::times::update();
    TIME_UPDATED.with(|t| t.set(true));

    crate::times::update_event_msec();

    let pt = process_type();
    let exit = SIG_TERMINATE.load(Ordering::SeqCst) || (pt != ProcessType::Worker && SIG_QUIT.load(Ordering::SeqCst));

    if !interrupted && !exit {
        return;
    }

    let cycle = match try_cycle() {
        Some(c) => c,
        None => return,
    };

    if process_signals(&cycle.log, false) {
        // the pipe the control task waits for is drained: the cycle checks
        // the flags (ngx_quit of SIGWINCH, ngx_reconfigure, ...) anyway
        let notify = flags_notify();
        notify.notify_waiters();
        notify.notify_one();
    }

    if interrupted {
        ngx_log_error!(NGX_LOG_INFO, cycle.log, Some(libc::EINTR), "epoll_wait() failed");
    }

    if !exit {
        return;
    }

    match pt {
        ProcessType::Single => {
            for m in cycle.modules.iter() {
                if let Some(f) = m.def.exit_process {
                    f(&cycle);
                }
            }
            master_exit_single(&cycle);
        }
        ProcessType::Worker => {
            ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exiting");
            worker_process_exit(&cycle);
        }
        _ => {
            // ngx_cache_manager_process_cycle
            ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exiting");
            std::process::exit(0);
        }
    }
}

fn run_event_loop(cycle: Rc<Cycle>, single: bool) -> ! {
    let rt = event_runtime();
    let local = LocalSet::new();
    let c2 = cycle.clone();
    block_on_events(&rt, &local, async move {
        let mut cycle = c2;
        spawn(control_task(cycle.clone(), single));
        spawn_posted_tasks();
        start_accepting(&cycle);
        let notify = flags_notify();
        let close_notify = close_notify();
        // ngx_shutdown_event's timer (worker_shutdown_timeout)
        let shutdown = EventTimer::new();
        // the cycle checks the flags at least once a second
        let tick = EventTimer::new();
        loop {
            if SIG_TERMINATE.load(Ordering::SeqCst) {
                if single {
                    for m in cycle.modules.iter() {
                        if let Some(f) = m.def.exit_process {
                            f(&cycle);
                        }
                    }
                    master_exit_single(&cycle);
                }
                ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exiting");
                worker_process_exit(&cycle);
            }
            if SIG_QUIT.swap(false, Ordering::SeqCst) {
                if single {
                    for m in cycle.modules.iter() {
                        if let Some(f) = m.def.exit_process {
                            f(&cycle);
                        }
                    }
                    master_exit_single(&cycle);
                }
                ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "gracefully shutting down");
                setproctitle(b"worker process is shutting down");
                if !is_exiting() {
                    EXITING.with(|e| e.set(true));
                    let ccf = core_conf(&cycle);
                    let to = *ccf.borrow().shutdown_timeout;
                    if to > 0 {
                        shutdown.add(to);
                    }
                    close_listening_sockets(&cycle);
                    close_idle_connections();
                }
            }
            if SIG_RECONFIGURE.swap(false, Ordering::SeqCst) && single {
                ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "reconfiguring");
                match init_cycle(cycle.clone(), &crate::connection::init_hooks()) {
                    Ok(c) => {
                        cycle = c;
                        set_cycle(cycle.clone());
                        start_accepting(&cycle);
                    }
                    Err(()) => {}
                }
            }
            if SIG_REOPEN.swap(false, Ordering::SeqCst) {
                ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "reopening logs");
                cycle.reopen_files(None);
            }
            if is_exiting() && active_connections() == 0 && no_pending_work() {
                ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exiting");
                worker_process_exit(&cycle);
            }
            tick.add(1000);
            tokio::select! {
                _ = notify.notified() => {}
                _ = close_notify.notified() => {}
                // ngx_shutdown_timer_handler
                _ = shutdown.expired() => close_all_connections(),
                _ = tick.expired() => {}
            }
        }
    });
    std::process::exit(0);
}

thread_local! {
    static PENDING_WORK: Cell<usize> = const { Cell::new(0) };
}

/// Track non-connection work (resolver, timers) that should delay graceful exit.
pub fn add_pending_work() {
    PENDING_WORK.with(|p| p.set(p.get() + 1));
}

pub fn remove_pending_work() {
    PENDING_WORK.with(|p| p.set(p.get().saturating_sub(1)));
    crate::connection::wake_exiting_cycle();
}

pub fn no_pending_work() -> bool {
    PENDING_WORK.with(|p| p.get() == 0)
}

fn master_exit_single(cycle: &Rc<Cycle>) -> ! {
    crate::core_module::delete_pidfile(cycle);
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "exit");
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.exit_master {
            f(cycle);
        }
    }
    close_listening_sockets(cycle);
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    fn run<F: std::future::Future<Output = ()>>(f: F) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(f);
    }

    /// The timer expired within `within`.
    async fn expires(t: &EventTimer, within: u64) -> bool {
        tokio::time::timeout(Duration::from_millis(within), t.expired()).await.is_ok()
    }

    #[test]
    fn timer_add_expire() {
        run(async {
            let t = EventTimer::new();
            assert!(!t.is_set() && !t.timedout());
            assert!(!expires(&t, 30).await, "not set: never");

            let start = Instant::now();
            t.add(40);
            assert!(t.is_set());
            assert!(t.deadline().unwrap() >= start + Duration::from_millis(40));
            assert!(expires(&t, 2000).await);
            assert!(start.elapsed() >= Duration::from_millis(40));
            assert!(!t.is_set() && t.timedout(), "expired: timer_set = 0, timedout = 1");
            assert!(!expires(&t, 30).await, "expired once");

            // the handler clears timedout; the timer is set again
            t.set_timedout(false);
            t.add(10);
            assert!(expires(&t, 2000).await);
            assert!(t.timedout());
        });
    }

    #[test]
    fn timer_lazy_delay() {
        run(async {
            let t = EventTimer::new();

            t.add(1000);
            let key = t.deadline().unwrap();

            // less than NGX_TIMER_LAZY_DELAY away: the timer stays
            t.add(1000 + NGX_TIMER_LAZY_DELAY - 50);
            assert_eq!(t.deadline(), Some(key));
            t.add_at(key - Duration::from_millis(NGX_TIMER_LAZY_DELAY - 1));
            assert_eq!(t.deadline(), Some(key));

            // as much or more: moved, later or earlier
            t.add_at(key + Duration::from_millis(NGX_TIMER_LAZY_DELAY));
            assert_eq!(t.deadline(), Some(key + Duration::from_millis(NGX_TIMER_LAZY_DELAY)));
            t.add(20);
            assert!(t.deadline().unwrap() < key);
            assert!(expires(&t, 2000).await, "moved earlier, it expires then");

            // not set: any expiry is taken
            t.add(1000);
            t.del();
            t.add(1100);
            assert!(t.deadline().unwrap() > key);
        });
    }

    #[test]
    fn timer_moved_later_and_deleted() {
        run(async {
            let t = EventTimer::new();

            // a wait polled the timer at the first expiry, then it is
            // moved later: it does not expire at the first one
            t.add(30);
            assert!(!expires(&t, 5).await);
            let start = Instant::now();
            t.add(30 + NGX_TIMER_LAZY_DELAY + 100);
            assert!(!expires(&t, 200).await);
            assert!(expires(&t, 2000).await);
            assert!(start.elapsed() >= Duration::from_millis(NGX_TIMER_LAZY_DELAY + 100));

            // deleted while waited for, it never expires
            t.add(20);
            let wait = tokio::time::timeout(Duration::from_millis(100), t.expired());
            let del = async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                t.del();
            };
            let (r, ()) = tokio::join!(wait, del);
            assert!(r.is_err());
            assert!(!t.is_set());

            // set again after a delete and an old expiry passed
            t.add(10);
            assert!(expires(&t, 2000).await);
        });
    }
}
