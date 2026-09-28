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
use crate::listening::Listening;
use crate::log::*;
use crate::module::*;
use crate::process::*;
use crate::string::B;
use crate::{cmd, cmd_fn, ngx_log_debug, ngx_log_error, os};

pub const DEFAULT_CONNECTIONS: u64 = 512;

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
    static ACCEPT_TASKS: RefCell<HashMap<i32, tokio::task::AbortHandle>> = RefCell::new(HashMap::new());
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

fn flags_notify() -> Rc<tokio::sync::Notify> {
    FLAGS_NOTIFY.with(|n| n.clone())
}

/// Called after fork in a worker (ngx_worker_process_init).
fn worker_process_init(cycle: &Rc<Cycle>, worker: i64) {
    set_environment(cycle);
    let ccf = core_conf(cycle);
    let (priority, rlimit_nofile, rlimit_core, user, group, username, workdir, cpu_affinity, cpu_auto) = {
        let c = ccf.borrow();
        (c.priority, c.rlimit_nofile.clone(), c.rlimit_core.clone(), c.user, c.group, c.username.clone(), c.working_directory.clone(), c.cpu_affinity.clone(), c.cpu_affinity_auto)
    };
    if worker >= 0 && priority != 0 {
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, priority as i32) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "setpriority({}) failed", priority);
        }
    }
    if let Some(n) = rlimit_nofile.as_option() {
        let r = libc::rlimit { rlim_cur: *n as libc::rlim_t, rlim_max: *n as libc::rlim_t };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "setrlimit(RLIMIT_NOFILE, {}) failed", n);
        }
    }
    if let Some(n) = rlimit_core.as_option() {
        let r = libc::rlimit { rlim_cur: *n as libc::rlim_t, rlim_max: *n as libc::rlim_t };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &r) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "setrlimit(RLIMIT_CORE, {}) failed", n);
        }
    }
    if os::geteuid() == 0 {
        if let (Some(uid), Some(gid)) = (user, group) {
            if unsafe { libc::setgid(gid) } == -1 {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "setgid({}) failed", gid);
                std::process::exit(2);
            }
            let uname = os::cstr(&username);
            if unsafe { libc::initgroups(uname.as_ptr(), gid) } == -1 {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "initgroups({}, {}) failed", B(&username), gid);
            }
            if unsafe { libc::setuid(uid) } == -1 {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "setuid({}) failed", uid);
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
            unsafe {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_ZERO(&mut set);
                for (i, &on) in mask.iter().enumerate() {
                    if on && i < libc::CPU_SETSIZE as usize {
                        libc::CPU_SET(i, &mut set);
                    }
                }
                if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == -1 {
                    ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "sched_setaffinity() failed");
                }
            }
        }
    }
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    }
    if !workdir.is_empty() {
        let c = os::cstr(&workdir);
        if unsafe { libc::chdir(c.as_ptr()) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "chdir(\"{}\") failed", B(&workdir));
            std::process::exit(2);
        }
    }
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        if libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "sigprocmask() failed");
        }
    }
    for m in cycle.modules.iter() {
        if let Some(f) = m.def.init_process {
            if f(cycle).is_err() {
                std::process::exit(2);
            }
        }
    }
    // close other workers' channel[1] and our channel[0]
    let slot = PROCESS_SLOT.with(|p| p.get());
    PROCESSES.with(|p| {
        let p = p.borrow();
        for (n, pr) in p.iter().enumerate() {
            if pr.pid == -1 || n == slot || pr.channel[1] == -1 {
                continue;
            }
            if unsafe { libc::close(pr.channel[1]) } == -1 {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "close() channel failed");
            }
        }
        if slot < p.len() && p[slot].channel[0] != -1 && unsafe { libc::close(p[slot].channel[0]) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "close() channel failed");
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
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = LocalSet::new();
    let c2 = cycle.clone();
    local.block_on(&rt, async move {
        spawn(control_task(c2.clone(), false));
        if data == 0 {
            // manager: run every path manager on its schedule
            tokio::time::sleep(std::time::Duration::from_millis(0)).await;
            loop {
                let mut next: u64 = 60 * 60 * 1000;
                for p in c2.paths.iter() {
                    let m = p.manager.borrow().clone();
                    if let Some(m) = m {
                        let d = p.data.borrow().clone();
                        if let Some(d) = d {
                            let n = m(&d);
                            if n < next {
                                next = n;
                            }
                        }
                    }
                    crate::times::update();
                }
                if next == 0 {
                    next = 1;
                }
                tokio::time::sleep(std::time::Duration::from_millis(next)).await;
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(60000)).await;
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
    });
    std::process::exit(0);
}

/// Task that watches signal wakeups and the master channel, setting flags.
async fn control_task(cycle: Rc<Cycle>, _single: bool) {
    let wake = wake_fd();
    let chan = CHANNEL.with(|c| c.get());
    let wake_afd = if wake >= 0 { AsyncFd::with_interest(Fd(wake), tokio::io::Interest::READABLE).ok() } else { None };
    let chan_afd = if chan >= 0 && process_type() != ProcessType::Single { AsyncFd::with_interest(Fd(chan), tokio::io::Interest::READABLE).ok() } else { None };
    let notify = flags_notify();
    loop {
        tokio::select! {
            r = async { match &wake_afd { Some(a) => a.readable().await.map(|mut g| { g.clear_ready(); }), None => std::future::pending().await } } => {
                let _ = r;
                drain_wake_pipe();
                drain_signal_log(&cycle.log);
                notify.notify_waiters();
                notify.notify_one();
            }
            r = async { match &chan_afd { Some(a) => a.readable().await.map(|mut g| { g.clear_ready(); }), None => std::future::pending().await } } => {
                if r.is_err() { break; }
                loop {
                    match read_channel(chan, &cycle.log) {
                        Err(()) => { return; }
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
                                            if unsafe { libc::close(p[s].channel[0]) } == -1 {
                                                ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "close() channel failed");
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

/// Accept loop for one listening socket.
async fn accept_loop(cycle: Rc<Cycle>, ls: Rc<Listening>) {
    let fd = ls.fd.get();
    let afd = match AsyncFd::with_interest(Fd(fd), tokio::io::Interest::READABLE) {
        Ok(a) => a,
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, ls.log.borrow(), e.raw_os_error(), "epoll_ctl() failed for {}", B(&ls.addr_text));
            return;
        }
    };
    let handler = ls.handler.borrow().clone();
    let handler = match handler {
        Some(h) => h,
        None => return,
    };
    let log = ls.log.borrow().clone();
    loop {
        let mut guard = match afd.readable().await {
            Ok(g) => g,
            Err(_) => return,
        };
        loop {
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let s = unsafe { libc::accept4(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len, libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
            if s == -1 {
                let err = os::errno();
                if err == libc::EAGAIN {
                    guard.clear_ready();
                    break;
                }
                let level = if err == libc::ECONNABORTED { NGX_LOG_ERR } else if err == libc::EMFILE || err == libc::ENFILE { NGX_LOG_CRIT } else { NGX_LOG_ALERT };
                ngx_log_error!(level, log, Some(err), "accept4() failed");
                if err == libc::ECONNABORTED {
                    continue;
                }
                if err == libc::EMFILE || err == libc::ENFILE {
                    let delay = event_conf().map(|c| *c.borrow().accept_mutex_delay).unwrap_or(500);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    break;
                }
                return;
            }
            stats().accepted.fetch_add(1, Ordering::Relaxed);
            let sa = match crate::inet::SockAddr::from_libc(&ss as *const _ as *const libc::sockaddr, len) {
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
                    continue;
                }
            };
            stats().handled.fetch_add(1, Ordering::Relaxed);
            stats().active.fetch_add(1, Ordering::Relaxed);
            // debug_connection
            if log.level() & NGX_LOG_DEBUG_CONNECTION == 0 {
                let cidrs = debug_connection_cidrs();
                if !cidrs.is_empty() {
                    let peer = c.sockaddr.borrow().clone();
                    if cidrs.iter().any(|ci| ci.matches(&peer)) {
                        c.log.set_level(NGX_LOG_DEBUG_CONNECTION | NGX_LOG_DEBUG_ALL);
                    }
                }
            }
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "*{} accept: {} fd:{}", c.number, B(&c.addr_text.borrow()), s);
            if ls.addr_ntop.get() {
                // already set
            }
            handler(c);
        }
        if is_exiting() {
            return;
        }
    }
    #[allow(unreachable_code)]
    {
        let _ = cycle;
    }
}

/// Stop the accept task for a listening socket (before closing it).
pub fn stop_accepting(ls: &Listening) {
    let fd = ls.fd.get();
    ACCEPT_TASKS.with(|t| {
        if let Some(h) = t.borrow_mut().remove(&fd) {
            h.abort();
        }
    });
}

fn start_accepting(cycle: &Rc<Cycle>) {
    let worker = worker_index();
    for ls in cycle.listening.iter() {
        if ls.ignore.get() || ls.fd.get() == -1 {
            continue;
        }
        if ls.reuseport.get() && ls.worker.get() as i64 != worker && process_type() == ProcessType::Worker {
            continue;
        }
        let h = spawn(accept_loop(cycle.clone(), ls.clone()));
        ACCEPT_TASKS.with(|t| t.borrow_mut().insert(ls.fd.get(), h.abort_handle()));
    }
}

fn run_event_loop(cycle: Rc<Cycle>, single: bool) -> ! {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    let local = LocalSet::new();
    let c2 = cycle.clone();
    local.block_on(&rt, async move {
        let mut cycle = c2;
        spawn(control_task(cycle.clone(), single));
        spawn_posted_tasks();
        start_accepting(&cycle);
        let notify = flags_notify();
        let close_notify = close_notify();
        let mut shutdown_deadline: Option<tokio::time::Instant> = None;
        loop {
            crate::times::update();
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
                        shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(to));
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
            let deadline = shutdown_deadline;
            tokio::select! {
                _ = notify.notified() => {}
                _ = close_notify.notified() => {}
                _ = async { match deadline { Some(d) => tokio::time::sleep_until(d).await, None => std::future::pending().await } } => {
                    shutdown_deadline = None;
                    close_all_connections();
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {}
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
    close_notify().notify_waiters();
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
