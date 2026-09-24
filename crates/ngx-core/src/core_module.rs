//! ngx_core_module and ngx_errlog_module (nginx.c / ngx_log.c directives).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use crate::conf::*;
use crate::cycle::*;
use crate::log::*;
use crate::module::*;
use crate::string::{atoi, B};
use crate::{cmd, cmd_fn, ngx_log_error, os};

pub const NGX_OLDPID_EXT: &str = ".oldbin";

pub struct CoreConf {
    pub daemon: Val<bool>,
    pub master: Val<bool>,
    pub timer_resolution: Val<u64>,
    pub shutdown_timeout: Val<u64>,
    pub worker_processes: Val<i64>,
    pub debug_points: Val<u32>,
    pub rlimit_nofile: Val<i64>,
    pub rlimit_core: Val<i64>,
    pub priority: i64,
    pub cpu_affinity_auto: bool,
    pub cpu_affinity: Vec<Vec<bool>>,
    pub username: Vec<u8>,
    pub user: Option<u32>,
    pub group: Option<u32>,
    pub working_directory: Vec<u8>,
    pub lock_file: Vec<u8>,
    pub pid: Vec<u8>,
    pub oldpid: Vec<u8>,
    /// "env" directive entries: (name, full "NAME=value" or None if inherit)
    pub env: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

pub const NGX_DEBUG_POINTS_STOP: u32 = 1;
pub const NGX_DEBUG_POINTS_ABORT: u32 = 2;

fn create_conf(_cycle: &mut Cycle) -> Rc<dyn Any> {
    make_slot(CoreConf {
        daemon: Val::unset(),
        master: Val::unset(),
        timer_resolution: Val::unset(),
        shutdown_timeout: Val::unset(),
        worker_processes: Val::unset(),
        debug_points: Val::unset(),
        rlimit_nofile: Val::unset(),
        rlimit_core: Val::unset(),
        priority: 0,
        cpu_affinity_auto: false,
        cpu_affinity: Vec::new(),
        username: Vec::new(),
        user: None,
        group: None,
        working_directory: Vec::new(),
        lock_file: Vec::new(),
        pid: Vec::new(),
        oldpid: Vec::new(),
        env: Vec::new(),
    })
}

fn init_conf(cycle: &mut Cycle, conf: &Rc<dyn Any>) -> Result<(), ()> {
    let cell = conf_cell::<CoreConf>(conf);
    let mut ccf = cell.borrow_mut();
    ccf.daemon.init(true);
    ccf.master.init(true);
    ccf.timer_resolution.init(0);
    ccf.shutdown_timeout.init(0);
    ccf.worker_processes.init(1);
    ccf.debug_points.init(0);

    if !ccf.cpu_affinity_auto && !ccf.cpu_affinity.is_empty() && ccf.cpu_affinity.len() != 1 && ccf.cpu_affinity.len() as i64 != *ccf.worker_processes {
        ngx_log_error!(
            NGX_LOG_WARN,
            cycle.log,
            None,
            "the number of \"worker_processes\" is not equal to the number of \"worker_cpu_affinity\" masks, using last mask for remaining worker processes"
        );
    }

    if ccf.pid.is_empty() {
        ccf.pid = crate::NGX_PID_PATH.as_bytes().to_vec();
    }
    ccf.pid = cycle.full_name(&ccf.pid, false);
    let mut oldpid = ccf.pid.clone();
    oldpid.extend_from_slice(NGX_OLDPID_EXT.as_bytes());
    ccf.oldpid = oldpid;

    if ccf.user.is_none() && os::geteuid() == 0 {
        match os::getpwnam(b"nobody") {
            Some((uid, _)) => {
                ccf.username = b"nobody".to_vec();
                ccf.user = Some(uid);
            }
            None => {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "getpwnam(\"nobody\") failed");
                return Err(());
            }
        }
        match os::getgrnam(b"nobody") {
            Some(gid) => ccf.group = Some(gid),
            None => {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "getgrnam(\"nobody\") failed");
                return Err(());
            }
        }
    }

    if ccf.lock_file.is_empty() {
        ccf.lock_file = crate::NGX_LOCK_PATH.as_bytes().to_vec();
    }
    ccf.lock_file = cycle.full_name(&ccf.lock_file, false);

    let old_lock = cycle.old_cycle.as_ref().map(|o| o.lock_file.clone()).unwrap_or_default();
    if !old_lock.is_empty() {
        if ccf.lock_file != old_lock {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, None, "\"lock_file\" could not be changed, ignored");
        }
        cycle.lock_file = old_lock;
    } else {
        cycle.lock_file = ccf.lock_file.clone();
    }
    Ok(())
}

fn set_user(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    if ccf.user.is_some() {
        return Err(msg("is duplicate"));
    }
    if os::geteuid() != 0 {
        cf.warn(format_args!("the \"user\" directive makes sense only if the master process runs with super-user privileges, ignored"));
        return Ok(());
    }
    let name = cf.args[1].clone();
    ccf.username = name.clone();
    match os::getpwnam(&name) {
        Some((uid, _)) => ccf.user = Some(uid),
        None => {
            cf.log_error(NGX_LOG_EMERG, Some(os::errno()), format_args!("getpwnam(\"{}\") failed", B(&name)));
            return Err(ConfError::Logged);
        }
    }
    let group = if cf.args.len() == 2 { name.clone() } else { cf.args[2].clone() };
    match os::getgrnam(&group) {
        Some(gid) => ccf.group = Some(gid),
        None => {
            cf.log_error(NGX_LOG_EMERG, Some(os::errno()), format_args!("getgrnam(\"{}\") failed", B(&group)));
            return Err(ConfError::Logged);
        }
    }
    Ok(())
}

fn set_env(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    let v = cf.args[1].clone();
    match memchr::memchr(b'=', &v) {
        Some(i) => ccf.env.push((v[..i].to_vec(), Some(v.clone()))),
        None => ccf.env.push((v, None)),
    }
    Ok(())
}

fn set_priority(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    if ccf.priority != 0 {
        return Err(msg("is duplicate"));
    }
    let v = &cf.args[1];
    let (n, minus) = match v.first() {
        Some(b'-') => (1, true),
        Some(b'+') => (1, false),
        _ => (0, false),
    };
    let p = match atoi(&v[n..]) {
        Some(p) => p,
        None => return Err(msg("invalid number")),
    };
    ccf.priority = if minus { -p } else { p };
    Ok(())
}

fn set_cpu_affinity(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    if !ccf.cpu_affinity.is_empty() {
        return Err(msg("is duplicate"));
    }
    const CPU_SETSIZE: usize = 1024;
    let mut n = 1;
    if cf.args[1] == b"auto" {
        if cf.args.len() > 3 {
            return Err(cf.emerg(format_args!("invalid number of arguments in \"worker_cpu_affinity\" directive")));
        }
        ccf.cpu_affinity_auto = true;
        let ncpu = os::ncpu().min(CPU_SETSIZE);
        let mut m = vec![false; CPU_SETSIZE];
        for i in 0..ncpu {
            m[i] = true;
        }
        ccf.cpu_affinity.push(m);
        n = 2;
    }
    while n < cf.args.len() {
        let v = &cf.args[n];
        if v.len() > CPU_SETSIZE {
            return Err(cf.emerg(format_args!("\"worker_cpu_affinity\" supports up to {} CPUs only", CPU_SETSIZE)));
        }
        let mut m = vec![false; CPU_SETSIZE];
        let mut i = 0;
        for &ch in v.iter().rev() {
            match ch {
                b' ' => continue,
                b'0' => {
                    i += 1;
                }
                b'1' => {
                    m[i] = true;
                    i += 1;
                }
                _ => {
                    return Err(cf.emerg(format_args!("invalid character \"{}\" in \"worker_cpu_affinity\"", ch as char)));
                }
            }
        }
        ccf.cpu_affinity.push(m);
        n += 1;
    }
    Ok(())
}

fn set_worker_processes(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    if ccf.worker_processes.is_set() {
        return Err(msg("is duplicate"));
    }
    if cf.args[1] == b"auto" {
        ccf.worker_processes = Val::set(os::ncpu() as i64);
        return Ok(());
    }
    match atoi(&cf.args[1]) {
        Some(n) => {
            ccf.worker_processes = Val::set(n);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

fn load_module(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let file = cf.full_name(&cf.args[1].clone(), false);
    Err(cf.emerg(format_args!("dlopen() \"{}\" failed (dynamic modules are not supported in this build)", B(&file))))
}

fn set_str_field(cf: &mut Conf, conf: Option<Rc<dyn Any>>, f: fn(&mut CoreConf) -> &mut Vec<u8>) -> ConfResult {
    let conf = conf.unwrap();
    let cell = conf_cell::<CoreConf>(&conf);
    let mut ccf = cell.borrow_mut();
    let slot = f(&mut ccf);
    if !slot.is_empty() {
        return Err(msg("is duplicate"));
    }
    *slot = cf.args[1].clone();
    Ok(())
}

pub fn core_module() -> ModuleDef {
    const M: u32 = NGX_MAIN_CONF | NGX_DIRECT_CONF;
    let mut m = ModuleDef::new("ngx_core_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "core", create_conf: Some(create_conf), init_conf: Some(init_conf) }));
    m.commands = vec![
        cmd!("daemon", M | NGX_CONF_FLAG, ConfLevel::None, CoreConf, daemon, set_flag),
        cmd!("master_process", M | NGX_CONF_FLAG, ConfLevel::None, CoreConf, master, set_flag),
        cmd!("timer_resolution", M | NGX_CONF_TAKE1, ConfLevel::None, CoreConf, timer_resolution, set_msec),
        cmd_fn!("pid", M | NGX_CONF_TAKE1, ConfLevel::None, |cf, _cmd, conf| set_str_field(cf, conf, |c| &mut c.pid)),
        cmd_fn!("lock_file", M | NGX_CONF_TAKE1, ConfLevel::None, |cf, _cmd, conf| set_str_field(cf, conf, |c| &mut c.lock_file)),
        cmd_fn!("worker_processes", M | NGX_CONF_TAKE1, ConfLevel::None, set_worker_processes),
        cmd!("debug_points", M | NGX_CONF_TAKE1, ConfLevel::None, CoreConf, debug_points, set_enum, &[("stop", NGX_DEBUG_POINTS_STOP), ("abort", NGX_DEBUG_POINTS_ABORT)]),
        cmd_fn!("user", M | NGX_CONF_TAKE12, ConfLevel::None, set_user),
        cmd_fn!("worker_priority", M | NGX_CONF_TAKE1, ConfLevel::None, set_priority),
        cmd_fn!("worker_cpu_affinity", M | NGX_CONF_1MORE, ConfLevel::None, set_cpu_affinity),
        cmd!("worker_rlimit_nofile", M | NGX_CONF_TAKE1, ConfLevel::None, CoreConf, rlimit_nofile, set_num),
        cmd!("worker_rlimit_core", M | NGX_CONF_TAKE1, ConfLevel::None, CoreConf, rlimit_core, set_off),
        cmd!("worker_shutdown_timeout", M | NGX_CONF_TAKE1, ConfLevel::None, CoreConf, shutdown_timeout, set_msec),
        cmd_fn!("working_directory", M | NGX_CONF_TAKE1, ConfLevel::None, |cf, _cmd, conf| set_str_field(cf, conf, |c| &mut c.working_directory)),
        cmd_fn!("env", M | NGX_CONF_TAKE1, ConfLevel::None, set_env),
        cmd_fn!("load_module", NGX_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::None, load_module),
    ];
    m
}

// ---------------------------------------------------------------------------
// errlog module

/// ngx_log_set_log: handle an error_log directive adding to `chain`.
pub fn log_set_log(cf: &mut Conf, chain: &Rc<LogChain>) -> ConfResult {
    let target = cf.args[1].clone();
    let writer = if target == b"stderr" {
        cf.cycle.log_use_stderr = true;
        LogWriter::File(cf.cycle.open_file(b""))
    } else if target.starts_with(b"memory:") {
        // debug memory log: accept and discard
        LogWriter::Custom(Rc::new(|_, _| {}))
    } else if target.starts_with(b"syslog:") {
        let peer = crate::syslog::process_conf(cf, &target)?;
        crate::syslog::make_writer(peer)
    } else {
        LogWriter::File(cf.cycle.open_file(&target))
    };
    let level = match parse_log_levels(&cf.args) {
        Ok(l) => l,
        Err(m) => return Err(cf.emerg(format_args!("{}", m))),
    };
    chain.insert(LogEntry::new(level, writer));
    Ok(())
}

fn error_log(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let chain = cf.cycle.new_log.clone();
    log_set_log(cf, &chain)
}

pub fn errlog_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_errlog_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "errlog", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("error_log", NGX_MAIN_CONF | NGX_CONF_1MORE, ConfLevel::None, error_log)];
    m
}

/// ngx_conf_module: "include"
pub fn conf_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_conf_module", NGX_CONF_MODULE);
    m.commands = vec![cmd_fn!("include", NGX_ANY_CONF | NGX_CONF_TAKE1, ConfLevel::None, conf_include)];
    m
}

// ---------------------------------------------------------------------------
// helpers used by init_cycle / main

pub fn core_conf(cycle: &Cycle) -> Rc<RefCell<CoreConf>> {
    cycle.module_conf::<CoreConf>("ngx_core_module").expect("core conf")
}

pub fn pid_and_user(cycle: &Cycle) -> (Vec<u8>, Option<u32>) {
    let ccf = core_conf(cycle);
    let c = ccf.borrow();
    (c.pid.clone(), c.user)
}

/// ngx_create_pidfile
pub fn create_pidfile(name: &[u8], log: &Log) -> Result<(), ()> {
    if process_type() == ProcessType::Worker || process_type() == ProcessType::Helper {
        return Ok(());
    }
    let test = is_test_config();
    let flags = libc::O_RDWR | if test { libc::O_CREAT } else { libc::O_CREAT | libc::O_TRUNC };
    let fd = match os::open(name, flags, 0o644) {
        Ok(fd) => fd,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "open() \"{}\" failed", B(name));
            return Err(());
        }
    };
    let mut rc = Ok(());
    if !test {
        let s = format!("{}\n", os::getpid());
        if os::write_fd(fd, s.as_bytes()).is_err() {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(os::errno()), "pwrite() \"{}\" failed", B(name));
            rc = Err(());
        }
    }
    os::close(fd);
    rc
}

pub fn delete_pidfile(cycle: &Cycle) {
    let ccf = core_conf(cycle);
    let c = ccf.borrow();
    let name = if globals(|g| g.new_binary != 0) { &c.oldpid } else { &c.pid };
    if let Err(e) = os::unlink(name) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "unlink() \"{}\" failed", B(name));
    }
}

/// ngx_log_redirect_stderr
pub fn log_redirect_stderr(cycle: &Cycle) -> Result<(), ()> {
    if cycle.log_use_stderr {
        return Ok(());
    }
    let chain = cycle.log.chain();
    let fd = match chain.file_log().and_then(|e| e.file()) {
        Some(f) => f.fd.get(),
        None => return Ok(()),
    };
    if fd != libc::STDERR_FILENO {
        if unsafe { libc::dup2(fd, libc::STDERR_FILENO) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(os::errno()), "dup2(STDERR) failed");
            return Err(());
        }
    }
    Ok(())
}

/// ngx_signal_process: read pid file and send signal.
pub fn signal_process(cycle: &Cycle, sig: &str) -> i32 {
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "signal process started");
    let ccf = core_conf(cycle);
    let name = ccf.borrow().pid.clone();
    let data = match std::fs::read(os::path(&name)) {
        Ok(d) => d,
        Err(e) => {
            ngx_log_error!(NGX_LOG_ERR, cycle.log, e.raw_os_error(), "open() \"{}\" failed", B(&name));
            return 1;
        }
    };
    let mut n = data.len();
    while n > 0 && (data[n - 1] == b'\r' || data[n - 1] == b'\n') {
        n -= 1;
    }
    let pid = match atoi(&data[..n]) {
        Some(p) => p as i32,
        None => {
            ngx_log_error!(NGX_LOG_ERR, cycle.log, None, "invalid PID number \"{}\" in \"{}\"", B(&data[..n]), B(&name));
            return 1;
        }
    };
    let signo = match sig {
        "stop" => libc::SIGTERM,
        "quit" => libc::SIGQUIT,
        "reopen" => libc::SIGUSR1,
        "reload" => libc::SIGHUP,
        _ => {
            ngx_log_error!(NGX_LOG_ERR, cycle.log, None, "unknown signal \"{}\"", sig);
            return 1;
        }
    };
    if let Err(e) = os::kill(pid, signo) {
        ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "kill({}, {}) failed", pid, signo);
        return 1;
    }
    0
}
