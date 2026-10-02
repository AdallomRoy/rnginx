//! The cycle: configuration lifecycle (ngx_cycle.c).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use crate::conf::*;
use crate::listening::Listening;
use crate::log::*;
use crate::module::*;
use crate::shm::ShmZone;
use crate::string::B;
use crate::{ngx_log_error, os};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessType {
    Single,
    Master,
    Signaller,
    Worker,
    Helper,
}

/// Global process-role state (ngx_process, ngx_test_config, ...).
pub struct Globals {
    pub process: ProcessType,
    pub test_config: bool,
    pub dump_config: bool,
    pub quiet_mode: bool,
    pub inherited: bool,
    pub daemonized: bool,
    pub new_binary: i32,
    pub worker: usize,
    pub last_process: usize,
    pub exiting: bool,
    pub terminate: bool,
    pub quit: bool,
    pub reopen: bool,
    pub reconfigure: bool,
    pub noaccept: bool,
    pub noaccepting: bool,
    pub restart: bool,
    pub change_binary: bool,
    pub sigalrm: bool,
    pub sigio: bool,
    pub reap: bool,
}

thread_local! {
    pub static GLOBALS: RefCell<Globals> = RefCell::new(Globals {
        process: ProcessType::Single,
        test_config: false,
        dump_config: false,
        quiet_mode: false,
        inherited: false,
        daemonized: false,
        new_binary: 0,
        worker: 0,
        last_process: 0,
        exiting: false,
        terminate: false,
        quit: false,
        reopen: false,
        reconfigure: false,
        noaccept: false,
        noaccepting: false,
        restart: false,
        change_binary: false,
        sigalrm: false,
        sigio: false,
        reap: false,
    });
}

pub fn globals<R>(f: impl FnOnce(&Globals) -> R) -> R {
    GLOBALS.with(|g| f(&g.borrow()))
}

pub fn globals_mut<R>(f: impl FnOnce(&mut Globals) -> R) -> R {
    GLOBALS.with(|g| f(&mut g.borrow_mut()))
}

pub fn process_type() -> ProcessType {
    globals(|g| g.process)
}

pub fn is_test_config() -> bool {
    globals(|g| g.test_config)
}

thread_local! {
    static CURRENT_CYCLE: RefCell<Option<Rc<Cycle>>> = const { RefCell::new(None) };
}

/// Set the process-wide current cycle (ngx_cycle).
pub fn set_cycle(c: Rc<Cycle>) {
    // the old cycle is dropped once the new one is current: its cleanups
    // (the ssl object cache) use ngx_cycle
    let old = CURRENT_CYCLE.with(|cc| cc.borrow_mut().replace(c));
    drop(old);
}

/// The current cycle (ngx_cycle). Panics if unset.
pub fn cycle() -> Rc<Cycle> {
    CURRENT_CYCLE.with(|cc| cc.borrow().clone().expect("no current cycle"))
}

pub fn try_cycle() -> Option<Rc<Cycle>> {
    CURRENT_CYCLE.with(|cc| cc.borrow().clone())
}

pub struct ConfigDump {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

pub struct Cycle {
    /// Core modules' confs, indexed by module.index.
    pub conf_ctx: Vec<Option<Rc<dyn Any>>>,
    pub modules: Rc<Vec<Module>>,
    pub log: Log,
    /// Chain being built from main-level error_log directives.
    pub new_log: Rc<LogChain>,
    pub log_use_stderr: bool,
    pub open_files: Vec<Rc<OpenFile>>,
    pub shared_memory: Vec<Rc<ShmZone>>,
    pub listening: Vec<Rc<Listening>>,
    pub paths: Vec<Rc<PathConf>>,
    pub config_dump: Vec<ConfigDump>,
    pub conf_file: Vec<u8>,
    pub conf_param: Vec<u8>,
    pub conf_prefix: Vec<u8>,
    pub prefix: Vec<u8>,
    pub error_log: Vec<u8>,
    pub lock_file: Vec<u8>,
    pub hostname: Vec<u8>,
    pub connection_n: usize,
    pub files_n: usize,
    pub old_cycle: Option<Rc<Cycle>>,
    /// Per-cycle runtime state slots for modules (keyed by module index).
    pub runtime: RefCell<Vec<Option<Rc<dyn Any>>>>,
    /// Set for the very first (init) cycle created from command line.
    pub is_init: bool,
    /// Environment variables from "env" directive, applied at process start.
    pub env: Vec<Vec<u8>>,
}

impl Cycle {
    /// The initial cycle built from command-line options (ngx_process_options).
    pub fn init_cycle(log: Log, modules: Rc<Vec<Module>>) -> Cycle {
        let n = modules.len();
        Cycle {
            conf_ctx: vec![None; n],
            modules,
            log,
            new_log: LogChain::new(),
            log_use_stderr: false,
            open_files: Vec::new(),
            shared_memory: Vec::new(),
            listening: Vec::new(),
            paths: Vec::new(),
            config_dump: Vec::new(),
            conf_file: Vec::new(),
            conf_param: Vec::new(),
            conf_prefix: Vec::new(),
            prefix: Vec::new(),
            error_log: Vec::new(),
            lock_file: Vec::new(),
            hostname: Vec::new(),
            connection_n: 0,
            files_n: 0,
            old_cycle: None,
            runtime: RefCell::new(vec![None; n]),
            is_init: true,
            env: Vec::new(),
        }
    }

    pub fn module_conf<T: 'static>(&self, name: &str) -> Option<Rc<RefCell<T>>> {
        let m = find_module(&self.modules, name)?;
        let c = self.conf_ctx[m.index].as_ref()?;
        c.clone().downcast::<RefCell<T>>().ok()
    }

    pub fn core_conf<T: 'static>(&self, module_index: usize) -> Rc<RefCell<T>> {
        conf_rc::<T>(self.conf_ctx[module_index].as_ref().expect("core conf missing"))
    }

    pub fn set_runtime<T: 'static>(&self, module_index: usize, v: Rc<T>) {
        self.runtime.borrow_mut()[module_index] = Some(v);
    }

    pub fn runtime<T: 'static>(&self, module_index: usize) -> Option<Rc<T>> {
        self.runtime.borrow()[module_index].clone().and_then(|v| v.downcast::<T>().ok())
    }

    /// ngx_get_full_name
    pub fn full_name(&self, name: &[u8], conf_prefix: bool) -> Vec<u8> {
        if name.first() == Some(&b'/') {
            return name.to_vec();
        }
        let prefix = if conf_prefix { &self.conf_prefix } else { &self.prefix };
        let mut v = Vec::with_capacity(prefix.len() + name.len());
        v.extend_from_slice(prefix);
        v.extend_from_slice(name);
        v
    }

    /// ngx_conf_open_file: dedup by full name; empty name is stderr.
    pub fn open_file(&mut self, name: &[u8]) -> Rc<OpenFile> {
        if !name.is_empty() {
            let full = self.full_name(name, false);
            for f in &self.open_files {
                if f.name == full {
                    return f.clone();
                }
            }
            let f = Rc::new(OpenFile::new(full));
            self.open_files.push(f.clone());
            return f;
        }
        let f = Rc::new(OpenFile::new(Vec::new()));
        self.open_files.push(f.clone());
        f
    }

    pub fn add_config_dump(&mut self, name: &[u8], data: &[u8]) -> Option<usize> {
        let want = globals(|g| g.dump_config) || cfg!(debug_assertions) || true;
        if !want {
            return None;
        }
        if self.config_dump.iter().any(|d| d.name == name) {
            return None;
        }
        self.config_dump.push(ConfigDump { name: name.to_vec(), data: data.to_vec() });
        Some(self.config_dump.len() - 1)
    }

    /// ngx_add_path
    pub fn add_path(&mut self, path: PathConf, log: &Log, conf_file: &[u8], line: usize) -> Result<Rc<PathConf>, ConfError> {
        let loc = |m: String| -> String {
            if conf_file.is_empty() {
                m
            } else {
                format!("{} in {}:{}", m, B(conf_file), line)
            }
        };
        for p in &self.paths {
            if p.name == path.name {
                for n in 0..3 {
                    if p.level[n] != path.level[n] {
                        if path.conf_file.is_empty() {
                            if p.conf_file.is_empty() {
                                ngx_log_error!(
                                    NGX_LOG_EMERG,
                                    log,
                                    None,
                                    "the default path name \"{}\" has the same name as another default path, but the different levels, you need to redefine one of them in http section",
                                    B(&p.name)
                                );
                                return Err(ConfError::Logged);
                            }
                            ngx_log_error!(
                                NGX_LOG_EMERG,
                                log,
                                None,
                                "the path name \"{}\" in {}:{} has the same name as default path, but the different levels, you need to define default path in http section",
                                B(&p.name),
                                B(&p.conf_file),
                                p.line
                            );
                            return Err(ConfError::Logged);
                        }
                        let m = format!("the same path name \"{}\" in {}:{} has the different levels than", B(&p.name), B(&p.conf_file), p.line);
                        ngx_log_error!(NGX_LOG_EMERG, log, None, "{}", loc(m));
                        return Err(ConfError::Logged);
                    }
                    if p.level[n] == 0 {
                        break;
                    }
                }
                return Ok(p.clone());
            }
        }
        let p = Rc::new(path);
        self.paths.push(p.clone());
        Ok(p)
    }

    /// ngx_create_paths
    pub fn create_paths(&self, user: Option<u32>) -> Result<(), ()> {
        for p in &self.paths {
            if let Err(e) = os::mkdir(&p.name, 0o700) {
                if e != libc::EEXIST {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "mkdir() \"{}\" failed", B(&p.name));
                    return Err(());
                }
            }
            let user = match user {
                Some(u) => u,
                None => continue,
            };
            let fi = match os::stat(&p.name) {
                Ok(fi) => fi,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "stat() \"{}\" failed", B(&p.name));
                    return Err(());
                }
            };
            if fi.st_uid != user {
                if let Err(e) = os::chown(&p.name, user, u32::MAX) {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "chown(\"{}\", {}) failed", B(&p.name), user);
                    return Err(());
                }
            }
            if fi.st_mode & 0o700 != 0o700 {
                if let Err(e) = os::chmod(&p.name, fi.st_mode | 0o700) {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "chmod() \"{}\" failed", B(&p.name));
                    return Err(());
                }
            }
        }
        Ok(())
    }

    /// ngx_log_open_default
    pub fn log_open_default(&mut self) {
        if self.new_log.file_log().is_some() {
            return;
        }
        let name = self.error_log.clone();
        let file = self.open_file(&name);
        let e = LogEntry::new(NGX_LOG_ERR, LogWriter::File(file));
        self.new_log.insert(e);
    }

    /// Open all files in open_files (append/create).
    pub fn open_files(&self) -> Result<(), ()> {
        for f in &self.open_files {
            if f.name.is_empty() {
                continue;
            }
            let fd = match open_log_file(&f.name) {
                Ok(fd) => fd,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "open() \"{}\" failed", B(&f.name));
                    return Err(());
                }
            };
            f.fd.set(fd);
        }
        Ok(())
    }

    /// ngx_reopen_files: reopen logs (USR1).
    pub fn reopen_files(&self, user: Option<u32>) {
        for f in &self.open_files {
            if f.name.is_empty() {
                continue;
            }
            if let Some(flush) = f.flush.borrow().clone() {
                flush(f, &self.log);
            }
            let fd = match open_log_file(&f.name) {
                Ok(fd) => fd,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_EMERG, self.log, Some(e), "open() \"{}\" failed", B(&f.name));
                    continue;
                }
            };
            if let Some(user) = user {
                if let Ok(fi) = os::fstat(fd) {
                    if fi.st_uid != user {
                        if let Err(e) = os::fchown(fd, user, u32::MAX) {
                            ngx_log_error!(NGX_LOG_ALERT, self.log, Some(e), "chown(\"{}\", {}) failed", B(&f.name), user);
                            os::close(fd);
                            continue;
                        }
                    }
                    if fi.st_mode & (libc::S_IRUSR | libc::S_IWUSR) != (libc::S_IRUSR | libc::S_IWUSR) {
                        let mode = fi.st_mode | libc::S_IRUSR | libc::S_IWUSR;
                        if let Err(e) = os::fchmod(fd, mode) {
                            ngx_log_error!(NGX_LOG_ALERT, self.log, Some(e), "chmod() \"{}\" failed", B(&f.name));
                            os::close(fd);
                            continue;
                        }
                    }
                }
            }
            let old = f.fd.replace(fd);
            if old >= 0 && old != libc::STDERR_FILENO {
                os::close(old);
            }
        }
    }

    pub fn close_files(&self) {
        for f in &self.open_files {
            let fd = f.fd.get();
            if fd < 0 || fd == libc::STDERR_FILENO {
                continue;
            }
            os::close(fd);
            f.fd.set(-1);
        }
    }

    /// Emit the -T dump to stdout.
    pub fn dump_config(&self) {
        for d in &self.config_dump {
            let mut out = Vec::with_capacity(d.data.len() + d.name.len() + 32);
            out.extend_from_slice(b"# configuration file ");
            out.extend_from_slice(&d.name);
            out.extend_from_slice(b":\n");
            out.extend_from_slice(&d.data);
            out.extend_from_slice(b"\n");
            write_stdout(&out);
        }
    }
}

/// Result of `init_cycle`.
pub type CycleResult = Result<Rc<Cycle>, ()>;

/// Callback hooks used by init_cycle for OS-level steps implemented in other modules.
pub struct InitHooks {
    pub open_listening_sockets: fn(&mut Cycle) -> Result<(), ()>,
    pub configure_listening_sockets: fn(&mut Cycle),
    pub init_zone_pool: fn(&Cycle, &Rc<ShmZone>) -> Result<(), ()>,
    pub cmp_sockaddr: fn(&Listening, &Listening) -> bool,
}

/// ngx_init_cycle: build a new cycle from `old`.
pub fn init_cycle(old: Rc<Cycle>, hooks: &InitHooks) -> CycleResult {
    crate::times::update();
    let log = old.log.clone();
    let modules = old.modules.clone();
    let n = modules.len();

    let mut cycle = Box::new(Cycle {
        conf_ctx: vec![None; n],
        modules: modules.clone(),
        log: log.clone(),
        new_log: LogChain::new(),
        log_use_stderr: false,
        open_files: Vec::new(),
        shared_memory: Vec::new(),
        listening: Vec::new(),
        paths: Vec::new(),
        config_dump: Vec::new(),
        conf_file: old.conf_file.clone(),
        conf_param: old.conf_param.clone(),
        conf_prefix: old.conf_prefix.clone(),
        prefix: old.prefix.clone(),
        error_log: old.error_log.clone(),
        lock_file: Vec::new(),
        hostname: os::hostname(),
        connection_n: 0,
        files_n: 0,
        old_cycle: None,
        runtime: RefCell::new(vec![None; n]),
        is_init: false,
        env: Vec::new(),
    });

    // create core module confs
    for m in modules.iter() {
        if m.def.ty != NGX_CORE_MODULE {
            continue;
        }
        if let Some(ctx) = m.ctx::<CoreModuleCtx>() {
            if let Some(create) = ctx.create_conf {
                let c = create(&mut cycle);
                cycle.conf_ctx[m.index] = Some(c);
            }
        }
    }

    // temporarily attach old cycle so directives can consult it (lock_file, listen inheritance)
    let old_lock_file = old.lock_file.clone();
    cycle.old_cycle = Some(old.clone());

    {
        let mut cf = Conf::new(&mut cycle, log.clone());
        cf.module_type = NGX_CORE_MODULE;
        cf.cmd_type = NGX_MAIN_CONF;
        if cf.parse_param().is_err() {
            return Err(());
        }
        let conf_file = cf.cycle.conf_file.clone();
        if cf.parse_file(&conf_file).is_err() {
            return Err(());
        }
    }

    if globals(|g| g.test_config && !g.quiet_mode) {
        crate::ngx_log_stderr!(None, "the configuration file {} syntax is ok", B(&cycle.conf_file));
    }

    for m in modules.iter() {
        if m.def.ty != NGX_CORE_MODULE {
            continue;
        }
        if let Some(ctx) = m.ctx::<CoreModuleCtx>() {
            if let Some(init) = ctx.init_conf {
                let c = cycle.conf_ctx[m.index].clone().expect("core conf");
                if init(&mut cycle, &c).is_err() {
                    return Err(());
                }
            }
        }
    }
    let _ = old_lock_file;

    if globals(|g| g.process == ProcessType::Signaller) {
        cycle.old_cycle = None;
        return Ok(Rc::from(cycle));
    }

    cycle.old_cycle = None;

    // pid file
    let (pid_path, user) = crate::core_module::pid_and_user(&cycle);
    if globals(|g| g.test_config) {
        if crate::core_module::create_pidfile(&pid_path, &log).is_err() {
            return Err(());
        }
    } else if !old.is_init {
        let (old_pid, _) = crate::core_module::pid_and_user(&old);
        if old_pid != pid_path {
            if crate::core_module::create_pidfile(&pid_path, &log).is_err() {
                return Err(());
            }
            crate::core_module::delete_pidfile(&old);
        }
    }

    if cycle.create_paths(user).is_err() {
        return Err(());
    }

    cycle.log_open_default();

    if cycle.open_files().is_err() {
        return Err(());
    }

    cycle.log = Log::new(cycle.new_log.clone());

    // shared memory
    let zones = cycle.shared_memory.clone();
    for z in zones.iter() {
        if z.shm.size.get() == 0 {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, None, "zero size shared memory zone \"{}\"", B(&z.shm.name));
            return Err(());
        }
        *z.shm.log.borrow_mut() = Some(cycle.log.clone());
        let mut data: Option<Rc<dyn Any>> = None;
        let mut found = false;
        for oz in old.shared_memory.iter() {
            if oz.shm.name != z.shm.name {
                continue;
            }
            if z.tag == oz.tag && z.noreuse.get() {
                data = oz.data.borrow().clone();
                break;
            }
            if z.tag == oz.tag && z.shm.size.get() == oz.shm.size.get() {
                z.shm.share(&oz.shm);
                let init = z.init.borrow().clone().expect("zone init");
                if init(z, oz.data.borrow().clone()).is_err() {
                    return Err(());
                }
                found = true;
                break;
            }
            break;
        }
        if found {
            continue;
        }
        if z.shm.alloc(&cycle.log).is_err() {
            return Err(());
        }
        if (hooks.init_zone_pool)(&cycle, z).is_err() {
            return Err(());
        }
        let init = z.init.borrow().clone().expect("zone init");
        if init(z, data).is_err() {
            return Err(());
        }
    }

    // SO_REUSEPORT fanout: duplicate each reuseport listening (worker==0) once
    // per additional worker so each worker gets its own kernel socket. Ported
    // from ngx_clone_listening; must happen before inheritance so both fresh
    // startup and reload see the same set of listening entries in both cycles.
    {
        let n = *crate::core_module::core_conf(&cycle).borrow().worker_processes;
        if n > 1 {
            let originals: Vec<Rc<Listening>> = cycle
                .listening
                .iter()
                .filter(|ls| ls.reuseport.get() && ls.worker.get() == 0)
                .cloned()
                .collect();
            for ls in &originals {
                for w in 1..(n as usize) {
                    cycle.listening.push(Rc::new(ls.clone_for_worker(w)));
                }
            }
        }
    }

    // listening sockets: inherit fds from old cycle where addresses match
    if !old.listening.is_empty() {
        for ls in old.listening.iter() {
            ls.remain.set(false);
        }
        for nls in cycle.listening.iter() {
            for ls in old.listening.iter() {
                if ls.ignore.get() || ls.remain.get() || ls.ty != nls.ty {
                    continue;
                }
                if (hooks.cmp_sockaddr)(nls, ls) {
                    nls.fd.set(ls.fd.get());
                    *nls.previous.borrow_mut() = Some(ls.clone());
                    if ls.protocol.get() != nls.protocol.get() {
                        nls.change_protocol.set(true);
                    } else {
                        nls.inherited.set(ls.inherited.get());
                        ls.remain.set(true);
                    }
                    if ls.backlog.get() != nls.backlog.get() {
                        nls.listen.set(true);
                    }
                    if ls.deferred_accept.get() && !nls.deferred_accept.get() {
                        nls.delete_deferred.set(true);
                    } else if ls.deferred_accept.get() != nls.deferred_accept.get() {
                        nls.add_deferred.set(true);
                    }
                    if nls.reuseport.get() && !ls.reuseport.get() {
                        nls.add_reuseport.set(true);
                    }
                    break;
                }
            }
            if nls.fd.get() == -1 && nls.deferred_accept.get() {
                nls.add_deferred.set(true);
            }
        }
    } else {
        for ls in cycle.listening.iter() {
            if ls.deferred_accept.get() {
                ls.add_deferred.set(true);
            }
        }
    }

    if (hooks.open_listening_sockets)(&mut cycle).is_err() {
        return Err(());
    }

    if !globals(|g| g.test_config) {
        (hooks.configure_listening_sockets)(&mut cycle);
    }

    // commit
    if !use_stderr() {
        let _ = crate::core_module::log_redirect_stderr(&cycle);
    }

    for m in modules.iter() {
        if let Some(f) = m.def.init_module {
            if f(&mut cycle).is_err() {
                // fatal
                std::process::exit(1);
            }
        }
    }

    // free old shared memory not reused
    for oz in old.shared_memory.iter() {
        let live = cycle.shared_memory.iter().any(|z| {
            z.shm.name == oz.shm.name && z.tag == oz.tag && z.shm.size.get() == oz.shm.size.get() && !oz.noreuse.get()
        });
        if !live {
            oz.shm.free(&cycle.log);
        }
    }

    // close unnecessary old listening sockets
    for ls in old.listening.iter() {
        if ls.remain.get() || ls.fd.get() == -1 {
            continue;
        }
        // its read event goes with it (a single process reloading)
        crate::event::stop_accepting(ls);
        if let Err(e) = os::close_fd(ls.fd.get()) {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "close() listening socket on {} failed", B(&ls.addr_text));
        }
        if ls.is_unix() {
            let name = &ls.addr_text[5..];
            ngx_log_error!(NGX_LOG_WARN, cycle.log, None, "deleting socket {}", B(name));
            if let Err(e) = os::unlink(name) {
                ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e), "unlink() {} failed", B(name));
            }
        }
    }

    // close old open files
    old.close_files();

    cycle.old_cycle = None;
    Ok(Rc::from(cycle))
}

/// ngx_shared_memory_add
pub fn shared_memory_add(cf: &mut Conf, name: &[u8], size: usize, tag: &'static str) -> Result<Rc<ShmZone>, ConfError> {
    let found = cf.cycle.shared_memory.iter().find(|z| z.shm.name.as_slice() == name).cloned();

    if let Some(z) = found {
        if z.tag != tag {
            cf.log_error(
                NGX_LOG_EMERG,
                None,
                format_args!("the shared memory zone \"{}\" is already declared for a different use", B(name)),
            );
            return Err(ConfError::Logged);
        }

        if z.shm.size.get() == 0 {
            z.shm.size.set(size);
        }

        if size != 0 && size != z.shm.size.get() {
            cf.log_error(
                NGX_LOG_EMERG,
                None,
                format_args!(
                    "the size {} of shared memory zone \"{}\" conflicts with already declared size {}",
                    size,
                    B(name),
                    z.shm.size.get()
                ),
            );
            return Err(ConfError::Logged);
        }

        return Ok(z);
    }

    let z = ShmZone::new(name.to_vec(), size, tag);
    cf.cycle.shared_memory.push(z.clone());
    Ok(z)
}
