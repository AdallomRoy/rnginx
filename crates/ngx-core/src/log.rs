//! Error logging, ported from ngx_log.c.

use std::cell::{Cell, RefCell};
use std::fmt::Arguments;
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::times;

pub const NGX_LOG_STDERR: u32 = 0;
pub const NGX_LOG_EMERG: u32 = 1;
pub const NGX_LOG_ALERT: u32 = 2;
pub const NGX_LOG_CRIT: u32 = 3;
pub const NGX_LOG_ERR: u32 = 4;
pub const NGX_LOG_WARN: u32 = 5;
pub const NGX_LOG_NOTICE: u32 = 6;
pub const NGX_LOG_INFO: u32 = 7;
pub const NGX_LOG_DEBUG: u32 = 8;

pub const NGX_LOG_DEBUG_CORE: u32 = 0x010;
pub const NGX_LOG_DEBUG_ALLOC: u32 = 0x020;
pub const NGX_LOG_DEBUG_MUTEX: u32 = 0x040;
pub const NGX_LOG_DEBUG_EVENT: u32 = 0x080;
pub const NGX_LOG_DEBUG_HTTP: u32 = 0x100;
pub const NGX_LOG_DEBUG_MAIL: u32 = 0x200;
pub const NGX_LOG_DEBUG_STREAM: u32 = 0x400;

pub const NGX_LOG_DEBUG_FIRST: u32 = NGX_LOG_DEBUG_CORE;
pub const NGX_LOG_DEBUG_LAST: u32 = NGX_LOG_DEBUG_STREAM;
pub const NGX_LOG_DEBUG_CONNECTION: u32 = 0x80000000;
pub const NGX_LOG_DEBUG_ALL: u32 = 0x7ffffff0;

pub const ERR_LEVELS: [&str; 9] = ["", "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"];
pub const DEBUG_LEVELS: [&str; 7] = ["debug_core", "debug_alloc", "debug_mutex", "debug_event", "debug_http", "debug_mail", "debug_stream"];

pub const NGX_MAX_ERROR_STR: usize = 2048;

static USE_STDERR: AtomicBool = AtomicBool::new(true);

pub fn set_use_stderr(v: bool) {
    USE_STDERR.store(v, Ordering::Relaxed);
}

pub fn use_stderr() -> bool {
    USE_STDERR.load(Ordering::Relaxed)
}

thread_local! {
    static LOG_PID: Cell<i32> = Cell::new(unsafe { libc::getpid() });
}

/// Refresh cached pid (call after fork).
pub fn update_pid() {
    LOG_PID.with(|p| p.set(unsafe { libc::getpid() }));
}

pub fn pid() -> i32 {
    LOG_PID.with(|p| p.get())
}

/// strerror text like nginx's ngx_strerror.
pub fn strerror(err: i32) -> String {
    let mut buf = [0u8; 256];
    unsafe {
        let r = libc::strerror_r(err, buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        if r != 0 {
            return format!("Unknown error {}", err);
        }
        let cs = std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
        cs.to_string_lossy().into_owned()
    }
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// An open log file shared across the cycle (reopened on USR1).
pub struct OpenFile {
    pub fd: Cell<RawFd>,
    pub name: Vec<u8>,
    /// Buffered access-log state hook (set by http log module).
    pub data: RefCell<Option<Rc<dyn std::any::Any>>>,
    pub flush: RefCell<Option<Rc<dyn Fn(&OpenFile, &Log)>>>,
}

impl OpenFile {
    pub fn new(name: Vec<u8>) -> Self {
        let fd = if name.is_empty() { libc::STDERR_FILENO } else { -1 };
        OpenFile { fd: Cell::new(fd), name, data: RefCell::new(None), flush: RefCell::new(None) }
    }

    pub fn write_all(&self, buf: &[u8]) -> Result<(), i32> {
        let fd = self.fd.get();
        if fd < 0 {
            return Err(libc::EBADF);
        }
        let mut off = 0;
        while off < buf.len() {
            let n = unsafe { libc::write(fd, buf[off..].as_ptr() as *const libc::c_void, buf.len() - off) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(e);
            }
            off += n as usize;
        }
        Ok(())
    }
}

/// Where a log entry writes to.
#[derive(Clone)]
pub enum LogWriter {
    File(Rc<OpenFile>),
    /// Custom writer (syslog, memory): receives level and the full formatted line.
    Custom(Rc<dyn Fn(u32, &[u8])>),
}

/// One `error_log` directive.
pub struct LogEntry {
    pub log_level: Cell<u32>,
    pub writer: RefCell<LogWriter>,
    pub disk_full_time: Cell<i64>,
}

impl LogEntry {
    pub fn new(level: u32, writer: LogWriter) -> Rc<LogEntry> {
        Rc::new(LogEntry { log_level: Cell::new(level), writer: RefCell::new(writer), disk_full_time: Cell::new(0) })
    }

    pub fn file(&self) -> Option<Rc<OpenFile>> {
        match &*self.writer.borrow() {
            LogWriter::File(f) => Some(f.clone()),
            _ => None,
        }
    }
}

/// A chain of log entries sorted by descending level (ngx_log_insert order).
#[derive(Default)]
pub struct LogChain {
    pub entries: RefCell<Vec<Rc<LogEntry>>>,
}

impl LogChain {
    pub fn new() -> Rc<LogChain> {
        Rc::new(LogChain::default())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.borrow().is_empty()
    }

    /// Insert keeping descending order; equal levels go after existing (like ngx_log_insert).
    pub fn insert(&self, e: Rc<LogEntry>) {
        let mut v = self.entries.borrow_mut();
        let lvl = e.log_level.get();
        let pos = v.iter().position(|x| lvl > x.log_level.get()).unwrap_or(v.len());
        v.insert(pos, e);
    }

    pub fn head_level(&self) -> u32 {
        self.entries.borrow().first().map(|e| e.log_level.get()).unwrap_or(0)
    }

    /// First file-backed entry (ngx_log_get_file_log).
    pub fn file_log(&self) -> Option<Rc<LogEntry>> {
        self.entries.borrow().iter().find(|e| e.file().is_some()).cloned()
    }
}

/// Provides per-connection/request context appended to log lines.
pub trait LogContext {
    fn write_context(&self, buf: &mut Vec<u8>);
}

pub struct LogInner {
    pub level: Cell<u32>,
    pub chain: RefCell<Rc<LogChain>>,
    pub connection: Cell<u64>,
    pub action: Cell<Option<&'static str>>,
    pub ctx: RefCell<Option<Rc<dyn LogContext>>>,
}

/// Cheap handle to a log context. Cloning shares state.
#[derive(Clone)]
pub struct Log {
    pub inner: Rc<LogInner>,
}

impl Log {
    pub fn new(chain: Rc<LogChain>) -> Log {
        let level = chain.head_level();
        Log {
            inner: Rc::new(LogInner {
                level: Cell::new(level),
                chain: RefCell::new(chain),
                connection: Cell::new(0),
                action: Cell::new(None),
                ctx: RefCell::new(None),
            }),
        }
    }

    /// A log writing to stderr at the given level (used before config is read).
    pub fn stderr(level: u32) -> Log {
        let chain = LogChain::new();
        chain.insert(LogEntry::new(level, LogWriter::File(Rc::new(OpenFile::new(Vec::new())))));
        Log::new(chain)
    }

    /// Independent copy (new connection/action state) sharing the same chain.
    pub fn fork(&self) -> Log {
        let l = Log::new(self.inner.chain.borrow().clone());
        l.inner.level.set(self.inner.level.get());
        l
    }

    pub fn level(&self) -> u32 {
        self.inner.level.get()
    }

    pub fn set_level(&self, level: u32) {
        self.inner.level.set(level);
    }

    pub fn chain(&self) -> Rc<LogChain> {
        self.inner.chain.borrow().clone()
    }

    /// ngx_http_set_connection_log semantics: adopt chain and level unless debug_connection.
    pub fn set_chain(&self, chain: Rc<LogChain>) {
        let lvl = chain.head_level();
        *self.inner.chain.borrow_mut() = chain;
        if self.inner.level.get() & NGX_LOG_DEBUG_CONNECTION == 0 {
            self.inner.level.set(lvl);
        }
    }

    pub fn set_connection(&self, n: u64) {
        self.inner.connection.set(n);
    }

    pub fn connection(&self) -> u64 {
        self.inner.connection.get()
    }

    pub fn set_action(&self, a: Option<&'static str>) {
        self.inner.action.set(a);
    }

    pub fn action(&self) -> Option<&'static str> {
        self.inner.action.get()
    }

    pub fn set_context(&self, ctx: Option<Rc<dyn LogContext>>) {
        *self.inner.ctx.borrow_mut() = ctx;
    }

    #[inline]
    pub fn enabled(&self, level: u32) -> bool {
        self.inner.level.get() >= level
    }

    #[inline]
    pub fn debug_enabled(&self, dbg: u32) -> bool {
        self.inner.level.get() & dbg != 0
    }

    pub fn error(&self, level: u32, err: Option<i32>, args: Arguments<'_>) {
        self.error_core(level, err, args);
    }

    pub fn error_str(&self, level: u32, err: Option<i32>, msg: &str) {
        self.error_core(level, err, format_args!("{}", msg));
    }

    pub fn error_core(&self, level: u32, err: Option<i32>, args: Arguments<'_>) {
        use std::io::Write;
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        times::with_cached(|c| buf.extend_from_slice(c.err_log_time.as_bytes()));
        let lvl_name = ERR_LEVELS[level.min(8) as usize];
        let _ = write!(buf, " [{}] {}#{}: ", lvl_name, pid(), pid());
        let conn = self.inner.connection.get();
        if conn != 0 {
            let _ = write!(buf, "*{} ", conn);
        }
        let msg_start = buf.len();
        let _ = buf.write_fmt(args);
        if let Some(e) = err {
            if e != 0 {
                let _ = write!(buf, " ({}: {})", e, strerror(e));
            }
        }
        if level != NGX_LOG_DEBUG {
            if let Some(ctx) = self.inner.ctx.borrow().as_ref() {
                ctx.write_context(&mut buf);
            }
        }
        if buf.len() > NGX_MAX_ERROR_STR - 1 {
            buf.truncate(NGX_MAX_ERROR_STR - 1);
        }
        buf.push(b'\n');

        let mut wrote_stderr = false;
        let debug_connection = self.inner.level.get() & NGX_LOG_DEBUG_CONNECTION != 0;
        let chain = self.inner.chain.borrow().clone();
        let now = times::time();
        for e in chain.entries.borrow().iter() {
            if e.log_level.get() < level && !debug_connection {
                break;
            }
            let w = e.writer.borrow().clone();
            match w {
                LogWriter::Custom(f) => f(level, &buf),
                LogWriter::File(f) => {
                    if e.disk_full_time.get() == now {
                        continue;
                    }
                    if let Err(errno) = f.write_all(&buf) {
                        if errno == libc::ENOSPC {
                            e.disk_full_time.set(now);
                        }
                    }
                    if f.fd.get() == libc::STDERR_FILENO {
                        wrote_stderr = true;
                    }
                }
            }
        }

        if !use_stderr() || level > NGX_LOG_WARN || wrote_stderr {
            return;
        }

        let mut out = Vec::with_capacity(buf.len() + 16);
        out.extend_from_slice(b"nginx: [");
        out.extend_from_slice(lvl_name.as_bytes());
        out.extend_from_slice(b"] ");
        out.extend_from_slice(&buf[msg_start..]);
        write_stderr(&out);
    }
}

pub fn write_stderr(buf: &[u8]) {
    unsafe {
        let _ = libc::write(libc::STDERR_FILENO, buf.as_ptr() as *const libc::c_void, buf.len());
    }
}

pub fn write_stdout(buf: &[u8]) {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe { libc::write(libc::STDOUT_FILENO, buf[off..].as_ptr() as *const libc::c_void, buf.len() - off) };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

/// ngx_log_stderr: "nginx: msg (errno: text)\n" to stderr.
pub fn log_stderr(err: Option<i32>, args: Arguments<'_>) {
    use std::io::Write;
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"nginx: ");
    let _ = buf.write_fmt(args);
    if let Some(e) = err {
        if e != 0 {
            let _ = write!(buf, " ({}: {})", e, strerror(e));
        }
    }
    buf.push(b'\n');
    write_stderr(&buf);
}

#[macro_export]
macro_rules! ngx_log_error {
    ($level:expr, $log:expr, $err:expr, $($arg:tt)*) => {
        if $log.enabled($level) {
            $log.error($level, $err, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! ngx_log_debug {
    ($dbg:expr, $log:expr, $($arg:tt)*) => {
        if $log.debug_enabled($dbg) {
            $log.error($crate::log::NGX_LOG_DEBUG, None, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! ngx_log_stderr {
    ($err:expr, $($arg:tt)*) => {
        $crate::log::log_stderr($err, format_args!($($arg)*));
    };
}

/// Parse "error_log" level arguments (args[2..]) into a level bitmask, as ngx_log_set_levels.
/// Returns Err(message) suitable for conf_log_error.
pub fn parse_log_levels(args: &[Vec<u8>]) -> Result<u32, String> {
    if args.len() == 2 {
        return Ok(NGX_LOG_ERR);
    }
    let mut level: u32 = 0;
    for a in &args[2..] {
        let mut found = false;
        for n in 1..=NGX_LOG_DEBUG {
            if a.as_slice() == ERR_LEVELS[n as usize].as_bytes() {
                if level != 0 {
                    return Err(format!("duplicate log level \"{}\"", crate::string::B(a)));
                }
                level = n;
                found = true;
                break;
            }
        }
        let mut d = NGX_LOG_DEBUG_FIRST;
        let mut n = 0;
        while d <= NGX_LOG_DEBUG_LAST {
            if a.as_slice() == DEBUG_LEVELS[n].as_bytes() {
                if level & !NGX_LOG_DEBUG_ALL != 0 {
                    return Err(format!("invalid log level \"{}\"", crate::string::B(a)));
                }
                level |= d;
                found = true;
                break;
            }
            n += 1;
            d <<= 1;
        }
        if !found {
            return Err(format!("invalid log level \"{}\"", crate::string::B(a)));
        }
    }
    if level == NGX_LOG_DEBUG {
        level = NGX_LOG_DEBUG_ALL;
    }
    Ok(level)
}

/// Open the initial log (ngx_log_init): stderr or prefix-relative error log path.
pub fn log_init(prefix: Option<&[u8]>, error_log: Option<&[u8]>) -> Log {
    let error_log = error_log.unwrap_or(b"logs/error.log");
    if error_log.is_empty() {
        return Log::stderr(NGX_LOG_NOTICE);
    }
    let mut name = Vec::new();
    if error_log[0] != b'/' {
        let prefix = prefix.unwrap_or(b"/usr/local/nginx/");
        if !prefix.is_empty() {
            name.extend_from_slice(prefix);
            if *name.last().unwrap() != b'/' {
                name.push(b'/');
            }
        }
    }
    name.extend_from_slice(error_log);
    let file = Rc::new(OpenFile::new(name.clone()));
    let fd = open_log_file(&name);
    if fd < 0 {
        let e = errno();
        log_stderr(Some(e), format_args!("[alert] could not open error log file: open() \"{}\" failed", crate::string::B(&name)));
        file.fd.set(libc::STDERR_FILENO);
    } else {
        file.fd.set(fd);
    }
    let chain = LogChain::new();
    chain.insert(LogEntry::new(NGX_LOG_NOTICE, LogWriter::File(file)));
    Log::new(chain)
}

/// open(name, O_WRONLY|O_APPEND|O_CREAT, 0644)
pub fn open_log_file(name: &[u8]) -> RawFd {
    let c = match std::ffi::CString::new(name.to_vec()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC, 0o644) }
}
