//! ngx_stream_log_module.c: log_format, access_log (files, buffered and
//! gzipped files, files with variables in names, syslog), and
//! open_log_file_cache.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress, Status};

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::open_file_cache::{open_cached_file, OpenFileCache, OpenFileInfo};
use ngx_core::os;
use ngx_core::rc::*;
use ngx_core::string::{atoi, eq_ignore_case, escape_json_into, B};
use ngx_core::syslog::SyslogPeer;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_log_module");

pub const NGX_STREAM_LOG_ESCAPE_DEFAULT: usize = 0;
pub const NGX_STREAM_LOG_ESCAPE_JSON: usize = 1;
pub const NGX_STREAM_LOG_ESCAPE_NONE: usize = 2;

/// NGX_LINEFEED_SIZE
const LINEFEED_SIZE: usize = 1;

/// Z_BEST_SPEED
const Z_BEST_SPEED: i64 = 1;

/// NGX_TIMER_LAZY_DELAY
const TIMER_LAZY_DELAY: u64 = 300;

/// ngx_stream_log_op_t: its run and getlen
#[derive(Debug)]
pub enum LogOp {
    /// ngx_stream_log_copy_short, ngx_stream_log_copy_long: op->len bytes
    Copy(Vec<u8>),
    /// ngx_stream_log_variable_compile(): the variable index and the
    /// escaping (ngx_stream_log_variable, ngx_stream_log_json_variable,
    /// ngx_stream_log_unescaped_variable)
    Variable { index: usize, escape: usize },
}

/// ngx_stream_log_fmt_t
pub struct LogFmt {
    pub name: Vec<u8>,
    pub flushes: Vec<usize>,
    pub ops: Vec<LogOp>,
}

/// ngx_stream_log_main_conf_t
#[derive(Default)]
pub struct LogMainConf {
    pub formats: Vec<Rc<LogFmt>>,
}

/// ngx_stream_log_buf_t: the buffer of a file (file->data)
pub struct LogBuf {
    /// start..pos
    pub buf: RefCell<Vec<u8>>,
    /// last - start
    pub size: usize,
    /// buffer->event: the flush timer and its deadline, when set
    pub event: RefCell<Option<(tokio::task::JoinHandle<()>, tokio::time::Instant)>>,
    /// the flush time, 0 without the event
    pub flush: u64,
    pub gzip: i64,
}

/// ngx_stream_log_t
pub struct StreamLog {
    pub file: Option<Rc<OpenFile>>,
    /// ngx_stream_log_script_t: the codes of the file name
    pub script: Option<Vec<Code>>,
    pub disk_full_time: Cell<i64>,
    pub error_log_time: Cell<i64>,
    pub syslog_peer: Option<Rc<SyslogPeer>>,
    pub format: Rc<LogFmt>,
    pub filter: Option<ComplexValue>,
}

/// ngx_stream_log_srv_conf_t
pub struct LogSrvConf {
    pub logs: Option<Vec<Rc<StreamLog>>>,

    /// NGX_CONF_UNSET_PTR, NULL ("off") or the cache
    pub open_file_cache: Val<Option<Rc<OpenFileCache>>>,
    pub open_file_cache_valid: i64,
    pub open_file_cache_min_uses: u32,

    pub off: bool,
}

/// ngx_time()
fn ngx_time() -> i64 {
    ngx_core::times::cached().sec
}

/// The buffer of a file.
fn file_buffer(file: &OpenFile) -> Option<Rc<LogBuf>> {
    file.data.borrow().clone().and_then(|d| d.downcast::<LogBuf>().ok())
}

/// ngx_stream_log_handler
async fn log_handler(s: S) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream log handler");

    let lscf = s.srv_conf::<LogSrvConf>(ctx_index());

    let logs = {
        let l = lscf.borrow();

        if l.off {
            return NGX_OK;
        }

        match &l.logs {
            None => return NGX_OK,
            Some(logs) => logs.clone(),
        }
    };

    for log in logs.iter() {
        if let Some(filter) = &log.filter {
            let val = match complex_value(&s, filter) {
                Ok(v) => v,
                Err(()) => return NGX_ERROR,
            };

            if val.is_empty() || val == b"0" {
                continue;
            }
        }

        if ngx_time() == log.disk_full_time.get() {
            // on FreeBSD writing to a full filesystem with enabled softupdates
            // may block process for much longer time than writing to non-full
            // filesystem, so we skip writing to a log for one second

            continue;
        }

        flush_no_cacheable_variables(&s, Some(&log.format.flushes));

        let mut len = 0;

        for op in log.format.ops.iter() {
            len += op_getlen(&s, op);
        }

        len += LINEFEED_SIZE;

        if let Some(peer) = &log.syslog_peer {
            // length of syslog's PRI and HEADER message parts
            len += "<255>Jan 01 00:00:00 ".len() + ngx_core::cycle::cycle().hostname.len() + 1 + peer.tag.len() + 2;

            // alloc_line:

            let mut line = Vec::with_capacity(len);

            peer.add_header(&mut line);

            if !run_ops(&s, &log.format.ops, &mut line, len - LINEFEED_SIZE) {
                return NGX_ERROR;
            }

            let size = line.len();

            // peer->logp: the errors of the peer go to the cycle log
            if peer.log.borrow().is_none() {
                peer.set_log(ngx_core::cycle::cycle().log.clone());
            }

            let n = peer.send(&line);

            if n < 0 {
                ngx_log_error!(NGX_LOG_WARN, s.connection.log, None, "send() to syslog failed");
            } else if n as usize != size {
                ngx_log_error!(NGX_LOG_WARN, s.connection.log, None, "send() to syslog has written only {} of {}", n, size);
            }

            continue;
        }

        let buffer = log.file.as_ref().and_then(|f| file_buffer(f));

        if let Some(buffer) = &buffer {
            let pos = buffer.buf.borrow().len();

            if len > buffer.size - pos {
                let contents = std::mem::take(&mut *buffer.buf.borrow_mut());

                log_write(&s, log, &contents);

                let mut b = buffer.buf.borrow_mut();
                *b = contents;
                b.clear();
            }

            let pos = buffer.buf.borrow().len();

            if len <= buffer.size - pos {
                if buffer.flush != 0 && pos == 0 {
                    add_flush_timer(buffer, log.file.as_ref().unwrap());
                }

                let mut line = Vec::with_capacity(len);

                if !run_ops(&s, &log.format.ops, &mut line, len - LINEFEED_SIZE) {
                    return NGX_ERROR;
                }

                line.push(b'\n');

                buffer.buf.borrow_mut().extend_from_slice(&line);

                continue;
            }

            del_flush_timer(buffer);
        }

        // alloc_line:

        let mut line = Vec::with_capacity(len);

        if !run_ops(&s, &log.format.ops, &mut line, len - LINEFEED_SIZE) {
            return NGX_ERROR;
        }

        line.push(b'\n');

        log_write(&s, log, &line);
    }

    NGX_OK
}

/// ngx_add_timer(buffer->event, buffer->flush)
fn add_flush_timer(buffer: &Rc<LogBuf>, file: &Rc<OpenFile>) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(buffer.flush);

    if let Some((_, key)) = buffer.event.borrow().as_ref() {
        // the timer is set, it is not updated for the small changes

        let diff = if deadline > *key { deadline - *key } else { *key - deadline };

        if diff < Duration::from_millis(TIMER_LAZY_DELAY) {
            return;
        }
    }

    del_flush_timer(buffer);

    let weak = Rc::downgrade(buffer);
    let file = file.clone();

    let handle = ngx_core::event::spawn(async move {
        tokio::time::sleep_until(deadline).await;

        // the timer is expired: ev->timer_set = 0, ev->handler(ev)

        if let Some(buffer) = weak.upgrade() {
            buffer.event.borrow_mut().take();
        }

        log_flush_handler(&file);
    });

    *buffer.event.borrow_mut() = Some((handle, deadline));
}

/// ngx_del_timer(buffer->event) if the timer is set
fn del_flush_timer(buffer: &LogBuf) {
    if let Some((handle, _)) = buffer.event.borrow_mut().take() {
        handle.abort();
    }
}

/// The length of an op: op->len or op->getlen().
fn op_getlen(s: &Session, op: &LogOp) -> usize {
    match op {
        LogOp::Copy(text) => text.len(),

        LogOp::Variable { index, escape } => match *escape {
            NGX_STREAM_LOG_ESCAPE_JSON => json_variable_getlen(s, *index),
            NGX_STREAM_LOG_ESCAPE_NONE => unescaped_variable_getlen(s, *index),
            _ => variable_getlen(s, *index),
        },
    }
}

/// The runs of the ops: false if the line is out of the length (end)
/// computed with getlen.
fn run_ops(s: &Session, ops: &[LogOp], buf: &mut Vec<u8>, end: usize) -> bool {
    for op in ops {
        let ok = match op {
            LogOp::Copy(text) => log_copy(s, buf, end, text),

            LogOp::Variable { index, escape } => match *escape {
                NGX_STREAM_LOG_ESCAPE_JSON => json_variable(s, buf, end, *index),
                NGX_STREAM_LOG_ESCAPE_NONE => unescaped_variable(s, buf, end, *index),
                _ => log_variable(s, buf, end, *index),
            },
        };

        if !ok {
            return false;
        }
    }

    true
}

/// ngx_stream_log_write
fn log_write(s: &Session, log: &StreamLog, buf: &[u8]) {
    let len = buf.len();

    let (name, n) = match &log.script {
        None => {
            let file = log.file.as_ref().expect("log file");

            let n = match file_buffer(file) {
                Some(buffer) if buffer.gzip != 0 => log_gzip(file.fd.get(), buf, buffer.gzip, &s.connection.log),
                _ => os::write_fd(file.fd.get(), buf),
            };

            (file.name.clone(), n)
        }

        Some(script) => log_script_write(s, script, buf),
    };

    let now = ngx_time();

    match n {
        Ok(n) if n == len => {}

        Err(err) => {
            if err == libc::ENOSPC {
                log.disk_full_time.set(now);
            }

            if now - log.error_log_time.get() > 59 {
                ngx_log_error!(NGX_LOG_ALERT, s.connection.log, if err != 0 { Some(err) } else { None }, "write() to \"{}\" failed", B(&name));

                log.error_log_time.set(now);
            }
        }

        Ok(n) => {
            if now - log.error_log_time.get() > 59 {
                ngx_log_error!(NGX_LOG_ALERT, s.connection.log, None, "write() to \"{}\" was incomplete: {} of {}", B(&name), n, len);

                log.error_log_time.set(now);
            }
        }
    }
}

/// ngx_stream_log_script_write: the name of the file and the result of
/// write()
fn log_script_write(s: &Session, script: &[Code], buf: &[u8]) -> (Vec<u8>, Result<usize, i32>) {
    let len = buf.len();

    let log = match script_run(s, script) {
        Some(l) => l,
        // simulate successful logging
        None => return (Vec::new(), Ok(len)),
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream log \"{}\"", B(&log));

    let lscf = s.srv_conf::<LogSrvConf>(ctx_index());

    let (cache, valid, min_uses) = {
        let l = lscf.borrow();
        (l.open_file_cache.as_option().cloned().flatten(), l.open_file_cache_valid, l.open_file_cache_min_uses)
    };

    let mut of = OpenFileInfo { log: true, valid, min_uses, directio: usize::MAX, ..Default::default() };

    let handle = match open_cached_file(cache.as_ref(), &log, &mut of, &s.connection.log) {
        Ok(Some(h)) => h,
        _ => {
            if of.err == 0 {
                // simulate successful logging
                return (log, Ok(len));
            }

            ngx_log_error!(NGX_LOG_CRIT, s.connection.log, Some(of.err), "{} \"{}\" failed", of.failed, B(&log));

            // simulate successful logging
            return (log, Ok(len));
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream log #{}", of.fd);

    let n = os::write_fd(of.fd, buf);

    drop(handle);

    (log, n)
}

/// ngx_stream_log_gzip: Ok(len) unless write() fails ("simulate successful
/// logging")
fn log_gzip(fd: i32, buf: &[u8], level: i64, log: &Log) -> Result<usize, i32> {
    let len = buf.len();

    let mut wbits: i64 = 15;
    let mut memlevel: i64 = 8;

    while (len as i64) < ((1 << (wbits - 1)) - 262) {
        wbits -= 1;
        memlevel -= 1;
    }

    let _ = memlevel;

    // This is a formula from deflateBound() for conservative upper bound of
    // compressed data plus 18 bytes of gzip wrapper.

    let size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    let mut out = vec![0u8; size];

    let mut zstream = Compress::new_gzip(Compression::new(level as u32), wbits as u8);

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, log, "deflate in: ni:{:p} no:{:p} ai:{} ao:{}", buf.as_ptr(), out.as_ptr(), len, size);

    let rc = zstream.compress(buf, &mut out, FlushCompress::Finish);

    match rc {
        Ok(Status::StreamEnd) => {}

        Ok(Status::Ok) => {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "deflate(Z_FINISH) failed: 0");
            return Ok(len);
        }

        Ok(Status::BufError) | Err(_) => {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "deflate(Z_FINISH) failed: -5");
            return Ok(len);
        }
    }

    let size = zstream.total_out() as usize;

    ngx_log_debug!(
        NGX_LOG_DEBUG_STREAM,
        log,
        "deflate out: ni:{:p} no:{:p} ai:{} ao:{} rc:1",
        buf[zstream.total_in() as usize..].as_ptr(),
        out[size..].as_ptr(),
        len - zstream.total_in() as usize,
        out.len() - size
    );

    match os::write_fd(fd, &out[..size]) {
        Ok(n) if n == size => {}
        // a partial write: ngx_set_errno(0)
        Ok(_) => return Err(0),
        Err(err) => return Err(err),
    }

    // simulate successful logging
    Ok(len)
}

/// ngx_stream_log_flush: the flush of the buffer of a file
fn log_flush(file: &OpenFile, log: &Log) {
    let buffer = match file_buffer(file) {
        Some(b) => b,
        None => return,
    };

    let contents = std::mem::take(&mut *buffer.buf.borrow_mut());

    let len = contents.len();

    if len == 0 {
        *buffer.buf.borrow_mut() = contents;
        return;
    }

    let n = if buffer.gzip != 0 { log_gzip(file.fd.get(), &contents, buffer.gzip, log) } else { os::write_fd(file.fd.get(), &contents) };

    match n {
        Err(err) => {
            ngx_log_error!(NGX_LOG_ALERT, log, if err != 0 { Some(err) } else { None }, "write() to \"{}\" failed", B(&file.name));
        }

        Ok(n) if n != len => {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "write() to \"{}\" was incomplete: {} of {}", B(&file.name), n, len);
        }

        Ok(_) => {}
    }

    {
        let mut b = buffer.buf.borrow_mut();
        *b = contents;
        b.clear();
    }

    del_flush_timer(&buffer);
}

/// ngx_stream_log_flush_handler: the buffer->event handler, ev->log is the
/// cycle log
fn log_flush_handler(file: &Rc<OpenFile>) {
    let log = ngx_core::cycle::cycle().log.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "stream log buffer flush handler");

    log_flush(file, &log);
}

/// ngx_stream_log_copy_short, ngx_stream_log_copy_long
fn log_copy(s: &Session, buf: &mut Vec<u8>, end: usize, text: &[u8]) -> bool {
    if !check_length(s, buf, end, text.len()) {
        return false;
    }

    buf.extend_from_slice(text);

    true
}

/// ngx_stream_log_variable_getlen
fn variable_getlen(s: &Session, index: usize) -> usize {
    let value = match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v,
        _ => return 1,
    };

    let len = log_escape_count(&value.data);

    value.data.len() + len * 3
}

/// ngx_stream_log_variable
fn log_variable(s: &Session, buf: &mut Vec<u8>, end: usize, index: usize) -> bool {
    let value = match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v,
        _ => {
            if !check_length(s, buf, end, 1) {
                return false;
            }

            buf.push(b'-');

            return true;
        }
    };

    // value->escape is set by getlen: the escaping of a value without the
    // characters to escape is the value itself

    let len = log_escape_count(&value.data);

    if !check_length(s, buf, end, value.data.len() + len * 3) {
        return false;
    }

    log_escape(buf, &value.data);

    true
}

/// The escape[] table of ngx_stream_log_escape
static LOG_ESCAPE: [u32; 8] = [
    0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
    //             ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!
    0x00000004, // 0000 0000 0000 0000  0000 0000 0000 0100
    //             _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@
    0x10000000, // 0001 0000 0000 0000  0000 0000 0000 0000
    //              ~}| {zyx wvut srqp  onml kjih gfed cba`
    0x80000000, // 1000 0000 0000 0000  0000 0000 0000 0000
    0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
    0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
    0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
    0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
];

fn needs_escape(c: u8) -> bool {
    LOG_ESCAPE[(c >> 5) as usize] & (1u32 << (c & 0x1f)) != 0
}

/// ngx_stream_log_escape(NULL, ...): the number of the characters to be
/// escaped
fn log_escape_count(src: &[u8]) -> usize {
    src.iter().filter(|&&c| needs_escape(c)).count()
}

/// ngx_stream_log_escape
fn log_escape(dst: &mut Vec<u8>, src: &[u8]) {
    static HEX: &[u8; 16] = b"0123456789ABCDEF";

    for &c in src {
        if needs_escape(c) {
            dst.push(b'\\');
            dst.push(b'x');
            dst.push(HEX[(c >> 4) as usize]);
            dst.push(HEX[(c & 0xf) as usize]);
        } else {
            dst.push(c);
        }
    }
}

/// ngx_escape_json(NULL, ...): the number of the additional characters
fn escape_json_count(src: &[u8]) -> usize {
    let mut len = 0;

    for &ch in src {
        if ch == b'\\' || ch == b'"' {
            len += 1;
        } else if ch <= 0x1f {
            match ch {
                b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => len += 1,
                _ => len += "\\u001F".len() - 1,
            }
        }
    }

    len
}

/// ngx_stream_log_json_variable_getlen
fn json_variable_getlen(s: &Session, index: usize) -> usize {
    let value = match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v,
        _ => return 0,
    };

    value.data.len() + escape_json_count(&value.data)
}

/// ngx_stream_log_json_variable
fn json_variable(s: &Session, buf: &mut Vec<u8>, end: usize, index: usize) -> bool {
    let value = match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v,
        _ => return true,
    };

    let len = escape_json_count(&value.data);

    if !check_length(s, buf, end, value.data.len() + len) {
        return false;
    }

    escape_json_into(buf, &value.data);

    true
}

/// ngx_stream_log_unescaped_variable_getlen
fn unescaped_variable_getlen(s: &Session, index: usize) -> usize {
    match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v.data.len(),
        _ => 0,
    }
}

/// ngx_stream_log_unescaped_variable
fn unescaped_variable(s: &Session, buf: &mut Vec<u8>, end: usize, index: usize) -> bool {
    let value = match get_indexed_variable(s, index) {
        Some(v) if !v.not_found => v,
        _ => return true,
    };

    if !check_length(s, buf, end, value.data.len()) {
        return false;
    }

    buf.extend_from_slice(&value.data);

    true
}

/// ngx_stream_log_check_length
fn check_length(s: &Session, buf: &[u8], end: usize, len: usize) -> bool {
    if end < buf.len() || end - buf.len() < len {
        ngx_log_error!(NGX_LOG_ALERT, s.connection.log, None, "no buffer space in log script copy");
        return false;
    }

    true
}

/// ngx_stream_log_create_main_conf
fn log_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LogMainConf::default())
}

/// ngx_stream_log_create_srv_conf
fn log_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LogSrvConf { logs: None, open_file_cache: Val::unset(), open_file_cache_valid: 0, open_file_cache_min_uses: 0, off: false })
}

/// ngx_stream_log_merge_srv_conf
fn log_merge_srv_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let pcell = conf_cell::<LogSrvConf>(parent);
    let cell = conf_cell::<LogSrvConf>(child);

    if std::ptr::eq(pcell, cell) {
        return Ok(());
    }

    let prev = pcell.borrow();
    let mut conf = cell.borrow_mut();

    if !conf.open_file_cache.is_set() {
        conf.open_file_cache = prev.open_file_cache.clone();
        conf.open_file_cache_valid = prev.open_file_cache_valid;
        conf.open_file_cache_min_uses = prev.open_file_cache_min_uses;

        if !conf.open_file_cache.is_set() {
            conf.open_file_cache = Val::set(None);
        }
    }

    if conf.logs.is_some() || conf.off {
        return Ok(());
    }

    conf.logs = prev.logs.clone();
    conf.off = prev.off;

    Ok(())
}

/// ngx_stream_log_set_log: "access_log"
fn log_set_log(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lscf = conf_rc::<LogSrvConf>(conf.as_ref().expect("log srv conf"));

    let value = cf.args.clone();

    if value[1] == b"off" {
        lscf.borrow_mut().off = true;

        if value.len() == 2 {
            return Ok(());
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
    }

    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());

    let mut file = None;
    let mut script = None;
    let mut syslog_peer = None;

    if value[1].starts_with(b"syslog:") {
        syslog_peer = Some(ngx_core::syslog::process_conf(cf, &value[1])?);
    } else {
        let n = script_variables_count(&value[1]);

        if n == 0 {
            file = Some(cf.cycle.open_file(&value[1]));
        } else {
            let source = cf.full_name(&value[1], false);

            let mut sc = ScriptCompile { source, flushes: None, codes: Vec::new(), variables: n, ncaptures: 0, size: 0, zero: false, conf_prefix: false, root_prefix: false };

            script_compile(cf, &mut sc)?;

            script = Some(sc.codes);
        }
    }

    // process_formats:

    let name = if value.len() >= 3 {
        value[2].clone()
    } else {
        return Err(cf.emerg(format_args!("log format is not specified")));
    };

    let format = lmcf.borrow().formats.iter().find(|f| f.name.len() == name.len() && eq_ignore_case(&f.name, &name)).cloned();

    let format = match format {
        Some(f) => f,
        None => return Err(cf.emerg(format_args!("unknown log format \"{}\"", B(&name)))),
    };

    let mut size: usize = 0;
    let mut flush: u64 = 0;
    let mut gzip: i64 = 0;
    let mut filter = None;

    for v in &value[3..] {
        if let Some(s) = v.strip_prefix(b"buffer=") {
            size = match ngx_core::parse::parse_size(s) {
                Some(n) if n != 0 => n,
                _ => return Err(cf.emerg(format_args!("invalid buffer size \"{}\"", B(s)))),
            };

            continue;
        }

        if let Some(s) = v.strip_prefix(b"flush=") {
            flush = match ngx_core::parse::parse_time(s, false) {
                Some(n) if n != 0 => n as u64,
                _ => return Err(cf.emerg(format_args!("invalid flush time \"{}\"", B(s)))),
            };

            continue;
        }

        if v.starts_with(b"gzip") && (v.len() == 4 || v[4] == b'=') {
            if size == 0 {
                size = 64 * 1024;
            }

            if v.len() == 4 {
                gzip = Z_BEST_SPEED;
                continue;
            }

            let s = &v[5..];

            gzip = atoi(s).unwrap_or(-1);

            if !(1..=9).contains(&gzip) {
                return Err(cf.emerg(format_args!("invalid compression level \"{}\"", B(s))));
            }

            continue;
        }

        if let Some(s) = v.strip_prefix(b"if=") {
            let mut ccv = CompileComplexValue::default();
            filter = Some(compile_complex_value(cf, s, &mut ccv)?);

            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    if flush != 0 && size == 0 {
        return Err(cf.emerg(format_args!("no buffer is defined for access_log \"{}\"", B(&value[1]))));
    }

    let has_script = script.is_some();
    let has_syslog = syslog_peer.is_some();

    let log = Rc::new(StreamLog {
        file: file.clone(),
        script,
        disk_full_time: Cell::new(0),
        error_log_time: Cell::new(0),
        syslog_peer,
        format,
        filter,
    });

    lscf.borrow_mut().logs.get_or_insert_with(Vec::new).push(log);

    if size != 0 {
        if has_script {
            return Err(cf.emerg(format_args!("buffered logs cannot have variables in name")));
        }

        if has_syslog {
            return Err(cf.emerg(format_args!("logs to syslog cannot be buffered")));
        }

        let file = file.expect("log file");

        if let Some(buffer) = file_buffer(&file) {
            if buffer.size != size || buffer.flush != flush || buffer.gzip != gzip {
                return Err(cf.emerg(format_args!("access_log \"{}\" already defined with conflicting parameters", B(&value[1]))));
            }

            return Ok(());
        }

        let buffer = Rc::new(LogBuf { buf: RefCell::new(Vec::with_capacity(size)), size, event: RefCell::new(None), flush, gzip });

        *file.flush.borrow_mut() = Some(Rc::new(log_flush));
        *file.data.borrow_mut() = Some(buffer as Rc<dyn Any>);
    }

    Ok(())
}

/// ngx_stream_log_set_format: "log_format"
fn log_set_format(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lmcf = conf_rc::<LogMainConf>(conf.as_ref().expect("log main conf"));

    let value = cf.args.clone();

    if lmcf.borrow().formats.iter().any(|f| f.name == value[1]) {
        return Err(cf.emerg(format_args!("duplicate \"log_format\" name \"{}\"", B(&value[1]))));
    }

    let mut flushes = Vec::new();
    let mut ops = Vec::new();

    log_compile_format(cf, Some(&mut flushes), &mut ops, &value, 2)?;

    lmcf.borrow_mut().formats.push(Rc::new(LogFmt { name: value[1].clone(), flushes, ops }));

    Ok(())
}

/// ngx_stream_log_compile_format
pub fn log_compile_format(cf: &mut Conf, mut flushes: Option<&mut Vec<usize>>, ops: &mut Vec<LogOp>, args: &[Vec<u8>], mut s: usize) -> ConfResult {
    let mut escape = NGX_STREAM_LOG_ESCAPE_DEFAULT;

    if s < args.len() && args[s].starts_with(b"escape=") {
        let data = &args[s][7..];

        if data == b"json" {
            escape = NGX_STREAM_LOG_ESCAPE_JSON;
        } else if data == b"none" {
            escape = NGX_STREAM_LOG_ESCAPE_NONE;
        } else if data != b"default" {
            return Err(cf.emerg(format_args!("unknown log format escaping \"{}\"", B(data))));
        }

        s += 1;
    }

    while s < args.len() {
        let value = &args[s];

        let mut i = 0;

        while i < value.len() {
            let data = i;

            if value[i] == b'$' {
                let invalid = |cf: &Conf| cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[data..])));

                i += 1;

                if i == value.len() {
                    return Err(invalid(cf));
                }

                let mut bracket = false;

                if value[i] == b'{' {
                    bracket = true;

                    i += 1;

                    if i == value.len() {
                        return Err(invalid(cf));
                    }
                }

                let var = i;
                let mut len = 0;

                while i < value.len() {
                    let ch = value[i];

                    if ch == b'}' && bracket {
                        i += 1;
                        bracket = false;
                        break;
                    }

                    if ch.is_ascii_alphanumeric() || ch == b'_' {
                        i += 1;
                        len += 1;
                        continue;
                    }

                    break;
                }

                if bracket {
                    return Err(cf.emerg(format_args!("the closing bracket in \"{}\" variable is missing", B(&value[var..var + len]))));
                }

                if len == 0 {
                    return Err(invalid(cf));
                }

                // ngx_stream_log_variable_compile

                let index = get_variable_index(cf, &value[var..var + len])?;

                ops.push(LogOp::Variable { index, escape });

                if let Some(f) = flushes.as_mut() {
                    f.push(index);
                }

                continue;
            }

            i += 1;

            while i < value.len() && value[i] != b'$' {
                i += 1;
            }

            ops.push(LogOp::Copy(value[data..i].to_vec()));
        }

        s += 1;
    }

    Ok(())
}

/// ngx_stream_log_open_file_cache: "open_log_file_cache"
fn log_open_file_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lscf = conf_rc::<LogSrvConf>(conf.as_ref().expect("log srv conf"));

    if lscf.borrow().open_file_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;
    let mut min_uses: i64 = 1;

    for v in &value[1..] {
        let ok = if let Some(s) = v.strip_prefix(b"max=") {
            atoi(s).map(|n| max = n).is_some()
        } else if let Some(s) = v.strip_prefix(b"inactive=") {
            ngx_core::parse::parse_time(s, true).map(|n| inactive = n).is_some()
        } else if let Some(s) = v.strip_prefix(b"min_uses=") {
            atoi(s).map(|n| min_uses = n).is_some()
        } else if let Some(s) = v.strip_prefix(b"valid=") {
            ngx_core::parse::parse_time(s, true).map(|n| valid = n).is_some()
        } else if v == b"off" {
            lscf.borrow_mut().open_file_cache = Val::set(None);
            true
        } else {
            false
        };

        if !ok {
            return Err(cf.emerg(format_args!("invalid \"open_log_file_cache\" parameter \"{}\"", B(v))));
        }
    }

    if lscf.borrow().open_file_cache.is_set() {
        // "off"
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"open_log_file_cache\" must have \"max\" parameter")));
    }

    let mut l = lscf.borrow_mut();

    l.open_file_cache = Val::set(Some(OpenFileCache::new(max as usize, inactive)));
    l.open_file_cache_valid = valid;
    l.open_file_cache_min_uses = min_uses as u32;

    Ok(())
}

/// ngx_stream_log_init
fn log_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_LOG_PHASE, phase_fn(log_handler));
    Ok(())
}

pub fn log_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_log_module",
        StreamModuleDef {
            postconfiguration: Some(log_init),
            create_main_conf: Some(log_create_main_conf),
            create_srv_conf: Some(log_create_srv_conf),
            merge_srv_conf: Some(log_merge_srv_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("log_format", NGX_STREAM_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, log_set_format),
            cmd_fn!("access_log", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, log_set_log),
            cmd_fn!("open_log_file_cache", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1234, ConfLevel::Srv, log_open_file_cache),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape() {
        let mut out = Vec::new();
        log_escape(&mut out, b"a\"b\\c\x01\x7f\xff d");
        assert_eq!(&out[..], &b"a\\x22b\\x5Cc\\x01\\x7F\\xFF d"[..]);
        assert_eq!(log_escape_count(b"a\"b\\c\x01\x7f\xff d"), 5);
    }

    #[test]
    fn json_count() {
        let src = b"\" \\ \n\x01x";
        let mut out = Vec::new();
        escape_json_into(&mut out, src);
        assert_eq!(out.len(), src.len() + escape_json_count(src));
    }
}
