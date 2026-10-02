//! ngx_http_log_module.c: log_format, access_log (files, buffered and
//! gzipped files, files with variables in names, syslog), and
//! open_log_file_cache.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress, Status};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::{open_cached_file, OpenFileCache, OpenFileInfo};
use ngx_core::os;
use ngx_core::rc::*;
use ngx_core::string::{atoi, eq_ignore_case, escape_json_into, B};
use ngx_core::syslog::SyslogPeer;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::core_rt::map_uri_to_path;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_log_module");

pub const NGX_HTTP_LOG_ESCAPE_DEFAULT: usize = 0;
pub const NGX_HTTP_LOG_ESCAPE_JSON: usize = 1;
pub const NGX_HTTP_LOG_ESCAPE_NONE: usize = 2;

/// NGX_LINEFEED_SIZE
const LINEFEED_SIZE: usize = 1;

/// Z_BEST_SPEED
const Z_BEST_SPEED: i64 = 1;

/// NGX_TIMER_LAZY_DELAY
const TIMER_LAZY_DELAY: u64 = 300;

/// NGX_TIME_T_LEN, NGX_INT_T_LEN, NGX_OFF_T_LEN: NGX_INT64_LEN
const NGX_TIME_T_LEN: usize = "-9223372036854775808".len();
const NGX_INT_T_LEN: usize = "-9223372036854775808".len();
const NGX_OFF_T_LEN: usize = "-9223372036854775808".len();

/// sizeof(uintptr_t): the longest text of ngx_http_log_copy_short
const SIZEOF_UINTPTR: usize = std::mem::size_of::<usize>();

/// ngx_http_log_op_run_pt: the op appends its output to the line; false
/// (NULL) if the line has no space left for it up to `end`
pub type LogOpRun = fn(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool;

/// ngx_http_log_op_getlen_pt
pub type LogOpGetlen = fn(r: &R, data: usize) -> usize;

/// ngx_http_log_op_t
pub struct LogOp {
    /// the length of the output, 0 for the variables (op->getlen)
    pub len: usize,
    pub getlen: Option<LogOpGetlen>,
    pub run: LogOpRun,
    /// the variable index
    pub data: usize,
    /// op->data of ngx_http_log_copy_short and ngx_http_log_copy_long: the
    /// text
    pub text: Vec<u8>,
}

/// ngx_http_log_fmt_t
pub struct LogFmt {
    pub name: Vec<u8>,
    /// NULL for the predefined "combined" format
    pub flushes: Option<Vec<usize>>,
    /// the ops of the "combined" format are compiled in ngx_http_log_init,
    /// after the logs referring to it
    pub ops: RefCell<Vec<LogOp>>,
}

/// ngx_http_log_main_conf_t
pub struct LogMainConf {
    pub formats: Vec<Rc<LogFmt>>,
    pub combined_used: bool,
}

/// ngx_http_log_buf_t: the buffer of a file (file->data)
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

/// ngx_http_log_t
pub struct HttpLog {
    pub file: Option<Rc<OpenFile>>,
    /// ngx_http_log_script_t: the lengths and values of the file name
    pub script: Option<Vec<Part>>,
    pub disk_full_time: Cell<i64>,
    pub error_log_time: Cell<i64>,
    pub syslog_peer: Option<Rc<SyslogPeer>>,
    pub format: Rc<LogFmt>,
    pub filter: Option<ComplexValue>,
}

/// ngx_http_log_loc_conf_t
pub struct LogLocConf {
    pub logs: Option<Vec<Rc<HttpLog>>>,

    /// NGX_CONF_UNSET_PTR, NULL ("off") or the cache
    pub open_file_cache: Val<Option<Rc<OpenFileCache>>>,
    pub open_file_cache_valid: i64,
    pub open_file_cache_min_uses: u32,

    pub off: bool,
}

/// ngx_http_log_var_t
struct LogVar {
    name: &'static [u8],
    len: usize,
    run: LogOpRun,
}

/// ngx_http_access_log
const NGX_HTTP_ACCESS_LOG: &str = ngx_core::NGX_HTTP_LOG_PATH;

/// ngx_http_combined_fmt
pub const NGX_HTTP_COMBINED_FMT: &[u8] = b"$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

/// ngx_http_log_vars
static NGX_HTTP_LOG_VARS: [LogVar; 9] = [
    LogVar { name: b"pipe", len: 1, run: log_pipe },
    LogVar { name: b"time_local", len: "28/Sep/1970:12:00:00 +0600".len(), run: log_time },
    LogVar { name: b"time_iso8601", len: "1970-09-28T12:00:00+06:00".len(), run: log_iso8601 },
    LogVar { name: b"msec", len: NGX_TIME_T_LEN + 4, run: log_msec },
    LogVar { name: b"request_time", len: NGX_TIME_T_LEN + 4, run: log_request_time },
    LogVar { name: b"status", len: NGX_INT_T_LEN, run: log_status },
    LogVar { name: b"bytes_sent", len: NGX_OFF_T_LEN, run: log_bytes_sent },
    LogVar { name: b"body_bytes_sent", len: NGX_OFF_T_LEN, run: log_body_bytes_sent },
    LogVar { name: b"request_length", len: NGX_OFF_T_LEN, run: log_request_length },
];

/// ngx_time()
fn ngx_time() -> i64 {
    ngx_core::times::cached().sec
}

/// The buffer of a file.
fn file_buffer(file: &OpenFile) -> Option<Rc<LogBuf>> {
    file.data.borrow().clone().and_then(|d| d.downcast::<LogBuf>().ok())
}

/// ngx_http_log_handler
fn log_handler(r: &R) -> i64 {
    http_debug!(r, "http log handler");

    let lcf = r.loc_conf::<LogLocConf>(ctx_index());

    let logs = {
        let l = lcf.borrow();

        if l.off {
            return NGX_OK;
        }

        match &l.logs {
            Some(logs) => logs.clone(),
            None => return NGX_OK,
        }
    };

    for log in logs.iter() {
        if let Some(filter) = &log.filter {
            match with_complex_value(r, filter, |val| val.is_empty() || (val.len() == 1 && val[0] == b'0')) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => return NGX_ERROR,
            }
        }

        if ngx_time() == log.disk_full_time.get() {
            // on FreeBSD writing to a full filesystem with enabled softupdates
            // may block process for much longer time than writing to non-full
            // filesystem, so we skip writing to a log for one second

            continue;
        }

        script_flush_no_cacheable_variables(r, log.format.flushes.as_deref());

        let ops = log.format.ops.borrow();

        let mut len = 0;

        for op in ops.iter() {
            if op.len == 0 {
                len += (op.getlen.expect("log op getlen"))(r, op.data);
            } else {
                len += op.len;
            }
        }

        len += LINEFEED_SIZE;

        if let Some(peer) = &log.syslog_peer {
            // length of syslog's PRI and HEADER message parts
            len += "<255>Jan 01 00:00:00 ".len() + ngx_core::cycle::cycle().hostname.len() + 1 + peer.tag.len() + 2;

            // goto alloc_line

            let mut line = Vec::with_capacity(len);

            peer.add_header(&mut line);

            if !run_ops(r, &ops, &mut line, len - LINEFEED_SIZE) {
                return NGX_ERROR;
            }

            let size = line.len();

            // peer->logp: the errors of the peer go to the cycle log
            if peer.log.borrow().is_none() {
                peer.set_log(ngx_core::cycle::cycle().log.clone());
            }

            let n = peer.send(&line);

            if n < 0 {
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "send() to syslog failed");
            } else if n as usize != size {
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "send() to syslog has written only {} of {}", n, size);
            }

            continue;
        }

        let buffer = log.file.as_ref().and_then(|f| file_buffer(f));

        if let Some(buffer) = &buffer {
            if len > buffer.size - buffer.buf.borrow().len() {
                let contents = std::mem::take(&mut *buffer.buf.borrow_mut());

                log_write(r, log, &contents);

                // buffer->pos = buffer->start
                let mut b = buffer.buf.borrow_mut();
                *b = contents;
                b.clear();
            }

            let pos = buffer.buf.borrow().len();

            if len <= buffer.size - pos {
                if buffer.flush != 0 && pos == 0 {
                    add_flush_timer(buffer, log.file.as_ref().expect("log file"));
                }

                let mut line = Vec::with_capacity(len);

                if !run_ops(r, &ops, &mut line, len - LINEFEED_SIZE) {
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

        if !run_ops(r, &ops, &mut line, len - LINEFEED_SIZE) {
            return NGX_ERROR;
        }

        line.push(b'\n');

        log_write(r, log, &line);
    }

    NGX_OK
}

/// The runs of the ops: false (NULL) if an op has no space left in the
/// line, its length (up to `end`) being computed before.
fn run_ops(r: &R, ops: &[LogOp], buf: &mut Vec<u8>, end: usize) -> bool {
    for op in ops {
        if !(op.run)(r, buf, end, op) {
            return false;
        }
    }

    true
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

/// ngx_http_log_write
fn log_write(r: &R, log: &HttpLog, buf: &[u8]) {
    let len = buf.len();

    let (name, n) = match &log.script {
        None => {
            let file = log.file.as_ref().expect("log file");

            let n = match file_buffer(file) {
                Some(buffer) if buffer.gzip != 0 => log_gzip(file.fd.get(), buf, buffer.gzip, &r.connection.log),
                _ => os::write_fd(file.fd.get(), buf),
            };

            (file.name.clone(), n)
        }

        Some(script) => log_script_write(r, script, buf),
    };

    if n == Ok(len) {
        return;
    }

    let now = ngx_time();

    match n {
        Err(err) => {
            if err == libc::ENOSPC {
                log.disk_full_time.set(now);
            }

            if now - log.error_log_time.get() > 59 {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, if err != 0 { Some(err) } else { None }, "write() to \"{}\" failed", B(&name));

                log.error_log_time.set(now);
            }
        }

        Ok(n) => {
            if now - log.error_log_time.get() > 59 {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "write() to \"{}\" was incomplete: {} of {}", B(&name), n, len);

                log.error_log_time.set(now);
            }
        }
    }
}

/// ngx_http_log_script_write: the name of the file and the result of
/// write()
fn log_script_write(r: &R, script: &[Part], buf: &[u8]) -> (Vec<u8>, Result<usize, i32>) {
    let len = buf.len();

    let clcf = r.clcf();

    if !r.root_tested.get() {
        // test root directory existence

        let (mut path, root) = match map_uri_to_path(r, 0) {
            Some(p) => p,
            // simulate successful logging
            None => return (Vec::new(), Ok(len)),
        };

        // path.data[root] = '\0'
        path.truncate(root);

        let (cache, mut of) = {
            let c = clcf.borrow();

            let of = OpenFileInfo {
                valid: *c.open_file_cache_valid,
                min_uses: *c.open_file_cache_min_uses as u32,
                test_dir: true,
                test_only: true,
                errors: *c.open_file_cache_errors,
                events: *c.open_file_cache_events,
                ..Default::default()
            };

            (c.open_file_cache.as_option().cloned().flatten(), of)
        };

        if crate::core_rt::set_disable_symlinks(r, &clcf, &path, &mut of) != NGX_OK {
            // simulate successful logging
            return (Vec::new(), Ok(len));
        }

        match open_cached_file(cache.as_ref(), &path, &mut of, &r.connection.log) {
            Ok(_handle) => {}

            Err(()) => {
                if of.err == 0 {
                    // simulate successful logging
                    return (Vec::new(), Ok(len));
                }

                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(of.err), "testing \"{}\" existence failed", B(&path));

                // simulate successful logging
                return (Vec::new(), Ok(len));
            }
        }

        if !of.is_dir {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ENOTDIR), "testing \"{}\" existence failed", B(&path));

            // simulate successful logging
            return (Vec::new(), Ok(len));
        }
    }

    let log = match script_run(r, script) {
        Some(l) => l,
        // simulate successful logging
        None => return (Vec::new(), Ok(len)),
    };

    http_debug!(r, "http log \"{}\"", B(&log));

    let llcf = r.loc_conf::<LogLocConf>(ctx_index());

    let (cache, valid, min_uses) = {
        let l = llcf.borrow();
        (l.open_file_cache.as_option().cloned().flatten(), l.open_file_cache_valid, l.open_file_cache_min_uses)
    };

    // of.directio = NGX_OPEN_FILE_DIRECTIO_OFF
    let mut of = OpenFileInfo { log: true, valid, min_uses, directio: usize::MAX, ..Default::default() };

    if crate::core_rt::set_disable_symlinks(r, &clcf, &log, &mut of) != NGX_OK {
        // simulate successful logging
        return (log, Ok(len));
    }

    let handle = match open_cached_file(cache.as_ref(), &log, &mut of, &r.connection.log) {
        Ok(h) => h,

        Err(()) => {
            if of.err == 0 {
                // simulate successful logging
                return (log, Ok(len));
            }

            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(of.err), "{} \"{}\" failed", of.failed, B(&log));

            // simulate successful logging
            return (log, Ok(len));
        }
    };

    http_debug!(r, "http log #{}", of.fd);

    let n = os::write_fd(of.fd, buf);

    drop(handle);

    (log, n)
}


/// ngx_http_log_gzip: Ok(len) unless write() fails ("simulate successful
/// logging").  zlib (through flate2) allocates its memory itself, hence no
/// "gzip alloc" debug lines; flate2's deflateInit2() uses memLevel 8,
/// where C lowers the memory level with the window bits for short
/// buffers, so the compressed bytes of these can differ from C.
fn log_gzip(fd: i32, buf: &[u8], level: i64, log: &Log) -> Result<usize, i32> {
    let len = buf.len();

    let mut wbits: i32 = 15; // MAX_WBITS

    while (len as i64) < ((1i64 << (wbits - 1)) - 262) {
        wbits -= 1;
    }

    // This is a formula from deflateBound() for conservative upper bound of
    // compressed data plus 18 bytes of gzip wrapper.

    let mut size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    let mut out = vec![0u8; size];

    // deflateInit2(level, Z_DEFLATED, wbits + 16, memLevel 8,
    // Z_DEFAULT_STRATEGY); with valid parameters it fails only when out of
    // memory, which flate2 does not survive ("deflateInit2() failed")
    let mut zstream = Compress::new_gzip(Compression::new(level as u32), wbits as u8);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "deflate in: ni:{:016X} no:{:016X} ai:{} ao:{}", buf.as_ptr() as usize, out.as_ptr() as usize, len as u32, size as u32);

    // Z_OK, Z_STREAM_END, Z_BUF_ERROR or Z_STREAM_ERROR
    let rc = match zstream.compress(buf, &mut out, FlushCompress::Finish) {
        Ok(Status::Ok) => 0,
        Ok(Status::StreamEnd) => 1,
        Ok(Status::BufError) => -5,
        Err(_) => -2,
    };

    if rc != 1 {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "deflate(Z_FINISH) failed: {}", rc);
        return Ok(len);
    }

    let (consumed, produced) = (zstream.total_in() as usize, zstream.total_out() as usize);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "deflate out: ni:{:016X} no:{:016X} ai:{} ao:{} rc:{}", buf.as_ptr() as usize + consumed, out.as_ptr() as usize + produced, (len - consumed) as u32, (size - produced) as u32, rc);

    size = produced;

    // deflateEnd(): Z_OK after Z_STREAM_END, "deflateEnd() failed" cannot
    // happen
    drop(zstream);

    match os::write_fd(fd, &out[..size]) {
        Ok(n) if n == size => {}
        // a partial write: ngx_set_errno(0)
        Ok(_) => return Err(0),
        Err(err) => return Err(err),
    }

    // simulate successful logging
    Ok(len)
}

/// ngx_http_log_flush: the flush of the buffer of a file
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

/// ngx_http_log_flush_handler: the buffer->event handler, ev->log is the
/// cycle log
fn log_flush_handler(file: &Rc<OpenFile>) {
    let log = ngx_core::cycle::cycle().log.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "http log buffer flush handler");

    log_flush(file, &log);
}

/// ngx_http_log_copy_short
fn log_copy_short(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, op.len) {
        return false;
    }

    buf.extend_from_slice(&op.text);

    true
}

/// ngx_http_log_copy_long
fn log_copy_long(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, op.len) {
        return false;
    }

    buf.extend_from_slice(&op.text);

    true
}

/// ngx_http_log_pipe
fn log_pipe(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, 1) {
        return false;
    }

    if r.pipeline.get() {
        buf.push(b'p');
    } else {
        buf.push(b'.');
    }

    true
}

/// ngx_http_log_time
fn log_time(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    let time = ngx_core::times::cached_http_log_time();

    if !log_check_length(r, buf, end, time.len()) {
        return false;
    }

    buf.extend_from_slice(time.as_bytes());

    true
}

/// ngx_http_log_iso8601
fn log_iso8601(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    let time = ngx_core::times::cached_http_log_iso8601();

    if !log_check_length(r, buf, end, time.len()) {
        return false;
    }

    buf.extend_from_slice(time.as_bytes());

    true
}

/// ngx_http_log_msec
fn log_msec(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_TIME_T_LEN + 4) {
        return false;
    }

    let tp = ngx_core::times::cached();

    buf.extend_from_slice(format!("{}.{:03}", tp.sec, tp.msec).as_bytes());

    true
}

/// ngx_http_log_request_time
fn log_request_time(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_TIME_T_LEN + 4) {
        return false;
    }

    let tp = ngx_core::times::cached();

    let ms = (tp.sec - r.start_sec.get()) * 1000 + (tp.msec as i64 - r.start_msec.get() as i64);
    let ms = ms.max(0);

    buf.extend_from_slice(format!("{}.{:03}", ms / 1000, ms % 1000).as_bytes());

    true
}

/// ngx_http_log_status
fn log_status(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_INT_T_LEN) {
        return false;
    }

    let status = if r.err_status.get() != 0 {
        r.err_status.get()
    } else if r.headers_out.borrow().status != 0 {
        r.headers_out.borrow().status
    } else if r.http_version.get() == NGX_HTTP_VERSION_9 {
        9
    } else {
        0
    };

    buf.extend_from_slice(format!("{:03}", status).as_bytes());

    true
}

/// ngx_http_log_bytes_sent
fn log_bytes_sent(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_OFF_T_LEN) {
        return false;
    }

    buf.extend_from_slice(r.connection.sent.get().to_string().as_bytes());

    true
}

/// ngx_http_log_body_bytes_sent: although there is a real $body_bytes_sent
/// variable, this log operation code function is more optimized for
/// logging
fn log_body_bytes_sent(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_OFF_T_LEN) {
        return false;
    }

    let length = r.connection.sent.get() as i64 - r.header_size.get() as i64;

    if length > 0 {
        buf.extend_from_slice(length.to_string().as_bytes());
        return true;
    }

    buf.push(b'0');

    true
}

/// ngx_http_log_request_length
fn log_request_length(r: &R, buf: &mut Vec<u8>, end: usize, _op: &LogOp) -> bool {
    if !log_check_length(r, buf, end, NGX_OFF_T_LEN) {
        return false;
    }

    buf.extend_from_slice(r.request_length.get().to_string().as_bytes());

    true
}

/// ngx_http_log_variable_compile
fn log_variable_compile(cf: &mut Conf, value: &[u8], escape: usize) -> Result<LogOp, ConfError> {
    let index = get_variable_index(cf, value)?;

    let (getlen, run): (LogOpGetlen, LogOpRun) = match escape {
        NGX_HTTP_LOG_ESCAPE_JSON => (log_json_variable_getlen, log_json_variable),
        NGX_HTTP_LOG_ESCAPE_NONE => (log_unescaped_variable_getlen, log_unescaped_variable),
        // NGX_HTTP_LOG_ESCAPE_DEFAULT
        _ => (log_variable_getlen, log_variable),
    };

    Ok(LogOp { len: 0, getlen: Some(getlen), run, data: index, text: Vec::new() })
}

/// ngx_http_log_variable_getlen
fn log_variable_getlen(r: &R, data: usize) -> usize {
    with_indexed_variable(r, data, |value| match value {
        Some(v) if !v.not_found => v.data.len() + log_escape_count(&v.data) * 3,
        _ => 1,
    })
}

/// ngx_http_log_variable
fn log_variable(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool {
    with_indexed_variable(r, op.data, |value| {
        let value = match value {
            Some(v) if !v.not_found => v,
            _ => {
                if !log_check_length(r, buf, end, 1) {
                    return false;
                }

                buf.push(b'-');

                return true;
            }
        };

        // value->escape is set by the getlen: the escaping of a value without
        // the characters to escape is the value itself

        let len = log_escape_count(&value.data);

        if !log_check_length(r, buf, end, value.data.len() + len * 3) {
            return false;
        }

        log_escape(buf, &value.data);

        true
    })
}

/// The escape[] table of ngx_http_log_escape
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

/// ngx_http_log_escape(NULL, ...): the number of the characters to be
/// escaped
fn log_escape_count(src: &[u8]) -> usize {
    src.iter().filter(|&&c| needs_escape(c)).count()
}

/// ngx_http_log_escape
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

/// ngx_http_log_json_variable_getlen
fn log_json_variable_getlen(r: &R, data: usize) -> usize {
    with_indexed_variable(r, data, |value| match value {
        Some(v) if !v.not_found => v.data.len() + escape_json_count(&v.data),
        _ => 0,
    })
}

/// ngx_http_log_json_variable
fn log_json_variable(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool {
    with_indexed_variable(r, op.data, |value| {
        let value = match value {
            Some(v) if !v.not_found => v,
            _ => return true,
        };

        let len = escape_json_count(&value.data);

        if !log_check_length(r, buf, end, value.data.len() + len) {
            return false;
        }

        escape_json_into(buf, &value.data);

        true
    })
}

/// ngx_http_log_unescaped_variable_getlen
fn log_unescaped_variable_getlen(r: &R, data: usize) -> usize {
    with_indexed_variable(r, data, |value| match value {
        Some(v) if !v.not_found => v.data.len(),
        _ => 0,
    })
}

/// ngx_http_log_unescaped_variable
fn log_unescaped_variable(r: &R, buf: &mut Vec<u8>, end: usize, op: &LogOp) -> bool {
    with_indexed_variable(r, op.data, |value| {
        let value = match value {
            Some(v) if !v.not_found => v,
            _ => return true,
        };

        if !log_check_length(r, buf, end, value.data.len()) {
            return false;
        }

        buf.extend_from_slice(&value.data);

        true
    })
}

/// ngx_http_log_check_length
fn log_check_length(r: &R, buf: &[u8], end: usize, len: usize) -> bool {
    if end < buf.len() || end - buf.len() < len {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "no buffer space in log script copy");
        return false;
    }

    true
}

/// ngx_http_log_create_main_conf
fn log_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    let combined = Rc::new(LogFmt { name: b"combined".to_vec(), flushes: None, ops: RefCell::new(Vec::new()) });

    make_slot(LogMainConf { formats: vec![combined], combined_used: false })
}

/// ngx_http_log_create_loc_conf
fn log_create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LogLocConf { logs: None, open_file_cache: Val::unset(), open_file_cache_valid: 0, open_file_cache_min_uses: 0, off: false })
}

/// ngx_http_log_merge_loc_conf
fn log_merge_loc_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let pcell = conf_cell::<LogLocConf>(parent);
    let cell = conf_cell::<LogLocConf>(child);

    let (prev_cache, prev_valid, prev_min_uses, prev_logs, prev_off) = {
        let prev = pcell.borrow();
        (prev.open_file_cache.clone(), prev.open_file_cache_valid, prev.open_file_cache_min_uses, prev.logs.clone(), prev.off)
    };

    {
        let mut conf = cell.borrow_mut();

        if !conf.open_file_cache.is_set() {
            conf.open_file_cache = prev_cache;
            conf.open_file_cache_valid = prev_valid;
            conf.open_file_cache_min_uses = prev_min_uses;

            if !conf.open_file_cache.is_set() {
                conf.open_file_cache = Val::set(None);
            }
        }

        if conf.logs.is_some() || conf.off {
            return Ok(());
        }

        conf.logs = prev_logs;
        conf.off = prev_off;

        if conf.logs.is_some() || conf.off {
            return Ok(());
        }
    }

    let file = cf.cycle.open_file(NGX_HTTP_ACCESS_LOG.as_bytes());

    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());

    // the default "combined" format
    let format = lmcf.borrow().formats[0].clone();
    lmcf.borrow_mut().combined_used = true;

    let log = HttpLog {
        file: Some(file),
        script: None,
        disk_full_time: Cell::new(0),
        error_log_time: Cell::new(0),
        syslog_peer: None,
        format,
        filter: None,
    };

    cell.borrow_mut().logs = Some(vec![Rc::new(log)]);

    Ok(())
}

/// ngx_http_log_set_log: "access_log"
fn log_set_log(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let llcf = conf_rc::<LogLocConf>(conf.as_ref().expect("log loc conf"));

    let mut value = cf.args.clone();

    if value[1] == b"off" {
        llcf.borrow_mut().off = true;

        if value.len() == 2 {
            return Ok(());
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
    }

    if llcf.borrow().logs.is_none() {
        llcf.borrow_mut().logs = Some(Vec::new());
    }

    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());

    let mut file = None;
    let mut script = None;
    let mut syslog_peer = None;

    if value[1].starts_with(b"syslog:") {
        syslog_peer = Some(ngx_core::syslog::process_conf(cf, &value[1])?);

        // ngx_syslog_parse_args() splits the argument in place at the commas
        for c in value[1].iter_mut() {
            if *c == b',' {
                *c = b'\0';
            }
        }
    } else {
        let n = script_variables_count(&value[1]);

        if n == 0 {
            file = Some(cf.cycle.open_file(&value[1]));
        } else {
            // ngx_conf_full_name(cf->cycle, &value[1], 0) changes the argument
            value[1] = cf.full_name(&value[1], false);

            script = Some(script_compile(cf, &value[1])?);
        }
    }

    // process_formats:

    let name = if value.len() >= 3 {
        if value[2] == b"combined" {
            lmcf.borrow_mut().combined_used = true;
        }

        value[2].clone()
    } else {
        lmcf.borrow_mut().combined_used = true;

        b"combined".to_vec()
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

    for v in value.iter().skip(3) {
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
            filter = Some(compile_complex_value(cf, s, 0)?);

            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    if flush != 0 && size == 0 {
        return Err(cf.emerg(format_args!("no buffer is defined for access_log \"{}\"", B(&value[1]))));
    }

    let has_script = script.is_some();
    let has_syslog = syslog_peer.is_some();

    let log = Rc::new(HttpLog {
        file: file.clone(),
        script,
        disk_full_time: Cell::new(0),
        error_log_time: Cell::new(0),
        syslog_peer,
        format,
        filter,
    });

    llcf.borrow_mut().logs.get_or_insert_with(Vec::new).push(log);

    if size != 0 {
        if has_script {
            return Err(cf.emerg(format_args!("buffered logs cannot have variables in name")));
        }

        if has_syslog {
            return Err(cf.emerg(format_args!("logs to syslog cannot be buffered")));
        }

        let file = file.expect("log file");

        if file.data.borrow().is_some() {
            let conflicting = match file_buffer(&file) {
                Some(buffer) => buffer.size != size || buffer.flush != flush || buffer.gzip != gzip,
                // the buffer of another module (stream log)
                None => true,
            };

            if conflicting {
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

/// ngx_http_log_set_format: "log_format"
fn log_set_format(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lmcf = conf_rc::<LogMainConf>(conf.as_ref().expect("log main conf"));

    let value = cf.args.clone();

    if lmcf.borrow().formats.iter().any(|f| f.name == value[1]) {
        return Err(cf.emerg(format_args!("duplicate \"log_format\" name \"{}\"", B(&value[1]))));
    }

    let mut flushes = Vec::new();
    let mut ops = Vec::new();

    log_compile_format(cf, Some(&mut flushes), &mut ops, &value, 2)?;

    lmcf.borrow_mut().formats.push(Rc::new(LogFmt { name: value[1].clone(), flushes: Some(flushes), ops: RefCell::new(ops) }));

    Ok(())
}

/// ngx_http_log_compile_format
pub fn log_compile_format(cf: &mut Conf, mut flushes: Option<&mut Vec<usize>>, ops: &mut Vec<LogOp>, args: &[Vec<u8>], mut s: usize) -> ConfResult {
    let mut escape = NGX_HTTP_LOG_ESCAPE_DEFAULT;

    if s < args.len() && args[s].starts_with(b"escape=") {
        let data = &args[s][7..];

        if data == b"json" {
            escape = NGX_HTTP_LOG_ESCAPE_JSON;
        } else if data == b"none" {
            escape = NGX_HTTP_LOG_ESCAPE_NONE;
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

                let var = &value[var..var + len];

                if let Some(v) = NGX_HTTP_LOG_VARS.iter().find(|v| v.name == var) {
                    ops.push(LogOp { len: v.len, getlen: None, run: v.run, data: 0, text: Vec::new() });

                    continue;
                }

                let op = log_variable_compile(cf, var, escape)?;

                if let Some(f) = flushes.as_mut() {
                    // variable index
                    f.push(op.data);
                }

                ops.push(op);

                continue;
            }

            i += 1;

            while i < value.len() && value[i] != b'$' {
                i += 1;
            }

            let len = i - data;

            if len != 0 {
                let run: LogOpRun = if len <= SIZEOF_UINTPTR { log_copy_short } else { log_copy_long };

                ops.push(LogOp { len, getlen: None, run, data: 0, text: value[data..i].to_vec() });
            }
        }

        s += 1;
    }

    Ok(())
}

/// ngx_http_log_open_file_cache: "open_log_file_cache"
fn log_open_file_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let llcf = conf_rc::<LogLocConf>(conf.as_ref().expect("log loc conf"));

    if llcf.borrow().open_file_cache.is_set() {
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
            llcf.borrow_mut().open_file_cache = Val::set(None);
            true
        } else {
            false
        };

        if !ok {
            // failed:
            return Err(cf.emerg(format_args!("invalid \"open_log_file_cache\" parameter \"{}\"", B(v))));
        }
    }

    if llcf.borrow().open_file_cache.is_set() {
        // "off"
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"open_log_file_cache\" must have \"max\" parameter")));
    }

    let mut l = llcf.borrow_mut();

    l.open_file_cache = Val::set(Some(OpenFileCache::new(max as usize, inactive)));
    l.open_file_cache_valid = valid;
    l.open_file_cache_min_uses = min_uses as u32;

    Ok(())
}

/// ngx_http_log_init
fn log_init(cf: &mut Conf) -> ConfResult {
    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());

    let combined_used = lmcf.borrow().combined_used;

    if combined_used {
        let a = vec![NGX_HTTP_COMBINED_FMT.to_vec()];

        let fmt = lmcf.borrow().formats[0].clone();

        let mut ops = Vec::new();

        log_compile_format(cf, None, &mut ops, &a, 0)?;

        fmt.ops.borrow_mut().extend(ops);
    }

    add_log_handler(cf, Rc::new(|r| log_handler(r)));

    Ok(())
}

pub fn log_module() -> ModuleDef {
    http_module_def(
        "ngx_http_log_module",
        HttpModuleDef {
            postconfiguration: Some(log_init),
            create_main_conf: Some(log_create_main_conf),
            create_loc_conf: Some(log_create_loc_conf),
            merge_loc_conf: Some(log_merge_loc_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("log_format", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, log_set_format),
            cmd_fn!("access_log", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE, ConfLevel::Loc, log_set_log),
            cmd_fn!("open_log_file_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::Loc, log_open_file_cache),
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

        // the characters of the access_log.t "escape" test
        let mut out = Vec::new();
        log_escape(&mut out, b"/escape/\"1 \x1b\x1c \"");
        assert_eq!(&out[..], &b"/escape/\\x221 \\x1B\\x1C \\x22"[..]);
    }

    #[test]
    fn json_count() {
        let src = b"\" \\ \n\x01x\x1b";
        let mut out = Vec::new();
        escape_json_into(&mut out, src);
        assert_eq!(out.len(), src.len() + escape_json_count(src));
        assert_eq!(&out[..], &b"\\\" \\\\ \\n\\u0001x\\u001B"[..]);
    }

    #[test]
    fn log_vars_lengths() {
        // the sizeof() - 1 of the C table
        assert_eq!(NGX_HTTP_LOG_VARS[1].len, 26);
        assert_eq!(NGX_HTTP_LOG_VARS[2].len, 25);
        assert_eq!(NGX_HTTP_LOG_VARS[3].len, 24);
        assert_eq!(NGX_HTTP_LOG_VARS[5].len, 20);
    }

    #[test]
    fn gzip_roundtrip() {
        use std::io::Read;

        let (rd, wr) = rustix::pipe::pipe().unwrap();
        let wr = ngx_core::fd::register(wr);

        let data = b"/compressed:200\n/compressed:200\n".repeat(10);
        let log = Log::stderr(NGX_LOG_ALERT);

        assert_eq!(log_gzip(wr, &data, 1, &log), Ok(data.len()));

        // an empty buffer is an empty gzip member
        assert_eq!(log_gzip(wr, b"", 1, &log), Ok(0));

        os::close(wr);

        let mut gz = Vec::new();
        let mut f = std::fs::File::from(rd);
        f.read_to_end(&mut gz).unwrap();

        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();

        assert_eq!(out, data);
    }
}
