//! Syslog logging (ngx_syslog.c).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::conf::{Conf, ConfError, ConfResult};
use crate::inet::{parse_url, SockAddr, Url};
use crate::log::*;
use crate::string::{eq_ignore_case, B};
use crate::{ngx_log_error, os, times};

pub const NGX_SYSLOG_MAX_STR: usize = NGX_MAX_ERROR_STR + 512;

static FACILITIES: [&str; 20] = [
    "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp", "clock", "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0", "local1", "local2", "local3",
];
static FACILITIES2: [&str; 4] = ["local4", "local5", "local6", "local7"];
static SEVERITIES: [&str; 8] = ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"];

pub struct SyslogPeer {
    pub server: SockAddr,
    pub hostname: Vec<u8>,
    pub tag: Vec<u8>,
    pub facility: u32,
    pub severity: u32,
    pub nohostname: bool,
    pub fd: Cell<i32>,
    pub busy: Cell<bool>,
    pub log: RefCell<Option<Log>>,
}

fn facility_index(name: &[u8]) -> Option<u32> {
    for (i, f) in FACILITIES.iter().enumerate() {
        if f.as_bytes() == name {
            return Some(i as u32);
        }
    }
    for (i, f) in FACILITIES2.iter().enumerate() {
        if f.as_bytes() == name {
            return Some(20 + i as u32);
        }
    }
    None
}

/// ngx_syslog_process_conf: parse "syslog:server=...,facility=...,severity=...,tag=...,nohostname"
pub fn process_conf(cf: &Conf, arg: &[u8]) -> Result<Rc<SyslogPeer>, ConfError> {
    let mut facility: Option<u32> = None;
    let mut severity: Option<u32> = None;
    let mut tag: Option<Vec<u8>> = None;
    let mut nohostname = false;
    let mut server: Option<SockAddr> = None;

    let mut p = &arg[7..]; // skip "syslog:"
    while !p.is_empty() {
        let (item, rest) = match memchr::memchr(b',', p) {
            Some(i) => (&p[..i], &p[i + 1..]),
            None => (p, &p[p.len()..]),
        };
        p = rest;
        if item.starts_with(b"server=") {
            if server.is_some() {
                return Err(cf.emerg(format_args!("duplicate syslog \"server\"")));
            }
            let mut u = Url::new(&item[7..]);
            u.default_port = 514;
            if parse_url(&mut u).is_err() {
                if let Some(e) = u.err {
                    return Err(cf.emerg(format_args!("{} in syslog server \"{}\"", e, B(&u.url))));
                }
                return Err(ConfError::Logged);
            }
            server = Some(u.addrs[0].sockaddr.clone());
        } else if item.starts_with(b"facility=") {
            if facility.is_some() {
                return Err(cf.emerg(format_args!("duplicate syslog \"facility\"")));
            }
            match facility_index(&item[9..]) {
                Some(f) => facility = Some(f),
                None => return Err(cf.emerg(format_args!("unknown syslog facility \"{}\"", B(&item[9..])))),
            }
        } else if item.starts_with(b"severity=") {
            if severity.is_some() {
                return Err(cf.emerg(format_args!("duplicate syslog \"severity\"")));
            }
            let s = &item[9..];
            match SEVERITIES.iter().position(|x| x.as_bytes() == s) {
                Some(i) => severity = Some(i as u32),
                None => return Err(cf.emerg(format_args!("unknown syslog severity \"{}\"", B(s)))),
            }
        } else if item.starts_with(b"tag=") {
            if tag.is_some() {
                return Err(cf.emerg(format_args!("duplicate syslog \"tag\"")));
            }
            let t = &item[4..];
            if t.len() > 32 {
                return Err(cf.emerg(format_args!("syslog tag length exceeds 32")));
            }
            for &c in t {
                if c == b' ' {
                    return Err(cf.emerg(format_args!("syslog \"tag\" can't contain spaces")));
                }
            }
            tag = Some(t.to_vec());
        } else if item == b"nohostname" {
            nohostname = true;
        } else {
            return Err(cf.emerg(format_args!("unknown syslog parameter \"{}\"", B(item))));
        }
    }

    let server = match server {
        Some(s) => s,
        None => return Err(cf.emerg(format_args!("no syslog server specified"))),
    };
    let facility = facility.unwrap_or(23); // local7
    let severity = severity.unwrap_or(6); // info
    let tag = tag.unwrap_or_else(|| b"nginx".to_vec());
    let _ = eq_ignore_case;

    Ok(Rc::new(SyslogPeer {
        server,
        hostname: cf.cycle.hostname.clone(),
        tag,
        facility,
        severity,
        nohostname,
        fd: Cell::new(-1),
        busy: Cell::new(false),
        log: RefCell::new(None),
    }))
}

impl SyslogPeer {
    /// ngx_syslog_add_header: "<PRI>Mon DD HH:MM:SS hostname tag: "
    pub fn add_header(&self, buf: &mut Vec<u8>) {
        self.add_header_severity(buf, self.severity);
    }

    pub fn add_header_severity(&self, buf: &mut Vec<u8>, severity: u32) {
        let pri = self.facility * 8 + severity;
        let t = times::cached_syslog_time();
        if self.nohostname {
            buf.extend_from_slice(format!("<{}>{} {}: ", pri, t, B(&self.tag)).as_bytes());
        } else {
            buf.extend_from_slice(format!("<{}>{} {} {}: ", pri, t, B(&self.hostname), B(&self.tag)).as_bytes());
        }
    }

    fn init(&self, log: &Log) -> Result<(), ()> {
        let fd = unsafe { libc::socket(self.server.family(), libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "socket() failed");
            return Err(());
        }
        if os::set_nonblocking(fd).is_err() {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "ioctl(FIONBIO) failed");
            os::close(fd);
            return Err(());
        }
        let (ss, len) = self.server.to_libc();
        if unsafe { libc::connect(fd, &ss as *const _ as *const libc::sockaddr, len) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "connect() failed");
            os::close(fd);
            return Err(());
        }
        self.fd.set(fd);
        Ok(())
    }

    /// ngx_syslog_send
    pub fn send(&self, buf: &[u8]) -> isize {
        if self.log.borrow().is_none() {
            *self.log.borrow_mut() = Some(Log::stderr(NGX_LOG_ALERT));
        }
        let log = self.log.borrow().clone().unwrap();
        if self.fd.get() == -1 && self.init(&log).is_err() {
            return -1;
        }
        let n = unsafe { libc::send(self.fd.get(), buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
        if n == -1 {
            let e = os::errno();
            if e != libc::EAGAIN {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "send() failed");
            }
            os::close(self.fd.get());
            self.fd.set(-1);
        }
        n
    }

    /// Set the log used for reporting send errors (avoids recursion: cycle log with syslog stripped).
    pub fn set_log(&self, log: Log) {
        *self.log.borrow_mut() = Some(log);
    }
}

/// ngx_syslog_writer: build a syslog message from an error-log line.
pub fn writer(peer: &Rc<SyslogPeer>, level: u32, line: &[u8]) {
    if peer.busy.get() {
        return;
    }
    peer.busy.set(true);
    let mut msg = Vec::with_capacity(line.len() + 64);
    peer.add_header_severity(&mut msg, level.saturating_sub(1));
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    msg.extend_from_slice(body);
    if msg.len() > NGX_SYSLOG_MAX_STR {
        msg.truncate(NGX_SYSLOG_MAX_STR);
    }
    peer.send(&msg);
    peer.busy.set(false);
}

pub fn make_writer(peer: Rc<SyslogPeer>) -> LogWriter {
    LogWriter::Custom(Rc::new(move |level, line| writer(&peer, level, line)))
}

pub fn dummy() -> ConfResult {
    Ok(())
}
