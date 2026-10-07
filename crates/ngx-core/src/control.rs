//! ngx_control.c: the control API of "-l addr". The master process serves
//! it: a small HTTP/1.x server of JSON endpoints ("/1/nginx",
//! "/1/control/processes", "/1/control/config" and a PATCH of it reloading
//! the configuration) on O_ASYNC sockets it owns, so that SIGIO wakes it and
//! ngx_control_handle_events() polls them. Each connection is one request:
//! the request line is parsed, the response sent, and the connection closed.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cycle::*;
use crate::data::DataItem;
use crate::log::*;
use crate::rc::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, os};

const NGX_CTRL_MAX_FD: usize = 64;
const NGX_CTRL_MAX_REQUEST: usize = 1024;

const NGX_CTRL_OK: u32 = 200;
const NGX_CTRL_BAD_REQUEST: u32 = 400;
const NGX_CTRL_NOT_FOUND: u32 = 404;
const NGX_CTRL_NOT_ALLOWED: u32 = 405;
const NGX_CTRL_UNPROCESSABLE: u32 = 422;
const NGX_CTRL_INTERNAL_ERROR: u32 = 500;

const NGX_CTRL_GET: u32 = 1;
const NGX_CTRL_PATCH: u32 = 2;

const NGX_CTRL_ENV: &str = "NGINX_CTRL";

/// ngx_control_api_enabled
pub static CONTROL_API_ENABLED: AtomicBool = AtomicBool::new(false);

/// ngx_control_request_t
#[derive(Default)]
struct Request {
    fd: i32,
    state: u8,

    /// r->path: in the buffer from path_start, or the "/" of an empty path
    path_start: usize,
    path_len: usize,
    path_root: bool,
    method: u32,

    /// r->in: the request line read so far, and b->pos of the parser
    input: Vec<u8>,
    pos: usize,
    /// r->out: the response, and what of it is sent
    out: Vec<u8>,
    sent: usize,

    reloaded: bool,
}

impl Request {
    fn path(&self) -> &[u8] {
        if self.path_root {
            return b"/";
        }

        &self.input[self.path_start..self.path_start + self.path_len]
    }
}

/// struct pollfd
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// The state of ngx_control.c: ngx_control_requests[] and
/// ngx_control_pollfd[] (the listening socket first), the path of a unix
/// socket, ngx_control_inherited and ngx_control_env.
#[derive(Default)]
struct Control {
    requests: Vec<Request>,
    pollfd: Vec<PollFd>,
    unix_path: Vec<u8>,
    inherited: bool,
    env: Option<Vec<u8>>,
}

/// fcntl(F_SETFL, O_ASYNC|O_NONBLOCK): SIGIO once the socket is readable,
/// and nonblocking calls.
fn set_async(fd: i32) -> Result<(), i32> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let f = crate::fd::get(fd).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?;
    fcntl(&f, FcntlArg::F_SETFL(OFlag::O_ASYNC | OFlag::O_NONBLOCK)).map(drop).map_err(|e| e as i32)
}

/// poll() of the descriptors with a zero timeout: the number of those
/// ready, their revents set (POLLNVAL for a descriptor which is not open).
fn poll_now(pollfd: &mut [PollFd]) -> Result<usize, i32> {
    use rustix::event::{PollFd as RPollFd, PollFlags};

    let handles: Vec<Option<crate::fd::Fd>> = pollfd.iter().map(|p| crate::fd::get(p.fd).ok()).collect();

    let mut fds: Vec<RPollFd<'_>> = Vec::with_capacity(pollfd.len());
    let mut index = Vec::with_capacity(pollfd.len());

    for (i, h) in handles.iter().enumerate() {
        pollfd[i].revents = 0;

        match h {
            Some(h) => {
                fds.push(RPollFd::new(h, PollFlags::from_bits_retain(pollfd[i].events as u16)));
                index.push(i);
            }
            None => pollfd[i].revents = libc::POLLNVAL,
        }
    }

    let invalid = pollfd.len() - fds.len();
    let zero = rustix::time::Timespec { tv_sec: 0, tv_nsec: 0 };

    let n = if fds.is_empty() { 0 } else { rustix::event::poll(&mut fds, Some(&zero)).map_err(|e| e.raw_os_error())? };

    for (f, &i) in fds.iter().zip(index.iter()) {
        pollfd[i].revents = f.revents().bits() as i16;
    }

    Ok(n + invalid)
}

thread_local! {
    static CONTROL: RefCell<Control> = RefCell::new(Control::default());
}

fn with<T>(f: impl FnOnce(&mut Control) -> T) -> T {
    CONTROL.with(|c| f(&mut c.borrow_mut()))
}

/// ngx_control_preinit: the variable is read before ngx_init_cycle(), which
/// may replace the environment while parsing configuration
pub fn preinit() {
    use std::os::unix::ffi::OsStringExt;

    let env = std::env::var_os(NGX_CTRL_ENV).map(|v| v.into_vec());

    with(|c| c.env = env);
}

/// ngx_control_init: the listening socket of "-l addr", or the one the old
/// binary handed off
pub fn init(addr: Option<&[u8]>, log: &Log) -> Result<(), ()> {
    let addr = match addr {
        Some(a) => a,
        None => return Ok(()),
    };

    let mut u = crate::inet::Url::new(addr);
    u.listen = true;

    if crate::inet::parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            ngx_log_error!(NGX_LOG_EMERG, log, None, "control: {} in \"{}\"", err, B(&u.url));
        }

        return Err(());
    }

    if u.family == libc::AF_UNIX {
        with(|c| c.unix_path = u.host.clone());
    } else if u.no_port || u.last_port != 0 {
        ngx_log_error!(NGX_LOG_EMERG, log, None, "control: invalid port in \"{}\"", B(&u.url));
        return Err(());
    }

    if inherit(log).is_ok() {
        with(|c| c.inherited = true);
        return Ok(());
    }

    let sa = match u.sockaddr.clone().or_else(|| u.addrs.first().map(|a| a.sockaddr.clone())) {
        Some(sa) => sa,
        None => return Err(()),
    };

    // not close-on-exec: a new binary inherits it (ngx_control_handoff)
    let fd = match rustix::net::socket(rustix::net::AddressFamily::from_raw(u.family as u16), rustix::net::SocketType::STREAM, None) {
        Ok(s) => crate::fd::register(s),
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "control: socket() failed");
            return Err(());
        }
    };

    let fail = |msg: &str, err: i32| {
        ngx_log_error!(NGX_LOG_EMERG, log, Some(err), "control: {}", msg);
        os::close(fd);
        Err(())
    };

    if let Err(e) = set_async(fd) {
        return fail("fcntl(O_ASYNC|O_NONBLOCK) failed", e);
    }

    if let Err(e) = crate::process::set_owner(fd, os::getpid()) {
        return fail("fcntl(F_SETOWN) failed", e);
    }

    let reuseaddr = crate::fd::get(fd).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF)).and_then(|s| rustix::net::sockopt::set_socket_reuseaddr(&s, true).map_err(|e| e.raw_os_error()));

    if let Err(e) = reuseaddr {
        return fail("setsockopt(SO_REUSEADDR) failed", e);
    }

    if let Err(e) = nix::sys::socket::bind(fd, sa.to_nix().as_dyn()) {
        return fail("bind() failed", e as i32);
    }

    if u.family == libc::AF_UNIX {
        if let Err(e) = os::chmod(&u.host, libc::S_IRUSR | libc::S_IWUSR) {
            return fail("chmod() failed", e);
        }
    }

    let listened = crate::fd::get(fd).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF)).and_then(|s| rustix::net::listen(&s, crate::listening::NGX_LISTEN_BACKLOG).map_err(|e| e.raw_os_error()));

    if let Err(e) = listened {
        return fail("listen() failed", e);
    }

    with(|c| {
        c.pollfd = vec![PollFd { fd, events: libc::POLLIN, revents: 0 }];
        c.requests = vec![Request::default()];
    });

    Ok(())
}

/// ngx_control_uninit: the sockets closed, and the file of a unix socket
/// removed but by the master handing it off to a new binary, or the new
/// binary its old master still runs
pub fn uninit(log: &Log) {
    close_sockets();

    let (path, inherited) = with(|c| (c.unix_path.clone(), c.inherited));

    if !path.is_empty() && crate::process::NEW_BINARY.load(Ordering::Relaxed) == 0 && (!inherited || os::getppid() != crate::process::parent_pid()) {
        if let Err(e) = std::fs::remove_file(os::path(&path)) {
            ngx_log_error!(NGX_LOG_EMERG, log, e.raw_os_error(), "unlink() {} failed", B(&path));
        }
    }
}

/// ngx_control_close_sockets
pub fn close_sockets() {
    with(|c| {
        for p in c.pollfd.iter() {
            os::close(p.fd);
        }
    });
}

/// ngx_control_handoff: "NGINX_CTRL=fd" of the listening socket for a new
/// binary
pub fn handoff() -> Option<Vec<u8>> {
    with(|c| c.pollfd.first().map(|p| format!("{}={}", NGX_CTRL_ENV, p.fd).into_bytes()))
}

/// ngx_control_reown: SIGIO of the listening socket to this process again,
/// once the new binary it was handed to exited
pub fn reown(log: &Log) {
    let fd = match with(|c| c.pollfd.first().map(|p| p.fd)) {
        Some(fd) => fd,
        None => return,
    };

    if let Err(e) = crate::process::set_owner(fd, os::getpid()) {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "control: fcntl(F_SETOWN) failed");
    }
}

/// ngx_control_handle_events: the sockets polled once SIGIO came, and each
/// ready one handled. NGX_DONE when a request reloaded the configuration:
/// the cycle is the new one then.
pub fn handle_events(cycle: &mut Rc<Cycle>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "control: handle events");

    match with(|c| poll_now(&mut c.pollfd)) {
        Ok(0) => return NGX_OK,
        Ok(_) => {}
        Err(e) if e == libc::EINTR => return NGX_OK,
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, cycle.log, Some(e), "control: poll() failed");
            return NGX_ERROR;
        }
    }

    let mut reloaded = false;

    let mut i = 0;

    while i < with(|c| c.pollfd.len()) {
        let (fd, events, revents) = with(|c| {
            let p = &c.pollfd[i];
            (p.fd, p.events, p.revents)
        });

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "control: i:{} fd:{} e:{} re:{}", i, fd, events, revents);

        if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 && i != 0 {
            close(i);
            continue;
        }

        if revents & libc::POLLIN != 0 {
            if i == 0 {
                handle_accept(&cycle.log);
                i += 1;
                continue;
            }

            let rc = handle_read(i, cycle);

            reloaded |= with(|c| c.requests[i].reloaded);

            if rc != NGX_AGAIN {
                close(i);
                continue;
            }
        }

        if revents & libc::POLLOUT != 0 && handle_write(i, &cycle.log) != NGX_AGAIN {
            close(i);
            continue;
        }

        i += 1;
    }

    if reloaded {
        NGX_DONE
    } else {
        NGX_OK
    }
}

/// ngx_control_inherit: the listening socket of the old binary
fn inherit(log: &Log) -> Result<(), ()> {
    let env = match with(|c| c.env.clone()) {
        Some(e) => e,
        None => return Err(()),
    };

    let fd = match crate::string::atoi(&env) {
        Some(fd) => fd as i32,
        None => {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "control: invalid {} value \"{}\"", NGX_CTRL_ENV, B(&env));
            return Err(());
        }
    };

    // the descriptor the old binary passed, taken into the table; not
    // close-on-exec, as it is passed on to a next binary
    let fd = crate::process::adopt_inherited(fd);
    if let Ok(f) = crate::fd::get(fd) {
        let _ = nix::fcntl::fcntl(&f, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()));
    }

    if let Err(e) = crate::process::set_owner(fd, os::getpid()) {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "control: fcntl(F_SETOWN) failed");
        os::close(fd);
        return Err(());
    }

    with(|c| {
        c.pollfd = vec![PollFd { fd, events: libc::POLLIN, revents: 0 }];
        c.requests = vec![Request::default()];
    });

    Ok(())
}

/// ngx_control_close: the connection closed, those after it moved down
fn close(i: usize) {
    with(|c| {
        os::close(c.requests[i].fd);

        c.requests.remove(i);
        c.pollfd.remove(i);
    });
}

/// ngx_control_handle_accept: the connections of the accept queue, the
/// oldest one closed for each over the limit
fn handle_accept(log: &Log) {
    let lfd = with(|c| c.pollfd[0].fd);

    loop {
        let accepted = crate::fd::get(lfd).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF)).and_then(|l| rustix::net::accept(&l).map_err(|e| e.raw_os_error()));

        let fd = match accepted {
            Ok(s) => crate::fd::register(s),
            Err(err) => {
                if err == libc::EAGAIN {
                    return;
                }

                ngx_log_error!(NGX_LOG_ERR, log, Some(err), "control: accept() failed");

                if err == libc::ECONNABORTED {
                    continue;
                }

                return;
            }
        };

        if with(|c| c.pollfd.len()) == NGX_CTRL_MAX_FD {
            ngx_log_error!(NGX_LOG_WARN, log, None, "control: too many client connections");

            // close the oldest connection
            close(1);
        }

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "control accept fd:{}", fd);

        let failed = if os::set_cloexec(fd).is_err() {
            Some("control: fcntl(FD_CLOEXEC) failed")
        } else if set_async(fd).is_err() {
            Some("control: fcntl(O_ASYNC|O_NONBLOCK) failed")
        } else if crate::process::set_owner(fd, os::getpid()).is_err() {
            Some("control: fcntl(F_SETOWN) failed")
        } else {
            None
        };

        if let Some(msg) = failed {
            ngx_log_error!(NGX_LOG_ERR, log, None, "{}", msg);
            os::close(fd);
            continue;
        }

        with(|c| {
            // read in this pass of the events already
            c.pollfd.push(PollFd { fd, events: libc::POLLIN, revents: libc::POLLIN });
            c.requests.push(Request { fd, input: Vec::with_capacity(NGX_CTRL_MAX_REQUEST), ..Default::default() });
        });
    }
}

/// ngx_control_handle_read: what came of the request line, and the
/// response once it is all there
fn handle_read(i: usize, cycle: &mut Rc<Cycle>) -> i64 {
    let fd = with(|c| c.requests[i].fd);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, cycle.log, "control: read fd:{}", fd);

    let full = with(|c| c.requests[i].input.len() == NGX_CTRL_MAX_REQUEST);

    if full {
        ngx_log_error!(NGX_LOG_ERR, cycle.log, None, "control: request too large");
        return NGX_ERROR;
    }

    let n = with(|c| {
        let b = &mut c.requests[i].input;
        let last = b.len();

        b.resize(NGX_CTRL_MAX_REQUEST, 0);

        let n = crate::fd::get(fd)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))
            .and_then(|s| rustix::net::recv(&s, &mut b[last..], rustix::net::RecvFlags::empty()).map(|(n, _)| n).map_err(|e| e.raw_os_error()));

        b.truncate(last + *n.as_ref().unwrap_or(&0));

        n
    });

    let n = match n {
        Ok(n) => n,
        Err(err) => {
            if err == libc::EAGAIN {
                return NGX_AGAIN;
            }

            ngx_log_error!(NGX_LOG_ERR, cycle.log, Some(err), "control: recv() failed");
            return NGX_ERROR;
        }
    };

    if n == 0 {
        return NGX_DONE;
    }

    let rc = with(|c| parse_request_line(&mut c.requests[i]));

    if rc != NGX_AGAIN {
        with(|c| c.pollfd[i].events &= !libc::POLLIN);
    }

    match rc {
        NGX_AGAIN => NGX_AGAIN,

        NGX_DECLINED => {
            ngx_log_error!(NGX_LOG_ERR, cycle.log, None, "control: failed to parse request");
            send_response(i, NGX_CTRL_BAD_REQUEST, None, &cycle.log)
        }

        NGX_DONE => content(i, cycle),

        _ => NGX_ERROR,
    }
}

/// ngx_control_content: the response of the endpoint
fn content(i: usize, cycle: &mut Rc<Cycle>) -> i64 {
    const ROOT_ENDPOINTS: &[&str] = &["1"];
    const API_ENDPOINTS: &[&str] = &["control", "nginx"];
    const CONTROL_ENDPOINTS: &[&str] = &["processes", "config"];

    let (path, method) = with(|c| {
        let r = &mut c.requests[i];

        if r.path_len > 1 && r.path().last() == Some(&b'/') {
            r.path_len -= 1;
        }

        (r.path().to_vec(), r.method)
    });

    let log = cycle.log.clone();

    // the path always starts with "/"

    let not_allowed = || send_response(i, NGX_CTRL_NOT_ALLOWED, None, &log);

    match path.as_slice() {
        [_] => {
            if method != NGX_CTRL_GET {
                return not_allowed();
            }

            api_endpoints(i, method, ROOT_ENDPOINTS, &log)
        }

        b"/1" => {
            if method != NGX_CTRL_GET {
                return not_allowed();
            }

            api_endpoints(i, method, API_ENDPOINTS, &log)
        }

        b"/1/nginx" => {
            if method != NGX_CTRL_GET {
                return not_allowed();
            }

            show_version(i, &log)
        }

        b"/1/control" => {
            if method != NGX_CTRL_GET {
                return not_allowed();
            }

            api_endpoints(i, method, CONTROL_ENDPOINTS, &log)
        }

        b"/1/control/config" => {
            if method == NGX_CTRL_PATCH {
                return reload_config(i, cycle);
            }

            if method == NGX_CTRL_GET {
                return print_config(i, cycle);
            }

            not_allowed()
        }

        b"/1/control/processes" => {
            if method != NGX_CTRL_GET {
                return not_allowed();
            }

            show_processes(i, &log)
        }

        _ => send_response(i, NGX_CTRL_NOT_FOUND, None, &log),
    }
}

/// ngx_control_status_text
fn status_text(code: u32) -> &'static str {
    match code {
        NGX_CTRL_OK => "OK",
        NGX_CTRL_BAD_REQUEST => "Bad Request",
        NGX_CTRL_NOT_FOUND => "Not Found",
        NGX_CTRL_NOT_ALLOWED => "Not Allowed",
        NGX_CTRL_UNPROCESSABLE => "Unprocessable Entity",
        NGX_CTRL_INTERNAL_ERROR => "Internal Server Error",
        _ => "",
    }
}

/// ngx_control_send_response: the header, the body, and as much of them
/// sent as the socket takes
fn send_response(i: usize, code: u32, body: Option<Vec<u8>>, log: &Log) -> i64 {
    let n = body.as_ref().map_or(0, |b| b.len());

    let mut out = format!(
        "HTTP/1.1 {:03} {}\r\nServer: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        code,
        status_text(code),
        crate::NGINX_VER,
        n
    )
    .into_bytes();

    if let Some(b) = body {
        out.extend_from_slice(&b);
    }

    with(|c| {
        let r = &mut c.requests[i];
        r.out = out;
        r.sent = 0;
    });

    handle_write(i, log)
}

/// ngx_control_handle_write: NGX_DONE when all is sent, NGX_AGAIN with
/// POLLOUT waited for
fn handle_write(i: usize, log: &Log) -> i64 {
    loop {
        let (fd, rest) = with(|c| {
            let r = &c.requests[i];
            (r.fd, r.out.len() - r.sent)
        });

        if rest == 0 {
            return NGX_DONE;
        }

        let sent = with(|c| {
            let r = &c.requests[i];

            crate::fd::get(fd)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))
                .and_then(|s| rustix::net::send(&s, &r.out[r.sent..r.sent + rest], rustix::net::SendFlags::empty()).map_err(|e| e.raw_os_error()))
        });

        let n = match sent {
            Ok(n) if n > 0 => n,
            Ok(_) => {
                ngx_log_error!(NGX_LOG_ERR, log, Some(os::errno()), "control: send() failed");
                return NGX_ERROR;
            }
            Err(err) => {
                if err == libc::EAGAIN {
                    with(|c| c.pollfd[i].events |= libc::POLLOUT);
                    return NGX_AGAIN;
                }

                ngx_log_error!(NGX_LOG_ERR, log, Some(err), "control: send() failed");
                return NGX_ERROR;
            }
        };

        with(|c| c.requests[i].sent += n as usize);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "control: wrote {} bytes", n);
    }
}

/// ngx_control_send_json
fn send_json(i: usize, code: u32, obj: &DataItem, log: &Log) -> i64 {
    let b = crate::json::render(obj);

    send_response(i, code, Some(b), log)
}

/// ngx_control_api_endpoints: the list of the endpoints below
fn api_endpoints(i: usize, method: u32, paths: &[&str], log: &Log) -> i64 {
    if method != NGX_CTRL_GET {
        return send_response(i, NGX_CTRL_NOT_ALLOWED, None, log);
    }

    let mut json = DataItem::new_list();

    for p in paths {
        json.add_item(None, DataItem::string(p.as_bytes()));
    }

    send_json(i, NGX_CTRL_OK, &json, log)
}

/// ngx_control_show_processes: the processes of ngx_processes[] but those
/// reaped
fn show_processes(i: usize, log: &Log) -> i64 {
    let mut process_list = DataItem::new_list();

    crate::process::PROCESSES.with(|p| {
        for pr in p.borrow().iter() {
            if pr.pid == -1 {
                continue;
            }

            let mut obj = DataItem::new_object();

            obj.add_item(Some(b"name"), DataItem::string(pr.name.as_bytes()));
            obj.add_item(Some(b"pid"), DataItem::Integer(pr.pid as i64));
            obj.add_item(Some(b"exiting"), DataItem::Boolean(pr.exiting));

            process_list.add_item(None, obj);
        }
    });

    send_json(i, NGX_CTRL_OK, &process_list, log)
}

/// ngx_control_show_version: the version and NGX_BUILD
fn show_version(i: usize, log: &Log) -> i64 {
    let mut resp = DataItem::new_object();

    resp.add_item(Some(b"version"), DataItem::string(crate::NGINX_VERSION.as_bytes()));
    resp.add_item(Some(b"build"), DataItem::string(b""));

    send_json(i, NGX_CTRL_OK, &resp, log)
}

/// ngx_control_print_config: the configuration files as the cycle read
/// them
fn print_config(i: usize, cycle: &Rc<Cycle>) -> i64 {
    let mut list = DataItem::new_list();

    for d in cycle.config_dump.iter() {
        let mut obj = DataItem::new_object();

        obj.add_item(Some(b"name"), DataItem::string(&d.name));
        obj.add_item(Some(b"content"), DataItem::string(&d.data));

        list.add_item(None, obj);
    }

    send_json(i, NGX_CTRL_OK, &list, &cycle.log)
}

/// ngx_control_json_logs
fn json_logs(logs: &[Vec<u8>]) -> DataItem {
    let mut obj = DataItem::new_object();
    let mut log_list = DataItem::new_list();

    for l in logs {
        log_list.add_item(None, DataItem::string(l));
    }

    obj.add_item(Some(b"logs"), log_list);

    obj
}

/// ngx_control_reload_config: ngx_init_cycle() with the messages up to
/// "warn" of it captured for the response (a log of its own ahead of those
/// of the cycle)
fn reload_config(i: usize, cycle: &mut Rc<Cycle>) -> i64 {
    let mut status = NGX_CTRL_OK;

    let store: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));

    // ngx_control_log_capture
    let capture = {
        let store = store.clone();

        LogEntry::new(
            NGX_LOG_DEBUG,
            LogWriter::Custom(Rc::new(move |lvl, buf: &[u8]| {
                if lvl > NGX_LOG_WARN {
                    return;
                }

                store.borrow_mut().push(buf.to_vec());
            })),
        )
    };

    let tmp = cycle.log.chain();

    let chain = LogChain::new();

    {
        let mut entries = chain.entries.borrow_mut();

        entries.push(capture);
        entries.extend(tmp.entries.borrow().iter().cloned());
    }

    cycle.log.set_chain(chain);

    let new = init_cycle(cycle.clone(), &crate::connection::init_hooks());

    cycle.log.set_chain(tmp);

    match new {
        Err(()) => status = NGX_CTRL_UNPROCESSABLE,

        Ok(c) => {
            *cycle = c;
            set_cycle(cycle.clone());
            with(|c| c.requests[i].reloaded = true);
        }
    }

    let obj = json_logs(&store.borrow());

    send_json(i, status, &obj, &cycle.log)
}

/// ngx_control_parse_request_line: NGX_DONE with the method and the path,
/// NGX_AGAIN for more, NGX_DECLINED for an invalid one
fn parse_request_line(r: &mut Request) -> i64 {
    static USUAL: [u32; 8] = [
        0x00000000, // 0000 0000 0000 0000  0000 0000 0000 0000
        //             ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!
        0x7fff37d6, // 0111 1111 1111 1111  0011 0111 1101 0110
        //             _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@
        0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
        //              ~}| {zyx wvut srqp  onml kjih gfed cba`
        0x7fffffff, // 0111 1111 1111 1111  1111 1111 1111 1111
        0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
        0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
        0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
        0xffffffff, // 1111 1111 1111 1111  1111 1111 1111 1111
    ];

    const SW_START: u8 = 0;
    const SW_METHOD: u8 = 1;
    const SW_SPACES_BEFORE_URI: u8 = 2;
    const SW_SCHEMA: u8 = 3;
    const SW_SCHEMA_SLASH: u8 = 4;
    const SW_SCHEMA_SLASH_SLASH: u8 = 5;
    const SW_HOST_START: u8 = 7;
    const SW_HOST: u8 = 8;
    const SW_HOST_END: u8 = 9;
    const SW_HOST_IP_LITERAL: u8 = 10;
    const SW_PORT_START: u8 = 11;
    const SW_PORT: u8 = 12;
    const SW_URI: u8 = 13;
    const SW_HTTP_: u8 = 14;
    const SW_HTTP_H: u8 = 15;
    const SW_HTTP_HT: u8 = 16;
    const SW_HTTP_HTT: u8 = 17;
    const SW_HTTP_HTTP: u8 = 18;
    const SW_FIRST_MAJOR_DIGIT: u8 = 19;
    const SW_MAJOR_DIGIT: u8 = 20;
    const SW_FIRST_MINOR_DIGIT: u8 = 21;
    const SW_MINOR_DIGIT: u8 = 22;
    const SW_ALMOST_DONE: u8 = 23;

    let mut state = r.state;
    let mut p = r.pos;

    while p < r.input.len() {
        let ch = r.input[p];

        // the host states fall through into each other
        let mut s = state;

        loop {
            match s {
                // HTTP methods: GET, PATCH
                SW_START => {
                    if !ch.is_ascii_uppercase() && ch != b'_' && ch != b'-' {
                        return NGX_DECLINED;
                    }

                    state = SW_METHOD;
                }

                SW_METHOD => {
                    if ch == b' ' {
                        state = SW_SPACES_BEFORE_URI;

                        match &r.input[..p] {
                            b"GET" => r.method = NGX_CTRL_GET,
                            b"PATCH" => r.method = NGX_CTRL_PATCH,
                            _ => {}
                        }

                        break;
                    }

                    if !ch.is_ascii_uppercase() && ch != b'_' && ch != b'-' {
                        return NGX_DECLINED;
                    }
                }

                // space* before URI
                SW_SPACES_BEFORE_URI => {
                    if ch == b'/' {
                        r.path_start = p;
                        state = SW_URI;
                        break;
                    }

                    if (ch | 0x20).is_ascii_lowercase() {
                        state = SW_SCHEMA;
                        break;
                    }

                    if ch != b' ' {
                        return NGX_DECLINED;
                    }
                }

                SW_SCHEMA => {
                    if (ch | 0x20).is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'+' || ch == b'-' || ch == b'.' {
                        break;
                    }

                    if ch != b':' {
                        return NGX_DECLINED;
                    }

                    state = SW_SCHEMA_SLASH;
                }

                SW_SCHEMA_SLASH => {
                    if ch != b'/' {
                        return NGX_DECLINED;
                    }

                    state = SW_SCHEMA_SLASH_SLASH;
                }

                SW_SCHEMA_SLASH_SLASH => {
                    if ch != b'/' {
                        return NGX_DECLINED;
                    }

                    state = SW_HOST_START;
                }

                SW_HOST_START => {
                    if ch == b'[' {
                        state = SW_HOST_IP_LITERAL;
                        break;
                    }

                    state = SW_HOST;
                    s = SW_HOST;
                    continue;
                }

                SW_HOST => {
                    if (ch | 0x20).is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'.' || ch == b'-' {
                        break;
                    }

                    s = SW_HOST_END;
                    continue;
                }

                SW_HOST_END => {
                    if ch == b':' {
                        state = SW_PORT_START;
                        break;
                    }

                    // if we supported CONNECT verb we would need to decline
                    // here

                    match ch {
                        b'/' => {
                            r.path_start = p;
                            state = SW_URI;
                        }

                        // empty path cases
                        b'?' => {
                            r.path_root = true;
                            r.path_len = 1;
                            state = SW_URI;
                        }

                        b' ' => {
                            r.path_root = true;
                            r.path_len = 1;
                            state = SW_HTTP_;
                        }

                        _ => {}
                    }
                }

                SW_HOST_IP_LITERAL => {
                    if ch.is_ascii_digit() || (ch | 0x20).is_ascii_lowercase() {
                        break;
                    }

                    match ch {
                        b':' => {}
                        b']' => state = SW_HOST_END,
                        // unreserved
                        b'-' | b'.' | b'_' | b'~' => {}
                        // sub-delims
                        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
                        _ => return NGX_DECLINED,
                    }
                }

                SW_PORT_START => {
                    state = SW_PORT;

                    if ch.is_ascii_digit() {
                        break;
                    }

                    // if we supported CONNECT verb we would need to decline
                    // here

                    s = SW_PORT;
                    continue;
                }

                SW_PORT => {
                    if ch.is_ascii_digit() {
                        break;
                    }

                    match ch {
                        b'/' => {
                            r.path_start = p;
                            state = SW_URI;
                        }

                        // empty path cases
                        b'?' => {
                            r.path_root = true;
                            r.path_len = 1;
                            state = SW_URI;
                        }

                        b' ' => {
                            r.path_root = true;
                            r.path_len = 1;
                            state = SW_HTTP_;
                        }

                        _ => return NGX_DECLINED,
                    }
                }

                // URI
                SW_URI => {
                    if USUAL[(ch >> 5) as usize] & (1u32 << (ch & 0x1f)) != 0 {
                        break;
                    }

                    match ch {
                        b' ' | b'?' => {
                            if ch == b' ' {
                                state = SW_HTTP_;
                            }

                            if r.path_len == 0 {
                                r.path_len = p - r.path_start;
                            }
                        }

                        b'.' | b'%' | b'#' | b'+' | 0x7f => return NGX_DECLINED,

                        _ => {
                            if ch < 0x20 {
                                return NGX_DECLINED;
                            }
                        }
                    }
                }

                // space+ after URI
                SW_HTTP_ => match ch {
                    b' ' => {}
                    b'H' => state = SW_HTTP_H,
                    _ => return NGX_DECLINED,
                },

                SW_HTTP_H | SW_HTTP_HT | SW_HTTP_HTT | SW_HTTP_HTTP => {
                    let (want, next) = match s {
                        SW_HTTP_H => (b'T', SW_HTTP_HT),
                        SW_HTTP_HT => (b'T', SW_HTTP_HTT),
                        SW_HTTP_HTT => (b'P', SW_HTTP_HTTP),
                        _ => (b'/', SW_FIRST_MAJOR_DIGIT),
                    };

                    if ch != want {
                        return NGX_DECLINED;
                    }

                    state = next;
                }

                // first digit of major HTTP version
                SW_FIRST_MAJOR_DIGIT => {
                    if ch != b'1' {
                        return NGX_DECLINED;
                    }

                    state = SW_MAJOR_DIGIT;
                }

                // major HTTP version or dot
                SW_MAJOR_DIGIT => {
                    if ch != b'.' {
                        // major versions other than 1 are not supported
                        return NGX_DECLINED;
                    }

                    state = SW_FIRST_MINOR_DIGIT;
                }

                // first digit of minor HTTP version
                SW_FIRST_MINOR_DIGIT => {
                    if ch != b'0' && ch != b'1' {
                        return NGX_DECLINED;
                    }

                    state = SW_MINOR_DIGIT;
                }

                // minor HTTP version or end of request line
                SW_MINOR_DIGIT => {
                    if ch == b'\r' {
                        state = SW_ALMOST_DONE;
                    } else if ch == b'\n' {
                        return done(r, p);
                    } else {
                        // support only 1.1 or 1.0
                        return NGX_DECLINED;
                    }
                }

                // end of request line
                _ => {
                    if ch != b'\n' {
                        return NGX_DECLINED;
                    }

                    return done(r, p);
                }
            }

            break;
        }

        p += 1;
    }

    r.pos = p;
    r.state = state;

    NGX_AGAIN
}

fn done(r: &mut Request, p: usize) -> i64 {
    r.pos = p + 1;
    r.state = 0;

    NGX_DONE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// poll() of the control sockets: revents of the ready ones, POLLNVAL
    /// for a descriptor not open, and the count of both
    #[test]
    fn poll_descriptors() {
        use std::os::fd::OwnedFd;

        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (a, b) = (crate::fd::register(OwnedFd::from(a)), crate::fd::register(OwnedFd::from(b)));

        let mut p = vec![PollFd { fd: b, events: libc::POLLIN, revents: 0 }, PollFd { fd: 1 << 20, events: libc::POLLIN, revents: 0 }];

        assert_eq!(poll_now(&mut p), Ok(1));
        assert_eq!((p[0].revents, p[1].revents), (0, libc::POLLNVAL));

        os::write_fd(a, b"x").unwrap();
        p[0].events |= libc::POLLOUT;

        assert_eq!(poll_now(&mut p), Ok(2));
        assert_eq!(p[0].revents, libc::POLLIN | libc::POLLOUT);

        os::close(a);
        os::close(b);
    }

    /// (rc, method, path) of a request line given in pieces
    fn parse(pieces: &[&[u8]]) -> (i64, u32, Vec<u8>) {
        let mut r = Request::default();
        let mut rc = NGX_AGAIN;

        for piece in pieces {
            r.input.extend_from_slice(piece);
            rc = parse_request_line(&mut r);

            if rc != NGX_AGAIN {
                break;
            }
        }

        let path = if rc == NGX_DONE { r.path().to_vec() } else { Vec::new() };

        (rc, r.method, path)
    }

    fn ok(line: &str) -> (u32, String) {
        let (rc, method, path) = parse(&[line.as_bytes()]);
        assert_eq!(rc, NGX_DONE, "{:?}", line);
        (method, String::from_utf8(path).unwrap())
    }

    fn declined(line: &str) {
        let (rc, _, _) = parse(&[line.as_bytes()]);
        assert_eq!(rc, NGX_DECLINED, "{:?}", line);
    }

    #[test]
    fn test_parse_request_line() {
        assert_eq!(ok("GET /1/nginx HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("PATCH /1/control/config HTTP/1.1\n"), (NGX_CTRL_PATCH, "/1/control/config".into()));
        assert_eq!(ok("POST /1 HTTP/1.0\r\n"), (0, "/1".into()));
        assert_eq!(ok("X_Y /1/nginx HTTP/1.0\r\n"), (0, "/1/nginx".into()));
        assert_eq!(ok("GET /?arg=val HTTP/1.0\r\n"), (NGX_CTRL_GET, "/".into()));
        assert_eq!(ok("GET   /1/nginx  HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("GET http://localhost/1/nginx HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("GET http://localhost HTTP/1.0\r\n"), (NGX_CTRL_GET, "/".into()));
        assert_eq!(ok("GET http://localhost?a=b HTTP/1.0\r\n"), (NGX_CTRL_GET, "/".into()));
        assert_eq!(ok("GET http://localhost:8080 HTTP/1.0\r\n"), (NGX_CTRL_GET, "/".into()));
        assert_eq!(ok("GET http://localhost:8080?a=b HTTP/1.0\r\n"), (NGX_CTRL_GET, "/".into()));
        assert_eq!(ok("GET http://[::1]:8080/1/nginx HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("GET http://[::1-label]/1/nginx HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("GET http://[::1!sub]/1/nginx HTTP/1.0\r\n"), (NGX_CTRL_GET, "/1/nginx".into()));
        assert_eq!(ok("GET /1/\u{430}\u{431} HTTP/1.0\r\n").1, "/1/\u{430}\u{431}");
    }

    #[test]
    fn test_parse_request_line_split() {
        let (rc, method, path) = parse(&[b"GET /1/ng", b"inx HTTP/1.0\r", b"\n"]);

        assert_eq!((rc, method, path), (NGX_DONE, NGX_CTRL_GET, b"/1/nginx".to_vec()));

        let (rc, _, _) = parse(&[b"GET /1"]);
        assert_eq!(rc, NGX_AGAIN);
    }

    #[test]
    fn test_parse_request_line_invalid() {
        for line in [
            "foo /1/ HTTP/1.0\r\n",
            "GET /1/nginx HTTP/1.2\r\n",
            "GET /1/nginx HTTP/1.10\r\n",
            "GET /1/nginx HTTP/2.0\r\n",
            "GET /1/nginx HTTP/11.0\r\n",
            "GET /1/nginx\r\n",
            "GET http:/localhost/1/nginx HTTP/1.0\r\n",
            "GET http:x/localhost/1/nginx HTTP/1.0\r\n",
            "GET http_x://localhost/1/nginx HTTP/1.0\r\n",
            "GET 1/nginx HTTP/1.0\r\n",
            "GET http://localhost:abc/1/nginx HTTP/1.0\r\n",
            "GET /1/ngi%78 HTTP/1.0\r\n",
            "GET /1/nginx# HTTP/1.0\r\n",
            "GET /1/../x HTTP/1.0\r\n",
            "GET /1/nginx HTTP/1.0\rX\r\n",
            " /1/nginx HTTP/1.0\r\n",
            "   \r\n",
            "GET /1/nginx XTTP/1.0\r\n",
            "GET /1/nginx HTTP:1.0\r\n",
            "GET http://[bad@char]/1/nginx HTTP/1.0\r\n",
            "GET /1/ngi\u{0}x HTTP/1.0\r\n",
            "GE\u{0}T /1/nginx HTTP/1.0\r\n",
            "\r\n",
        ] {
            declined(line);
        }
    }
}
