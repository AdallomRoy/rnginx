// I/O-model A/B for an HTTP/1.1 "return 200" server, nginx-shaped:
// worker processes (fork), one per CPU, single-threaded, SO_REUSEPORT listeners.
//
//   epoll      edge-triggered epoll, recv once (a short read means drained), send
//   uring      io_uring, multishot recv from a provided-buffer ring, send SQEs,
//              SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN, one enter per loop
//   uring-arc  io_uring as Arc does it: recv SQE into a per-connection buffer,
//              send SQE, re-arm recv when the send completes; default setup flags
//   tokio-*    the same server inside a tokio current-thread runtime (tok.rs)
//
// Knobs (environment): NBUF (provided buffers, uring), FLAGS=default|modern,
// RECV=multi|select|select-lazy (uring) or eager (uring-arc), SYNCSEND=1
// (uring-arc, tokio-ring), DEFER=1 and SPIN=1 (tokio-*).
//
// usage: uring-proto MODE PORT CPU[,CPU...]   (bench/uring-proto/README.md)

mod tok;

use io_uring::{cqueue, opcode, types, IoUring};
use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU16, Ordering};

const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: nginx/1.31.7\r\nDate: Fri, 09 Oct 2026 14:19:14 GMT\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\nhello world\n";
const MAX_PIPE: usize = 32;

fn listener(port: u16) -> RawFd {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        let one: libc::c_int = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &one as *const _ as *const _, 4);
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32) < 0 {
            panic!("bind: {}", std::io::Error::last_os_error());
        }
        if libc::listen(fd, 4096) < 0 {
            panic!("listen: {}", std::io::Error::last_os_error());
        }
        fd
    }
}

fn set_nodelay(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &one as *const _ as *const _, 4) };
}

/// Complete requests in `buf` and the bytes they span.
fn count_requests(buf: &[u8]) -> (usize, usize) {
    let (mut n, mut i, mut used) = (0, 0, 0);
    while i + 4 <= buf.len() {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            n += 1;
            i += 4;
            used = i;
        } else {
            i += 1;
        }
    }
    (n, used)
}

/// Feeds received bytes through the connection's partial-request buffer; returns the
/// number of complete requests.
fn feed(pending: &mut Vec<u8>, data: &[u8]) -> usize {
    if pending.is_empty() {
        let (n, used) = count_requests(data);
        if used < data.len() {
            pending.extend_from_slice(&data[used..]);
        }
        n
    } else {
        pending.extend_from_slice(data);
        let (n, used) = count_requests(pending);
        pending.drain(..used);
        n
    }
}

fn pipe_resp() -> &'static [u8] {
    let mut v = Vec::with_capacity(RESP.len() * MAX_PIPE);
    for _ in 0..MAX_PIPE {
        v.extend_from_slice(RESP);
    }
    Box::leak(v.into_boxed_slice())
}

fn run_epoll(lfd: RawFd) {
    let resps = pipe_resp();
    unsafe {
        let ep = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: lfd as u64 };
        libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, lfd, &mut ev);
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 512];
        let mut buf = [0u8; 1024];
        let mut pending: Vec<Vec<u8>> = vec![Vec::new(); 1 << 16];
        loop {
            let n = libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, -1);
            for i in 0..n.max(0) as usize {
                let fd = events[i].u64 as RawFd;
                if fd == lfd {
                    loop {
                        let c = libc::accept4(lfd, ptr::null_mut(), ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC);
                        if c < 0 {
                            break;
                        }
                        set_nodelay(c);
                        let mut ev = libc::epoll_event {
                            events: (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32,
                            u64: c as u64,
                        };
                        libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, c, &mut ev);
                    }
                    continue;
                }
                loop {
                    let r = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
                    if r <= 0 {
                        if r == 0 || *libc::__errno_location() != libc::EAGAIN {
                            pending[fd as usize].clear();
                            libc::close(fd);
                        }
                        break;
                    }
                    let r = r as usize;
                    let reqs = feed(&mut pending[fd as usize], &buf[..r]).min(MAX_PIPE);
                    if reqs > 0 {
                        let len = reqs * RESP.len();
                        let s = libc::send(fd, resps.as_ptr() as *const _, len, 0);
                        if s != len as isize {
                            eprintln!("short send {s}");
                        }
                    }
                    if r < buf.len() {
                        break; // a short read means the socket is drained, as nginx assumes
                    }
                }
            }
        }
    }
}

const OP_ACCEPT: u64 = 1;
const OP_RECV: u64 = 2;
const OP_SEND: u64 = 3;

fn ud(op: u64, fd: RawFd) -> u64 {
    (op << 32) | (fd as u32 as u64)
}

fn nbuf() -> u16 { std::env::var("NBUF").ok().and_then(|v| v.parse().ok()).unwrap_or(4096) }
const BSZ: usize = 2048;

struct BufRing {
    ring: *mut u8,
    bufs: Vec<u8>,
    tail: u16,
    mask: u16,
}

impl BufRing {
    fn new(sub: &io_uring::Submitter<'_>) -> BufRing {
        let n = nbuf();
        let ring_bytes = n as usize * 16;
        let ring = unsafe {
            libc::mmap(ptr::null_mut(), ring_bytes, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        } as *mut u8;
        let mut br = BufRing { ring, bufs: vec![0u8; n as usize * BSZ], tail: 0, mask: n - 1 };
        unsafe { sub.register_buf_ring_with_flags(ring as u64, n, 0, 0).expect("register_buf_ring") };
        for bid in 0..n {
            br.add(bid);
        }
        br.publish();
        br
    }

    fn add(&mut self, bid: u16) {
        let idx = (self.tail & self.mask) as usize;
        unsafe {
            let e = self.ring.add(idx * 16);
            ptr::write_unaligned(e as *mut u64, self.bufs.as_ptr().add(bid as usize * BSZ) as u64);
            ptr::write_unaligned(e.add(8) as *mut u32, BSZ as u32);
            ptr::write_unaligned(e.add(12) as *mut u16, bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&self) {
        unsafe { (*(self.ring.add(14) as *const AtomicU16)).store(self.tail, Ordering::Release) };
    }

    fn data(&self, bid: u16, len: usize) -> &[u8] {
        &self.bufs[bid as usize * BSZ..bid as usize * BSZ + len]
    }
}

fn run_uring(lfd: RawFd) {
    let resps = pipe_resp();
    let modern = std::env::var("FLAGS").map(|v| v != "default").unwrap_or(true);
    let recv_mode = std::env::var("RECV").unwrap_or_else(|_| "multi".into());
    let multi = recv_mode == "multi";
    let lazy = recv_mode == "select-lazy";
    let mut b = IoUring::builder();
    if modern {
        b.setup_single_issuer().setup_defer_taskrun().setup_coop_taskrun().setup_submit_all();
    }
    let mut ring: IoUring = b.build(4096).expect("io_uring");
    let recv_op = move |fd: RawFd| {
        if multi {
            opcode::RecvMulti::new(types::Fd(fd), 0).build().user_data(ud(OP_RECV, fd))
        } else {
            opcode::Recv::new(types::Fd(fd), ptr::null_mut(), BSZ as u32).buf_group(0).build()
                .flags(io_uring::squeue::Flags::BUFFER_SELECT).user_data(ud(OP_RECV, fd))
        }
    };
    let mut br = BufRing::new(&ring.submitter());
    let mut pending: Vec<Vec<u8>> = vec![Vec::new(); 1 << 16];
    let accept = opcode::AcceptMulti::new(types::Fd(lfd)).flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC).build().user_data(ud(OP_ACCEPT, lfd));
    unsafe { ring.submission().push(&accept).unwrap() };
    loop {
        ring.submit_and_wait(1).expect("enter");
        let (_sub, mut sq, mut cq) = ring.split();
        cq.sync();
        let mut recycled = false;
        for cqe in &mut cq {
            let op = cqe.user_data() >> 32;
            let fd = cqe.user_data() as u32 as RawFd;
            let res = cqe.result();
            let fl = cqe.flags();
            match op {
                OP_ACCEPT => {
                    if res >= 0 {
                        set_nodelay(res);
                        unsafe { sq.push(&recv_op(res)).unwrap() };
                    }
                    if !cqueue::more(fl) {
                        unsafe { sq.push(&accept).unwrap() };
                    }
                }
                OP_RECV => {
                    if res > 0 {
                        let bid = cqueue::buffer_select(fl).expect("bid");
                        let reqs = feed(&mut pending[fd as usize], br.data(bid, res as usize)).min(MAX_PIPE);
                        br.add(bid);
                        recycled = true;
                        if reqs > 0 {
                            let s = opcode::Send::new(types::Fd(fd), resps.as_ptr(), (reqs * RESP.len()) as u32)
                                .build()
                                .user_data(ud(OP_SEND, fd));
                            unsafe { sq.push(&s).unwrap() };
                        }
                        if !cqueue::more(fl) && !(lazy && reqs > 0) {
                            unsafe { sq.push(&recv_op(fd)).unwrap() };
                        }
                    } else if res == -libc::ENOBUFS {
                        unsafe { sq.push(&recv_op(fd)).unwrap() };
                    } else if !cqueue::more(fl) {
                        pending[fd as usize].clear();
                        unsafe { libc::close(fd) };
                    }
                }
                OP_SEND => {
                    if lazy && res >= 0 {
                        unsafe { sq.push(&recv_op(fd)).unwrap() };
                    }
                }
                _ => {}
            }
        }
        if recycled {
            br.publish();
        }
        cq.sync();
        sq.sync();
    }
}

fn run_uring_arc(lfd: RawFd) {
    let resps = pipe_resp();
    let mut b = IoUring::builder();
    if std::env::var("FLAGS").map(|v| v == "modern").unwrap_or(false) {
        b.setup_single_issuer().setup_defer_taskrun().setup_coop_taskrun().setup_submit_all();
    }
    let mut ring: IoUring = b.build(4096).expect("io_uring");
    let eager = std::env::var("RECV").map(|v| v == "eager").unwrap_or(false);
    let syncsend = std::env::var("SYNCSEND").is_ok();
    let mut bufs: Vec<Vec<u8>> = (0..1 << 16).map(|_| Vec::new()).collect();
    let mut pending: Vec<Vec<u8>> = vec![Vec::new(); 1 << 16];
    let accept = opcode::AcceptMulti::new(types::Fd(lfd)).flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC).build().user_data(ud(OP_ACCEPT, lfd));
    unsafe { ring.submission().push(&accept).unwrap() };
    loop {
        ring.submit_and_wait(1).expect("enter");
        let (_sub, mut sq, mut cq) = ring.split();
        cq.sync();
        for cqe in &mut cq {
            let op = cqe.user_data() >> 32;
            let fd = cqe.user_data() as u32 as RawFd;
            let res = cqe.result();
            let fl = cqe.flags();
            match op {
                OP_ACCEPT => {
                    if res >= 0 {
                        set_nodelay(res);
                        let b = &mut bufs[res as usize];
                        if b.is_empty() {
                            b.resize(BSZ, 0);
                        }
                        let r = opcode::Recv::new(types::Fd(res), b.as_mut_ptr(), BSZ as u32).build().user_data(ud(OP_RECV, res));
                        unsafe { sq.push(&r).unwrap() };
                    }
                    if !cqueue::more(fl) {
                        unsafe { sq.push(&accept).unwrap() };
                    }
                }
                OP_RECV => {
                    if res > 0 {
                        let reqs = feed(&mut pending[fd as usize], &bufs[fd as usize][..res as usize]).min(MAX_PIPE);
                        if reqs > 0 && syncsend {
                            let len = reqs * RESP.len();
                            let n = unsafe { libc::send(fd, resps.as_ptr() as *const _, len, libc::MSG_NOSIGNAL) };
                            if n != len as isize {
                                eprintln!("short send {n}");
                            }
                            let b = &mut bufs[fd as usize];
                            let r = opcode::Recv::new(types::Fd(fd), b.as_mut_ptr(), BSZ as u32).build().user_data(ud(OP_RECV, fd));
                            unsafe { sq.push(&r).unwrap() };
                        } else if reqs > 0 {
                            let s = opcode::Send::new(types::Fd(fd), resps.as_ptr(), (reqs * RESP.len()) as u32)
                                .build()
                                .user_data(ud(OP_SEND, fd));
                            unsafe { sq.push(&s).unwrap() };
                            if eager {
                                let b = &mut bufs[fd as usize];
                                let r = opcode::Recv::new(types::Fd(fd), b.as_mut_ptr(), BSZ as u32).build().user_data(ud(OP_RECV, fd));
                                unsafe { sq.push(&r).unwrap() };
                            }
                        } else {
                            let b = &mut bufs[fd as usize];
                            let r = opcode::Recv::new(types::Fd(fd), b.as_mut_ptr(), BSZ as u32).build().user_data(ud(OP_RECV, fd));
                            unsafe { sq.push(&r).unwrap() };
                        }
                    } else {
                        pending[fd as usize].clear();
                        unsafe { libc::close(fd) };
                    }
                }
                OP_SEND => {
                    if res >= 0 && !eager {
                        let b = &mut bufs[fd as usize];
                        let r = opcode::Recv::new(types::Fd(fd), b.as_mut_ptr(), BSZ as u32).build().user_data(ud(OP_RECV, fd));
                        unsafe { sq.push(&r).unwrap() };
                    }
                }
                _ => {}
            }
        }
        cq.sync();
        sq.sync();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args[1].clone();
    let port: u16 = args[2].parse().unwrap();
    let cpus: Vec<usize> = args[3].split(',').map(|c| c.parse().unwrap()).collect();
    let mut kids = Vec::new();
    for &cpu in &cpus {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(cpu, &mut set);
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            }
            let lfd = listener(port);
            match mode.as_str() {
                "epoll" => run_epoll(lfd),
                "uring" => run_uring(lfd),
                "uring-arc" => run_uring_arc(lfd),
                "tokio-epoll" => tok::run_tokio_epoll(lfd),
                "tokio-uring" => tok::run_tokio_uring(lfd),
                "tokio-ring" => tok::run_tokio_ring(lfd),
                m => panic!("mode {m}"),
            }
            std::process::exit(0);
        }
        kids.push(pid);
    }
    println!("{}", kids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" "));
    unsafe {
        let mut st = 0;
        libc::waitpid(-1, &mut st, 0);
        for &k in &kids {
            libc::kill(k, libc::SIGKILL);
        }
    }
}
