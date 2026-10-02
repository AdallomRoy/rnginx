//! fork(), and the socket and descriptor options that nix, rustix and
//! socket2 have no setter for (TCP_DEFER_ACCEPT, TCP_FASTOPEN, TCP_INFO,
//! FIOASYNC, F_SETOWN).

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// The result of fork().
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fork {
    /// In the parent: the pid of the child.
    Parent(i32),
    /// In the child.
    Child,
}

/// The threads of the process, from /proc/self/task.
fn threads() -> io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}

/// fork(2), for a single-threaded process only (nginx's master and its
/// helpers are): it fails with EAGAIN while the process has other threads,
/// as their locks could be held in the child forever.
pub fn fork() -> io::Result<Fork> {
    if threads()? != 1 {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "fork() of a multi-threaded process"));
    }

    // SAFETY: the process has a single thread, so the child is a complete
    // copy of it, with no lock held by a thread that does not exist there.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child),
        pid => Ok(Fork::Parent(pid)),
    }
}

/// setsockopt() of an int option, for the options nix and rustix have no
/// setter for (TCP_DEFER_ACCEPT, TCP_FASTOPEN, ...).
pub fn setsockopt_int(fd: BorrowedFd<'_>, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: fd is an open descriptor for the duration of the borrow; the
    // option value is an int the kernel copies from the address given,
    // valid for the size given.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            &value as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// getsockopt() of an int option.
pub fn getsockopt_int(fd: BorrowedFd<'_>, level: i32, name: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;

    // SAFETY: fd is an open descriptor for the duration of the borrow; the
    // kernel writes at most len bytes to the address of value, and len.
    let rc = unsafe { libc::getsockopt(fd.as_raw_fd(), level, name, &mut value as *mut i32 as *mut libc::c_void, &mut len) };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(value)
}

/// The fields of struct tcp_info nginx uses ($tcpinfo_* variables).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpInfo {
    pub rtt: u32,
    pub rttvar: u32,
    pub snd_cwnd: u32,
    pub rcv_space: u32,
}

/// getsockopt(TCP_INFO).
pub fn tcp_info(fd: BorrowedFd<'_>) -> io::Result<TcpInfo> {
    // SAFETY: tcp_info is plain data, all-zero is a valid value of it.
    let mut ti: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;

    // SAFETY: fd is an open descriptor for the duration of the borrow; the
    // kernel writes at most len bytes to the address of ti, and len.
    let rc = unsafe {
        libc::getsockopt(fd.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, &mut ti as *mut libc::tcp_info as *mut libc::c_void, &mut len)
    };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(TcpInfo { rtt: ti.tcpi_rtt, rttvar: ti.tcpi_rttvar, snd_cwnd: ti.tcpi_snd_cwnd, rcv_space: ti.tcpi_rcv_space })
}

/// ioctl(FIOASYNC): signal-driven I/O on the descriptor (SIGIO to its
/// owner, see fcntl_setown()).
pub fn ioctl_fioasync(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
    let mut value: libc::c_int = on as libc::c_int;

    // SAFETY: fd is an open descriptor for the duration of the borrow;
    // FIOASYNC reads an int from the address given.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIOASYNC, &mut value as *mut libc::c_int) };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// fcntl(F_SETOWN): the process the descriptor's SIGIO and SIGURG go to.
pub fn fcntl_setown(fd: BorrowedFd<'_>, pid: i32) -> io::Result<()> {
    // SAFETY: fd is an open descriptor for the duration of the borrow;
    // F_SETOWN takes an int argument.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETOWN, pid) };

    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn int_options() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

        setsockopt_int(l.as_fd(), libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 5).unwrap();
        assert!(getsockopt_int(l.as_fd(), libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT).unwrap() > 0);

        assert!(getsockopt_int(l.as_fd(), libc::SOL_SOCKET, libc::SO_TYPE).unwrap() == libc::SOCK_STREAM);
        assert!(setsockopt_int(l.as_fd(), libc::SOL_SOCKET, -1, 1).is_err());
    }

    #[test]
    fn tcp_info_of_a_connection() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let ti = tcp_info(c.as_fd()).unwrap();
        assert!(ti.snd_cwnd > 0);
    }

    #[test]
    fn async_owner() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        ioctl_fioasync(a.as_fd(), true).unwrap();
        fcntl_setown(a.as_fd(), std::process::id() as i32).unwrap();
        ioctl_fioasync(a.as_fd(), false).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The process title (ngx_setproctitle).

/// The block of argument and environment strings that execve() copied to
/// the top of the stack, from /proc/self/stat (fields 48 to 51): the start
/// of the arguments, their end, and the end of the environment strings
/// (that of the arguments if the environment strings do not follow them).
/// /proc/self/cmdline, and so ps, shows its bytes.
fn cmdline_area() -> io::Result<(usize, usize, usize)> {
    let invalid = || io::Error::from_raw_os_error(libc::EINVAL);
    let stat = std::fs::read_to_string("/proc/self/stat")?;

    // the fields after the command name, which is in parentheses and may
    // have spaces and parentheses in it: the first of them is field 3
    let rest = &stat[stat.rfind(')').ok_or_else(invalid)? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let field = |n: usize| fields.get(n - 3).and_then(|f| f.parse::<usize>().ok()).ok_or_else(invalid);

    let (arg_start, arg_end, env_start, env_end) = (field(48)?, field(49)?, field(50)?, field(51)?);

    let end = if env_start == arg_end && env_end > env_start { env_end } else { arg_end };

    if arg_start == 0 || arg_end <= arg_start || end < arg_end {
        return Err(invalid());
    }

    Ok((arg_start, arg_end, end))
}

/// ngx_setproctitle(): the title written over the argument strings of the
/// process, and over the first `room` bytes of the environment strings
/// which follow them if it is longer, so that /proc/self/cmdline (and ps)
/// shows it: the title (cut to that size, a NUL kept), a NUL, and NULs up
/// to the end of the arguments.
///
/// The caller moves the variables of those environment strings out of
/// them first, as ngx_init_setproctitle() does (a setenv() of a variable
/// makes glibc copy it), or getenv() returns pieces of the title for them.
///
/// Fails with EAGAIN while the process has other threads, which could read
/// the strings while they are written.
pub fn setproctitle(title: &[u8], room: usize) -> io::Result<()> {
    if threads()? != 1 {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }

    let (start, arg_end, end) = cmdline_area()?;
    let limit = arg_end.saturating_add(room).min(end);
    let n = title.len().min(limit - start - 1);
    let fill = (start + n + 1).max(arg_end);

    let p = std::ptr::with_exposed_provenance_mut::<u8>(start);

    // SAFETY: [start, end) is the block of strings the kernel put on the
    // stack at execve() (/proc/self/stat), mapped read-write as long as the
    // process lives and not in any allocation of the program: nothing in it
    // is referenced by Rust. glibc and std keep only raw pointers to it
    // (argv[], environ[], program_invocation_name) and read it through them
    // without synchronization, which no other thread can do while it is
    // written (the process has one thread, checked above, and creates none
    // here). start + n < fill <= limit <= end, so the writes stay in the
    // block; the byte before `fill` is a NUL after them and the bytes from
    // `fill` on are not changed, so the C strings argv[] and environ[] point
    // to stay terminated within the block.
    unsafe {
        std::ptr::copy_nonoverlapping(title.as_ptr(), p, n);
        std::ptr::write_bytes(p.add(n), 0, fill - start - n);
    }

    Ok(())
}

/// clearenv(3): an empty environment, as ngx_set_environment() makes it
/// (std has no call for it, and unsetting the variables one by one is
/// quadratic in glibc). Fails with EAGAIN while the process has other
/// threads, which could read the environment meanwhile.
pub fn clearenv() -> io::Result<()> {
    if threads()? != 1 {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }

    // SAFETY: clearenv() takes no argument: it frees the array of environ
    // if glibc allocated it and sets environ to NULL, which no other thread
    // reads meanwhile (the process has one, checked above); std keeps no
    // reference into the environment, copying what it reads of it.
    if unsafe { libc::clearenv() } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod proctitle_tests {
    use super::*;

    #[test]
    fn area_of_the_strings() {
        let (start, arg_end, end) = cmdline_area().unwrap();
        let cmdline = std::fs::read("/proc/self/cmdline").unwrap();

        // the arguments are at the start of the area
        assert_eq!(arg_end - start, cmdline.len());
        assert!(end >= arg_end);

        // the test harness has threads: the title is refused, and so is
        // clearenv()
        if threads().unwrap() > 1 {
            assert_eq!(setproctitle(b"x", 0).unwrap_err().raw_os_error(), Some(libc::EAGAIN));
            assert_eq!(clearenv().unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        }
    }
}

// ---------------------------------------------------------------------------
// UDP datagrams with control messages (ngx_sendmsg(),
// ngx_quic_send_segments()), without the allocations of nix's sendmsg().

/// The source address of a datagram sent on a wildcard socket: the control
/// message of ngx_set_srcaddr_cmsg(), IP_PKTINFO with the address in
/// ipi_spec_dst or IPV6_PKTINFO with it in ipi6_addr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSrcAddr {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
}

/// CMSG_SPACE(n)
const fn cmsg_space(n: usize) -> usize {
    // SAFETY: CMSG_SPACE only computes a length
    unsafe { libc::CMSG_SPACE(n as libc::c_uint) as usize }
}

/// CMSG_LEN(n)
const fn cmsg_len(n: usize) -> usize {
    // SAFETY: CMSG_LEN only computes a length
    unsafe { libc::CMSG_LEN(n as libc::c_uint) as usize }
}

/// The control data of a datagram: CMSG_SPACE(sizeof(uint16_t)) for
/// UDP_SEGMENT and CMSG_SPACE(sizeof(ngx_addrinfo_t)) for the source
/// address, aligned as struct cmsghdr (whose first member is a size_t).
#[repr(C, align(8))]
struct UdpControl([u8; cmsg_space(std::mem::size_of::<u16>()) + cmsg_space(std::mem::size_of::<libc::in6_pktinfo>())]);

/// sendmsg(2) of `iov` as one UDP datagram to `dest`, or with `segment` as
/// datagrams of that size (UDP_SEGMENT: GSO), from `src` on a wildcard
/// socket. The control messages are built in a buffer on the stack, in
/// nginx's order (UDP_SEGMENT first), msg_controllen their CMSG_SPACE()s
/// (no control data without either). The bytes sent, or the error (EAGAIN
/// among them).
pub fn sendmsg_udp(fd: BorrowedFd<'_>, iov: &[io::IoSlice<'_>], dest: &std::net::SocketAddr, segment: Option<u16>, src: Option<UdpSrcAddr>) -> io::Result<usize> {
    /// The destination, as nix makes it from std's addresses.
    enum Name {
        V4(libc::sockaddr_in),
        V6(libc::sockaddr_in6),
    }

    let mut name = match dest {
        std::net::SocketAddr::V4(a) => Name::V4(libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: a.port().to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
            sin_zero: [0; 8],
        }),

        std::net::SocketAddr::V6(a) => Name::V6(libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: a.port().to_be(),
            sin6_flowinfo: a.flowinfo(),
            sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
            sin6_scope_id: a.scope_id(),
        }),
    };

    let (name_ptr, name_len) = match &mut name {
        Name::V4(sin) => (sin as *mut libc::sockaddr_in as *mut libc::c_void, std::mem::size_of::<libc::sockaddr_in>()),
        Name::V6(sin6) => (sin6 as *mut libc::sockaddr_in6 as *mut libc::c_void, std::mem::size_of::<libc::sockaddr_in6>()),
    };

    // zeroed, as nix does: the padding bytes of the messages are sent
    let mut control = UdpControl([0; std::mem::size_of::<UdpControl>()]);

    // SAFETY: msghdr is plain data, all-zero is a valid value of it
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    msg.msg_name = name_ptr;
    msg.msg_namelen = name_len as libc::socklen_t;

    // IoSlice is ABI compatible with struct iovec on Unix (std's
    // guarantee); sendmsg() only reads the array
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = iov.len();

    if segment.is_some() || src.is_some() {
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.0.len();

        let mut clen = 0usize;

        // SAFETY: msg_control is the start of `control`, a buffer of
        // msg_controllen bytes aligned as struct cmsghdr, which holds the
        // two messages at most: CMSG_FIRSTHDR() is its start and
        // CMSG_NXTHDR() the next message within it (both non-null, as
        // checked); each header and its data (CMSG_DATA(), CMSG_LEN() of
        // the data written) lie in the buffer, the data written unaligned.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);

            if let Some(segment) = segment {
                if cmsg.is_null() {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }

                (*cmsg).cmsg_level = libc::SOL_UDP;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<u16>());

                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, segment);

                clen += cmsg_space(std::mem::size_of::<u16>());

                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }

            if let Some(src) = src {
                if cmsg.is_null() {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }

                match src {
                    UdpSrcAddr::V4(addr) => {
                        (*cmsg).cmsg_level = libc::IPPROTO_IP;
                        (*cmsg).cmsg_type = libc::IP_PKTINFO;
                        (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<libc::in_pktinfo>());

                        let pkt = libc::in_pktinfo { ipi_ifindex: 0, ipi_spec_dst: libc::in_addr { s_addr: u32::from_ne_bytes(addr.octets()) }, ipi_addr: libc::in_addr { s_addr: 0 } };

                        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo, pkt);

                        clen += cmsg_space(std::mem::size_of::<libc::in_pktinfo>());
                    }

                    UdpSrcAddr::V6(addr) => {
                        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                        (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<libc::in6_pktinfo>());

                        let pkt6 = libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: addr.octets() }, ipi6_ifindex: 0 };

                        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo, pkt6);

                        clen += cmsg_space(std::mem::size_of::<libc::in6_pktinfo>());
                    }
                }
            }
        }

        msg.msg_controllen = clen;
    }

    // SAFETY: fd is an open descriptor for the duration of the borrow; msg
    // points to the destination address (name, of msg_namelen bytes), the
    // caller's slices (iov, borrowed for the call) and the control data
    // (control, msg_controllen bytes), all alive for the call, which only
    // reads them.
    let n = unsafe { libc::sendmsg(fd.as_raw_fd(), &msg, 0) };

    if n == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(n as usize)
}

#[cfg(test)]
mod udp_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::os::fd::AsFd;

    #[test]
    fn control_buffer_layout() {
        // CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(struct in6_pktinfo))
        assert_eq!(std::mem::size_of::<UdpControl>(), cmsg_space(2) + cmsg_space(20));
        assert_eq!(std::mem::align_of::<UdpControl>(), std::mem::align_of::<libc::cmsghdr>());
        assert!(cmsg_len(2) <= cmsg_space(2));
    }

    #[test]
    fn datagrams_sent() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();

        let dest = rx.local_addr().unwrap();
        let mut buf = [0u8; 2048];

        // plain, from two slices
        let n = sendmsg_udp(tx.as_fd(), &[io::IoSlice::new(b"hello "), io::IoSlice::new(b"world")], &dest, None, None).unwrap();
        assert_eq!(n, 11);
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
        assert_eq!(from.port(), tx.local_addr().unwrap().port());

        // from a source address (IP_PKTINFO on the wildcard socket)
        let n = sendmsg_udp(tx.as_fd(), &[io::IoSlice::new(b"pktinfo")], &dest, None, Some(UdpSrcAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        assert_eq!(n, 7);
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from.ip()), (&b"pktinfo"[..], std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)));

        // segments of 100 bytes (UDP GSO), with the source address: the
        // datagrams as they were cut (a kernel without GSO refuses it)
        let data: Vec<u8> = (0..250u32).map(|i| i as u8).collect();

        match sendmsg_udp(tx.as_fd(), &[io::IoSlice::new(&data)], &dest, Some(100), Some(UdpSrcAddr::V4(Ipv4Addr::LOCALHOST))) {
            Ok(n) => {
                assert_eq!(n, 250);

                for want in [&data[..100], &data[100..200], &data[200..]] {
                    let (n, _) = rx.recv_from(&mut buf).unwrap();
                    assert_eq!(&buf[..n], want);
                }
            }

            Err(e) => assert!(matches!(e.raw_os_error(), Some(libc::EIO) | Some(libc::EINVAL) | Some(libc::ENOPROTOOPT)), "{}", e),
        }

        // errors are errno
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(sendmsg_udp(closed.as_fd(), &[io::IoSlice::new(b"x")], &unreachable, None, None).is_err());
    }

    #[test]
    fn datagrams_over_ipv6() {
        let rx = match UdpSocket::bind("[::1]:0") {
            Ok(s) => s,
            Err(_) => return, // no IPv6 here
        };

        rx.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();

        let tx = UdpSocket::bind("[::]:0").unwrap();
        let dest = rx.local_addr().unwrap();

        let n = sendmsg_udp(tx.as_fd(), &[io::IoSlice::new(b"six")], &dest, None, Some(UdpSrcAddr::V6(Ipv6Addr::LOCALHOST))).unwrap();
        assert_eq!(n, 3);

        let mut buf = [0u8; 16];
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from.ip()), (&b"six"[..], std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
