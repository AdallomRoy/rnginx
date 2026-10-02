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
