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
