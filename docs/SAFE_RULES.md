# Converting rnginx to safe Rust — rules for the conversion agents

Read CONVENTIONS.md first (the port's style). This file replaces the porting
workflow of PORTING.md / docs/AGENT_RULES.md for this job.

## The goal
Remove every `unsafe` block, `unsafe fn`, `unsafe impl` and `unsafe extern`
from the files you own, without changing behaviour: same log messages, same
responses, same timeouts; the nginx-tests that pass today must still pass.
At the end the workspace crates (ngx-core, ngx-http, ngx-stream, ngx-mail,
nginx) get `#![forbid(unsafe_code)]`; the only crate allowed to keep
`unsafe` is `crates/ngx-sys` (see below).

Raw pointers go too: no `*mut`/`*const` in data structures, no pointer casts
to reach a type (`&*(data as *const T)` becomes an `Rc<dyn Any>` downcast or
a typed field), no `transmute`, no `from_raw_parts`, no `get_unchecked`, no
`Pin::new_unchecked` (use `Pin::new` on Unpin types).

## What to use instead (all already in the workspace Cargo.toml)
- std first (`std::fs`, `std::net`, `std::os::unix`, `std::process::Command`, ...).
- `nix` 0.29: functions that take a `RawFd` are safe (recv, send, recvmsg,
  sendmsg, bind, connect, getsockname, shutdown, fcntl, fstat, fchmod,
  fchown, futimens, read, close, dup2, ...); those taking `AsFd` need a
  borrowed descriptor (see fd.rs below). nix sockopts: `IpTransparent`,
  `Ipv4PacketInfo`, `Ipv6RecvPacketInfo`, `UdpGsoSegment`,
  `IpBindAddressNoPort`, `ReusePort`, `KeepAlive`, `TcpKeepIdle`, ... ;
  `ControlMessage`/`ControlMessageOwned` for cmsgs (PKTINFO, SCM_RIGHTS,
  UDP_SEGMENT); `User::from_name`, `Group::from_name`, `setrlimit`,
  `sched_setaffinity`, `sigprocmask`, `waitpid`, `kill`, `setsid`, `umask`,
  `nix::sys::timer::Timer`, `nix::sys::prctl`.
- `rustix` 1.x (features fs, net, process, pipe, event, time, thread, system,
  param, stdio): returns `OwnedFd` for everything that makes a descriptor
  (`fs::open`, `fs::openat`, `net::socket_with`, `net::accept_with`,
  `net::acceptfrom_with`, `net::socketpair`, `pipe::pipe_with`,
  `io::dup`, `io::fcntl_dupfd_cloexec`); sockopts in `rustix::net::sockopt`
  (`set_tcp_nodelay`, `set_tcp_cork`, `set_socket_linger`, `socket_error`,
  `socket_type`, `socket_protocol`, `socket_cookie`, `set_ip_mtu_discover`,
  `set_ipv6_mtu_discover`, buffer sizes, ...); `event::epoll`;
  `stdio::dup2_stderr`; `process::setpriority_process`; `fs::fadvise`,
  `fs::sendfile`.
- `socket2` 0.6 (`SockRef::from(&fd)`): `set_ip_transparent_v6`, keepalive
  parameters, and the rest of its option setters.
- `signal-hook` 0.3: safe signal registration (`flag::register`,
  `iterator::SignalsInfo<exfiltrator::WithOrigin>` gives the sender's pid).
- `chrono` (default-features off, `clock` + `std`): local time
  (`chrono::Local`), which honours TZ and /etc/localtime like localtime_r().
- `mmap-rs` + `zerocopy`: shared memory (only shm.rs uses them; zones get a
  safe API, see "Shared memory").
- `openssl` 0.10.81 safe API (`SslContextBuilder`, `Ssl`, `SslRef`,
  `X509`, `ocsp::*`, `symm::Crypter`, `pkey_ctx::PkeyCtx` (HKDF),
  `rand::rand_bytes`, ...). `foreign_types::ForeignType{,Ref}::as_ptr` is
  fine only inside ngx-sys.
- `flate2` (zlib backend) for deflate/inflate; `pwhash` for crypt(3).
- `ngx_core::os`: safe wrappers already there: `open`, `openat`, `close`,
  `close_fd`, `dup`, `read`, `write_fd`, `pread`, `pwrite`, `pwritev`,
  `ftruncate`, `unlink`, `mkdir`, `rmdir`, `rename`, `chmod`, `fchmod`,
  `chown`, `fchown`, `utimes`, `futimes`, `stat`, `fstat`, `lstat`,
  `set_nonblocking`, `set_blocking`, `directio_on/off`, `set_cloexec`, `kill`,
  `getpid`, `getppid`, `geteuid`, `getpwnam`, `getgrnam`, `glob`, `Dir`,
  `strerror` (glibc's text of an errno), `pagesize`, `ncpu`. Errors are errno
  values (`Result<_, i32>`).
- `ngx_core::random::random()`: glibc's random() (same sequence) for the
  `extern "C" { fn random(); }` calls (ngx_random).

## Descriptors: crates/ngx-core/src/fd.rs
The port passes descriptors around as numbers. The safe wrappers want a
borrowed descriptor, which needs an owner: `ngx_core::fd` is the process's
table of owned descriptors.
- Whatever makes a descriptor must get an `OwnedFd` (rustix / nix / std
  return one) and `fd::register(owned)` it; the number is what you store.
- `fd::get(n)` lends it: the handle implements `AsFd`, pass `&handle` to
  nix/rustix/socket2. 0, 1, 2 are lent from std.
- Close with `fd::close(n)` (or `os::close`/`os::close_fd`); never with
  `nix::unistd::close` on a registered number.
- `fd::take(n)` gives the `OwnedFd` back (to make a `File`, `UdpSocket`, ...).
- `fd::adopt(n)` takes a descriptor inherited across exec() (binary upgrade
  listening sockets) or received some way that gives only a number.
- `fd::duplicate(n)` makes an owned duplicate of a descriptor the process
  does not own (e.g. the reactor's epoll instance), leaving `n` alone.
- During the conversion `fd::get` of a number that is NOT registered
  (opened by code another agent has not converted yet) lends a duplicate
  (pidfd_getfd) so that mixed code keeps working; it will become EBADF at
  the end, so register everything you open.

## crates/ngx-sys: the only place for unsafe
For what no safe crate provides, add a small function to ngx-sys
(`src/os.rs` for system calls, `src/ssl.rs` for OpenSSL), each making one
foreign call, with a `// SAFETY:` comment proving it sound from the
arguments its safe signature takes. No raw pointer in its public API: take
`BorrowedFd`, `&[u8]`, `&SslRef`, `&mut SslContextBuilder`, `&X509Ref`, ...,
return owned crate types. Callbacks: register a Rust fn/closure (e.g. kept
in ex_data) behind an `extern "C"` trampoline inside ngx-sys. Exhaust the
safe options first (the openssl crate has many callbacks: servername,
alpn_select, client_hello, status (OCSP), new/remove session, keylog,
custom extensions, verify ...); say in your report why each ngx-sys
function is needed. Already there: `os::fork`, `os::setsockopt_int`,
`os::getsockopt_int`, `os::tcp_info`, `os::ioctl_fioasync`,
`os::fcntl_setown`.

## Shared memory
Zones will get a safe API (offsets into an atomic word array instead of
pointers; slab allocator, rbtree and queue working on offsets). It is being
written on the `safe` branch; the agents converting shm users get it when
it lands. Others: don't touch shm.rs, slab.rs, rbtree.rs, queue.rs,
shmtx.rs, rwlock.rs.

## File ownership
Edit only your files. If you really need a change in a file you don't own
(a new function, a signature), keep it minimal, additive, and list it in
your report. Never delete or rename a function others may still call
(e.g. `SockAddr::to_libc`): leave it, the last user removes it at merge
time. Do not reformat files.

## Behaviour
Same messages, same order of system calls where nginx's logs or tests can
see it, same errno in messages. When a safe crate cannot do exactly what the
C does, say so in the report. Do not "improve" behaviour.

## Build and test
- Your worktree is your cwd: `cargo build 2>&1 | grep -E '^(error|warning: unused)' -A5`
  (debug profile; release only if you need speed for many test runs).
- Unit tests: `cargo test -p <crate> --lib <module>`; keep the existing
  tests, convert their unsafe too.
- nginx-tests (not in git):
  `cd /home/ubuntu/rnginx/nginx-tests && TEST_NGINX_BINARY=$WT/target/debug/nginx prove foo.t bar.t`
  Isolate your temp dirs: `mkdir -p /tmp/$NAME && env TMPDIR=/tmp/$NAME ...`.
  `TEST_NGINX_LEAVE=1` keeps the test dir with its error.log.
- Baseline (before the conversion, release build): 455 files pass; the 15
  failing are the mail_*.t files (the mail module is not ported). The list
  of passing files is /home/ubuntu/rnginx-unsafe-work/base-pass.txt.
- Run the tests touching your code as you go; at the end run the whole
  suite once with `-j4` and compare with the baseline:
  `cd /home/ubuntu/rnginx/nginx-tests && env TMPDIR=/tmp/$NAME TEST_NGINX_BINARY=$WT/target/debug/nginx prove -j4 --exec 'timeout 120 perl' . > /tmp/$NAME/suite.txt 2>&1`
  then `grep -a '\.t \.\+ ok' /tmp/$NAME/suite.txt | sed -E 's/^\[[^]]*\] \.\///; s/ \.+ ok.*//' | sort | comm -13 - /home/ubuntu/rnginx-unsafe-work/base-pass.txt`
  lists what regressed. Some tests are timing-sensitive under load (re-run a
  failure alone before chasing it).
- Several agents share the 8 cores: never run more than one full suite at a
  time, use `-j4`.

## Commits and report
Commit on your branch as you go (`git add <files>`; descriptive message).
The branch must build at the end. Your final report: (1) the files you
converted and the `unsafe` count left in each (should be 0:
`rg -c '\bunsafe\b' <files>`, comments aside), (2) every ngx-sys function you
added and why no safe crate could do it, (3) behaviour differences, if any,
and why, (4) the test results (which files you ran, and the suite run),
(5) changes to files you don't own.
