# Memory safety in rnginx

The crates of the port — ngx-core, ngx-http, ngx-stream, ngx-mail and the
nginx binary — are `#![forbid(unsafe_code)]`: the compiler rejects any
`unsafe` block, function, impl or extern in them, tests and macro expansions
included. The only crate with `unsafe` is `crates/ngx-sys`: the few system
and OpenSSL calls no safe crate provides, each behind a safe function.

## What replaced the unsafe code

- System calls: std, `nix`, `rustix` and `socket2`. They want borrowed
  descriptors (`AsFd`), and nginx passes descriptors around as numbers:
  `ngx_core::fd` is the process's table of owned descriptors (`OwnedFd`) by
  number. Whatever opens a descriptor registers it, `fd::get(n)` lends it,
  `fd::close(n)` closes it (reporting close() errors as nginx does);
  `fd::adopt(n)` and `fd::duplicate(n)` take descriptors inherited across
  exec() (binary upgrade) or not owned by the process (the reactor's epoll
  instance) through pidfd_getfd(). A number the table does not have is
  EBADF. The common calls are wrapped in `ngx_core::os`, which also sets
  errno on failure as libc does.
- Shared memory: `ngx_core::shmem`. A zone is a `ShmMem`, a MAP_SHARED
  anonymous mapping owned by vm-memory's `MmapRegion` (unmapped when the
  last user drops it), accessed as atomic words, because the other
  processes write it concurrently. What C keeps as pointers in a zone are
  byte offsets from its start (0 for NULL). `shm_struct!` declares the
  structures with C's layout (so allocation sizes, hence zone capacities,
  are C's) and `Field<T>` accessors; the slab allocator (ngx_slab.c), the
  red-black tree (ngx_rbtree.c, generic over node storage: `ShmRbtree` in
  zones, `LocalRbtree` in process memory) and queues (ngx_queue.h) work on
  offsets. Sub-word fields and byte strings are written by
  read-modify-write of their words, under the zone's mutex as in C.
- OpenSSL: the safe API of the `openssl` crate (contexts, SSL objects,
  sessions, certificates, OCSP, symmetric ciphers and HKDF for QUIC), plus
  `ngx_sys::ssl` for what it lacks (below).
- Signals: `signal-hook` (the handlers set flags and record the sender's
  pid); fork(): `ngx_sys::os::fork`, which refuses in a multi-threaded
  process.
- libGeoIP (was dlopen()ed): a pure Rust port of what nginx uses of
  libGeoIP 1.6.12 (`ngx_core::geoip`), tables included.
- zlib (was libz-sys with custom allocators): `flate2` on the system zlib.
- crypt_r(): Rust ports of libxcrypt 4.4.27's formats (`ngx_core::crypt`,
  with pwhash and blowfish).
- localtime_r()/mktime()/strftime(): `ngx_core::libc_time`, glibc 2.35's in
  the C locale, with glibc's time zone handling (localtime_r() reads the
  zone once; mktime() and ngx_timezone_update() read it again).
- random(): `ngx_core::random`, glibc's generator (same sequence).
- Pointer casts of type-erased data: `Rc<dyn Any>` downcasts and indexes.

## ngx-sys

Each function makes the foreign calls of one operation, with arguments its
safe signature guarantees to be valid, as its `// SAFETY:` comment explains;
no raw pointer crosses the crate's API (descriptors are `BorrowedFd`, except
`ssl::set_fd`, whose number the SSL object keeps).

`os.rs`: `fork` (single-threaded processes only), `setsockopt_int` and
`getsockopt_int` (TCP_DEFER_ACCEPT, TCP_FASTOPEN: no safe crate has them),
`tcp_info` ($tcpinfo_*), `ioctl_fioasync` and `fcntl_setown` (SIGIO of the
channels and the control API), `setproctitle` (the "nginx: master process"
titles, written over the argument strings), `clearenv`.

`ssl.rs`: what the openssl crate has no (sound) safe API for:
- SSL I/O on the socket (SSL_set_fd, SSL_read/write/peek/shutdown,
  SSL_do_handshake, early data, SSL_sendfile/kTLS), so that errno, the
  error queue and record boundaries are OpenSSL's own;
- the error queue (peeking at errors without draining them, nginx's own
  formatting), OPENSSL_init_ssl;
- BIOs and PEM/DER reading as nginx does it (file BIOs, the chain read one
  object at a time, password retries), ENGINE and OSSL_STORE keys;
- printers and getters of variables (X509_NAME_print_ex, the cipher list,
  curves, signature algorithms, groups), digests of names and public keys,
  issuer lookup, X509_check_host, CRLs in stores;
- context settings on byte strings or on built contexts (cipher and curve
  lists, timeouts, options, chains, SSL_CONF for ssl_conf_command);
- the callbacks the crate lacks or restricts (info, cert, session ticket
  key, get-session, msg (QUIC compat), servername and client hello alerts,
  verify copied onto an SSL at SNI), behind `extern "C"` trampolines;
- SSL state setters (quiet shutdown, shutdown flags, session time/timeout,
  host name as bytes, session reuse on clients, handshake buffer size).

## Rules for new code

- Use std, nix, rustix, socket2, the openssl crate's safe API; open
  descriptors with APIs returning `OwnedFd` and register them.
- Keep data in zones with `shm_struct!` and offsets.
- If something really needs `unsafe`, add the smallest function to
  ngx-sys, taking safe types, with a `// SAFETY:` comment proving it sound
  from its arguments.

## Differences from C introduced by the conversion

- flate2 has no memLevel parameter (it uses 8): gzip output bytes differ
  from C's where nginx picks another memLevel (gzip_hash other than 64k,
  short responses of known length, access_log gzip buffers under ~16k);
  the decompressed content is the same. zlib allocates its own memory, so
  the "gzip alloc" debug lines and the preallocation alert are gone.
- SIGSYS gets a do-nothing handler instead of SIG_IGN (no safe way to set
  SIG_IGN); a batch of different signals is logged in signal number order.
- Each worker keeps an owned duplicate of the reactor's epoll descriptor
  (EPOLLEXCLUSIVE listening sockets): one descriptor more per worker.
- The environment of a new binary (binary upgrade) is passed sorted by
  name (std's Command).
- The GeoIP database file is close-on-exec; reading a corrupt database
  gives zeros where C reads past the end of its buffer.
