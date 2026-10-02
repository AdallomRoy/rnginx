# rnginx — conventions for contributors (human or agent)

This is a faithful Rust port of nginx 1.31.7 (C source in `/home/ubuntu/rnginx/nginx-c/src`,
NOT part of this git repo). The goal is byte-for-byte compatible behaviour: same directives,
defaults, error messages, log formats, timeouts, response bytes. When in doubt, read the C
and port it; do not "improve" behaviour.

## Layout
- `crates/ngx-core`  : core (string utils, conf parser, log, cycle, process model, connection
                       layer on tokio AsyncFd, inet, shm/shmem, regex, syslog, ssl).
- `crates/ngx-http`  : http core + all http modules.
- `crates/ngx-stream`, `crates/ngx-mail`, `crates/nginx` (binary).
- `crates/ngx-sys`   : the only crate with `unsafe`: the few system and OpenSSL calls no safe
                       crate provides, behind safe functions (see docs/SAFETY.md).
- Tests: `/home/ubuntu/rnginx/nginx-tests` (Perl). Run one file:
  `cd /home/ubuntu/rnginx/nginx-tests && TEST_NGINX_BINARY=/home/ubuntu/rnginx/target/debug/nginx prove -v foo.t`

## Rules
- Strings are byte strings: `Vec<u8>` / `&[u8]` (nginx `ngx_str_t`). Use `crate::string::B(&bytes)`
  to Display them in format strings. Never assume UTF-8.
- Return codes: port `ngx_int_t` conventions literally as `i64`: `NGX_OK=0, NGX_ERROR=-1,
  NGX_AGAIN=-2, NGX_BUSY=-3, NGX_DONE=-4, NGX_DECLINED=-5, NGX_ABORT=-6` (see `ngx_core::rc`),
  HTTP statuses are positive values.
- Config values use `Val<T>` (`ngx_core::conf::Val`): unset = `Val::unset()`, merge with
  `.merge(&prev, default)` / `.init(default)`, read with `*v` or `v.get()`.
- Directive tables: `Command::new(name, TYPE_FLAGS, ConfLevel, handler)` or the `cmd!` /
  `cmd_fn!` macros. Handler signature: `fn(&mut Conf, &Command, Option<Rc<dyn Any>>) -> ConfResult`.
  Return `Err(msg("is duplicate"))` for `"directive" is duplicate` style messages; use
  `cf.emerg(format_args!(..))` for fully-formed messages (it appends ` in file:line`).
- Module conf structs live in slots `Rc<RefCell<T>>` stored as `Rc<dyn Any>`; use
  `conf_cell::<T>(&slot)` / `conf_rc::<T>(&slot)`.
- Logging: `ngx_log_error!(LEVEL, log, Some(errno)|None, "fmt", args)` and
  `ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "fmt", args)`. Levels in `ngx_core::log`.
  Messages must match the C text exactly (tests grep error.log).
- Time: `ngx_core::times` (cached time, http_time formatting). Sizes/times parsing: `ngx_core::parse`.
- Single-threaded per process: use `Rc`, `Cell`, `RefCell`; no `Arc`/`Mutex`. Never hold a
  `RefCell` borrow across an `.await`.
- Async I/O: `ngx_core::connection::Connection` (`recv/send/writev/sendfile` async fns, all
  cancel-safe). Timeouts via `tokio::time::timeout`.
- Shared memory: zones are `ngx_core::shm::ShmZone`; their memory is a `ngx_core::shmem::ShmMem`
  (atomic words), structures in it are declared with `shm_struct!` (C layout) and link each
  other by offsets, not pointers; slab pool, rbtree and queue in `ngx_core::shmem`.
- Descriptors are numbers owned by the process's table (`ngx_core::fd`): whatever opens one
  registers the `OwnedFd`, `fd::get(n)` lends it to nix/rustix, `fd::close(n)` closes it.
- No `unsafe`: ngx-core, ngx-http, ngx-stream, ngx-mail and nginx are `#![forbid(unsafe_code)]`.
  Use std, nix, rustix, socket2, openssl (safe API); what none of them provides goes to
  `crates/ngx-sys` as a small safe function with a `// SAFETY:` comment (docs/SAFETY.md).
- Each new file gets `#[cfg(test)] mod tests` with unit tests for the tricky paths.
- Do not add crate dependencies without need; allowed: libc, nix, rustix, socket2, tokio,
  signal-hook, openssl (openssl-sys and foreign-types in ngx-sys only), pcre2, flate2, md-5,
  sha1, crc32fast, memchr, bytes, vm-memory, mmap-rs, zerocopy, pwhash, blowfish.
