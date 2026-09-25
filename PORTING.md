# PORTING.md — workflow for porting agents

Read CONVENTIONS.md first. This file explains how work is organised.

## Ground rules
1. Port the C faithfully (`nginx-c/src/...`). Same directive names/flags, same defaults, same
   error/log messages (tests grep error.log), same response bytes and header order.
2. Work only on the files you were assigned plus the minimal registration hooks:
   - `crates/ngx-http/src/lib.rs`: add `pub mod <name>;` and one line in `modules()` at the
     position matching `nginx-c/objs/ngx_modules.c` order. Remove the corresponding stub from
     `crates/ngx-http/src/stubs.rs` if there is one.
   - Do NOT reformat, reorder or "clean up" files you do not own. Keep diffs minimal so
     parallel branches merge cleanly.
   - If you need a change in core (`ngx-core`, `core.rs`, `request*.rs`, `variables.rs`,
     filters), keep it small and additive (new fields/functions), never rename or remove
     existing APIs. Describe every core change in your final report.
3. `cargo build --release` must succeed with no errors before you commit. Warnings are
   tolerated but do not add new `#[allow]` blanket attributes.
4. Run the relevant nginx-tests and report the exact pass/fail numbers. Never claim a test
   passes without running it.
5. Commit your work on your branch with a descriptive message (git add the specific files).

## Build and test
```
cd <your worktree>
cargo build --release 2>&1 | tail -20
cd nginx-tests
TEST_NGINX_BINARY=<your worktree>/target/release/nginx prove -v foo.t          # one test, verbose
TEST_NGINX_BINARY=<your worktree>/target/release/nginx prove foo.t bar.t       # several
TEST_NGINX_BINARY=<your worktree>/target/release/nginx TEST_NGINX_LEAVE=1 prove foo.t   # keep temp dir
TEST_NGINX_BINARY=<your worktree>/target/release/nginx TEST_NGINX_CATLOG=1 prove -v foo.t  # dump error.log
```
Expected behaviour: run the same test against the C reference binary
`TEST_NGINX_BINARY=/home/ubuntu/rnginx/nginx-c/objs/nginx prove -v foo.t` and diff.
The temp dir is `/tmp/nginx-test-XXXX`; `error.log` there has the debug log
(tests run nginx with `error_log ... debug`).

You can also run the binary manually: write a small nginx.conf, then
`target/release/nginx -p /tmp/x -c nginx.conf -g 'daemon off; master_process off;'`.

## Where things are
- Directive tables: `Command::new(..)` / `cmd_fn!`. Handlers get `Option<Rc<dyn Any>>` = the
  module's conf slot at the directive's ConfLevel; use `conf_rc::<T>(conf.as_ref().unwrap())`.
- Module template: `crates/ngx-http/src/index.rs` (handler module),
  `crates/ngx-http/src/not_modified_filter.rs` / `chunked_filter.rs` (filter modules),
  `crates/ngx-http/src/map.rs` (variables), `crates/ngx-http/src/log.rs` (log phase).
- Phase handlers: `add_phase_handler(cf, NGX_HTTP_*_PHASE, Rc::new(|r| Box::pin(handler(r))))`.
  Handler is `async fn(R) -> i64`, returning NGX_OK/NGX_DECLINED/status codes like C.
- Filters: `install_header_filter(|r, next| async move { ... next(r).await })`,
  `install_body_filter(|r, chain, next| async move { ... })` in `postconfiguration`.
  Body data is `ngx_core::buf::Chain` (Vec of `Buf`, see `crates/ngx-core/src/buf.rs`).
- Variables: `crates/ngx-http/src/variables.rs` (`add_variable`, `get_indexed_variable`,
  `get_variable`, `VariableGetter`), complex values/scripts: `crates/ngx-http/src/script.rs`.
- Request: `crates/ngx-http/src/request.rs` (`Request`, `HeadersIn`, `HeadersOut`, `TableElt`),
  lifecycle `request_rt.rs` (`finalize_request`, `subrequest`, `internal_redirect` in `core_rt.rs`).
- Sending: `send_header(&r).await`, `output_filter(&r, chain).await` (core_rt.rs).
- Request body: `crates/ngx-http/src/request_body.rs` (`read_client_request_body`,
  `discard_request_body`).
- Connections/sockets: `crates/ngx-core/src/connection.rs` (async `recv/send/writev/sendfile`),
  `ngx_core::inet` (addresses, `parse_url`), `ngx_core::resolver`.
- Shared memory zones: `ngx_core::shm` + `ngx_core::slab` + `ngx_core::rbtree`.
- Time formats: `ngx_core::times`. Hash tables: `ngx_core::hash`. Regex: `ngx_core::regex`.
