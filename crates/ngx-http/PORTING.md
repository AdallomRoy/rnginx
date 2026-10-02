# Porting an nginx HTTP module to ngx-http

Read `/home/ubuntu/rnginx/CONVENTIONS.md` first. Then study these files (in this order):
`src/lib.rs` (module def, filter chains, conf helpers), `src/request.rs` (Request, HeadersIn/Out,
TableElt), `src/core.rs` (CoreLocConf/CoreSrvConf/CoreMainConf, phases, add_phase_handler),
`src/core_rt.rs` (send_header, output_filter, map_uri_to_path, internal_redirect, subrequest lives in
request_rt.rs), `src/index.rs` (a content handler with confs), `src/headers_filter.rs` (a header
filter), `src/chunked_filter.rs` (a body filter), `src/variables.rs` (variables), `src/script.rs`
(complex values), `src/log.rs` (log phase).

## Module skeleton
```rust
crate::http_module_index!("ngx_http_foo_module");   // gives ctx_index()
pub struct FooLocConf { pub enable: Val<bool>, ... }
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> { make_slot(FooLocConf { enable: Val::unset(), .. }) }
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<FooLocConf>(prev).borrow(); let mut c = conf_cell::<FooLocConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false); Ok(())
}
pub fn foo_module() -> ModuleDef {
    let def = HttpModuleDef { preconfiguration: Some(add_vars), postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf), merge_loc_conf: Some(merge_loc_conf), ..Default::default() };
    let commands = vec![ ngx_core::cmd!("foo", NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
                          ConfLevel::Loc, FooLocConf, enable, set_flag), ngx_core::cmd_fn!("foo_x", ..., ConfLevel::Loc, my_handler) ];
    http_module_def("ngx_http_foo_module", def, commands)
}
fn init(cf: &mut Conf) -> ConfResult {
    // or ACCESS/PREACCESS/PRECONTENT/REWRITE...; phase_handler(idle, async_fn) for an async handler
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, crate::core::phase_handler_fn(handler)); // fn(R) -> Step
    install_header_filter(|r, next| async move { ... next(r).await });          // header filter (async)
    install_body_filter(|r, chain, next| async move { ... next(r, chain).await }); // body filter (async)
    // plain filters: install_header_filter_fn(fn(R, &HeaderFilter) -> Step) and
    // install_body_filter_fn(fn(R, Chain, &BodyFilter) -> Step) return next's Step,
    // Step::boxed(async move { ... }) only where they have to wait
    Ok(())
}
```
Register the module in `src/lib.rs::modules()` at the position matching `objs/ngx_modules.c` order
(replace the placeholder in `src/stubs.rs` if one exists for it). Filter order matters: a filter
installed later runs earlier.

## Request API cheat sheet
- `r.loc_conf::<T>(ctx_index())`, `r.srv_conf::<T>(idx)`, `r.main_conf::<T>(idx)` → `Rc<RefCell<T>>` (borrow briefly).
- `r.clcf()` core loc conf. `r.method.get()`, `r.uri.borrow()`, `r.args`, `r.headers_in.borrow()`,
  `r.headers_out.borrow_mut()` (`.add(key, value)` returns `Header`; named fields like `location`
  must also be set; removing a header = `h.hash.set(0)`).
- Per-request module ctx: `r.get_ctx::<Ctx>(ctx_index())` / `r.set_ctx(ctx_index(), Ctx{..})` (`Rc<RefCell<Ctx>>`).
- Return codes are `i64` (`NGX_OK`, `NGX_DECLINED`, `NGX_DONE`, `NGX_ERROR`, or an HTTP status).
- Sending a response: set `headers_out.status/content_length_n/content_type`, `send_header(&r).await`,
  then `output_filter(&r, chain).await` with `Buf`s (`Buf::from_vec`, `last_buf = r.is_main()`).
  `send_response(&r, status, ct, &complex_value).await` does it all.
- Request body: `crate::request_body::read_client_request_body(&r).await` then
  `r.request_body.borrow()` (`in_memory` bytes or `temp_file`). `discard_request_body(&r).await`.
- Subrequests: `crate::request_rt::subrequest(&r, uri, args, flags, post).await -> Result<(R, i64),()>`;
  it runs to completion and its output already went through the filter chain.
- Variables: `crate::variables::add_variables(cf, &[VarDef{..}])` in preconfiguration; handlers
  `fn(&R, &mut VariableValue, usize) -> i64`; `get_indexed_variable`, `get_variable(r, name)`.
- Complex values: `compile_complex_value(cf, &bytes, 0)` / `complex_value(&r, &cv)`.
- Logging: `ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "...")`, `http_debug!(r, "...")`.
- Never hold a `RefCell` borrow across `.await` or across a call that may borrow the same cell
  (e.g. do NOT write `f(&r.uri.borrow())` when `f` mutates `r.uri`; clone first).
- Async handlers are `Rc<dyn Fn(R) -> BoxFut<i64>>`; async filters take `R` by value.

## Testing
`cd /home/ubuntu/rnginx/nginx-tests && TEST_NGINX_BINARY=/home/ubuntu/rnginx/target/debug/nginx prove -v foo.t`
(add `TEST_NGINX_CATLOG=1` to dump the error log, `TEST_NGINX_LEAVE=1` to keep the temp dir).
Compare against the C binary: `TEST_NGINX_BINARY=/home/ubuntu/rnginx/nginx-c/objs/nginx prove -v foo.t`.
The tests fail with "no alerts" if any `[alert]` line appears in error.log — so panics (which end up
in error.log via stderr) and alerts must be fixed, not hidden. Build the binary with `cargo build`
(the `nginx` binary in target/debug is what the tests run).
