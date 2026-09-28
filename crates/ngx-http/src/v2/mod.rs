//! HTTP/2 — port of `nginx-c/src/http/v2/`.
//!
//! `module` is `ngx_http_v2_module.c` (directives, configuration and the
//! `$http2` variable). The connection and stream runtime is ported next (see
//! docs/HTTP2_PLAN.md); until it lands, TLS clients are not offered `h2` via
//! ALPN and plaintext connections are served as HTTP/1.

pub mod module;

// ngx_http_v2.h
pub const NGX_HTTP_V2_STATE_BUFFER_SIZE: usize = 16;
pub const NGX_HTTP_V2_DEFAULT_FRAME_SIZE: usize = 1 << 14;
pub const NGX_HTTP_V2_MAX_FRAME_SIZE: usize = (1 << 24) - 1;
pub const NGX_HTTP_V2_MAX_WINDOW: usize = (1 << 31) - 1;
pub const NGX_HTTP_V2_DEFAULT_WINDOW: usize = 65535;
