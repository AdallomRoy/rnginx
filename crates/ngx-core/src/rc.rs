//! ngx_int_t return code conventions.

pub const NGX_OK: i64 = 0;
pub const NGX_ERROR: i64 = -1;
pub const NGX_AGAIN: i64 = -2;
pub const NGX_BUSY: i64 = -3;
pub const NGX_DONE: i64 = -4;
pub const NGX_DECLINED: i64 = -5;
pub const NGX_ABORT: i64 = -6;
