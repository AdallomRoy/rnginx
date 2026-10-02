//! Raw OpenSSL declarations: none of the OpenSSL layer uses them anymore
//! (the openssl crate and ngx_sys::ssl do). RAND_bytes() is left for the
//! QUIC files converted on other branches (quic/connid.rs, migration.rs,
//! output.rs, http v3/module.rs use openssl::rand::rand_bytes there); this
//! file goes when they are merged.

#![allow(non_snake_case)]

use std::os::raw::c_int;

extern "C" {
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
}
