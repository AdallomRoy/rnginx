//! The system and library calls that no safe crate wraps.
//!
//! The other crates of the workspace are `#![forbid(unsafe_code)]`: they
//! use std, nix, rustix, socket2, openssl, ... and, for what none of them
//! provides, the functions here. Each one makes the foreign calls of one
//! operation with arguments its safe signature guarantees to be valid, as
//! its `SAFETY` comment explains; keep it that way: no raw pointer crosses
//! this crate's API (see docs/SAFETY.md).

#![deny(unsafe_op_in_unsafe_fn)]

pub mod os;
pub mod ssl;
