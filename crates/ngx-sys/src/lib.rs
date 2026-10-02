//! The system and library calls that no safe crate wraps.
//!
//! The other crates of the workspace are `#![forbid(unsafe_code)]`: they
//! use std, nix, rustix, socket2, openssl, ... and, for what none of them
//! provides, the functions here. Each one makes a single foreign call
//! whose arguments its safe signature guarantees to be valid, as the
//! `SAFETY` comments explain; keep it that way: no raw pointer crosses
//! this crate's API.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod os;
pub mod ssl;
