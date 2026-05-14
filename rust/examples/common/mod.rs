//! Shared helpers for the example binaries.
//!
//! Cargo treats every top-level file in `examples/` as a standalone binary,
//! so consumers `mod common;` this module rather than depending on it as a
//! library. Members may go unused in any single example, hence the
//! crate-wide `dead_code` allow.

#![allow(dead_code)]

pub mod local_demo_fixture;
