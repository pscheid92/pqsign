//! pqsign is a command-line tool for hybrid post-quantum file signing with Ed25519 and ML-DSA-65.
//!
//! This library only exists so the `pqsign` binary, its tests and its benchmarks can share code. It is not
//! a stable API: anything in it may change in any release. Use the [`pqsign`
//! command](https://github.com/pscheid92/pqsign#readme) instead.

#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod commands;
#[doc(hidden)]
pub mod domain;
#[doc(hidden)]
pub mod errors;
#[doc(hidden)]
pub mod format;
#[doc(hidden)]
pub mod password;
