//! The deterministic generator host (spec §23, design §8).
//!
//! A `.ctf` challenge is a pure function `challenge(seed) -> (artifacts, flag)`,
//! carried as `gen.wasm`. This crate runs that function under a sandbox that makes
//! "pure" enforceable rather than promised:
//!
//! - the module has **no imports**, so it cannot observe a clock, a network, a
//!   filesystem, host randomness, or WASI (G2);
//! - relaxed SIMD is lowered deterministically and float NaN bits are
//!   canonicalized, so codegen cannot vary the result (G5, §23.6);
//! - threads are off, and CPU limits use **fuel** rather than wall-clock
//!   interruption, so a near-limit generator cannot pass ingest and fail in
//!   production (G5);
//! - the gate runs the generator twice in one process and additionally on a second
//!   engine, and rejects a disagreement (G9, G10). The settings are validated by
//!   agreement, not trusted.
//!
//! # What this crate is not
//!
//! It does not read a bundle, select a suite, or decide whether a challenge is
//! publishable. It runs bytes and reports their output root. The ingest pipeline
//! (phase 5) is what joins this to the format.

pub mod abi;
pub mod gate;
pub mod host;
pub mod second;

pub use abi::{AbiError, GeneratorOutput, INTERFACE_VERSION, OUTPUT_LABEL, Output, WASM_PROFILE};
pub use gate::{GateReport, determinism_gate};
pub use host::{EngineKind, Generator, GeneratorError, Limits};
pub use second::second_engine_supported;
