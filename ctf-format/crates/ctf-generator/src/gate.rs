//! The determinism gate (rules G9, G10; design §8).
//!
//! Ingest runs the generator twice with the reference seed and rejects a bundle
//! whose output roots differ, so a challenge that would rot cannot be published.
//! Two runs in one process catch nondeterminism from call state; a second engine
//! catches host misconfiguration. The gate returns the first run's output, which
//! the caller compares against the derived flag.

use crate::abi::GeneratorOutput;
use crate::host::{Generator, GeneratorError, Limits};
use crate::second::{run_second_engine, second_engine_supported};

/// The result of a passing gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReport {
    /// The output root every run agreed on (spec §23.4).
    pub output_root: [u8; 32],
    /// The first run's decoded output.
    pub outputs: GeneratorOutput,
    /// How many in-process runs agreed.
    pub runs: usize,
    /// Whether the second engine was available for, and passed, the cross-check.
    ///
    /// `false` means the module uses a feature `wasmi` does not implement (SIMD), so
    /// only one engine ran. That is reported rather than hidden: a caller that
    /// requires two-engine agreement must treat it as not satisfied.
    pub cross_engine: bool,
}

/// Run the gate: `runs` in-process runs on Wasmtime, then a `wasmi` cross-check.
///
/// `runs` below 2 is raised to 2, because a gate of one run checks nothing. A
/// module `wasmi` cannot load is not cross-checked; see [`GateReport::cross_engine`].
pub fn determinism_gate(
    wasm: &[u8],
    seed: &[u8],
    limits: &Limits,
    runs: usize,
) -> Result<GateReport, GeneratorError> {
    let runs = runs.max(2);
    let generator = Generator::new(wasm)?;
    let results = generator.run_repeated(seed, limits, runs)?;
    let first = results
        .first()
        .ok_or(GeneratorError::GuestReturnedFailure)?;
    let root = first.output_root();
    for (i, r) in results.iter().enumerate().skip(1) {
        if r.output_root() != root {
            return Err(GeneratorError::Nondeterministic { run: i });
        }
    }

    let cross_engine = second_engine_supported(wasm);
    if cross_engine {
        let second = run_second_engine(wasm, seed, limits)?;
        if second.output_root() != root {
            return Err(GeneratorError::EngineDisagreement);
        }
    }

    Ok(GateReport {
        output_root: root,
        outputs: first.clone(),
        runs,
        cross_engine,
    })
}
