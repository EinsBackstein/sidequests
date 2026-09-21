//! The determinism gate (rules G9, G10; design §8).
//!
//! Ingest runs the generator twice with the reference seed and rejects a bundle
//! whose output roots differ, so a challenge that would rot cannot be published.
//! Two runs in one process catch nondeterminism from call state; a second engine
//! catches host misconfiguration. The gate returns the first run's output, which
//! the caller compares against the derived flag.

use crate::abi::{ArtifactBlock, GeneratorOutput};
use crate::host::{Generator, GeneratorError, Limits};
use crate::second::{run_second_engine, second_engine_supported};
use crate::solver::Solver;

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

/// The tri-state outcome of the offline solvability gate (design §3 pillar 5,
/// ticket 28).
///
/// `Unverified` is a real state, not a failure: a `runtime`-bearing bundle needs a
/// booted instance to be solved, which the orchestrator project provides (design
/// §2). Recording such a bundle as `unverified` is honest; recording it as `passed`
/// would be worse than no gate at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// The solver recovered the derived flag from the generated artifacts.
    Passed,
    /// The solver ran but its flag did not match the derived flag.
    Failed,
    /// The gate could not be run — a live instance is required, or the bundle has
    /// no generator and no solver to run.
    Unverified,
}

impl core::fmt::Display for GateStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unverified => "unverified",
        })
    }
}

/// What the offline gate needs to run (ticket 28).
#[derive(Debug, Clone, Copy)]
pub struct OfflineGate<'a> {
    /// The generator module (`gen.wasm`), when the challenge has one.
    pub generator: Option<&'a [u8]>,
    /// The solver module (`solver.wasm`), when the challenge has one.
    pub solver: Option<&'a [u8]>,
    /// The reference subject's seed.
    pub seed: &'a [u8],
    /// The derived flag for the reference subject (spec §22.3).
    pub expected_flag: &'a str,
    /// Whether the manifest declares `runtime`, which needs a live instance.
    pub runtime_declared: bool,
    /// Whether `verify.offline` declares the offline gate (spec §7.6).
    ///
    /// When it is false or absent, the gate does not run and the bundle is
    /// `unverified`: a bundle that did not ask to be gated is not passed silently.
    pub offline_declared: bool,
}

/// The offline gate's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGateReport {
    /// The tri-state outcome.
    pub status: GateStatus,
    /// The generator output root, when the generator ran.
    pub generator_root: Option<[u8; 32]>,
    /// The flag the solver produced, when the solver ran.
    pub solver_flag: Option<String>,
    /// The flag the solver was expected to produce.
    pub expected_flag: Option<String>,
}

/// Run the offline solvability gate (spec §25, design §3 pillar 5).
///
/// Runs the generator at the reference seed under the determinism gate, feeds the
/// resulting artifact block to the solver in the same sandbox, and compares the
/// solver's flag to `expected_flag`. A `runtime`-bearing bundle, or one missing
/// either module, is [`GateStatus::Unverified`] rather than `passed`.
pub fn offline_gate(
    input: OfflineGate<'_>,
    limits: &Limits,
) -> Result<OfflineGateReport, GeneratorError> {
    if input.runtime_declared {
        return Ok(OfflineGateReport {
            status: GateStatus::Unverified,
            generator_root: None,
            solver_flag: None,
            expected_flag: None,
        });
    }
    if !input.offline_declared {
        return Ok(OfflineGateReport {
            status: GateStatus::Unverified,
            generator_root: None,
            solver_flag: None,
            expected_flag: None,
        });
    }
    let (Some(generator_wasm), Some(solver_wasm)) = (input.generator, input.solver) else {
        return Ok(OfflineGateReport {
            status: GateStatus::Unverified,
            generator_root: None,
            solver_flag: None,
            expected_flag: None,
        });
    };

    let gate = determinism_gate(generator_wasm, input.seed, limits, 2)?;
    let artifacts = ArtifactBlock::from_generator(&gate.outputs);
    let solver = Solver::new(solver_wasm)?;
    let flag = solver.run(&artifacts.encode(), limits)?;
    let status = if flag == input.expected_flag {
        GateStatus::Passed
    } else {
        GateStatus::Failed
    };
    Ok(OfflineGateReport {
        status,
        generator_root: Some(gate.output_root),
        solver_flag: Some(flag),
        expected_flag: Some(input.expected_flag.to_owned()),
    })
}
