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
    /// How many in-process generator runs agreed, when the generator ran (§23.8).
    pub generator_runs: Option<usize>,
    /// Whether the second engine agreed, when the generator ran (rule G10).
    pub cross_engine: Option<bool>,
    /// How many named outputs the generator produced, when it ran.
    pub artifact_count: Option<usize>,
    /// Why the gate did not run, when the status is `unverified`.
    pub unverified_reason: Option<UnverifiedReason>,
}

/// Why a gate could not run (spec §25.6).
///
/// Each variant names one of §25.6's conditions for `unverified`, so a caller can
/// report the reason rather than only the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiedReason {
    /// The challenge declares `runtime`, so solving needs a live instance (§32).
    RuntimeDeclared,
    /// `verify.offline` is false or absent, so the bundle did not ask to be gated.
    OfflineNotDeclared,
    /// The challenge declares no generator.
    NoGenerator,
    /// The challenge declares no solver.
    NoSolver,
}

impl core::fmt::Display for UnverifiedReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::RuntimeDeclared => {
                "the challenge declares a runtime, which needs a live instance (spec §32)"
            }
            Self::OfflineNotDeclared => {
                "the challenge does not declare `verify.offline`, so it did not ask to be gated"
            }
            Self::NoGenerator => "the challenge declares no generator",
            Self::NoSolver => "the challenge declares no solver",
        })
    }
}

/// The stage of the §25.5 procedure at which a hard failure occurred.
///
/// Only the two stages that can fail outright are represented. Building the
/// artifact block (step 2) cannot fail, and the flag comparison (step 4) produces
/// [`GateStatus::Failed`] rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStage {
    /// Step 1: the generator determinism gate (§23.8, rules G9 and G10).
    Determinism,
    /// Step 3: the solver ran but its sandbox or ABI failed (rules S2–S7).
    Solver,
}

impl core::fmt::Display for GateStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Determinism => "determinism",
            Self::Solver => "solver",
        })
    }
}

/// A hard gate failure, tagged with the §25.5 stage that produced it.
///
/// A flag mismatch is not an error: it is [`GateStatus::Failed`]. This type is only
/// for a stage that could not complete at all, so a caller can name the stage and
/// the reason (ticket 29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateError {
    /// The stage that failed.
    pub stage: GateStage,
    /// The underlying sandbox, ABI, or determinism failure.
    pub source: GeneratorError,
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.stage, self.source)
    }
}

impl core::error::Error for GateError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Run the offline solvability gate (spec §25, design §3 pillar 5).
///
/// Runs the generator at the reference seed under the determinism gate, feeds the
/// resulting artifact block to the solver in the same sandbox, and compares the
/// solver's flag to `expected_flag`. A `runtime`-bearing bundle, or one missing
/// either module, is [`GateStatus::Unverified`] rather than `passed`, with the
/// reason recorded.
pub fn offline_gate(
    input: OfflineGate<'_>,
    limits: &Limits,
) -> Result<OfflineGateReport, GateError> {
    let unverified = |reason: UnverifiedReason| OfflineGateReport {
        status: GateStatus::Unverified,
        generator_root: None,
        solver_flag: None,
        expected_flag: None,
        generator_runs: None,
        cross_engine: None,
        artifact_count: None,
        unverified_reason: Some(reason),
    };
    if input.runtime_declared {
        return Ok(unverified(UnverifiedReason::RuntimeDeclared));
    }
    if !input.offline_declared {
        return Ok(unverified(UnverifiedReason::OfflineNotDeclared));
    }
    let (generator_wasm, solver_wasm) = match (input.generator, input.solver) {
        (Some(generator), Some(solver)) => (generator, solver),
        (None, _) => return Ok(unverified(UnverifiedReason::NoGenerator)),
        (_, None) => return Ok(unverified(UnverifiedReason::NoSolver)),
    };

    let gate =
        determinism_gate(generator_wasm, input.seed, limits, 2).map_err(|source| GateError {
            stage: GateStage::Determinism,
            source,
        })?;
    let artifact_count = gate.outputs.outputs.len();
    let artifacts = ArtifactBlock::from_generator(&gate.outputs);
    let solver = Solver::new(solver_wasm).map_err(|source| GateError {
        stage: GateStage::Solver,
        source,
    })?;
    let flag = solver
        .run(&artifacts.encode(), limits)
        .map_err(|source| GateError {
            stage: GateStage::Solver,
            source,
        })?;
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
        generator_runs: Some(gate.runs),
        cross_engine: Some(gate.cross_engine),
        artifact_count: Some(artifact_count),
        unverified_reason: None,
    })
}

/// A persisted gate outcome for one bundle (ticket 30, spec §25.6).
///
/// The record the reference tooling writes alongside a bundle, so a platform can
/// store the tri-state without re-running the gate. It is **derived data** about a
/// run, not a container structure: it is never inside a bundle and is never covered
/// by the commitment root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRecord {
    /// The manifest `id` the gate ran for.
    pub challenge: String,
    /// The manifest `version` the gate ran for.
    pub version: u64,
    /// The reference subject the expected flag was derived for.
    pub subject: String,
    /// The tri-state outcome.
    pub status: GateStatus,
    /// A human-readable reason for a non-`passed` outcome, or the pass sentence.
    pub reason: String,
    /// The generator output root, when the generator ran.
    pub generator_root: Option<[u8; 32]>,
    /// Whether the second engine agreed, when the generator ran. `None` when the
    /// gate did not run.
    pub cross_engine: Option<bool>,
    /// How many in-process generator runs agreed, when the generator ran.
    pub runs: Option<usize>,
}

impl VerificationRecord {
    /// Build a record from a gate report.
    pub fn from_report(
        challenge: &str,
        version: u64,
        subject: &str,
        report: &OfflineGateReport,
    ) -> Self {
        let reason = match report.status {
            GateStatus::Passed => "the solver recovered the derived flag".to_owned(),
            GateStatus::Failed => {
                "the solver produced a different flag than the derived flag".to_owned()
            }
            GateStatus::Unverified => report
                .unverified_reason
                .map_or_else(|| "the gate did not run".to_owned(), |r| r.to_string()),
        };
        Self {
            challenge: challenge.to_owned(),
            version,
            subject: subject.to_owned(),
            status: report.status,
            reason,
            generator_root: report.generator_root,
            cross_engine: report.cross_engine,
            runs: report.generator_runs,
        }
    }

    /// Serialize as the `ctf/verification/v1` JSON record (spec §25.6).
    pub fn to_json(&self) -> String {
        let root = self
            .generator_root
            .map_or_else(|| "null".to_owned(), |r| format!("\"{}\"", hex(&r)));
        let cross = self
            .cross_engine
            .map_or_else(|| "null".to_owned(), |b| b.to_string());
        let runs = self
            .runs
            .map_or_else(|| "null".to_owned(), |n| n.to_string());
        format!(
            "{{\n  \"schema\": \"ctf/verification/v1\",\n  \"challenge\": {},\n  \
             \"version\": {},\n  \"subject\": {},\n  \"status\": \"{}\",\n  \
             \"reason\": {},\n  \"generator_root\": {},\n  \"cross_engine\": {},\n  \
             \"runs\": {}\n}}\n",
            json_string(&self.challenge),
            self.version,
            json_string(&self.subject),
            self.status,
            json_string(&self.reason),
            root,
            cross,
            runs,
        )
    }
}

/// Lowercase hex, for the JSON record's `generator_root`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// A JSON string literal with the two characters that can appear in this record's
/// free text escaped; the rest are fixed.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
