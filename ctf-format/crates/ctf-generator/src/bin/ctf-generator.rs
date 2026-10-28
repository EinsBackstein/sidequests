//! `ctf-generator` — run a `.ctf` generator module inside a challenge container.
//!
//! This is the executable the challenge base image runs (spec §26, §23; ticket 67).
//! It reads the per-subject seed the platform injected, runs `gen.wasm`, and writes
//! the generated artifacts to the data mount. A container with no injected seed
//! fails rather than guessing.
//!
//! ```text
//! ctf-generator --module gen.wasm --out /ctf/data [--seed-file /ctf/seed]
//!               [--flag-out /ctf/flag] [--determinism strict|none|flag_only]
//! ```
//!
//! The seed comes from `CTF_SEED` or `/ctf/seed` (spec §26); the environment wins
//! over `--seed-file` and the mount when both are present. The generator's flag is
//! compared against `CTF_FLAG` when that is injected, so a generator that disagrees
//! with the platform's oracle fails at start rather than for the first player.
//!
//! [`DeterminismMode`] selects what the runtime does about reproducibility. The
//! runtime container carries the module, not the manifest, so it cannot read
//! `generate.determinism` (§23.7); `--determinism` is how the operator passes the
//! declaration down:
//!
//! - `strict` (default) — run the module twice in one instance; both runs must
//!   agree (rules G9/G10). This is the ingest behaviour.
//! - `none` — run the module exactly once and write its outputs/flag. §23.7 says
//!   reproducibility is not required and the gate is not run, so there is nothing
//!   to compare.
//! - `flag_only` — refuse: §23.7 declares that no generator exists, so there is
//!   nothing for this executable to run.
//!
//! The runtime container carries the module, not the manifest, so it cannot *read*
//! either declaration-dependent check the ingest gate applies: G8's
//! `generate.outputs` membership and the `generate.determinism` value. Both come
//! from the manifest, which `ctf run` and `ctf verify` hold; the operator passes the
//! mode down with `--determinism`. The runtime still re-checks every output name for
//! path traversal, because it turns a module-supplied name into a filename.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ctf_generator::{
    Generator, GeneratorError, Limits, check_flag, determinism_gate, resolve_flag,
    resolve_seed_with,
};

/// How the runtime treats reproducibility (§23.7).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeterminismMode {
    /// Run twice in one instance and require agreement (G9/G10).
    Strict,
    /// Run once; §23.7 says reproducibility is not required and the gate is not run.
    None,
    /// §23.7 declares no generator exists, so there is nothing to run.
    FlagOnly,
}

impl DeterminismMode {
    /// Parse the `--determinism` value strictly, naming the accepted values on a
    /// miss instead of silently choosing one.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "strict" => Ok(Self::Strict),
            "none" => Ok(Self::None),
            "flag_only" => Ok(Self::FlagOnly),
            other => Err(format!(
                "unknown --determinism value `{other}` (accepted: strict, none, flag_only)"
            )),
        }
    }
}

fn main() -> ExitCode {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut seed_file: Option<PathBuf> = None;
    let mut flag_out: Option<PathBuf> = None;
    let mut determinism = DeterminismMode::Strict;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next();
        match arg.as_str() {
            "--module" => module = value().map(PathBuf::from),
            "--out" => out = value().map(PathBuf::from),
            "--seed-file" => seed_file = value().map(PathBuf::from),
            "--flag-out" => flag_out = value().map(PathBuf::from),
            "--determinism" => match value() {
                Some(v) => match DeterminismMode::parse(&v) {
                    Ok(mode) => determinism = mode,
                    Err(message) => {
                        eprintln!("ctf-generator: {message}");
                        return ExitCode::FAILURE;
                    }
                },
                None => {
                    eprintln!(
                        "ctf-generator: --determinism needs a value (accepted: strict, none, flag_only)"
                    );
                    return ExitCode::FAILURE;
                }
            },
            "--help" | "-h" => {
                println!(
                    "usage: ctf-generator --module <wasm> --out <dir> \
                     [--seed-file <path>] [--flag-out <path>] \
                     [--determinism <strict|none|flag_only>]\n\
                     \n\
                     --determinism  strict (default): run twice, the runs must agree;\n\
                     \x20              none: run once, no reproducibility check (§23.7);\n\
                     \x20              flag_only: refuse, §23.7 declares no generator"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ctf-generator: unknown argument `{other}`");
                return ExitCode::FAILURE;
            }
        }
    }

    let (Some(module), Some(out)) = (module, out) else {
        eprintln!("ctf-generator: --module and --out are required");
        return ExitCode::FAILURE;
    };

    match run(
        &module,
        &out,
        seed_file.as_deref(),
        flag_out.as_deref(),
        determinism,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ctf-generator: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    module: &Path,
    out: &Path,
    seed_file: Option<&Path>,
    flag_out: Option<&Path>,
    determinism: DeterminismMode,
) -> Result<(), Box<dyn std::error::Error>> {
    // §23.7 `flag_only`: there is no generator to run, so this executable is the
    // wrong entrypoint and must not invent a run.
    if determinism == DeterminismMode::FlagOnly {
        return Err("`flag_only` declares no generator; do not run ctf-generator".into());
    }

    // §26.1/I3: CTF_SEED wins over an explicit --seed-file, which wins over the
    // mount.
    let seed = resolve_seed_with(seed_file)?;
    let wasm = std::fs::read(module)?;
    let limits = Limits::default();
    let outputs = match determinism {
        // §23.7 `strict`: two runs in one instance, compared by the gate.
        DeterminismMode::Strict => {
            let gate = determinism_gate(&wasm, &seed, &limits, 2)?;
            let injected = resolve_flag()?;
            check_flag(&gate.outputs.flag, injected.as_deref())?;
            print_outputs(out, flag_out, &gate.outputs)?;
            println!(
                "ctf-generator: {} output(s), root {}, cross_engine {}",
                gate.outputs.outputs.len(),
                hex(&gate.output_root),
                gate.cross_engine
            );
            return Ok(());
        }
        // §23.7 `none`: the gate is not run. One run, written as-is.
        DeterminismMode::None => Generator::new(&wasm)?.run(&seed, &limits)?,
        DeterminismMode::FlagOnly => unreachable!("refused above"),
    };

    // The platform's injected flag, if any, must match what the generator computed.
    let injected = resolve_flag()?;
    check_flag(&outputs.flag, injected.as_deref())?;
    print_outputs(out, flag_out, &outputs)?;
    println!(
        "ctf-generator: {} output(s) (determinism none, no gate)",
        outputs.outputs.len()
    );
    Ok(())
}

fn print_outputs(
    out: &Path,
    flag_out: Option<&Path>,
    outputs: &ctf_generator::GeneratorOutput,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    for output in &outputs.outputs {
        check_output_name(&output.name)?;
        let dest = out.join(&output.name);
        std::fs::write(&dest, &output.bytes)?;
        println!("{}: {} bytes", dest.display(), output.bytes.len());
    }
    if let Some(path) = flag_out {
        std::fs::write(path, &outputs.flag)?;
    }
    Ok(())
}

/// A generated name becomes a filename, so it must not escape the data directory.
/// The manifest enforces this too (spec §7.2); the container re-checks because the
/// name here comes from a module, not a manifest.
fn check_output_name(name: &str) -> Result<(), GeneratorError> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name
            .bytes()
            .any(|c| c == b'/' || c == b'\\' || c < 0x20 || c == 0x7f);
    if bad {
        return Err(GeneratorError::Module(
            "a generator output name is path-like".to_owned(),
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}
