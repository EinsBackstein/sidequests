//! `ctf-generator` — run a `.ctf` generator module inside a challenge container.
//!
//! This is the executable the challenge base image runs (spec §26, §23; ticket 67).
//! It reads the per-subject seed the platform injected, runs `gen.wasm` under the
//! determinism gate, and writes the generated artifacts to the data mount. A
//! container with no injected seed fails rather than guessing.
//!
//! ```text
//! ctf-generator --module gen.wasm --out /ctf/data [--seed-file /ctf/seed]
//!               [--flag-out /ctf/flag]
//! ```
//!
//! The seed comes from `CTF_SEED` or `/ctf/seed` (spec §26). The generator's flag is
//! compared against `CTF_FLAG` when that is injected, so a generator that disagrees
//! with the platform's oracle fails at start rather than for the first player.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ctf_generator::{GeneratorError, Limits, determinism_gate, resolve_flag, resolve_seed};

fn main() -> ExitCode {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut seed_file: Option<PathBuf> = None;
    let mut flag_out: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next();
        match arg.as_str() {
            "--module" => module = value().map(PathBuf::from),
            "--out" => out = value().map(PathBuf::from),
            "--seed-file" => seed_file = value().map(PathBuf::from),
            "--flag-out" => flag_out = value().map(PathBuf::from),
            "--help" | "-h" => {
                println!(
                    "usage: ctf-generator --module <wasm> --out <dir> \
                     [--seed-file <path>] [--flag-out <path>]"
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

    match run(&module, &out, seed_file.as_deref(), flag_out.as_deref()) {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = match seed_file {
        Some(path) => ctf_generator::seed_from_file(path)?,
        None => resolve_seed()?,
    };
    let wasm = std::fs::read(module)?;
    let limits = Limits::default();
    let gate = determinism_gate(&wasm, &seed, &limits, 2)?;

    // The platform's injected flag, if any, must match what the generator computed.
    let injected = resolve_flag()?;
    ctf_generator::check_flag(&gate.outputs.flag, &injected)?;

    std::fs::create_dir_all(out)?;
    for output in &gate.outputs.outputs {
        check_output_name(&output.name)?;
        let dest = out.join(&output.name);
        std::fs::write(&dest, &output.bytes)?;
        println!("{}: {} bytes", dest.display(), output.bytes.len());
    }
    if let Some(path) = flag_out {
        std::fs::write(path, &gate.outputs.flag)?;
    }
    println!(
        "ctf-generator: {} output(s), root {}, cross_engine {}",
        gate.outputs.outputs.len(),
        hex(&gate.output_root),
        gate.cross_engine
    );
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
