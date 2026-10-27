//! `ctf-conformance` — run the committed conformance vectors and report.
//!
//! Default mode evaluates the committed corpus and prints one line per vector plus
//! a summary; the exit status is 0 when every vector passes, so CI can run it
//! directly.
//!
//! `--emit <dir>` is the maintenance mode that regenerates the committed fixtures
//! and `corpus.json` from the goldens. It is the only writer: a test asserts the
//! committed bytes are exactly what it produces.

use std::path::Path;
use std::process::ExitCode;

use ctf_conformance::{VectorKind, emit, run};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, None, None) => run_and_report(),
        (Some(flag), Some(dir), None) if flag == "--emit" => emit_and_report(Path::new(&dir)),
        _ => {
            eprintln!("usage: ctf-conformance [--emit <dir>]");
            ExitCode::from(2)
        }
    }
}

fn run_and_report() -> ExitCode {
    let report = run();
    for outcome in &report.outcomes {
        if outcome.passed {
            println!("PASS {}", outcome.name);
        } else {
            println!("FAIL {}: {}", outcome.name, outcome.detail);
        }
    }
    let total = report.outcomes.len();
    let failed = report.failed();
    let count = |kind: VectorKind| report.outcomes.iter().filter(|o| o.kind == kind).count();
    println!(
        "summary: {total} vectors ({} golden, {} hostile, {} future), {} passed, {failed} failed",
        count(VectorKind::Golden),
        count(VectorKind::Hostile),
        count(VectorKind::Future),
        total - failed
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn emit_and_report(dir: &Path) -> ExitCode {
    match emit(dir) {
        Ok(written) => {
            println!(
                "emitted {written} fixtures and corpus.json to {}",
                dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(detail) => {
            eprintln!("emit failed: {detail}");
            ExitCode::FAILURE
        }
    }
}
