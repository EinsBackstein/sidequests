//! `ctf-conformance` — run the committed conformance vectors and report.
//!
//! Exit status is 0 when every vector passes and non-zero otherwise, so CI can run
//! it directly. Output is one line per vector plus a summary.

use std::process::ExitCode;

use ctf_conformance::{VectorKind, run};

fn main() -> ExitCode {
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
    let golden = report
        .outcomes
        .iter()
        .filter(|o| o.kind == VectorKind::Golden)
        .count();
    let hostile = report
        .outcomes
        .iter()
        .filter(|o| o.kind == VectorKind::Hostile)
        .count();
    println!(
        "summary: {total} vectors ({golden} golden, {hostile} hostile), {} passed, {failed} failed",
        total - failed
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
