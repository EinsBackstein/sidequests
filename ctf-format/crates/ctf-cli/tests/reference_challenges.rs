//! Regression test for GitHub ticket #69: pack the two reference challenges
//! (`File And Seek`, `Mental Overflow`) and assert their ingest rows.
//!
//! The fixtures under `tests/fixtures/reference/` are authoring documents for
//! two real challenges from `CTF-FlagFrenzy/challenges`. This test drives the
//! built `ctf` binary exactly as an author would (`ctf pack`), checks the
//! platform ingest descriptor it emits, parses the bundle back, and — for the
//! challenge that has one — runs the generator through the determinism gate.
//!
//! The gate is the acceptance criterion that matters: the upstream Mental
//! Overflow generator used `random.sample`, and the vendored `gen.wasm` is the
//! deterministic port, so a regression that reintroduced randomness would fail
//! here rather than at ingest.
//!
//! Everything is hermetic: no network, no Docker, no image is ever pulled.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

/// The vendored fixtures, resolved from this crate's manifest directory.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/reference");

/// One reference challenge and the platform record it must produce.
struct Case {
    /// The subdirectory under `tests/fixtures/reference/` holding the fixture.
    dir: &'static str,
    slug: &'static str,
    name: &'static str,
    category: &'static str,
    image: &'static str,
}

const CASES: &[Case] = &[
    Case {
        dir: "file_and_seek",
        slug: "file-and-seek",
        name: "File And Seek",
        category: "Web-challenge",
        image: "ctf-fixture.invalid/file-and-seek@sha256:1111111111111111111111111111111111111111111111111111111111111111",
    },
    Case {
        dir: "mental_overflow",
        slug: "mental-overflow",
        name: "Mental Overflow",
        category: "Reverse Engineering",
        image: "ctf-fixture.invalid/mental-overflow@sha256:2222222222222222222222222222222222222222222222222222222222222222",
    },
];

/// A scratch directory named by the test process, removed on drop.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-reference-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run ctf");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Decode a 64-hex-digit string into the 32-byte seed the gate takes.
fn seed_from_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Both fixtures pack, and each descriptor carries the platform's challenge and
/// runtime records. The assertions are on the JSON text (this crate has no
/// `serde_json`), matching the style of `tests/pipeline.rs`.
#[test]
fn both_reference_challenges_pack_and_match_their_platform_records() {
    let dir = TempDir::new("pack");

    for case in CASES {
        let source = format!("{FIXTURES}/{}/challenge.yaml", case.dir);
        let out = dir.path(&format!("{}.ctf", case.slug));
        let (ok, stdout, stderr) = run(&["pack", &source, "--out", &out]);
        assert!(ok, "pack {} failed: {stdout}{stderr}", case.slug);

        let json = std::fs::read_to_string(format!("{out}.descriptor.json")).unwrap();
        for needle in [
            format!("\"slug\": \"{}\"", case.slug),
            format!("\"name\": \"{}\"", case.name),
            format!("\"category\": \"{}\"", case.category),
            "\"version\": 0".to_owned(),
            format!("\"image\": \"{}\"", case.image),
            "\"port\": 80".to_owned(),
            "\"referrer_policy\": \"no-referrer\"".to_owned(),
        ] {
            assert!(
                json.contains(&needle),
                "descriptor for {} is missing {needle}:\n{json}",
                case.slug
            );
        }

        let bytes = std::fs::read(&out).unwrap();
        let bundle = ctf_format::Bundle::parse(&bytes).unwrap();
        assert_eq!(bundle.manifest.id(), case.slug);
        assert_eq!(bundle.manifest.version(), 0);
    }
}

/// The vendored Mental Overflow generator is a pure function of the seed, so the
/// determinism gate passes with at least two in-process runs. The output flag is
/// pinned against the independent Python known-answer vector in
/// `crates/ctf-format/tests/derive.rs::known_answer_vectors_from_python`.
#[test]
fn mental_overflow_generator_passes_the_determinism_gate() {
    let wasm = std::fs::read(format!("{FIXTURES}/mental_overflow/gen.wasm")).unwrap();
    // The first `known_answer_vectors_from_python` seed: bytes 00..1f after the
    // spec's seed derivation, whose flag is `oil5phz5xep2ss7j`.
    let seed = seed_from_hex("20b0f7556a9de4382cda2501eb74791e85474831adfe1ccf84dab59305099f6e");

    let report =
        ctf_generator::determinism_gate(&wasm, &seed, &ctf_generator::Limits::default(), 2)
            .expect("the deterministic generator must pass the determinism gate");

    assert!(
        report.runs >= 2,
        "the gate must run the generator at least twice, ran {}",
        report.runs
    );
    assert_eq!(
        report.outputs.flag, "oil5phz5xep2ss7j",
        "the generator flag must match the independent known-answer vector"
    );

    let artifact = report
        .outputs
        .output("challenge.bin")
        .expect("the generator must emit `challenge.bin`");
    assert!(
        !artifact.bytes.is_empty(),
        "`challenge.bin` must not be empty"
    );

    // `cross_engine` is a report, not a promise: it must agree with whether the
    // second engine can actually load this module.
    assert_eq!(
        report.cross_engine,
        ctf_generator::second_engine_supported(&wasm),
        "`cross_engine` must be reported truthfully"
    );
}

/// A runtime challenge has no offline gate to run: `ctf run` must report it
/// `unverified`, never `passed` (spec §25.6).
#[test]
fn runtime_reference_challenges_are_unverified_not_passed() {
    let secret = "00".repeat(32);

    for case in CASES {
        let source = format!("{FIXTURES}/{}/challenge.yaml", case.dir);
        let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret]);
        assert!(ok, "run {} failed: {stdout}{stderr}", case.slug);
        // The gate prints a single `gate <status>` line; the explanatory prose
        // below it also contains the word "passed", so match the status line.
        let status_line = stdout
            .lines()
            .find(|line| line.trim_start().starts_with("gate"))
            .unwrap_or("");
        assert!(
            status_line.ends_with("unverified"),
            "{} must be unverified: {stdout}",
            case.slug
        );
        assert!(
            !status_line.ends_with("passed"),
            "{} must never be reported passed: {stdout}",
            case.slug
        );
    }
}
