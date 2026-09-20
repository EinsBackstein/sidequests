//! Inspector regression tests (ticket 36).
//!
//! The inspector is the one tool an operator uses end to end, so its output is
//! asserted rather than eyeballed: every section root, external size/mirrors/root,
//! the tri-state verification counts, and — because a bundle is attacker input —
//! that free-form manifest text cannot inject terminal escape sequences.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{
    Manifest, Payload, SectionFlags, SectionKind, SectionSpec, cbor::Value, write_bundle,
};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-inspect-{}-{tag}.ctf", std::process::id()));
        Self(p)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn inspect(path: &str, extra: &[&str]) -> (bool, String) {
    let out = Command::new(BIN)
        .arg("inspect")
        .args(extra)
        .arg(path)
        .output()
        .expect("run ctf inspect");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Like [`inspect`], but surfaces the exact exit code: the intact-but-not-authentic
/// case is code 2, distinct from the code 1 of a parse or usage failure.
fn inspect_status(path: &str, extra: &[&str]) -> (i32, String) {
    let out = Command::new(BIN)
        .arg("inspect")
        .args(extra)
        .arg(path)
        .output()
        .expect("run ctf inspect");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn manifest_with(category: Option<&str>) -> Manifest {
    let mut extra = Vec::new();
    if let Some(c) = category {
        extra.push((Value::Text("category".into()), Value::Text(c.to_owned())));
    }
    Manifest::build("chal", "Title", &["manifest", "notes"], extra).unwrap()
}

#[test]
fn prints_every_root_and_the_verification_counts() {
    let m = manifest_with(None);
    let file = write_bundle(
        1,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &m.encode().unwrap(),
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                b"hello",
            ),
        ],
    )
    .unwrap();
    let t = TempFile::new("roots");
    std::fs::write(t.path(), &file).unwrap();

    let (ok, out) = inspect(t.path(), &["--verify", "--allow-unsigned"]);
    assert!(ok, "inspect --verify failed:\n{out}");
    // Both inline sections verified, and both roots are shown.
    assert!(out.contains("verified      2 inline section(s)"), "{out}");
    assert!(
        out.contains("unverifiable 0") || !out.contains("NOT VERIFIED"),
        "{out}"
    );
    let root_count = out.matches("      root    ").count();
    assert_eq!(root_count, 2, "one root line per section:\n{out}");
}

#[test]
fn external_sections_show_size_mirrors_and_root() {
    let root = [0x11u8; 32];
    let size: u64 = 41_231_986_688;
    let m = Manifest::build(
        "chal",
        "Title",
        &["manifest", "image"],
        vec![(
            Value::Text("external".into()),
            Value::Map(vec![(
                Value::Uint(1),
                Value::Map(vec![
                    (Value::Text("size".into()), Value::Uint(size)),
                    (Value::Text("root".into()), Value::Bytes(root.to_vec())),
                    (
                        Value::Text("mirrors".into()),
                        Value::Array(vec![Value::Text("https://example.test/img".into())]),
                    ),
                ]),
            )]),
        )],
    )
    .unwrap();
    let file = write_bundle(
        1,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &m.encode().unwrap(),
            ),
            SectionSpec {
                kind: SectionKind::Artifact,
                name_id: 1,
                flags: SectionFlags(SectionFlags::EXTERNAL),
                chunk_size: 0,
                comp: ctf_format::Compression::None,
                payload: Payload::External {
                    len_plain: size,
                    root,
                },
                chunk_index: None,
                encryption: None,
            },
        ],
    )
    .unwrap();
    let t = TempFile::new("external");
    std::fs::write(t.path(), &file).unwrap();

    let (ok, out) = inspect(t.path(), &["--verify", "--allow-unsigned"]);
    assert!(ok, "inspect --verify failed:\n{out}");
    assert!(out.contains("external"), "{out}");
    assert!(out.contains("(external)"), "root marked external:\n{out}");
    assert!(out.contains(&size.to_string()), "size shown:\n{out}");
    assert!(out.contains("https://example.test/img"), "{out}");
    // Verification reports the external section rather than failing it.
    assert!(out.contains("1 external"), "{out}");
}

/// `category` is free-form text from an attacker-controllable manifest. Debug
/// formatting must escape it, so an embedded ESC cannot spoof the operator's
/// terminal — the L1 failure mode.
#[test]
fn escapes_attacker_controlled_text() {
    let m = manifest_with(Some("evil\u{1b}[31mRED"));
    let file = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m.encode().unwrap(),
        )],
    )
    .unwrap();
    let t = TempFile::new("escape");
    std::fs::write(t.path(), &file).unwrap();

    let (ok, out) = inspect(t.path(), &[]);
    assert!(ok, "{out}");
    assert!(
        !out.bytes().any(|b| b == 0x1b),
        "raw escape byte reached the terminal:\n{out:?}"
    );
    assert!(
        out.contains("\\u{1b}"),
        "escape should be visible as text:\n{out}"
    );
}

/// An unsigned bundle is intact but not authentic. `--verify` must say so and
/// signal it with the dedicated exit code 2, so a caller scripting on the exit
/// status cannot mistake "structurally sound" for "signed".
#[test]
fn unsigned_bundle_under_verify_exits_two() {
    let m = manifest_with(None);
    let file = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m.encode().unwrap(),
        )],
    )
    .unwrap();
    let t = TempFile::new("unsigned-verify");
    std::fs::write(t.path(), &file).unwrap();

    let (code, out) = inspect_status(t.path(), &["--verify"]);
    assert_eq!(code, 2, "unsigned --verify must exit 2:\n{out}");
    assert!(out.contains("NOT AUTHENTIC"), "{out}");
}

/// `--allow-unsigned` is the explicit opt-in: the bundle is still reported as
/// carrying no signatures, but the command succeeds.
#[test]
fn allow_unsigned_accepts_an_unsigned_bundle() {
    let m = manifest_with(None);
    let file = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m.encode().unwrap(),
        )],
    )
    .unwrap();
    let t = TempFile::new("allow-unsigned");
    std::fs::write(t.path(), &file).unwrap();

    let (code, out) = inspect_status(t.path(), &["--verify", "--allow-unsigned"]);
    assert_eq!(code, 0, "--allow-unsigned must succeed:\n{out}");
    assert!(out.contains("accepted"), "{out}");
}

/// Without `--verify`, inspect is a structural dump and says nothing about
/// authenticity, so the unsigned exit code does not apply.
#[test]
fn unsigned_bundle_without_verify_still_succeeds() {
    let m = manifest_with(None);
    let file = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m.encode().unwrap(),
        )],
    )
    .unwrap();
    let t = TempFile::new("unsigned-plain");
    std::fs::write(t.path(), &file).unwrap();

    let (ok, _out) = inspect(t.path(), &[]);
    assert!(ok);
}

/// Drive the binary with arbitrary arguments and surface the exact exit code plus
/// both streams, for the parser-level assertions below.
fn run_raw(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().expect("run ctf");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The L8 regression: `ctf inspect a.ctf b.ctf` must reject the second positional
/// instead of silently inspecting the last one. The report must not be printed.
#[test]
fn inspect_rejects_a_second_positional() {
    let (code, out, err) = run_raw(&["inspect", "a.ctf", "b.ctf"]);
    assert_ne!(code, 0, "a second positional must fail");
    assert!(!err.is_empty(), "a usage error must explain itself");
    assert!(
        !out.contains("file          "),
        "no report should be printed for a rejected invocation:\n{out}"
    );
}

/// clap exits 2 on usage errors by default, which would collide with the exit 2
/// that `inspect --verify` reserves for an intact-but-unauthentic bundle. A usage
/// error must therefore exit 1.
#[test]
fn a_usage_error_exits_one_not_two() {
    let (code, _out, err) = run_raw(&["inspect", "--definitely-not-a-flag", "a.ctf"]);
    assert_eq!(code, 1, "usage errors must exit 1, not clap's default 2");
    assert!(!err.is_empty(), "a usage error must explain itself");
}

/// Ticket 37: every subcommand is discoverable through `--help`.
#[test]
fn help_lists_every_subcommand() {
    let (code, out, err) = run_raw(&["--help"]);
    assert_eq!(code, 0, "--help must succeed:\n{err}");
    for cmd in [
        "inspect",
        "validate",
        "pack",
        "keygen",
        "sign",
        "completions",
    ] {
        assert!(out.contains(cmd), "`{cmd}` missing from --help:\n{out}");
    }
}

/// Ticket 37: `completions <shell>` emits a non-empty script generated from the
/// real clap `Command`.
#[test]
fn completions_bash_emits_a_script() {
    let (code, out, err) = run_raw(&["completions", "bash"]);
    assert_eq!(code, 0, "completions must succeed:\n{err}");
    assert!(
        !out.trim().is_empty(),
        "completion script must not be empty"
    );
    assert!(
        out.contains("ctf"),
        "script should mention the binary:\n{out}"
    );
}
