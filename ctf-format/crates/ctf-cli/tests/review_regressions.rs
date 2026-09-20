//! Regression test for ticket 81 (GitHub issue #82) at the CLI boundary:
//! `ctf inspect --verify` must print **every** mismatched section, not just the
//! first, and exit non-zero.
//!
//! Library-level coverage lives in `crates/ctf-format/tests/review_regressions.rs`;
//! this asserts the operator-facing half, which is the part ticket 81 actually
//! called out.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{Bundle, Manifest, SectionFlags, SectionKind, SectionSpec, write_bundle};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-review-{}-{tag}.ctf", std::process::id()));
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

/// Deterministic filler with no short period, without pulling `blake3` into this
/// crate (it is only a transitive dependency). A chunk-body swap is not under
/// test here, so this only needs to avoid a trivial repeating byte.
fn data(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push(x as u8);
    }
    v
}

/// Two sections whose payload bytes no longer hash to their record roots: the
/// report must name each by `name_id` and by full name, and `--verify` must
/// fail.
#[test]
fn verify_prints_every_mismatched_section_and_exits_nonzero() {
    let manifest = Manifest::build("chal", "Title", &["manifest", "alpha", "beta"], vec![])
        .unwrap()
        .encode()
        .unwrap();
    let mut file = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &data(64),
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                2,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &data(80),
            ),
        ],
    )
    .unwrap();

    // Flip one byte in each artifact payload. The header and table are untouched,
    // so the file still parses and only the two section roots disagree.
    let b = Bundle::parse(&file).unwrap();
    let (a, c) = (
        b.section(1).unwrap().offset as usize,
        b.section(2).unwrap().offset as usize,
    );
    drop(b);
    file[a] ^= 1;
    file[c] ^= 1;

    let t = TempFile::new("both-mismatch");
    std::fs::write(t.path(), &file).unwrap();

    let out = Command::new(BIN)
        .args(["inspect", "--verify", "--allow-unsigned", t.path()])
        .output()
        .expect("run ctf inspect");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        !out.status.success(),
        "a root mismatch must fail --verify:\n{stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "exit status:\n{stdout}");

    // Both sections are named on their own mismatch line, not just the first.
    assert!(
        stdout.contains(r#"section 1 ("alpha") does NOT match its root"#),
        "the first mismatch must be named:\n{stdout}"
    );
    assert!(
        stdout.contains(r#"section 2 ("beta") does NOT match its root"#),
        "the second mismatch must also be named:\n{stdout}"
    );
    assert_eq!(
        stdout.matches("does NOT match its root").count(),
        2,
        "exactly the two bad sections must be reported:\n{stdout}"
    );
}
