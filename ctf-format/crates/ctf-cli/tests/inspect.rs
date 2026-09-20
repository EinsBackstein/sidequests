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

    let (ok, out) = inspect(t.path(), &["--verify"]);
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
            },
        ],
    )
    .unwrap();
    let t = TempFile::new("external");
    std::fs::write(t.path(), &file).unwrap();

    let (ok, out) = inspect(t.path(), &["--verify"]);
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
