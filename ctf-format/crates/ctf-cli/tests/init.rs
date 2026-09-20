//! `ctf init` tests (ticket 26).
//!
//! A scaffold is only useful if it validates, so each archetype is scaffolded and
//! then checked with the same schema and policy validation `ctf validate` runs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-init-{}-{tag}", std::process::id()));
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

#[test]
fn every_archetype_scaffolds_and_validates() {
    for archetype in ["osint", "rev", "pwn", "web", "forensics"] {
        let dir = TempDir::new(archetype);
        let out = dir.path(archetype);
        let (ok, _, err) = run(&["init", archetype, "--out", &out, "--id", "my-chal"]);
        assert!(ok, "init {archetype} failed: {err}");

        let (ok, _, err) = run(&[
            "validate",
            &dir.path(&format!("{archetype}/challenge.yaml")),
        ]);
        assert!(ok, "{archetype} scaffold does not validate: {err}");
    }
}

#[test]
fn init_refuses_to_overwrite_an_existing_scaffold() {
    let dir = TempDir::new("clobber");
    let out = dir.path("chal");
    let (ok, _, _) = run(&["init", "osint", "--out", &out, "--id", "my-chal"]);
    assert!(ok);

    let (ok, _, err) = run(&["init", "osint", "--out", &out, "--id", "my-chal"]);
    assert!(!ok, "a second init must refuse to overwrite");
    assert!(err.contains("refusing to overwrite"), "{err}");
}

#[test]
fn an_unknown_archetype_is_rejected() {
    let dir = TempDir::new("unknown");
    let (ok, _, err) = run(&["init", "nope", "--out", &dir.path("x"), "--id", "my-chal"]);
    assert!(!ok);
    assert!(err.contains("nope"), "{err}");
}
