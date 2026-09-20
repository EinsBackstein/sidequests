//! `ctf keygen` and `ctf sign` tests (ticket 13).
//!
//! The point of these commands is that a signed bundle actually verifies, so the
//! test drives the whole chain — `pack`, `keygen`, `sign` — and then checks the
//! output in-process against the public key the CLI wrote. It also pins the refusal
//! to sign a bundle that already carries signatures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{Bundle, HybridPublicKey, Signing};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-sign-{}-{tag}", std::process::id()));
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

/// Decode the CLI's key-file format: two lines of lowercase hex, classical first,
/// post-quantum second.
fn read_public_key(path: &str) -> HybridPublicKey {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(hex_decode);
    let classical = lines.next().expect("classical component");
    let pq = lines.next().expect("post-quantum component");
    assert!(lines.next().is_none(), "a key file has exactly two lines");
    HybridPublicKey { classical, pq }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// Produce an unsigned bundle, a keypair, and the signed bundle; returns their paths.
fn signed_fixture(dir: &TempDir) -> (String, String, String, String) {
    let source = dir.path("chal.yaml");
    std::fs::write(
        &source,
        "spec: 1\nid: whos-that-bird\nname: \"Who's That Bird\"\n",
    )
    .unwrap();

    let unsigned = dir.path("chal.ctf");
    let (ok, _out, err) = run(&["pack", &source, "--out", &unsigned]);
    assert!(ok, "pack failed: {err}");

    let key = dir.path("signing.key");
    let public = dir.path("public.key");
    let (ok, _out, err) = run(&["keygen", "--out-key", &key, "--out-pub", &public]);
    assert!(ok, "keygen failed: {err}");

    let signed = dir.path("signed.ctf");
    let (ok, _out, err) = run(&[
        "sign", &unsigned, "--key", &key, "--pub", &public, "--out", &signed,
    ]);
    assert!(ok, "sign failed: {err}");

    (unsigned, key, public, signed)
}

#[test]
fn keygen_pack_sign_then_verify_in_process() {
    let dir = TempDir::new("roundtrip");
    let (_unsigned, _key, public, signed) = signed_fixture(&dir);

    let bytes = std::fs::read(&signed).unwrap();
    let bundle = Bundle::parse(&bytes).unwrap();
    assert_eq!(bundle.signing(), Signing::Present);

    let public_key = read_public_key(&public);
    bundle
        .verify_signatures(&public_key)
        .expect("the signed bundle must verify under the public key the CLI wrote");
}

#[test]
fn refuses_to_sign_an_already_signed_bundle() {
    let dir = TempDir::new("already-signed");
    let (_unsigned, key, public, signed) = signed_fixture(&dir);

    let twice = dir.path("twice.ctf");
    let (ok, _stdout, stderr) = run(&[
        "sign", &signed, "--key", &key, "--pub", &public, "--out", &twice,
    ]);
    assert!(!ok, "re-signing must be refused");
    assert!(
        stderr.contains("already") || stderr.contains("signatures"),
        "{stderr}"
    );
    assert!(
        !std::path::Path::new(&twice).exists(),
        "no output on refusal"
    );
}
