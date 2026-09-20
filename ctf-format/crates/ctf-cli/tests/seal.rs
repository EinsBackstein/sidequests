//! `ctf keys`, `ctf seal`, and `ctf unseal` tests (ticket 18).
//!
//! The key-envelope workflow only means something if it round-trips, so these
//! tests drive the whole chain — pack a challenge, generate a seal keypair, seal a
//! section, unseal it — and check the sealed bytes in-process. They also pin the
//! two properties the workflow exists for: a sealed section needs the seal key, and
//! the seal key itself never appears in the bundle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{
    Bundle, Encryption, SectionFlags, SectionKind, SectionSpec, cbor::Value, write_bundle,
};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-seal-{}-{tag}", std::process::id()));
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

/// Like [`run`], but surfaces the exact exit code so a failure can be pinned at 1
/// rather than merely "non-zero" (2 is reserved for `inspect --verify`).
fn run_status(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run ctf");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// The CLI's KEM key-file format: one non-empty line of lowercase hex.
fn read_hex_key(path: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        text.trim_end().lines().count(),
        1,
        "a KEM key file has exactly one line"
    );
    hex_decode(text.trim())
}

/// Whether `needle` occurs contiguously in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn append_name(value: &mut Value, name: &str) {
    let Value::Map(entries) = value else {
        panic!("manifest is not a CBOR map");
    };
    for (k, v) in entries.iter_mut() {
        if k.as_text() == Some("names") {
            let Value::Array(items) = v else {
                panic!("manifest `names` is not an array");
            };
            items.push(Value::Text(name.to_owned()));
        }
    }
}

/// Pack a small challenge with `ctf pack`, then add one inline `artifact` section
/// whose bytes are `plaintext`. The append mirrors what `ctf seal` does for a new
/// `keys` name: `names` may be longer than the section count (spec §7.2).
fn pack_challenge(dir: &TempDir, plaintext: &[u8]) -> String {
    let source = dir.path("chal.yaml");
    std::fs::write(
        &source,
        "spec: 1\nid: sealed-chal\nname: \"Sealed Challenge\"\n",
    )
    .unwrap();
    let base = dir.path("base.ctf");
    let (ok, _out, err) = run(&["pack", &source, "--out", &base]);
    assert!(ok, "pack failed: {err}");

    let bytes = std::fs::read(&base).unwrap();
    let bundle = Bundle::parse(&bytes).unwrap();
    let manifest_record = bundle
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .expect("packed bundle has a manifest");
    let manifest_plain = bundle.section_bytes(manifest_record).unwrap();
    let mut value = Value::decode(manifest_plain.as_ref()).unwrap();
    let artifact_name_id = u16::try_from(bundle.manifest.names().len()).unwrap();
    append_name(&mut value, "artifact");
    let manifest_bytes = value.encode().unwrap();

    let challenge = dir.path("chal.ctf");
    let file = write_bundle(
        bundle.header.suite_id,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                artifact_name_id,
                SectionFlags::empty(),
                plaintext,
            ),
        ],
    )
    .unwrap();
    std::fs::write(&challenge, &file).unwrap();
    challenge
}

/// Generate a seal keypair and seal the challenge's `artifact` section. Returns the
/// sealed bundle path, the secret-key path, and the public-key path.
fn seal_fixture(dir: &TempDir, plaintext: &[u8]) -> (String, String, String) {
    let challenge = pack_challenge(dir, plaintext);

    let key = dir.path("seal.key");
    let public = dir.path("seal.pub");
    let (ok, _out, err) = run(&[
        "keys",
        "--context",
        "seal",
        "--out-key",
        &key,
        "--out-pub",
        &public,
    ]);
    assert!(ok, "keys failed: {err}");

    let sealed = dir.path("sealed.ctf");
    let (ok, _out, err) = run(&[
        "seal",
        &challenge,
        "--pub",
        &public,
        "--context",
        "seal",
        "--section",
        "artifact",
        "--out",
        &sealed,
    ]);
    assert!(ok, "seal failed: {err}");

    (sealed, key, public)
}

#[test]
fn keys_writes_two_non_empty_hex_files() {
    let dir = TempDir::new("keys");
    let key = dir.path("k.key");
    let public = dir.path("k.pub");

    let (ok, out, err) = run(&[
        "keys",
        "--context",
        "seal",
        "--out-key",
        &key,
        "--out-pub",
        &public,
    ]);
    assert!(ok, "keys failed: {out}{err}");

    let secret = read_hex_key(&key);
    let public_bytes = read_hex_key(&public);
    assert!(!secret.is_empty(), "the secret key must not be empty");
    assert!(!public_bytes.is_empty(), "the public key must not be empty");
    assert_ne!(secret, public_bytes);
    assert!(out.contains("seal"), "the summary names the context: {out}");

    for path in [&key, &public] {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            text.trim()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "key file must be lowercase hex: {text}"
        );
    }
}

#[test]
fn keys_rejects_a_bad_context() {
    let dir = TempDir::new("keys-bad-context");
    let key = dir.path("k.key");
    let public = dir.path("k.pub");
    let (code, _out, err) = run_status(&[
        "keys",
        "--context",
        "everyone",
        "--out-key",
        &key,
        "--out-pub",
        &public,
    ]);
    assert_eq!(code, 1, "an invalid context must fail: {err}");
    assert!(
        err.contains("context"),
        "the error names the context: {err}"
    );
}

#[test]
fn seal_encrypts_the_section_and_adds_a_keys_section() {
    let dir = TempDir::new("sealed-shape");
    let plaintext = b"the-sealed-artifact-plaintext-that-must-not-appear-in-the-file";
    let (sealed, _key, _public) = seal_fixture(&dir, plaintext);

    let bytes = std::fs::read(&sealed).unwrap();
    let bundle = Bundle::parse(&bytes).unwrap();
    let record = bundle
        .sections
        .iter()
        .find(|r| bundle.manifest.name_of(r.name_id) == Some("artifact"))
        .expect("the artifact section survived the rewrite");
    assert_eq!(record.enc, Encryption::AeadStream);
    assert_ne!(record.chunk_size, 0, "R15: encrypted sections are chunked");
    assert!(
        bundle.sections.iter().any(|r| r.kind == SectionKind::Keys),
        "the envelope needs a keys section to carry it"
    );
    assert!(
        !contains(&bytes, plaintext),
        "the plaintext must not appear in a sealed bundle"
    );
}

#[test]
fn unseal_recovers_the_exact_plaintext() {
    let dir = TempDir::new("roundtrip");
    let plaintext = b"the-sealed-artifact-plaintext-that-must-not-appear-in-the-file";
    let (sealed, key, _public) = seal_fixture(&dir, plaintext);

    let recovered = dir.path("recovered.bin");
    let (ok, _out, err) = run(&[
        "unseal",
        &sealed,
        "--key",
        &key,
        "--context",
        "seal",
        "--section",
        "artifact",
        "--out",
        &recovered,
    ]);
    assert!(ok, "unseal failed: {err}");
    assert_eq!(std::fs::read(&recovered).unwrap(), plaintext);
}

#[test]
fn unseal_with_a_different_key_fails_and_writes_nothing() {
    let dir = TempDir::new("wrong-key");
    let plaintext = b"the-sealed-artifact-plaintext-that-must-not-appear-in-the-file";
    let (sealed, _key, _public) = seal_fixture(&dir, plaintext);

    let wrong_key = dir.path("wrong.key");
    let wrong_public = dir.path("wrong.pub");
    let (ok, _out, err) = run(&[
        "keys",
        "--context",
        "seal",
        "--out-key",
        &wrong_key,
        "--out-pub",
        &wrong_public,
    ]);
    assert!(ok, "keys failed: {err}");

    let out = dir.path("nothing.bin");
    let (code, _stdout, err) = run_status(&[
        "unseal",
        &sealed,
        "--key",
        &wrong_key,
        "--context",
        "seal",
        "--section",
        "artifact",
        "--out",
        &out,
    ]);
    assert_eq!(code, 1, "a wrong key must exit 1: {err}");
    assert!(
        !std::path::Path::new(&out).exists(),
        "a failed unseal must write no output"
    );
}

#[test]
fn the_secret_key_never_appears_in_the_sealed_bundle() {
    let dir = TempDir::new("key-leak");
    let plaintext = b"the-sealed-artifact-plaintext-that-must-not-appear-in-the-file";
    let (sealed, key, _public) = seal_fixture(&dir, plaintext);

    let bytes = std::fs::read(&sealed).unwrap();
    let secret = read_hex_key(&key);
    assert!(!secret.is_empty());
    assert!(
        !contains(&bytes, &secret),
        "the seal key must never be written into the bundle"
    );
}

#[test]
fn the_new_subcommands_are_discoverable() {
    let (code, out, err) = run_status(&["--help"]);
    assert_eq!(code, 0, "--help must succeed:\n{err}");
    for cmd in ["keys", "seal", "unseal"] {
        assert!(out.contains(cmd), "`{cmd}` missing from --help:\n{out}");
    }
    for cmd in ["keys", "seal", "unseal"] {
        let (code, _out, err) = run_status(&[cmd, "--help"]);
        assert_eq!(code, 0, "`{cmd} --help` must succeed:\n{err}");
    }
}
