//! The phase-4 and platform-facing CLI surfaces: the ingest descriptor, the
//! serving manifest, OCI export/import, and the local ingest gate.

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
        p.push(format!("ctf-pipeline-{}-{tag}", std::process::id()));
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

fn yaml(dir: &TempDir, name: &str, body: &str) -> String {
    let p = dir.path(name);
    std::fs::write(&p, body).unwrap();
    p
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run ctf");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const MINIMAL: &str = "\
spec: 1
id: whos-that-bird
name: \"Who's That Bird\"
category: osint
";

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn pack_emits_a_platform_ingest_descriptor() {
    let dir = TempDir::new("descriptor");
    let source = yaml(&dir, "chal.yaml", MINIMAL);
    let out = dir.path("chal.ctf");
    let (ok, stdout, stderr) = run(&["pack", &source, "--out", &out]);
    assert!(ok, "pack failed: {stdout}{stderr}");

    let descriptor_path = format!("{out}.descriptor.json");
    let json = std::fs::read_to_string(&descriptor_path).unwrap();
    assert!(
        json.contains("\"slug\": \"whos-that-bird\""),
        "descriptor must carry the slug: {json}"
    );
    assert!(
        json.contains("\"referrer_policy\": \"no-referrer\""),
        "descriptor must default to no-referrer: {json}"
    );
}

#[test]
fn pack_refuses_a_tagged_image() {
    let dir = TempDir::new("tagged");
    let source = yaml(
        &dir,
        "chal.yaml",
        "\
spec: 1
id: baby-rop
name: \"Baby ROP\"
runtime:
  image: \"ghcr.io/ctf/baby-rop:latest\"
  ports: [{ container: 1337, protocol: tcp }]
  resources: { cpu: \"0.5\", memory: \"256Mi\", pids: 64 }
  instancing: per_team
  ttl: 30m
  readiness: { tcp: 1337, timeout: 30s }
",
    );
    let out = dir.path("chal.ctf");
    let (ok, _stdout, stderr) = run(&["pack", &source, "--out", &out]);
    assert!(!ok, "a tagged image must be refused");
    assert!(
        stderr.contains("runtime.image"),
        "key must be named: {stderr}"
    );
}

#[test]
fn pack_accepts_a_digest_pinned_image_and_records_it() {
    let dir = TempDir::new("digest");
    let source = yaml(
        &dir,
        "chal.yaml",
        &format!(
            "\
spec: 1
id: baby-rop
name: \"Baby ROP\"
runtime:
  image: \"ghcr.io/ctf/baby-rop@{DIGEST}\"
  ports: [{{ container: 1337, protocol: tcp }}]
  resources: {{ cpu: \"0.5\", memory: \"256Mi\", pids: 64 }}
  instancing: per_team
  ttl: 30m
  readiness: {{ tcp: 1337, timeout: 30s }}
"
        ),
    );
    let out = dir.path("chal.ctf");
    let (ok, stdout, stderr) = run(&["pack", &source, "--out", &out]);
    assert!(ok, "a digest-pinned image must pack: {stdout}{stderr}");
    let json = std::fs::read_to_string(format!("{out}.descriptor.json")).unwrap();
    assert!(
        json.contains(DIGEST),
        "the digest must be in the descriptor"
    );
}

#[test]
fn serving_manifest_lists_only_player_visible_artifacts() {
    let dir = TempDir::new("serving");
    // Build a bundle with one player-visible artifact using the library.
    let manifest = ctf_format::Manifest::build("mixed", "Mixed", &["manifest", "chal"], Vec::new())
        .unwrap()
        .encode()
        .unwrap();
    let bundle = ctf_format::write_bundle(
        1,
        &[
            ctf_format::SectionSpec::inline(
                ctf_format::SectionKind::Manifest,
                0,
                ctf_format::SectionFlags::empty(),
                &manifest,
            ),
            ctf_format::SectionSpec::inline(
                ctf_format::SectionKind::Artifact,
                1,
                ctf_format::SectionFlags(ctf_format::SectionFlags::PLAYER_VISIBLE),
                b"artifact bytes",
            ),
        ],
    )
    .unwrap();
    let bundle_path = dir.path("mixed.ctf");
    std::fs::write(&bundle_path, &bundle).unwrap();
    let out = dir.path("serving.cbor");
    let (ok, stdout, stderr) = run(&["serving-manifest", &bundle_path, "--out", &out]);
    assert!(ok, "serving-manifest failed: {stdout}{stderr}");
    let bytes = std::fs::read(&out).unwrap();
    let value = ctf_format::cbor::Value::decode(&bytes).unwrap();
    assert_eq!(
        value.get("challenge_id").and_then(|v| v.as_text()),
        Some("mixed")
    );
    let artifacts = value.get("artifacts").and_then(|v| v.as_array()).unwrap();
    assert_eq!(artifacts.len(), 1);
}

#[test]
fn oci_export_then_import_round_trips_the_bundle() {
    let dir = TempDir::new("oci");
    let source = yaml(&dir, "chal.yaml", MINIMAL);
    let out = dir.path("chal.ctf");
    let (ok, _stdout, stderr) = run(&["pack", &source, "--out", &out]);
    assert!(ok, "pack failed: {stderr}");
    let layout = dir.path("layout");
    let (ok, _stdout, stderr) = run(&["oci-export", &out, "--out", &layout]);
    assert!(ok, "oci-export failed: {stderr}");
    let recovered = dir.path("recovered.ctf");
    let (ok, _stdout, stderr) = run(&["oci-import", &layout, "--out", &recovered]);
    assert!(ok, "oci-import failed: {stderr}");
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&out).unwrap(),
        "the bundle must survive an OCI round trip byte-for-byte"
    );
}

#[test]
fn run_reports_unverified_when_there_is_nothing_to_gate() {
    let dir = TempDir::new("run-unverified");
    let source = yaml(&dir, "chal.yaml", MINIMAL);
    let secret = "00".repeat(32);
    let (ok, stdout, stderr) = run(&["run", &source, "--secret", &secret]);
    assert!(ok, "an unverified gate is not a failure: {stdout}{stderr}");
    assert!(
        stdout.contains("unverified"),
        "status must be shown: {stdout}"
    );
}
