//! `ctf verify`: the rerunnable ingest verification artifact (ticket 64,
//! spec §25.6.1).
//!
//! The artifact is what a platform job gates on, so these tests pin the four
//! statuses and their exit codes, the required keys, byte-for-byte stability across
//! reruns, and the two things the artifact must never leak: the event secret and
//! the flag.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{Bundle, Manifest, Payload, SectionFlags, SectionKind, SectionSpec, write_bundle};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-verify-{}-{tag}", std::process::id()));
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

/// Run `ctf` and surface the exact exit code: 0 passed, 1 rejected/failed, 2
/// unverified.
fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run ctf");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn parse(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("artifact is not valid JSON: {e}\n{json}"))
}

fn manifest() -> Manifest {
    Manifest::build("chal", "Title", &["manifest", "notes"], vec![]).unwrap()
}

/// A valid, unsigned bundle with a manifest and one inline artifact.
fn minimal_bundle() -> Vec<u8> {
    let m = manifest();
    write_bundle(
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
    .unwrap()
}

/// A valid golden/minimal-style bundle with no gate requested is **unverified**,
/// never `passed`, and exits 2 — 2 already means "intact but not authentic" here.
#[test]
fn a_valid_bundle_without_a_gate_is_unverified_and_exits_two() {
    let dir = TempDir::new("unverified");
    let path = dir.path("chal.ctf");
    std::fs::write(&path, minimal_bundle()).unwrap();

    let (code, stdout, stderr) = run(&["verify", &path]);
    assert_eq!(code, 2, "unverified must not exit 0:\n{stdout}{stderr}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["schema"], "ctf/ingest-verification/v1");
    assert_eq!(artifact["bundle_digest_algorithm"], "blake3");
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["signing"], "unsigned");
    assert!(artifact["gate"].is_null(), "no gate was requested");
    assert_eq!(artifact["sections"]["verified"], 2);
    assert_eq!(artifact["sections"]["external"], 0);
    assert_eq!(artifact["sections"]["unverifiable"], 0);
    assert_eq!(artifact["sections"]["chunk_indices"], 0);
}

/// The required keys are present with the documented types, and the bundle digest
/// is BLAKE3 of the whole file bytes.
#[test]
fn the_artifact_parses_and_carries_the_required_keys() {
    let dir = TempDir::new("shape");
    let bytes = minimal_bundle();
    let path = dir.path("chal.ctf");
    std::fs::write(&path, &bytes).unwrap();

    let (code, stdout, _stderr) = run(&["verify", &path]);
    assert_eq!(code, 2);
    let artifact = parse(&stdout);

    assert!(artifact.is_object(), "{artifact}");
    for key in [
        "schema",
        "bundle_digest",
        "bundle_digest_algorithm",
        "bundle_size",
        "commitment_root",
        "intact",
        "sections",
        "signing",
        "gate",
        "status",
        "reason",
    ] {
        assert!(
            artifact.get(key).is_some(),
            "missing key `{key}`:\n{stdout}"
        );
    }

    assert_eq!(artifact["bundle_size"], bytes.len());
    assert_eq!(
        artifact["bundle_digest"],
        blake3::hash(&bytes).to_hex().to_string(),
        "the digest must be BLAKE3 of the whole file"
    );
    let parsed = Bundle::parse(&bytes).unwrap();
    assert_eq!(
        artifact["commitment_root"],
        format!("{}", hex(&parsed.footer.root)),
        "the artifact names the footer's commitment root"
    );
}

/// A byte flip in an inline payload leaves the file parseable but breaks that
/// section's root: the artifact is `rejected` and exits 1.
#[test]
fn a_byte_flipped_bundle_is_rejected_and_exits_one() {
    let dir = TempDir::new("flipped");
    let mut bytes = minimal_bundle();
    let off = {
        let b = Bundle::parse(&bytes).unwrap();
        b.section(1).unwrap().offset as usize
    };
    bytes[off] ^= 1;
    let path = dir.path("flipped.ctf");
    std::fs::write(&path, &bytes).unwrap();

    let (code, stdout, stderr) = run(&["verify", &path]);
    assert_eq!(code, 1, "a rejected bundle must exit 1:\n{stdout}{stderr}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "rejected");
    assert_eq!(artifact["intact"], false);
    assert_eq!(artifact["sections"]["mismatches"], serde_json::json!([1]));
    assert!(
        artifact["reason"].as_str().unwrap().contains("root"),
        "the reason must name the failure: {artifact}"
    );
}

/// A requested gate is not run when the bundle is rejected: `gate` stays `null` and
/// the rejection is carried by `status`, because the gate would be evaluating bytes
/// the footer does not commit to (spec §25.6.1).
#[test]
fn a_requested_gate_is_not_run_on_a_rejected_bundle() {
    let dir = TempDir::new("rejected-gate");
    let mut bytes = minimal_bundle();
    let off = {
        let b = Bundle::parse(&bytes).unwrap();
        b.section(1).unwrap().offset as usize
    };
    bytes[off] ^= 1;
    let path = dir.path("flipped.ctf");
    std::fs::write(&path, &bytes).unwrap();

    let secret = "00".repeat(32);
    let (code, stdout, stderr) = run(&[
        "verify",
        &path,
        "--challenge",
        "unused.yaml",
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 1, "a rejected bundle must exit 1:\n{stdout}{stderr}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "rejected");
    assert_eq!(artifact["intact"], false);
    assert!(
        artifact["gate"].is_null(),
        "the gate must not run on a rejected bundle: {artifact}"
    );
}

/// A block of garbage is rejected at parse: the artifact still names the digest and
/// the size, but it does not guess a commitment root or a signing state.
#[test]
fn an_unparseable_file_is_rejected_without_guessing() {
    let dir = TempDir::new("garbage");
    let path = dir.path("garbage.ctf");
    std::fs::write(&path, b"not a bundle at all").unwrap();

    let (code, stdout, _stderr) = run(&["verify", &path]);
    assert_eq!(code, 1);
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "rejected");
    assert_eq!(artifact["intact"], false);
    assert!(artifact["commitment_root"].is_null());
    assert!(artifact["signing"].is_null());
}

/// External payloads are absent by design: reported in `sections.external`, never a
/// rejection.
#[test]
fn external_sections_are_reported_not_rejected() {
    let root = [0x11u8; 32];
    let m = Manifest::build(
        "chal",
        "Title",
        &["manifest", "image"],
        vec![(
            ctf_format::cbor::Value::Text("external".into()),
            ctf_format::cbor::Value::Map(vec![(
                ctf_format::cbor::Value::Uint(1),
                ctf_format::cbor::Value::Map(vec![
                    (
                        ctf_format::cbor::Value::Text("size".into()),
                        ctf_format::cbor::Value::Uint(1024),
                    ),
                    (
                        ctf_format::cbor::Value::Text("root".into()),
                        ctf_format::cbor::Value::Bytes(root.to_vec()),
                    ),
                    (
                        ctf_format::cbor::Value::Text("mirrors".into()),
                        ctf_format::cbor::Value::Array(vec![ctf_format::cbor::Value::Text(
                            "https://example.test/image".into(),
                        )]),
                    ),
                ]),
            )]),
        )],
    )
    .unwrap();
    let bytes = write_bundle(
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
                    len_plain: 1024,
                    root,
                },
                chunk_index: None,
                encryption: None,
            },
        ],
    )
    .unwrap();
    let dir = TempDir::new("external");
    let path = dir.path("external.ctf");
    std::fs::write(&path, &bytes).unwrap();

    let (code, stdout, stderr) = run(&["verify", &path]);
    assert_eq!(
        code, 2,
        "external bytes are not a rejection:\n{stdout}{stderr}"
    );
    let artifact = parse(&stdout);
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["sections"]["external"], 1);
    assert_eq!(artifact["status"], "unverified");
}

// ---------------------------------------------------------------------------
// The offline gate
// ---------------------------------------------------------------------------

/// A WAT data-string escape: every byte as `\xx`.
fn escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("\\{b:02x}"));
    }
    s
}

/// The canonical generator output block (spec §23.3).
fn generator_block(flag: &str, artifacts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(artifacts.len() as u32).to_le_bytes());
    for (name, data) in artifacts {
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
    }
    v.extend_from_slice(&(flag.len() as u32).to_le_bytes());
    v.extend_from_slice(flag.as_bytes());
    v
}

/// A generator that ignores its seed and emits a fixed block.
fn generator_wasm(block: &[u8]) -> Vec<u8> {
    let src = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{}")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 8192)
  (func (export "ctf_generate") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const {})
)
"#,
        escape(block),
        block.len()
    );
    wat::parse_str(&src).unwrap()
}

/// A solver that ignores its input and answers a fixed flag.
fn solver_wasm(flag: &str) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&(flag.len() as u32).to_le_bytes());
    block.extend_from_slice(flag.as_bytes());
    let src = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{}")
  (func (export "ctf_alloc") (param i32) (result i32) i32.const 8192)
  (func (export "ctf_solve") (param i32 i32) (result i32) i32.const 1024)
  (func (export "ctf_output_len") (result i32) i32.const {})
)
"#,
        escape(&block),
        block.len()
    );
    wat::parse_str(&src).unwrap()
}

const ID: &str = "verify-gate";

/// The reference seed and derived flag for `ID`, version 0, subject `reference`.
fn reference(secret_hex: &str) -> ([u8; 32], String) {
    let mut secret = Vec::with_capacity(32);
    for pair in secret_hex.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
        secret.push((hi << 4) | lo);
    }
    let seed = ctf_format::derive::subject_seed(&secret, ID, 0, "reference").expect("subject seed");
    let flag = ctf_format::derive::flag(&seed);
    (seed, flag)
}

/// Write the gate fixture (authoring document plus modules) and pack it into a
/// bundle, returning the bundle and document paths.
fn gate_fixture(dir: &TempDir, tag: &str, solver_flag: &str) -> (String, String) {
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let block = generator_block(&expected, &[("artifact.bin", b"artifact bytes")]);
    std::fs::write(dir.path(&format!("{tag}-gen.wasm")), generator_wasm(&block)).unwrap();
    std::fs::write(
        dir.path(&format!("{tag}-solver.wasm")),
        solver_wasm(solver_flag),
    )
    .unwrap();
    let yaml = format!(
        "spec: 1\nid: {ID}\nname: Verify Gate\nflag: derived\n\
         generate:\n  wasm: {tag}-gen.wasm\n  determinism: strict\n  outputs:\n    \
         - {{ name: artifact.bin, player_visible: true }}\n\
         verify:\n  solver: {tag}-solver.wasm\n  expect: flag\n  offline: true\n"
    );
    let source = dir.path(&format!("{tag}.yaml"));
    std::fs::write(&source, yaml).unwrap();
    let bundle = dir.path(&format!("{tag}.ctf"));
    let (code, stdout, stderr) = run(&["pack", &source, "--out", &bundle]);
    assert_eq!(code, 0, "pack failed: {stdout}{stderr}");
    (source, bundle)
}

/// Rebuild `packed` with a `generator` section, keeping its manifest.
///
/// `ctf pack` reserves module names but emits no module sections, so a bundle that
/// carries one is the stricter case the gate must prefer. The generator's
/// `name_id` is `1`, the name `pack` reserved for `generate.wasm`.
fn with_generator_section(packed: &str, generator: &[u8]) -> Vec<u8> {
    let file = std::fs::read(packed).unwrap();
    let parsed = Bundle::parse(&file).unwrap();
    let manifest = parsed
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .expect("a bundle has a manifest");
    let manifest_bytes = parsed.section_bytes(manifest).unwrap().into_owned();
    write_bundle(
        1,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(SectionKind::Generator, 1, SectionFlags::empty(), generator),
        ],
    )
    .unwrap()
}

/// A correct solver and a correct gate: `passed`, exit 0.
#[test]
fn a_passing_gate_is_passed_and_exits_zero() {
    let dir = TempDir::new("pass");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, bundle) = gate_fixture(&dir, "pass", &expected);

    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 0, "a passing gate exits 0:\n{stdout}{stderr}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "passed");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["gate"]["schema"], "ctf/verification/v1");
    assert_eq!(artifact["gate"]["status"], "passed");
    assert_eq!(artifact["gate"]["subject"], "reference");
    assert!(
        artifact["gate"]["generator_root"].as_str().is_some(),
        "a passing run records the generator root: {artifact}"
    );
}

/// A solver that answers the wrong flag: `failed`, exit 1, and neither flag appears
/// in the artifact.
#[test]
fn a_failing_gate_is_failed_and_exits_one() {
    let dir = TempDir::new("fail");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let wrong = "not-the-derived-flag";
    let (source, bundle) = gate_fixture(&dir, "fail", wrong);

    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 1, "a failing gate exits 1:\n{stdout}{stderr}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "failed");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["gate"]["status"], "failed");
    assert!(
        !stdout.contains(&expected) && !stdout.contains(wrong),
        "no flag value may appear in the artifact:\n{stdout}"
    );
    assert!(
        !stdout.contains(&secret),
        "the event secret must never appear in the artifact:\n{stdout}"
    );
}

/// §25.6 reads the declarations from the **bundle**. A bundle that declares
/// `runtime` is `unverified` even when the document passed to `--challenge` omits
/// it: before this fix, the document's silence could turn a live challenge into a
/// false `passed`.
#[test]
fn a_bundle_declaring_runtime_is_unverified_even_when_the_document_omits_it() {
    let dir = TempDir::new("bundle-runtime");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, _packed) = gate_fixture(&dir, "runtime", &expected);

    // Pack a second bundle from the same document plus a schema-valid runtime map.
    // The bundle therefore carries `runtime`; the verification document below does
    // not.
    let text = std::fs::read_to_string(&source).unwrap();
    let digest = "1".repeat(64);
    let packing = dir.path("runtime-declared.yaml");
    std::fs::write(
        &packing,
        format!(
            "{text}runtime:\n  image: \"ctf-fixture.invalid/gate@sha256:{digest}\"\n  \
             ports: [{{ container: 80, protocol: tcp }}]\n  \
             resources: {{ cpu: \"0.5\", memory: \"256Mi\", pids: 64 }}\n  \
             instancing: per_team\n  ttl: 30m\n  \
             readiness: {{ tcp: 80, timeout: 30s }}\n"
        ),
    )
    .unwrap();
    let bundle = dir.path("runtime-declared.ctf");
    let (code, stdout, stderr) = run(&["pack", &packing, "--out", &bundle]);
    assert_eq!(code, 0, "pack failed: {stdout}{stderr}");

    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(
        code, 2,
        "a bundle that declares runtime is never passed:\n{stdout}{stderr}"
    );
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["gate"]["status"], "unverified");
    assert!(
        artifact["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("runtime"),
        "the runtime declaration is the reason: {artifact}"
    );
}

/// §25.6's "declares no solver" is the bundle's `verify.solver` declaration, not a
/// module the verification document happens to name. A bundle packed without a
/// `verify` map has no solver declaration, so a full passing document cannot make
/// it `passed`.
#[test]
fn a_bundle_that_declares_no_solver_is_unverified_even_when_the_document_does() {
    let dir = TempDir::new("no-solver-declaration");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, _packed) = gate_fixture(&dir, "nosolver", &expected);

    // Drop the whole `verify` map from the packing document; `generate` stays.
    let text = std::fs::read_to_string(&source).unwrap();
    let verify_at = text.find("verify:").expect("fixture declares verify");
    let packing = dir.path("no-solver.yaml");
    std::fs::write(&packing, &text[..verify_at]).unwrap();
    let bundle = dir.path("no-solver.ctf");
    let (code, stdout, stderr) = run(&["pack", &packing, "--out", &bundle]);
    assert_eq!(code, 0, "pack failed: {stdout}{stderr}");

    // The verification document is the full passing one, solver included.
    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(
        code, 2,
        "a bundle that declares no solver is never passed:\n{stdout}{stderr}"
    );
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["gate"]["status"], "unverified");
    assert!(
        artifact["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no solver"),
        "the absent declaration is the reason: {artifact}"
    );
}

/// §25.5 runs the modules *of the bundle* when it has them. A bundle that carries
/// a `generator` section whose output block is unreadable is `failed` even when the
/// document names a generator that would pass: the section wins over the path.
#[test]
fn a_bundle_generator_section_wins_over_the_documents_module() {
    let dir = TempDir::new("section-wins");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, packed) = gate_fixture(&dir, "section-wins", &expected);

    // A valid module returning a malformed output block: the determinism stage
    // fails, which is `failed` (exit 1), not `passed`.
    let wrong = generator_wasm(&[0xff; 4]);
    let bytes = with_generator_section(&packed, &wrong);
    let bundle = dir.path("section-wins.ctf");
    std::fs::write(&bundle, &bytes).unwrap();

    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(
        code, 1,
        "the bundle's generator must be the one that runs:\n{stdout}{stderr}"
    );
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "failed");
    assert_eq!(artifact["gate"]["status"], "failed");
    assert!(
        artifact["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("determinism"),
        "the failing stage is named: {artifact}"
    );
}

/// A gate that cannot run (a challenge with no generator or solver) is
/// `unverified`, never `passed`, and exits 2 even though integrity holds.
#[test]
fn a_gate_that_cannot_run_is_unverified_and_exits_two() {
    let dir = TempDir::new("nothing-to-gate");
    let source = dir.path("chal.yaml");
    let secret = "00".repeat(32);
    std::fs::write(
        &source,
        "spec: 1\nid: verify-nothing\nname: Nothing To Gate\n",
    )
    .unwrap();
    let bundle = dir.path("chal.ctf");
    let (code, stdout, stderr) = run(&["pack", &source, "--out", &bundle]);
    assert_eq!(code, 0, "pack failed: {stdout}{stderr}");

    let (code, stdout, _stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 2, "unverified must not exit 0:\n{stdout}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["gate"]["status"], "unverified");
    assert!(
        artifact["reason"].as_str().unwrap().contains("unverified"),
        "{artifact}"
    );
}

/// A gate whose inputs cannot be resolved is `unverified`, and the artifact must
/// not carry the path it failed on. S12 forbids a file path in the record, so the
/// detail goes to stderr and the record carries a fixed sentence.
#[test]
fn a_gate_input_error_does_not_leak_its_path() {
    let dir = TempDir::new("no-module");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, bundle) = gate_fixture(&dir, "leak", &expected);

    // Same document, but the generator module now points at a path that does not
    // exist. That path is exactly what `load_gate_setup`'s error names, and the
    // artifact must not reproduce it.
    let missing = dir.path("nowhere/absent-generator.wasm");
    let text = std::fs::read_to_string(&source)
        .unwrap()
        .replace("leak-gen.wasm", &missing);
    let broken = dir.path("broken.yaml");
    std::fs::write(&broken, text).unwrap();

    let (code, stdout, stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &broken,
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 2, "a gate that did not run is not a pass:\n{stdout}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["gate"]["status"], "unverified");
    for leak in [dir.path("nowhere").as_str(), "absent-generator.wasm"] {
        assert!(
            !stdout.contains(leak),
            "the artifact must not carry a path (`{leak}`):\n{stdout}"
        );
    }
    assert!(
        stderr.contains("absent-generator.wasm"),
        "the detail belongs on stderr, where an operator can see it: {stderr}"
    );
}

/// A document describing a different challenge must not be attached to this
/// bundle as a passing gate: the derived flag would belong to another challenge.
#[test]
fn a_document_for_another_challenge_is_unverified_not_mislabelled() {
    let dir = TempDir::new("other-id");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, bundle) = gate_fixture(&dir, "other", &expected);

    // Same modules, same secret, correct solver — only the id differs.
    let text = std::fs::read_to_string(&source)
        .unwrap()
        .replace(ID, "some-other-challenge");
    let other = dir.path("other.yaml");
    std::fs::write(&other, text).unwrap();

    let (code, stdout, _stderr) = run(&[
        "verify",
        &bundle,
        "--challenge",
        &other,
        "--secret",
        &secret,
    ]);
    assert_eq!(code, 2, "a mislabelled gate must not pass:\n{stdout}");
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["gate"]["status"], "unverified");
    assert_eq!(
        artifact["gate"]["challenge"], ID,
        "the record describes the bundle, not the document it was given"
    );
}

/// Rerunning on the same bytes with the same inputs produces byte-identical JSON.
#[test]
fn the_same_inputs_produce_byte_identical_json() {
    let dir = TempDir::new("stable");
    let secret = "00".repeat(32);
    let (_seed, expected) = reference(&secret);
    let (source, bundle) = gate_fixture(&dir, "stable", &expected);

    let args = [
        "verify",
        &bundle,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ];
    let (first_code, first, _) = run(&args);
    let (second_code, second, _) = run(&args);
    assert_eq!(first_code, 0);
    assert_eq!(second_code, 0);
    assert_eq!(first, second, "the artifact must be stable across reruns");

    // And a second bundle built from the same document is byte-identical too: the
    // artifact names bytes and inputs, not paths or times.
    let rebuilt = dir.path("rebuilt.ctf");
    let (code, _, stderr) = run(&["pack", &source, "--out", &rebuilt]);
    assert_eq!(code, 0, "pack failed: {stderr}");
    let (_, third, _) = run(&[
        "verify",
        &rebuilt,
        "--challenge",
        &source,
        "--secret",
        &secret,
    ]);
    assert_eq!(
        first, third,
        "identical bundle bytes give identical artifacts"
    );
}

/// `--out` writes the artifact to a file and leaves stdout as a one-line summary.
#[test]
fn out_writes_the_artifact_to_a_file() {
    let dir = TempDir::new("out");
    let path = dir.path("chal.ctf");
    std::fs::write(&path, minimal_bundle()).unwrap();
    let out = dir.path("verification.json");

    let (code, stdout, stderr) = run(&["verify", &path, "--out", &out]);
    assert_eq!(code, 2, "unverified still exits 2 with --out: {stderr}");
    let written = std::fs::read_to_string(&out).unwrap();
    assert_eq!(parse(&written)["status"], "unverified");
    assert!(
        !stdout.contains("\"schema\""),
        "the artifact belongs in the file, not stdout:\n{stdout}"
    );
}

/// An encrypted section's bytes are present but unreadable in this build. That is
/// `unverifiable`, not a pass: the bytes cannot be hashed, so the file is rejected.
#[test]
fn an_unreadable_section_is_disclosed_not_rejected() {
    let dir = TempDir::new("sealed");
    let path = dir.path("chal.ctf");
    std::fs::write(&path, minimal_bundle()).unwrap();

    let key = dir.path("seal.key");
    let pub_key = dir.path("seal.pub");
    let (code, stdout, stderr) = run(&[
        "keys",
        "--context",
        "seal",
        "--out-key",
        &key,
        "--out-pub",
        &pub_key,
    ]);
    assert_eq!(code, 0, "keys failed: {stdout}{stderr}");

    let sealed = dir.path("sealed.ctf");
    let (code, stdout, stderr) = run(&[
        "seal",
        &path,
        "--pub",
        &pub_key,
        "--context",
        "seal",
        "--section",
        "notes",
        "--out",
        &sealed,
    ]);
    assert_eq!(code, 0, "seal failed: {stdout}{stderr}");

    let (code, stdout, _stderr) = run(&["verify", &sealed]);
    // An encrypted section's plaintext cannot be hashed without a key, which is
    // not an input to `verify`. That is disclosed, not treated as corruption: a
    // conforming bundle with a sealed writeup is not a rejected bundle (§25.6.1).
    assert_eq!(
        code, 2,
        "an intact but unchecked bundle is not a pass:\n{stdout}"
    );
    let artifact = parse(&stdout);
    assert_eq!(artifact["status"], "unverified");
    assert_eq!(artifact["intact"], true);
    assert_eq!(artifact["sections"]["unverifiable"], 1);
    assert!(
        artifact["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("could not be read"),
        "the reason must disclose the unchecked section: {stdout}"
    );
}

/// `--challenge` and `--secret` are both required together: asking for a gate
/// without the secret is a usage error (exit 1), not an `unverified` artifact.
#[test]
fn challenge_without_secret_is_a_usage_error() {
    let dir = TempDir::new("pairing");
    let path = dir.path("chal.ctf");
    std::fs::write(&path, minimal_bundle()).unwrap();

    let (code, stdout, stderr) = run(&["verify", &path, "--challenge", "chal.yaml"]);
    assert_eq!(code, 1, "a usage error exits 1:\n{stdout}{stderr}");
    assert!(!stderr.is_empty(), "the usage error must explain itself");
    assert!(
        !stdout.contains("\"schema\""),
        "no artifact is emitted for a rejected invocation:\n{stdout}"
    );
}

/// Lowercase hex, for the commitment-root assertion.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
