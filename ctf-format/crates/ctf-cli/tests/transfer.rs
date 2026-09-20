//! `ctf transfer` tests (tickets 41, 43, 44).
//!
//! A handoff is only real if it verifies: the binary appends a holder-signed
//! transfer, seals progress to the new holder, and refuses to write a chain whose
//! signatures do not check out. These tests build a genesis with the library, drive
//! the binary, and then re-validate and re-open the result with the library — both
//! as a chain file and embedded in a bundle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::process::Command;

use ctf_format::{
    Bundle, EntitlementChain, HolderKeys, HybridPublicKey, HybridSigningKey, Manifest,
    SectionFlags, SectionKind, SectionSpec, VERSION_MAJOR, holder_hash, open_progress, suite,
};

const BIN: &str = env!("CARGO_BIN_EXE_ctf");
const SUITE: u16 = 1;
const ROOT: [u8; 32] = [0x11; 32];

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("ctf-transfer-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signing_keypair() -> (HybridSigningKey, HybridPublicKey) {
    suite(SUITE)
        .unwrap()
        .signature()
        .unwrap()
        .keypair()
        .unwrap()
}

fn write_signing_key(dir: &TempDir, name: &str, key: &HybridSigningKey) -> String {
    dir.write(
        name,
        format!("{}\n{}\n", hex(&key.classical), hex(&key.pq)).as_bytes(),
    )
}

fn write_public_key(dir: &TempDir, name: &str, key: &HybridPublicKey) -> String {
    dir.write(
        name,
        format!("{}\n{}\n", hex(&key.classical), hex(&key.pq)).as_bytes(),
    )
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
fn transfer_appends_a_verified_record_and_seals_progress() {
    let dir = TempDir::new("chain");

    let (platform_sk, platform_pk) = signing_keypair();
    let (holder_sk, holder_pk) = signing_keypair();
    let mut chain = EntitlementChain::new();
    chain
        .append_grant(
            "bird",
            "alice",
            holder_hash(&holder_pk),
            ROOT,
            SUITE,
            &platform_sk,
            None,
        )
        .unwrap();
    let chain_path = dir.write("chain.cbor", &chain.encode().unwrap());

    let holder_key_path = write_signing_key(&dir, "holder.key", &holder_sk);
    let holder_pub_path = write_public_key(&dir, "holder.pub", &holder_pk);
    let platform_key_path = write_signing_key(&dir, "platform.key", &platform_sk);
    let platform_pub_path = write_public_key(&dir, "platform.pub", &platform_pk);

    let (_, new_pk) = signing_keypair();
    let new_holder = hex(&holder_hash(&new_pk));
    let new_kem = suite(SUITE).unwrap().kem().unwrap().generate().unwrap();
    let kem_path = dir.write(
        "new.kem",
        format!("{}\n", hex(&new_kem.public_key)).as_bytes(),
    );
    let progress_path = dir.write("progress.bin", b"stages:1,2");

    let out = dir.path("chain.out");
    let (ok, _, err) = run(&[
        "transfer",
        &chain_path,
        "--out",
        &out,
        "--challenge",
        "bird",
        "--subject",
        "alice",
        "--new-holder",
        &new_holder,
        "--holder-key",
        &holder_key_path,
        "--holder-pub",
        &holder_pub_path,
        "--platform-key",
        &platform_key_path,
        "--platform-pub",
        &platform_pub_path,
        "--progress",
        &progress_path,
        "--holder-kem",
        &kem_path,
        "--suite",
        "1",
    ]);
    assert!(ok, "transfer failed: {err}");

    let updated = EntitlementChain::from_bytes(&std::fs::read(&out).unwrap()).unwrap();
    updated.validate().unwrap();
    assert_eq!(updated.len(), 2);

    let mut holders = HolderKeys::new();
    holders.insert(holder_hash(&holder_pk), holder_pk);
    updated
        .verify_signatures(SUITE, &platform_pk, &holders)
        .unwrap();

    // The progress opens only with the new holder's KEM key.
    let payload = updated.get(1).unwrap().payload.clone().unwrap();
    let opened = open_progress(
        SUITE,
        VERSION_MAJOR,
        &new_kem.secret_key,
        "bird",
        "alice",
        &payload,
    )
    .unwrap();
    assert_eq!(opened, b"stages:1,2");
}

#[test]
fn transfer_embeds_the_updated_chain_back_into_a_bundle() {
    let dir = TempDir::new("bundle");

    let (platform_sk, platform_pk) = signing_keypair();
    let (holder_sk, holder_pk) = signing_keypair();
    let (_, new_pk) = signing_keypair();
    let new_holder = hex(&holder_hash(&new_pk));

    let mut chain = EntitlementChain::new();
    chain
        .append_grant(
            "bird",
            "alice",
            holder_hash(&holder_pk),
            ROOT,
            SUITE,
            &platform_sk,
            None,
        )
        .unwrap();
    let chain_bytes = chain.encode().unwrap();

    // A bundle with a manifest and the genesis entitlement section.
    let manifest = Manifest::minimal("bird", "Bird", &["manifest", "entitlement"]).unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let bundle = ctf_format::write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(
                SectionKind::Entitlement,
                1,
                SectionFlags::empty(),
                &chain_bytes,
            ),
        ],
    )
    .unwrap();
    let bundle_path = dir.write("chal.ctf", &bundle);

    let holder_key_path = write_signing_key(&dir, "holder.key", &holder_sk);
    let holder_pub_path = write_public_key(&dir, "holder.pub", &holder_pk);
    let platform_key_path = write_signing_key(&dir, "platform.key", &platform_sk);
    let platform_pub_path = write_public_key(&dir, "platform.pub", &platform_pk);

    let out = dir.path("chal.out.ctf");
    let (ok, _, err) = run(&[
        "transfer",
        &bundle_path,
        "--out",
        &out,
        "--bundle",
        "--challenge",
        "bird",
        "--subject",
        "alice",
        "--new-holder",
        &new_holder,
        "--holder-key",
        &holder_key_path,
        "--holder-pub",
        &holder_pub_path,
        "--platform-key",
        &platform_key_path,
        "--platform-pub",
        &platform_pub_path,
        "--suite",
        "1",
    ]);
    assert!(ok, "bundle transfer failed: {err}");

    let bytes = std::fs::read(&out).unwrap();
    let parsed = Bundle::parse(&bytes).unwrap();
    let record = parsed
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Entitlement)
        .expect("output bundle keeps an entitlement section");
    let updated = EntitlementChain::from_bytes(&parsed.section_bytes(record).unwrap()).unwrap();
    updated.validate().unwrap();
    assert_eq!(updated.len(), 2);
}
