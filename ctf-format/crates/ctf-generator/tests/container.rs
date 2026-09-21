//! The container entrypoint (ticket 67): the `ctf-generator` binary runs a sample
//! generator end to end with an injected seed and writes its artifacts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

const SAMPLE: &[u8] = include_bytes!("fixtures/generator.wasm");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ctf-bin-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_binary_runs_a_sample_generator_with_an_injected_seed() {
    let dir = scratch("sample");
    let module = dir.join("gen.wasm");
    let seed = dir.join("seed");
    let out = dir.join("data");
    let flag = dir.join("flag");
    std::fs::write(&module, SAMPLE).unwrap();
    std::fs::write(&seed, [0x5au8; 32]).unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_ctf-generator"))
        .arg("--module")
        .arg(&module)
        .arg("--out")
        .arg(&out)
        .arg("--seed-file")
        .arg(&seed)
        .arg("--flag-out")
        .arg(&flag)
        .status()
        .unwrap();
    assert!(status.success(), "the generator binary must succeed");

    assert_eq!(std::fs::read(out.join("chal")).unwrap().len(), 44);
    assert!(out.join("key.bin").is_file());
    assert_eq!(std::fs::read_to_string(&flag).unwrap(), "ctf{example}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_binary_refuses_to_run_without_a_seed() {
    let dir = scratch("no-seed");
    let module = dir.join("gen.wasm");
    let out = dir.join("data");
    std::fs::write(&module, SAMPLE).unwrap();

    // A seed file that does not exist: the binary must fail, not guess.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_ctf-generator"))
        .arg("--module")
        .arg(&module)
        .arg("--out")
        .arg(&out)
        .arg("--seed-file")
        .arg(dir.join("absent"))
        .env_remove("CTF_SEED")
        .status()
        .unwrap();
    assert!(!status.success(), "a container with no seed must fail");
    let _ = std::fs::remove_dir_all(&dir);
}
