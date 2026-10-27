# Fuzz targets and the committed corpus

`fuzz/` is deliberately outside the Cargo workspace: `cargo-fuzz` needs a nightly
toolchain with sanitizer instrumentation, and `rust-toolchain.toml` pins stable
1.97.1 because generator determinism is only meaningful relative to a pinned
toolchain. Fuzzing must not be a reason to unpin it.

## Two lanes, one oracle

| Lane | Toolchain | Entry point |
|---|---|---|
| Interactive coverage-guided fuzzing | nightly | `cargo +nightly fuzz run <target>` |
| CI regression lane | **pinned stable 1.97.1** | `cargo test -p ctf-format --test fuzzmirror --test mutation` |

`crates/ctf-format/tests/fuzzmirror.rs` compiles and runs each target's body on the
pinned toolchain over the committed corpus. `tests/mutation.rs` applies the same
oracle to flips, truncations, corruption, and arbitrary bytes. The CI workflow
names that lane `Fuzz oracle (pinned toolchain)` so a regression cannot hide inside
a larger workspace result.

**The mirror's target bodies are hand-copied.** `fuzz/` is a separate crate, so
`tests/fuzzmirror.rs` cannot call into it; each target's body is duplicated there
with only the `#[test]` wrapper changed. When a target changes, change its mirror
in the same commit — `tests/fuzzmirror.rs::fuzz_targets_still_compile_and_run`
executes every copy, so a mirror that no longer compiles or no longer reaches the
accepted-and-re-encoded branch fails, but it cannot notice a *new* assertion added
only to the nightly target. Treat the pair as one edit.

The oracle in every target is:

- no panic, no unbounded allocation from an unvalidated length;
- deterministic parse;
- anything accepted re-encodes byte-for-byte.

## Targets and seeds

| Target | Seed(s) | What the seed reaches |
|---|---|---|
| `bundle` | `corpus/bundle/demo.ctf` | the whole §10 procedure |
| `section_table` | `corpus/section_table/padding.ctf` | T8 non-zero padding (offset 200) |
| `header` | `corpus/header/demo-header.bin` | a valid 64-byte header |
| `manifest` | `corpus/manifest/demo.cbor` | a canonical CBOR manifest |
| `chunk_index` | `corpus/chunk_index/demo-index.bin` | `count` byte + `count × 32` chaining values |
| `entitlement` | `corpus/entitlement/chain.cbor` | a valid encoded §18 chain |

`chunk_index` and `entitlement` inputs carry their own framing: see the target
body. The rest take the raw structure.

## A crash becomes a regression test

1. `cargo +nightly fuzz run <target>` writes the offending input to
   `fuzz/artifacts/<target>/<hash>`.
2. Copy that file into `fuzz/corpus/<target>/` (any filename; the corpus is
   data-driven).
3. Add an assertion to `tests/fuzzmirror.rs` only when the input must reach a
   *specific* rule — the mutation suite already pins named rules. Most crash
   reproductions need no code: the mirror runs every file in every corpus
   directory on the next CI run.
4. Commit the seed. A fix without the seed is not fixed: the next change can
   reintroduce it with nothing failing.

Because the corpus is the seed set the stable-toolchain mirror executes, a
regression input committed here is also a permanent, toolchain-independent test.
