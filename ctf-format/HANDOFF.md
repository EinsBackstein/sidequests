# Handoff — `.ctf` challenge transport format

Cold-start context for whoever picks this up. Read this, then
[`docs/FORMAT-DESIGN.md`](docs/FORMAT-DESIGN.md) (the spec source) and
[`docs/ROADMAP.md`](docs/ROADMAP.md) (what is built and what is next).

> **Resuming mid-stream?** [`TODO.md`](TODO.md) holds the state of the 0.3 review.
> **All review tiers are complete** — B1–B4, H1–H6, L1–L8. The 2026-09-20 post-fix
> re-review recorded 28 further findings as tickets (70–97) and explicitly deferred
> them rather than folding them in; see
> `docs/reviews/0.3-phase1/post-fix/REVIEW.md`. **0.3 is tagged.** TODO.md also carries
> one rejected finding that must not be re-raised, and the reasoning behind every
> decision, including cases where what shipped is deliberately *not* what a review
> proposed.

**Last updated:** 2026-09-20, at format version 0.3 / release 0.6.0 (phase 1
complete, phase 2 constructions landed; `cargo test` 234 pass).

## Where this lives

`sidequests` is a collection repo for unrelated side projects. This project owns
the `ctf-format/` subfolder and nothing outside it. Do not add files to the repo
root except shared housekeeping like `.gitignore`.

```
ctf-format/
  Cargo.toml            workspace root
  rust-toolchain.toml   pinned 1.97.1 — load-bearing, see below
  crates/ctf-format/    the library
    src/lib.rs          constants, LE readers, the reading order
    src/error.rs        every way a byte stream can be wrong
    src/header.rs       64-byte header            spec §4
    src/section.rs      128-byte records + table   spec §5, §6
    src/cbor.rs         canonical CBOR             spec §7.1
    src/manifest.rs     manifest schema            spec §7
    src/footer.rs       footer + commitment root   spec §8
    src/chunk.rs        chunk index                spec §9
    src/compress.rs     zstd framing + caps        spec §5.4
    src/suite.rs        crypto suite registry      spec §19
    src/authoring.rs    YAML authoring schema      spec §7.8
    src/bundle.rs       whole-file read and write  spec §10
    examples/demo.rs    writes a demo .ctf to try the CLI against
    tests/              container, cbor, chunk, bundle, mutation, fuzzmirror
  crates/ctf-cli/       the `ctf` binary — `inspect` only so far
  fuzz/                 cargo-fuzz targets + committed seed corpus
  spec/SPEC.md          normative byte-level spec — wins over the design doc
  docs/FORMAT-DESIGN.md design rationale and threat model
  docs/ROADMAP.md       phased plan, checkboxes reflect reality
  CHANGELOG.md
  HANDOFF.md            this file
```

## What the project is

A single-file container format, extension `.ctf`, that carries **one CTF
challenge** from an author's machine to a platform's admin TUI and into a
long-term archive.

The premise that makes it more than a zip-plus-YAML wrapper:

> A challenge is a **pure deterministic function** `challenge(seed) -> (artifacts,
> flag, oracle)`, plus a **verifiable commitment** to that function.

Five pillars follow from it: deterministic WASM generator, derived flags (the
bundle stores a rule, never a flag value), publish-before/prove-after sealing,
cryptographic stage gating, and a solvability publish gate. Design §3.

## Requirements the user fixed (do not relitigate)

| # | Requirement |
|---|---|
| R1 | Encryption at rest, hybrid classical **and** post-quantum |
| R2 | Every archetype: OSINT text-only (~6 KB) → 40 GB forensics image |
| R3 | Subject = single player, team, or transferred between players |
| R4 | Extension `.ctf` |
| R5 | Low-level performance without weakening security |
| R6 | Trivial for challenge developers, however hard that makes the standard |
| R7 | Runtime is a digest-pinned image ref; no in-bundle Docker build context |
| R8 | Shared **and** per-team instancing — as *schema*, see scope note |
| R9 | Static and per-subject derived flags |
| R10 | Bundles authored in-house, single trusted author org |

**Scope boundary:** container orchestration is a *separate downstream project*,
started once this standard is stable. The manifest still *declares* the runtime
contract, because that declaration is the interface the future orchestrator
consumes. Consequence: the solvability gate splits into an offline half
(implemented here) and a live half (specified here, implemented there).

## Tech stack, decided

| Layer | Choice | Note |
|---|---|---|
| Core lib + CLI | **Rust** | Compiles native + `wasm32` + C ABI, so one validator serves CLI, server, and browser |
| WASM host | **Wasmtime**, `wasmi` as cross-check | Only engine with every determinism knob §8 needs |
| Generator interface | WIT + `wit-bindgen` | Serves R6: guest SDKs for many languages free |
| Crypto | `aws-lc-rs` + `blake3`/`bao` + `libcrux-ml-kem` + pinned `ml-dsa` | See the ML-DSA warning below |
| Platform UI | **TUI (ratatui)** | Not a web dashboard |
| DB | **Postgres / CloudNativePG** | Plain SQL, no CNPG awareness in code |
| Second impl (§13) | **Go** | Deliberately a different language, written from spec text alone |

Orchestration, object storage, and a web frontend are explicitly *not* this
project's problem.

## Verified library facts that shaped the design

Confirmed against current docs, not from memory. Re-verify before changing:

- **Wasmtime**: `relaxed-simd` does not need banning —
  `Config::relaxed_simd_deterministic(true)` forces one defined behaviour on every
  architecture. Pair with `Config::cranelift_nan_canonicalization(true)`.
- **CPU limits must use fuel, not epochs.** `Config::consume_fuel` traps at a fixed
  fuel count, so the limit is part of the deterministic result.
  `Config::epoch_interruption` is wall-clock driven, so a generator near the limit
  would pass ingest and fail in production. This is a correctness requirement, not
  a preference.
- Wasmtime's `rr` config *validates* the determinism settings above and fails
  otherwise. Use it in the conformance suite.
- **aws-lc-rs**: ML-KEM is stable (`kem::ML_KEM_768`). **ML-DSA is `unstable` only
  and mutually exclusive with the `fips` feature.** So "one audited provider for
  everything" is not available. ML-DSA is the least mature primitive in the whole
  stack — keep it behind its own trait so `suite_id` can retire a suite without a
  format change.
- **`blake3::hazmat` is stable and does what `bao` was wanted for.** `blake3`
  1.8.6 exposes `HasherExt::set_input_offset`, `finalize_non_root`,
  `merge_subtrees_non_root`, and `merge_subtrees_root` in the main crate — enough
  to compute subtree chaining values and merge them back to a root without an
  extra dependency and without an extra on-disk encoding.
- **`bao` 0.13.1 was audited and rejected**, on spec surface rather than quality.
  It is by BLAKE3's author, with its own written spec and vectors, but depending on
  it makes *its* encoding a normative part of `.ctf`, which the Go second
  implementation would have to reproduce with no Go `bao` available. Pre-1.0 with a
  single maintainer was the secondary concern. See `docs/ROADMAP.md` phase 1.

## Current state — format version 0.3, phase 1 complete

The **container** is done: header, section table, canonical CBOR manifest, chunk
index, footer, and the commitment root over header plus table. `Bundle::parse`
runs the whole spec §10 conformance procedure; `write_bundle` produces files and
parses them back before returning. 234 tests, 0 clippy warnings, `unsafe_code =
"forbid"`.

`ctf inspect` prints the header, manifest, section table, chunk indices, mirrors,
and commitment root, with `--verify` to re-hash every inline section and `--hex`
for the annotated dump.

**Intact is not authentic**, and the distinction is in the type system rather than
in a comment. A successful parse proves the file commits to its own bytes.
`Bundle::signing()` returns `Signing::Unsigned` or `Signing::Present` — never
"valid" — because verifying the signatures needs phase 2's suite registry. There
is deliberately no API that reports a bundle as authentic.

> An attacker who rewrites a bundle and recomputes the root produces a perfectly
> intact file. Only the signatures distinguish the author's bundle from anyone
> else's, and that step does not exist yet, so nothing downstream may consume this
> crate as an authentication boundary today.

Implemented since 0.6.0 (spec §20): the hybrid KEM combiner (X25519 + ML-KEM-768),
the AEAD-STREAM construction (AES-256-GCM and XChaCha20-Poly1305), and hybrid
signature verification (Ed25519 + ML-DSA-65, both required). `Authentication` is a
token whose only constructor is a successful two-component check, so there is still
no API that reports a bundle authentic without having verified it. Suite 3's SLH-DSA
signature role reports `NotImplemented`.

Not implemented: **key envelopes**, **derived flags**, entitlement signature
verification, key distribution, and the live gate. No generator, no solver gate.
The writer still emits `enc = 0` only, but it *does*
write `comp = 1` zstd sections: the reader enforces an absolute output cap and an
expansion-ratio cap before running the decoder (spec §5.4, D1–D2). The authoring
surface (`authoring.rs`) parses design §10 YAML, rejects unknown keys, and now
policy-checks via `ctf validate`; `ctf pack` is not wired up yet.

### What 0.3 changed, and why the bit is `ro_compat`

0.3 adds R19, R20, T6, and T7, which reject files 0.2 would have accepted. A
narrowing needs a feature bit (spec §15), so 0.3 assigns `feat_ro_compat` bit 0,
`CONTAINER_V1`, and every 0.3 writer sets it.

**Two separate questions, and conflating them is the trap.** *Does this narrow
what is legal?* decides whether a bit is needed. The criticality test decides
which word it goes in — and it says `ro_compat` here. A 0.2 reader meeting a 0.3
file serves nothing new, trusts nothing, verifies nothing, and does not
mis-locate the chunk index, because 0.2 §5.5 forbids dereferencing
`chunk_index_off` at all. It merely fails to *account* for bytes it never touches.
A valid 0.3 file satisfies every 0.2 rule too, since R19, R20, T6 and T7 only
narrow.

The severe hazard is the 0.2 **rewriter**, which would drop the footer, the
manifest, and every chunk index while re-emitting — spec §4.4's definition of
`ro_compat`, word for word.

So: 0.3 files are readable by 0.2 readers and unrewritable by them; 0.3 readers
read everything a 0.2 file defines and name what is missing before a
whole-container read. Both directions are tested. 0.1 and 0.2 golden headers still
parse and are still asserted.

An earlier cut put this in `feat_incompat`, which would have made every 0.3 file
unreadable to every 0.2 reader — spending the forward-compatibility mechanism on
its first use. If you are about to reach for `feat_incompat` because a change feels
big, that is the wrong reason; run the four clauses.

## Next three things, in order

**0.5.0 lands the phase 2 groundwork and the authoring surface** (tickets 9, 19,
32, 33, 36, 38, 57): the suite registry, zstd with its caps, the YAML schema with
strict key rejection, the declaration keys and `platform` overlay, the entitlement
record format, and inspector regression tests. What remains, in order:

1. **The rest of phase 2.** Tickets 10–12 landed in 0.6.0 (spec §20). What remains:
   key envelopes (14), signing bundles (13), flag derivation (15), encrypted
   sections end to end (16), and cross-library primitive vectors (17). Each plugs
   into an existing trait and needs no byte-layout change.
2. **`ctf pack`** (ticket 35). The authoring schema, the manifest declaration keys,
   and `ctf validate` now exist, so `pack` is the wiring: YAML → manifest +
   sections, resolving output names to `name_id`s and external entries to records.
3. **The entitlement chain implementation** (ticket 39). The record format is
   specified (spec §18) and the signature primitive now exists (spec §20.3), so E9
   is implementable.

## Gotchas that will bite you

- **`rust-toolchain.toml` is load-bearing.** Generator determinism is only
  meaningful relative to a pinned toolchain. Bumping it is a format-relevant
  decision, not routine maintenance.
- **Reject unknown, never ignore.** Unknown flag bits, unknown enum discriminants,
  and non-zero reserved fields are all hard rejects. A typo'd field silently
  publishing a hidden challenge mid-event is a real incident.
- **Test fixtures trip earlier checks.** Two tests failed on first run because a
  fixture violated a stricter rule before reaching the rule under test — a
  misaligned offset firing before the overflow check, a footer past EOF firing
  before overlap detection. Every rejection test mutates a known-good fixture by
  exactly one field, and the ones with traps carry a comment saying so. Keep that
  discipline or tests will pass while proving nothing.
- **Clippy config is deliberate**, not decoration: `indexing_slicing`, `panic`,
  `unwrap_used`, `expect_used` all warn. Parsing uses `Option`-returning
  little-endian helpers so a panic on hostile input is *unrepresentable* rather
  than merely absent. Tests opt out via a file-level `allow`.
- **Little-endian, normatively.** Every integer is read and written explicitly, so
  a big-endian host produces identical bytes. Do not reach for `to_ne_bytes`.
- **Unknown section kinds go through `SectionKind::unknown(v) -> Option`, and the
  payload is opaque.** `SectionKind::Unknown` carries a `FutureKind`, not a bare
  `u16`, so a known discriminant cannot be wrapped as an unknown one — `Unknown(1)`
  would otherwise serialize as `kind = 1` and produce a section falsely claiming to
  be the manifest. Get the raw value with `FutureKind::get()`. When phase 1 gains a
  writer, this is the difference between a mislabelled section being impossible and
  being merely unlikely.
- **Invariants belong in types, not in comments**, wherever the cost is a newtype.
  The rule above started as a `debug_assert` plus a doc comment, which is a
  convention a release build does not enforce. Prefer the version a caller cannot
  get wrong: the format outlives any single implementation of it, and a second
  language will be checked against this one.
- **Canonical CBOR is enforced on decode, not only on encode.** This is the part a
  general-purpose CBOR library will not do, and it is why `cbor.rs` is hand-written
  rather than a dependency. The commitment is over bytes, so an encoding a decoder
  tolerates but an encoder would never produce is a second spelling of one manifest
  and therefore a second commitment root. Duplicate map keys are unrepresentable
  rather than resolved, because last-wins and first-wins are both defensible and
  that is exactly how two conforming readers end up disagreeing about a file they
  both accepted.
- **The chunk index stores chaining values, not hashes.** `blake3::hazmat` is
  marked hazardous material for good reason: get the tree shape wrong and you get
  a plausible-looking value that never matches `blake3::hash`. The invariant is
  checked against `blake3::hash` directly, over 48 input shapes, in
  `tests/chunk.rs::index_reduces_to_the_blake3_hash`. Do not change the merge
  without re-running it.
- **A test filler with a short period hides real bugs.** The chunk-swap test
  originally used `(i * 31) as u8`, which repeats every 256 bytes — so every
  4096-byte chunk was byte-identical and a swapped chunk passed because it
  genuinely was the same bytes. The filler is now a BLAKE3 XOF stream.
- **The writer parses its own output** before returning it. Cheap, and it means a
  writer that could emit a file its own reader rejects does not exist.
- **`fuzz/` is outside the workspace** because `cargo-fuzz` needs nightly and the
  toolchain pin is load-bearing. `tests/fuzzmirror.rs` compiles and runs each
  target's body on the pinned toolchain, so an API change cannot silently rot the
  fuzz targets between nightly CI runs.
- Rust was installed with rustup `--no-modify-path`; `~/.cargo/bin` has since been
  appended to `~/.zshrc`.

## Two design divergences from the original doc, already synced into §6

- **`external` is a flag, not a kind.** Kind says what a section *is*; where its
  bytes live is orthogonal. Folding them made "external writeup" unrepresentable.
- **Section layout order is free** within `[HEADER_LEN, footer_off)`. The layout
  diagram is illustrative. Mandating a region order would force a writer streaming
  40 GB to buffer to learn sizes. Only overlap and bounds are normative.

## Invariants deliberately enforced in the container, not the caller

These stop the failure mode design §4 calls primary. Do not relax them into
serving-layer checks:

- `SEALED` and `PLAYER_VISIBLE` are mutually exclusive — a sealed-yet-servable
  section cannot be expressed.
- `SEALED` requires `enc ≠ 0` (R21) — a sealed-yet-*readable* section cannot be
  expressed either. Consequence: with no encryption in phase 1, the writer cannot
  emit a `solver`, `writeup`, or `progress` section at all. That is intended.
- No byte of a bundle is uncommitted (T8): unclaimed bytes between structures MUST
  be zero, so a padding byte cannot be changed without changing the file's identity.
  Without it a phase 2 signature would cover two different files.
- `solver`, `writeup`, `progress` **must** carry `SEALED`.
- The manifest may carry none of `SEALED`, `PLAYER_VISIBLE`, `EXTERNAL`.
- Section kind `0` is invalid, so a zero-filled record rejects rather than reading
  as a plausible manifest section.

## Open questions for the user

1. **`.ctf` collides with Compact C Type Format** (`libctf`, `ctfdump`, magic
   `0xcff1`). Different magic bytes, so `file`/libmagic disambiguates cleanly, but
   the extension is shared. Accepted, not blocking.

## Commands

```bash
cd ctf-format
cargo test                    # 234 tests
cargo clippy --all-targets    # must stay at zero warnings
cargo fmt --all

cargo run --example demo -- /tmp/demo.ctf
cargo run --bin ctf -- inspect --verify --hex /tmp/demo.ctf

cargo +nightly fuzz run bundle          # needs cargo-fuzz; not the pinned toolchain
```
