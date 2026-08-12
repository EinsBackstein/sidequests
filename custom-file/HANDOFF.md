# Handoff — `.ctf` challenge transport format

Cold-start context for whoever picks this up. Read this, then
[`docs/FORMAT-DESIGN.md`](docs/FORMAT-DESIGN.md) (the spec source) and
[`docs/ROADMAP.md`](docs/ROADMAP.md) (what is built and what is next).

**Last updated:** 2026-08-12, at release `ctf-format-v0.1.0`.

## Where this lives

`sidequests` is a collection repo for unrelated side projects. This project owns
the `custom-file/` subfolder and nothing outside it. Do not add files to the repo
root except shared housekeeping like `.gitignore`.

```
custom-file/
  Cargo.toml           workspace root — members = ["ctf-format"]
  rust-toolchain.toml   pinned 1.97.1 — load-bearing, see below
  ctf-format/           the only crate today
    src/{lib,error,header,section}.rs
    tests/container.rs  44 tests
  docs/FORMAT-DESIGN.md design + normative spec text
  docs/ROADMAP.md       phased plan, checkboxes reflect reality
  CHANGELOG.md
  HANDOFF.md            this file
  LICENSE               GPL-3.0
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

## Current state — release 0.1.0

Implemented and green: the header and section table, with the full design §14
hardening list. 44 tests, 0 clippy warnings, zero dependencies,
`unsafe_code = "forbid"`.

Not implemented: **everything cryptographic.** No manifest parsing, no BLAKE3, no
footer, no signatures, no encryption, no generator, no solver gate. A parsed bundle
is *structurally* valid and nothing more.

> A reader MUST NOT treat a bundle as trusted until the footer commitment root and
> both signatures verify. That step does not exist yet, so nothing downstream may
> consume this crate as an authentication boundary today.

## Next three things, in order

1. **Canonical CBOR manifest** encode/decode, RFC 8949 §4.2. Deterministic encoding
   is mandatory — the commitment in pillar 3 is byte-exact, so a non-canonical
   encoder silently breaks it. Depth cap on nesting; reject duplicate map keys.
2. **BLAKE3 section roots + footer commitment.** Audit `bao` maturity before
   committing to it for verified streaming; fall back to an explicit chunk index
   with per-chunk BLAKE3 if it is not solid. Then the chunk index's own length can
   finally be bounds-checked — see the `ponytail:` comment in `section.rs`.
3. **`ctf inspect`** and the full-file golden vector, which is blocked on 1 and 2.

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
- `solver`, `writeup`, `progress` **must** carry `SEALED`.
- The manifest may carry none of `SEALED`, `PLAYER_VISIBLE`, `EXTERNAL`.
- Section kind `0` is invalid, so a zero-filled record rejects rather than reading
  as a plausible manifest section.

## Open questions for the user

1. **GPL-3.0 for a format reference implementation?** `Cargo.toml` now declares
   `GPL-3.0-only` to match `LICENSE`. Design §13 wants an independent second
   implementation, and GPL on the reference library means anyone implementing the
   format against it inherits GPL obligations. A permissive licence for the format
   crate specifically may be what is actually wanted.
2. **`custom-file/docs/FORMAT-DESIGN.md` has a stale duplicate** at
   `custom-file/file-format/docs/FORMAT-DESIGN.md` — a pre-edit copy, still naming
   the platform "p4ssive" and missing the scope boundary and layout sections. It
   was offered for deletion twice and left in place, so it is committed as-is. It
   will mislead a reader who finds it first.
3. **Folder name `custom-file/`** does not describe the project. Renaming later
   costs nothing but breaks the release tag's path association.
4. **`.ctf` collides with Compact C Type Format** (`libctf`, `ctfdump`, magic
   `0xcff1`). Different magic bytes, so `file`/libmagic disambiguates cleanly, but
   the extension is shared. Accepted, not blocking.

## Commands

```bash
cd custom-file
cargo test                    # 44 tests
cargo clippy --all-targets    # must stay at zero warnings
cargo fmt --all
```
