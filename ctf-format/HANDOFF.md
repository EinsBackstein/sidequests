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

**Last updated:** 2026-10-28, at format version 0.3 / release 1.0.0. Phases 1–8
complete, including the **Phase 5 platform** (`crates/ctf-tui`), and Phase 9's
v1.0.0 release checklist is closed. Phase 8 is complete: the **hardening audit**
(ticket 48, `docs/HARDENING-AUDIT.md`), the **hostile-input and future-file
corpora** (tickets 49/50, 35 fixtures in `spec/vectors/conformance/`), the
**independent Go implementation** (tickets 53/54, `go/`, byte-identical on both
goldens and 35/35 fixtures), the **rerunnable ingest artifact** (ticket 64, `ctf
verify`, spec §25.6.1), **`ctf pack` path emission** (ticket 88), and **fuzzing in
CI with the entitlement target** (tickets 51/107). **The specification has no
gaps** (ticket 55): §34 fixes trusted-key distribution, §20.3 fixes suite 3's
SLH-DSA parameters, and §25.6/§25.6.1 fix the gate's record and the ingest
artifact. Release **0.13.1**
is a post-release audit round (PRs #114–#118): every reader path that still
disagreed with §4.4, §5.2, §5.4, §7.6, §10, §18, §23, §24, §25, or §34 was fixed,
with no byte layout moved and both goldens unchanged. Release **0.13.2** closes the
document-veto path — a bundle that carries its own generator section is no longer
vetoed by a document naming a missing module file (a carried solver section stays
`unverified`, since R6/R21 force it sealed) — and a present non-integer
`generate.interface`/`generate.profile` is `unverified` rather than run as `1`, with
the same format version and goldens. Release **0.13.3** then makes the declaration
identify the section: the gate resolves `generate.wasm`/`verify.solver` through
`names` and never runs a section of the right kind under another name (§7.6, §25.6).
Release **0.13.4** keeps the determinism fields in a `failed` record when the solver
stage fails, and persists `ctf run`'s hard stage failures wherever it writes a record
(`--status` or `--bundle`) (§25.6, S9–S10). Release **0.13.5** states the
record boundary 0.13.4 overgeneralised: `ctf run` writes no record when it cannot reach
a gate outcome (unreadable inputs, a mismatched document, an invalid document, an
unusable secret), writes `unverified` when it identifies the bundle but a declaration
leaves the gate unrunnable, and refuses a bare document's own unrunnable declarations
without a record. Release **0.13.14** makes both implementations run §5.4's D1/D2 caps on every non-external compressed section before any encryption or decoder skip, and escapes free-form text on every CLI path that echoes it — `ctf validate`/`ctf pack` origins, `ctf run`/`ctf verify` schema keys, the gate's module path, and `ctf release` destinations — including zero-width and other format characters a `check_name`-valid name can carry (§13). Release **0.13.13** gives Go's §24 progress helper a fresh content key per payload and enforces the envelope `name_id` and the two-key shape, makes a negative projected port the §29.1 policy error it always was, matches §29.3 origins case-insensitively, and runs the descriptor policy pass in `ctf validate`. Release **0.13.12** brings the independent Go reader in line with §19.2 S2/S3 (it accepted an unregistered suite as intact), fixes Go's `VerifyChunk` double-slice (which failed chunk 1 and panicked on chunk 2), makes `CTF_SEED` outrank `--seed-file` (I3), treats an empty flag injection as a mismatch rather than an absence (I4), and gives the runtime host a `--determinism` mode so a `none` challenge can start (§23.7). Release **0.13.11** resolves `suite_id` through the registry on the read path (an unregistered suite was accepted as intact), refuses a `sealed` declaration that omits its required `members` instead of releasing every sealed section, records `event_end` rather than an invented `all`, refuses `stage_key(_, 0)` as Go already did, escapes C1 controls in `ctf inspect`'s tables, and makes an out-of-range runtime port a pack-time policy error. Release **0.13.10** makes the determinism gate honour §23.7's `none`/`flag_only` modes and report an unrecognised mode as `unverified` (never a failed run), enforces G8's declared-output rule with an escaped diagnostic, and gives each G9 run the full fuel budget. Release **0.13.9** validates a `keys` section as a whole (EN5), tries every matching envelope so multi-recipient bundles unseal in any order, makes §22.2's `event_secret` length unconstrained, makes OCI export a byte-copy that needs a valid header but not a whole-container read, applies §29.2's read-time policy pass in `ctf inspect`, `ctf verify`, `ctf run`, `ctf serving-manifest`, and `ctf release`, and gives Go the reference's 0.3-missing-bit diagnostic. Release **0.13.8** aligns Go's `SealStream`/`OpenStream` with §20.2 (zero chunks for an empty plaintext; validate chunk size, chunk count, and per-chunk lengths), states in §18.4 that hashing a section is not reading its chain, and brings the ROADMAP, hardening audit, and this file in line with the shipped tree. Release **0.13.7** fixes two `write_bundle` paths that emitted `comp = 1` sections their own reader rejected, and states in §25.6/§25.6.1 what `ctf verify` records when a requested gate cannot run. Release 0.13.6 aligned the Go CBOR depth cap with the reference, defined the M1h count in §7.1, and repaired the corpus vectors that were meant to prove §5.4's `OPTIONAL` rule. The live gate is
specified (§32) but not implemented, per design §2's scope boundary. `cargo test
--workspace` green, `go test ./...` green, 0 clippy warnings, 0 gofmt diffs.

**1.0.0 (2026-10-28) is the freeze release.** Suite 3's SLH-DSA-SHA2-128s
signature role is implemented in both Rust and Go: `sig_pq =
ML-DSA-65 (3309) ‖ SLH-DSA (7856) = 11165` bytes, split at 3309; `pk_pq = 1952 +
32 = 1984`; all three components verify over the §8.4 transcript. Go now also
covers zstd `comp = 1` with D1/D2 before the decoder, the §18 entitlement chain
E1–E9 with the §34 trust roles, and suite 3. The authoring surface gains
`external:` (design §10): entries are validated, compiled to the manifest
`external` map and `EXTERNAL` section records, and emitted by `ctf init
forensics`. Phase 5 ships as `crates/ctf-tui`: the Postgres 17 schema and `sqlx`
migrations with a committed offline cache, the validate → verify → offline gate →
store ingest pipeline, the `ratatui` admin TUI (six screens plus chunk progress),
and the dual serving checks, alongside a CI database job. **No byte-layout
change:** `version_minor` stays `3` and both goldens are byte-identical
(`minimal.ctf` 4344 B `a23cd1b3…`, `demo.ctf` 18328 B `ce1a930e…`). 1.0.0 is the
first release where the 0.3 byte layout is declared stable.

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
    src/envelope.rs     key envelopes              spec §21
    src/derive.rs       derived flags, stage keys  spec §22
    src/entitlement.rs  entitlement chain     spec §18
    src/progress.rs     sealed progress payloads   spec §24
    src/policy.rs       platform policy: digest pinning, origins  spec §29
    src/descriptor.rs   platform ingest descriptor  spec §29
    src/serving.rs      static artifact serving manifest  spec §28
    src/release.rs      sealed release + audit record     spec §27
    src/oci.rs          bundle as an OCI image            spec §30
    src/wtflag.rs       WTFlag adapter                    spec §33
    src/pack.rs         YAML -> .ctf               design §10
    src/scaffold.rs     ctf init archetypes        design §10
    examples/demo.rs    writes a demo .ctf to try the CLI against
    tests/              container, cbor, chunk, bundle, mutation, fuzzmirror,
                        policy, descriptor, serving, release, oci, wtflag
  crates/ctf-generator/ the deterministic WASM host (spec §23): Wasmtime,
                        wasmi cross-check, the determinism gate, the offline
                        solver host (spec §25), seed injection (spec §26), and
                        the `ctf-generator` container binary
  crates/ctf-conformance/ the phase-8 vector runner (tickets 49/50/52): executes
                        the golden, hostile, and future-file fixtures indexed by
                        `spec/vectors/conformance/corpus.json` against the library
  crates/ctf-cli/       the `ctf` binary — inspect, validate, pack, keygen, sign,
                        keys, seal, unseal, init, transfer, serving-manifest,
                        oci-export, oci-import, release, run, verify, completions
                        (clap); `src/verify.rs` is the §25.6.1 ingest artifact
  crates/ctf-tui/       the operator surface (design §10): Postgres 17 schema +
                        `sqlx` migrations with a committed `.sqlx` offline cache,
                        the ingest pipeline (validate -> verify -> offline gate ->
                        store), the ratatui admin TUI (six screens + chunk
                        progress), and the default-deny serving checks
  go/                   independent second implementation (tickets 53/54), written
                        from `spec/SPEC.md` alone: read path, byte-identical
                        writer, primitive vectors, the 35-fixture conformance
                        runner, and `AMBIGUITIES.md`
  sdk/rust/             Rust guest SDK + sample generator (built to wasm)
  sdk/c/                C guest SDK (header + example)
  sdk/reference/        detached guest generators for the ticket-69 fixtures
  fuzz/                 cargo-fuzz targets + committed seed corpus
  spec/SPEC.md          normative byte-level spec — wins over the design doc
  spec/generator.wit    the generator interface's source of truth
  spec/vectors/         primitive vectors (ticket 17) + `conformance/` bundles
  docs/FORMAT-DESIGN.md design rationale and threat model
  docs/ROADMAP.md       phased plan, checkboxes reflect reality
  docs/HARDENING-AUDIT.md         design §14 checklist, audited (ticket 48)
  docs/CHALLENGE-KEY-MIGRATION.md challenge-key -> (id, version) runbook (ticket 59)
  docs/WTFLAG-ADAPTER.md the flag-oracle adapter (spec §33)
  docs/MEDIA-TYPE.md    the media-type decision and the .ctf extension collision
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

## Current state — format version 0.3, phases 1–8 complete

The **container** is done: header, section table, canonical CBOR manifest, chunk
index, footer, and the commitment root over header plus table. `Bundle::parse`
runs the whole spec §10 conformance procedure; `write_bundle` produces files and
parses them back before returning. The full workspace test suite passes, with 0
clippy warnings and `unsafe_code = "forbid"`.

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

**Superseded 2026-10-27 (0.6.0–0.7.0):** the step now exists —
`Bundle::verify_signatures` returns `Authentication` only when both hybrid
components verify, and `sign_bundle` writes the footer (§20.3). The type-level
distinction above is unchanged and still the rule: parsing reports
`Signing::Present`, never "valid", so a consumer must call `verify_signatures` with
the trusted key it already has (§34). `ctf verify` does not take such a key and so
reports the footer as present or absent, not as authentic.

Implemented since 0.6.0 (spec §20): the hybrid KEM combiner (X25519 + ML-KEM-768),
the AEAD-STREAM construction (AES-256-GCM and XChaCha20-Poly1305), and hybrid
signature verification (Ed25519 + ML-DSA-65, both required). `Authentication` is a
token whose only constructor is a successful two-component check, so there is still
no API that reports a bundle authentic without having verified it. Suite 3's SLH-DSA
signature role is implemented in both implementations (1.0.0): the `sig_pq` slot is
`ML-DSA-65 ‖ SLH-DSA-SHA2-128s`, split at 3309 bytes, and all three components must
verify.

Implemented since 0.7.0: **bundle signing** (`bundle::sign_bundle`, the production
half of §20.3 — no byte outside the footer changes), **key envelopes**
(`envelope.rs`, spec §21 — a KEM-DEM wrap of a section's `content_key` to a named
recipient), **derived flags and stage keys** (`derive.rs`, spec §22 — a bundle
carries the rule, never the flag), and **`ctf pack`** (`pack.rs`, ticket 35), with
`ctf keygen`/`ctf sign` as CLI conveniences.

The only two non-implementations are key distribution (deployment, spec §34.3) and
the live gate (orchestrator project, spec §32.4); both are external by design. The
generator now **is**
implemented (0.10.0): `ctf-generator` runs a capability-free module under profile 1
and the determinism gate, with a `wasmi` cross-check.
The writer now emits `enc = 1` for an encrypted section — compress, then encrypt —
as well as `comp = 1` zstd sections; the reader enforces an absolute output cap and
an expansion-ratio cap before running the decoder (spec §5.4, D1–D2), and a
`comp = 1` + `enc = 1` body seals one zstd frame per STREAM chunk.

**Superseded 2026-10-27 (0.11.0):** the solver gate landed — `gate::offline_gate`
runs the generator at the reference seed, feeds its artifacts to `solver.wasm` in
the same sandbox, and compares the recovered flag with the derived one (§25.5).

Implemented since 0.8.0: **encrypted sections end to end** (ticket 16; the writer
seals, wraps the content key in a per-recipient envelope in the `keys` section, and
a key holder can recover and verify the plaintext), the **entitlement chain** E1–E9
(ticket 39, `entitlement.rs`), **stage gating** (tickets 45–47, `flag.stage_gate`),
`ctf keys`/`seal`/`unseal` (ticket 18), and the **`clap`** CLI with completions and
integration tests (tickets 37, 83).

**Where E1–E8 run.** Parsing the chain is what a reader must validate, so the rules
run on the paths that parse it: `EntitlementChain::from_bytes` (and therefore
`ctf transfer`, which decodes, appends, and re-embeds a chain) and the offline
validators in `entitlement.rs`. `ctf verify` is a hash-and-account pass, not a chain
reader: it reports a kind-6 section's bytes against their `root` and never decodes
the records, so it cannot and does not report a chain as structurally valid. E9
additionally needs the trusted key, exactly as §18.4 states. This is the same
boundary §18.4 now states normatively, not an undeclared gap.

**The envelope gained a `name_id` (spec §21.3, EN5)** — the identity of the section
whose content key it wraps — so one `keys` section serves every encrypted section.
No writer had ever emitted a `keys` section, so no existing file carried the old
three-key form.

Implemented since 0.9.0: the last of the post-fix review tickets. The one normative
addition is the optional **`paths`** manifest key (spec §7.2, M22–M25), which
represents a directory tree without widening `names`: a relative POSIX path per
`name_id`, checked component-by-component so `.`, `..`, an absolute path, and a `\`
are unrepresentable. `Manifest::path_of` exposes it. Everything else is diagnostic or test work: a
section root mismatch names its `name_id` and the verify pass reports every
mismatch; `crit` errors carry an entry index; `ExceedsFile` reports the real file
length; a pre-0.3 file is diagnosed as an older format; errors no longer echo input
bytes; and `ctf inspect` prints each section's full name. No byte-layout change and
no feature bit.

**Superseded 2026-10-27 (0.13.0):** `ctf pack` now emits `paths` — and lists it in
`crit` — for any authoring entry that names one (ticket 88). A document with no
paths still packs byte-for-byte as before.

Implemented since 0.10.0: **the generator** (spec §23, `ctf-generator`) — a core
WebAssembly module with no imports, run under a pinned profile (relaxed-SIMD
lowered deterministically, NaN bits canonicalized, threads off, fuel not epochs),
with a two-run gate and a `wasmi` cross-check; **Rust and C guest SDKs** and
`spec/generator.wit`; **`ctf init`** scaffolds; the **sealed-progress payload**
(spec §24, `progress.rs`) and **`ctf transfer`**, which embeds the updated chain
back into a bundle. The authoring `generate` declaration gained the `flag_only`
mode and `interface`/`profile`, and the output-to-`names` mapping is enforced by
`ctf pack`. Regression tests were added for tickets 81 and 85, whose fixes were
already shipped.

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

## v1.0.0 status

Everything in [`docs/ROADMAP.md`](docs/ROADMAP.md) is done, through Phase 9's
release checklist. Phase 5 is no longer future work: `crates/ctf-tui` is the
Postgres 17 + `sqlx` + `ratatui` operator surface, with the validate → verify →
offline gate → store ingest path, chunk progress, dual serving checks, and a CI
database job. The `external:` authoring surface landed as well, so `ctf init
forensics` packs a real external block instead of describing one in prose.

The only two non-implementations are external by design, and neither is a release
blocker:

1. **The live solvability gate** (spec §32): the orchestrator project implements
   the socket contract (§32.4). Until then a `runtime`-bearing bundle is
   `unverified`.
2. **Trusted-key provisioning** (spec §34.3): obtaining and distributing keys is a
   deployment concern. Verification takes the trust set as an input and never
   reads it from the file (§8.2).

Their absence is reported honestly as `unverified`, never as `passed`. Nothing else
in the specification is unimplemented; §14 now lists exactly these two items.

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
  fuzz targets between interactive nightly runs.
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
cargo test                    # full workspace suite
cargo clippy --all-targets    # must stay at zero warnings
cargo fmt --all

cargo run --example demo -- /tmp/demo.ctf
cargo run --bin ctf -- inspect --verify --hex /tmp/demo.ctf

cargo +nightly fuzz run bundle          # needs cargo-fuzz; not the pinned toolchain
```
