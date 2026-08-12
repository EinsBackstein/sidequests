# Changelog

All notable changes to the `.ctf` challenge transport format and its reference
implementation. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the on-disk byte layout is **not** frozen and any
minor release may break it.

## [0.1.0] — 2026-08-12

First release. Establishes the design, the byte layout of the container, and a
hardened reader and writer for it. Nothing cryptographic is implemented yet.

### Added

- **Design document** (`docs/FORMAT-DESIGN.md`) — the format's premise, threat
  model, five pillars, archetype coverage from OSINT to a 40 GB forensics image,
  cryptographic suite definitions, subject/holder model, authoring surface, and a
  parser-hardening checklist.
- **Roadmap** (`docs/ROADMAP.md`) — eight phases, each ending in something
  runnable, plus a record of deliberate simplifications so they cannot rot into
  permanent accidents.
- **Handoff document** (`HANDOFF.md`) — cold-start context, fixed requirements,
  decided tech stack, verified library facts, gotchas, and open questions.
- **`ctf-format` crate**, zero dependencies, `unsafe_code = "forbid"`:
  - `Header` — 64-byte header, normative little-endian offsets, parse and write,
    round-trips byte-for-byte.
  - `SectionRecord` — 128-byte fixed-width section table records. Fixed width is
    what lets a reader seek to record *N* without parsing records `0..N`.
  - `SectionKind`, `SectionFlags`, `Encryption`, `Compression` — the registries,
    with kind `0` reserved as always-invalid.
  - `section::parse_table` and `section::validate_layout` — per-record and
    whole-table validation.
  - `Error` — 19 typed variants, each naming the rule that rejected the input.
    Errors carry offending values but never input bytes, so an error string from a
    sealed section cannot become a decryption oracle.
- **External sections** — a section may declare its bytes live outside the file
  (hash, plaintext length, manifest-side mirror list), so a `.ctf` describing a
  40 GB forensics image stays a few kilobytes and remains mailable.
- **44 tests** covering round-trips, the header golden vector, and one case per
  hardening rule. Every rejection test mutates a known-good fixture by exactly one
  field, so a failure names the rule that broke.
- **Pinned toolchain** (`rust-toolchain.toml`, Rust 1.97.1). Load-bearing:
  generator determinism is only meaningful relative to a pinned toolchain.
- **Clippy gates** — `indexing_slicing`, `panic`, `unwrap_used`, `expect_used` all
  warn at workspace level. Currently zero warnings.

### Changed

- **`external` is a section flag, not a section kind.** A section's kind says what
  it semantically *is*; whether its bytes live inline or elsewhere is orthogonal.
  Folding them made "external writeup" unrepresentable. `SectionFlags::EXTERNAL` is
  now the single source of truth.
- **`public` is no longer a flag** — it is the absence of `SEALED`. Encoding both
  created a fourth state that meant nothing.
- **Section layout order is free** within `[HEADER_LEN, footer_off)`. The design
  doc's layout diagram is illustrative, not normative: mandating a region order
  would force a writer streaming a multi-GB payload to buffer in order to learn
  final sizes. Only non-overlap and bounds are enforced.
- **Determinism guidance corrected after checking Wasmtime's current API.**
  `relaxed-simd` need not be banned — `Config::relaxed_simd_deterministic(true)`
  forces one defined behaviour on every architecture. CPU limits **must** use
  `Config::consume_fuel` rather than `Config::epoch_interruption`: epochs are
  wall-clock driven, so a generator near the limit would pass ingest and fail in
  production.
- **Determinism gate widened** to require the same bundle on two architectures
  (x86-64 and aarch64), since two in-process runs cannot catch codegen-level
  nondeterminism.
- Header and section record layouts promoted to normative offset tables in design
  §6, matching the implementation field for field.
- Workspace `members` updated to `["ctf-format"]` after the crate moved up a level.

### Fixed

- **Crate metadata declared `Apache-2.0` while `LICENSE` is GPL-3.** Corrected to
  `GPL-3.0-only`; `-only` rather than `-or-later` because a bare `LICENSE` file
  grants no "any later version" permission on its own. See known issues.
- **Header signature was 6 bytes against a declared `magic[8]`.** Now a true 8-byte
  signature, `89 43 54 46 0d 0a 1a 0a`, following PNG's construction: high-bit
  first byte detects 7-bit stripping, `0d 0a` detects newline translation, `1a`
  stops DOS `type`, trailing `0a` detects the reverse translation.
- Two test fixtures asserted the wrong rejection reason because they violated a
  stricter rule first — a misaligned offset firing before the overflow check, and a
  footer past end-of-file firing before overlap detection. Both fixtures corrected
  and annotated with the trap they must avoid.
- Removed the empty `crates/` directory left behind by the crate move.

### Security

- **Parser hardening**, per design §14. The reader is the attack surface; every
  item below has shipped as a CVE in some real format:
  - Section count is capped **before** it can size an allocation — the single most
    common format-parser bug.
  - All integer reads go through `Option`-returning little-endian helpers, so a
    panic on hostile input is *unrepresentable* rather than merely absent.
  - Checked arithmetic on every untrusted length and offset; overflow is an error,
    never a wrap.
  - Reserved fields must be zero. Tolerating garbage there would foreclose every
    future use of the field.
  - Unknown flag bits and unknown enum discriminants are rejected, never ignored.
  - Offsets are bounds-checked and alignment-checked before use; none may point
    into the header, backwards, or past `footer_off`.
  - No two sections may overlap each other or the section table. Overlap is the
    ambiguity that becomes a parser-differential exploit.
  - `name_id` must be unique across sections.
  - Section kind `0` is invalid, so a zero-filled record rejects rather than
    reading as a plausible manifest section.
- **Leak-prevention invariants moved into the container itself**, where a caller
  cannot skip them, rather than living only in a serving layer:
  - `SEALED` and `PLAYER_VISIBLE` are mutually exclusive — a sealed-yet-servable
    section cannot be expressed at all.
  - `solver`, `writeup`, and `progress` sections must carry `SEALED`. An author who
    forgets to seal a writeup is stopped at parse time.
  - The manifest may carry none of `SEALED`, `PLAYER_VISIBLE`, `EXTERNAL`.
- **Threat model documented explicitly, including what is *not* covered**: a
  compromised platform during an event holds `event_secret` and the storage key by
  necessity, so at-rest encryption defends stolen media, not a live attacker. And
  sealing is cryptography only if the seal key is *not* resident on the platform
  during the event; otherwise it is policy. Stated normatively so the guarantee is
  not claimed falsely.

### Known issues

- **No cryptography is implemented.** No manifest parsing, no BLAKE3, no footer, no
  signatures, no encryption, no generator, no solver gate. A parsed bundle is
  structurally valid and nothing more. A reader MUST NOT treat a bundle as trusted
  until the footer commitment root and both signatures verify, and that step does
  not exist yet — so this crate is not yet an authentication boundary.
- **Byte layout is not frozen.** Major version `0`; any `0.x` release may break it.
- A section's `chunk_index_off` is bounds- and alignment-checked, but the chunk
  index's own **length** is not, because the index record format lands with verified
  streaming. Marked with a `ponytail:` comment at the site in `section.rs`.
- **ML-DSA is the least mature primitive** in the planned stack: `aws-lc-rs`
  exposes it only under the `unstable` feature, mutually exclusive with `fips`. It
  is kept behind its own trait so a `suite_id` can be retired without a format
  change, but a hybrid signature scheme resting on it is a real risk to track.
- **`bao` maturity is unaudited.** BLAKE3 verified streaming is planned on it; if
  it does not hold up, the fallback is an explicit chunk index with per-chunk
  BLAKE3.
- **Stale duplicate design doc** committed at
  `file-format/docs/FORMAT-DESIGN.md` — a pre-edit copy missing the scope boundary
  and layout sections. It will mislead a reader who finds it first.
- **Licence choice warrants review.** GPL-3 on a format reference implementation
  means anyone implementing the format against it inherits GPL obligations, which
  sits awkwardly with design §13's call for an independent second implementation.
- **`.ctf` collides with Compact C Type Format** (`libctf`, `ctfdump`, magic
  `0xcff1`). Different magic bytes, so `file`/libmagic disambiguates, but the
  extension is shared. Accepted.
- The `custom-file/` folder name does not describe the project.

### Documentation

- `docs/FORMAT-DESIGN.md` — design and normative spec text, including the threat
  model's explicit non-coverage, normative header and section-record offset tables,
  layout-freedom rules, and the parser-hardening checklist.
- `docs/ROADMAP.md` — eight phases with per-phase definitions of done, target
  repository layout, deliberate simplifications, and an explicit out-of-scope list.
- `HANDOFF.md` — cold-start context: fixed requirements, scope boundary, decided
  tech stack with rationale, verified library facts, gotchas, and open questions.
- Module-level docs in `header.rs` and `section.rs` carry the normative offset
  tables, so the layout is visible where it is implemented.
- `lib.rs` documents the mandatory outside-in reading order and states that nothing
  may be treated as trusted before signature verification exists.
- Both divergences from the original design doc are recorded at their site in the
  code as well as in the doc.

[0.1.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.1.0
