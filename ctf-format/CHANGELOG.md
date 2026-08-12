# Changelog

All notable changes to the `.ctf` challenge transport format and its reference
implementation. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the on-disk byte layout is **not** frozen and any
minor release may break it.

## [0.2.0] — 2026-08-12

Two themes: the format becomes extensible without becoming permissive, and a
review of the design document closes sixteen decisions that were cheap to fix now
and expensive once bundles exist.

**No field moved.** The 0.1 header remains valid — its 24 zeroed reserved bytes are
exactly what 0.2 reads as "no features in use" — and the section-record golden
vector is unchanged. Only `version_minor` differs, at offset 10.

### Added — compatibility model (spec §2.3, §11, §12)

- **`feat_incompat` and `feat_ro_compat`**, two `u32` words carved from the
  header's reserved space at offsets 40 and 44. An unimplemented `incompat` bit
  rejects the file and names the missing feature; an unimplemented `ro_compat` bit
  leaves it readable but not rewritable, which is what stops a future
  `ctf transfer` from silently dropping data it does not understand while
  re-signing the bundle. Both are checked **before** the reserved-zero and
  flag rules, so a future file yields an accurate diagnostic instead of a
  confusing structural one.
- **`SectionFlags::OPTIONAL`** (bit 3): a section kind a reader does not implement
  is skipped rather than rejected. Skipped sections are still bounds- and
  overlap-checked, still committed, and never served, executed, or decrypted.
  `OPTIONAL` on a *known* kind is legal and inert — required, or the mechanism
  would break the day a formerly-unknown kind becomes known.
- **The criticality test**, which decides which mechanism a future change may use:
  an extension may be ignorable only if not understanding it cannot lead a reader
  to serve, execute, mis-verify, or mis-locate anything. Anything else is
  incompatible. Ignoring is safe only because the commitment covers what is
  skipped.
- **Extension policy (§11) and compatibility matrix (§12)** — the first binds
  future editors of the spec, the second states honestly that readers older than
  0.2 reject what they cannot understand, so graceful forward compatibility begins
  here and is not retroactive.
- `Header::may_rewrite`, `SectionKind::is_known`, `SectionKind::to_u16`,
  `SUPPORTED_INCOMPAT`, `SUPPORTED_RO_COMPAT`, and `Error::UnsupportedFeature`.
- Nine tests, including the 0.1 golden header kept as a permanent backward
  compatibility regression, and a test pinning the feature-before-reserved check
  order that the diagnostics depend on.

### Fixed — design review (`docs/FORMAT-DESIGN.md`)

Ordered by what they would have cost.

- **Unlength-prefixed concatenation in seed derivation.** `HKDF(event_secret,
  chal_id ‖ version ‖ subject_id)` is ambiguous: `("ab","c")` and `("a","bc")`
  produce identical input, so two subjects derive the same flag and per-subject
  attribution fails silently and open. Every variable-length input is now
  length-prefixed (`LP(x) = u32_le(len) ‖ x`) and every derivation carries a
  versioned domain label.
- **The AEAD nonce was built from fields that do not exist.** `section_id` and
  `key_epoch` appeared in the STREAM construction but in no layout. Resolving
  `section_id` to a record's table index — the obvious reading — would repeat a
  nonce whenever a bundle was re-emitted, since record order is free: a total break
  for GCM. `section_id` is now `name_id`, which is unique, stable, and committed;
  `key_epoch` is deleted in favour of the stronger rule that every encryption draws
  a fresh `content_key`.
- **Trailing bytes were unconstrained.** Data appended to a valid `.ctf` stayed
  valid and sat outside the commitment — the archive-format ambiguity behind a long
  line of CVEs. The file now ends at its footer, `total_len` must equal the real
  length, and the footer's repeated magic is documented as a recovery heuristic
  only.
- **The commitment root did not cover the header**, which would have made the new
  feature words strippable: clear the bits and an old reader misparses a file it
  was told to refuse. Root is now
  `BLAKE3("ctf/root/v1" ‖ header[0,64) ‖ section_table_bytes)`. Hashing the table
  covers every section root without the redundant second pass the old wording
  implied — and whose order was undefined, which was enough for two conforming
  writers to disagree.
- **The signed message was never defined.** Now
  `"ctf/footer-sig/v1" ‖ u16_le(suite_id) ‖ root ‖ u64_le(total_len)`, both
  algorithms over the identical transcript. Binding `suite_id` blocks
  suite-downgrade replay; the domain label blocks replay against the entitlement
  chain, which shares the keys.
- **`SEALED` contradicted its own rule.** It was defined as "encrypted to the seal
  recipient" while `progress` sections are required to carry it and are sealed to a
  *holder* key. Redefined by who cannot open the section: a key the platform does
  not hold during the event.
- **Stage-gated sections had no stated encoding** and would have been broken by the
  obvious guess: marking one `SEALED` makes it permanently unservable, since
  `SEALED` excludes `PLAYER_VISIBLE`. They are `enc = 1` to a `stage:N` recipient
  and player-visible.
- **External sections had two sources of truth** for root and length, record and
  manifest, with no precedence — so two implementations could verify against
  different values. The record wins; a mismatch rejects.
- **The KDF salt bound the full format version**, so every minor bump would have
  silently re-keyed every bundle. It binds `version_major` only.
- **The WASM feature set was pinned to "the format version"**, same failure mode.
  It pins to its own `wasm_profile` number, retired by number the way `suite_id`
  retires a suite.
- **The entitlement chain bound only `challenge_id`**, so a grant for one packing
  of a challenge would validate against another. The genesis record binds the
  bundle commitment root.
- **The manifest had no extensibility model** — the container would have become
  extensible while the CBOR manifest, where most growth lands, stayed frozen. A
  COSE-style `crit` array: unknown keys not listed are ignorable, unknown keys
  listed are rejected, and a typo is still caught because it appears in neither.
- `root` is 32 bytes forever, so every future suite must use a 32-byte digest; a
  different digest size needs a major version.
- The manifest's `spec:` number versions the schema and is independent of
  `version_major.minor`, which versions the bytes.
- A `zerocopy` cast path is valid only through little-endian typed fields; a
  native-endian cast is correct on x86 by luck.
- Threat model gains two honest limits: a sealed section's length and compression
  ratio leak an entropy bound before release, and stage gating is 2^80 against an
  offline attacker, because the stage key must derive from the flag the player
  types.

### Changed

- `SectionKind` gains an `Unknown(FutureKind)` variant and loses `#[repr(u16)]`;
  `to_u16()` replaces `as u16` as the discriminant source of truth.
- **`FutureKind` makes an invalid section kind unrepresentable.** The first cut of
  the unknown-kind variant was `Unknown(u16)`, which admits a state the format does
  not have: `Unknown(1)` is a valid Rust value, and `to_bytes` would write it as
  `kind = 1`, producing a section that claims to be the manifest. That is a writer
  bug rather than a parser one — no input can trigger it, since `parse` never
  constructs a known discriminant as unknown — but bundles are signed and
  long-lived, so a mislabelled section is exactly the sort of defect that surfaces
  long after the pack that caused it. `FutureKind` is a newtype with a private
  field, built only by the parser or by `SectionKind::unknown(v)`, which returns
  `None` for every discriminant this version defines. Reading the raw value is
  `FutureKind::get()`.

  `SectionKind::unknown` returns `Option` rather than `Error` deliberately: `Error`
  describes what can be wrong with a byte stream, and passing `1` here is a caller
  passing the wrong number, which no file can cause.

  Two tests pin the invariant from both directions — the constructor refuses
  `0..=8`, and parsing a known discriminant always yields its named variant.
- Section parsing now validates `flags` before `kind`, since whether an undefined
  kind is a rejection or a skippable section depends on `OPTIONAL`.
- `Error::OverlapsSectionTable` replaces the `name_id = u16::MAX` sentinel that
  made a real section numbered 65535 indistinguishable from the table in
  diagnostics.
- Header reserved region is now `[48, 64)`; spec rules H14 and R18 added, R3
  narrowed to `kind = 0`, R4 widened to bits above 3. Rule numbers are stable by
  policy, so a narrowed rule keeps its number.

### Added

- **`spec/SPEC.md`** — the normative specification, written to RFC conventions
  (BCP 14 keywords) and now authoritative over `docs/FORMAT-DESIGN.md` for every
  byte and every rule. Each rule is numbered so a conformance vector can cite it:
  `H1`–`H13` for the header, `R1`–`R17` per section record, `T1`–`T5` for the
  table as a whole. Also carries the reader conformance procedure, security
  considerations, a constants table, and §10, an explicit list of everything the
  format does *not* yet define, so a second implementation cannot fill a gap by
  guessing.
- **Section-record golden vector** — the 128 bytes of the minimal bundle's
  manifest record, asserted by `tests/container.rs::record_golden_vector` and
  reproduced in spec §5.7. The header vector had one; the record did not, so half
  of the "frozen" layout was unpinned.

### Changed

- **Rules that lived only in code are now stated in the spec.** Each was
  enforced by the reader but undiscoverable from the documentation, so an
  independent implementation would have diverged: `chunk_index_off` must be `≥ 64`
  and 8-byte aligned (`R17`); `section_table_count` is capped at 4096 (`H7`), a
  normative limit rather than an implementation detail; both offsets are
  cross-checked against the real file length (`H12`, `H13`); a non-external
  `offset` must be non-zero, its smallest legal value being 4096 (`R12`).
- **`len_stored` and `len_plain` semantics restored to the spec** — stored is
  after compression *and* encryption, plaintext is before either, and the
  transform order is fixed as compress-then-encrypt. zstd frames must align to
  chunk boundaries, which is what keeps a large section seekable.
- **Chunking rules disambiguated.** A non-zero `chunk_index_off` requires a
  non-zero `chunk_size`, but the converse does not hold: a chunked section that
  fits in a single chunk correctly carries `chunk_index_off = 0`. Earlier wording
  implied a chunked section always has an index, which nothing enforced and which
  a writer would have been wrong to assume.
- **Behaviour deliberately left unconstrained is now labelled as such**, rather
  than being inferable only by reading the reference implementation: `version_minor`
  accepts any value; `suite_id` is not validated during parsing; `len_plain` is
  unchecked beyond the equality rule; section records may appear in any order; a
  zero-length inline payload cannot overlap anything; an `EXTERNAL` section may
  still carry `chunk_size`.
- Module docs in `header.rs` and `section.rs` now point at the spec rules they
  implement. Their "divergence from design §6" notes are gone: the design doc no
  longer diverges, so the notes described a disagreement that had been resolved.
- Design §6 clarified: `PLAYER_VISIBLE` is an allowlist for *serving* and is not
  the complement of `SEALED`. The previous paragraph about `public` read as though
  the two were the same question. Three states exist and all three are used.
- Design §6's layout diagram listed `section_table_off` before
  `section_table_count`; the normative order is count at offset 20, offset at 24.

### Security

- The spec states plainly what a Phase 0 parse does **not** establish: no
  authentication, `root` unverified, `chunk_index_off` not to be dereferenced (its
  target has no known length and is excluded from overlap detection), and no
  decompression of untrusted input, since output and ratio caps are still
  undefined.

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

[0.2.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.2.0
[0.1.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.1.0
