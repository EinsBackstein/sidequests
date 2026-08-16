# Changelog

All notable changes to the `.ctf` challenge transport format and its reference
implementation. Format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the on-disk byte layout is **not** frozen and any
minor release may break it.

## [0.3.0] — 2026-08-13

Phase 1 complete: the container is whole. A `.ctf` now carries a manifest, commits
to itself, and can be verified incrementally at forensics scale. No field moved.

**A parse still establishes `intact`, never `authentic`.** The commitment root is
computed and checked; the signatures are located and bounded but not verified,
because the suite registry is phase 2. `Bundle::signing()` returns `Unsigned` or
`Present` — never "valid" — and there is deliberately no API that says otherwise.

### Added — the rest of the container

- **Canonical CBOR manifest** (spec §7, rules M1–M21). RFC 8949 §4.2.1 core
  deterministic encoding, restricted to six major types and three simple values,
  and **enforced on decode as well as on encode** — which is the part a
  general-purpose CBOR library will not do, and the reason `cbor.rs` is
  hand-written rather than a dependency. The commitment is over bytes, so an
  encoding a decoder tolerates but an encoder would never produce is a second
  spelling of one manifest and therefore a second commitment root for one
  challenge. Duplicate map keys are *unrepresentable* rather than resolved: keys
  must be strictly increasing in encoded-byte order, so "which duplicate wins"
  never becomes the policy difference that lets two conforming readers disagree
  about a file both accepted. Floats and tags are excluded outright, nesting is
  capped at 16, and a declared length never sizes an allocation before its bytes
  are consumed.
- **Manifest schema** with the name table `name_id` indexes, `id` shape rules, and
  the `crit` criticality list from design §10 — unknown keys named in `crit` are
  rejected, unknown keys not named are carried byte-for-byte so a rewriter cannot
  destroy what it does not understand. Name entries are rejected for path shapes
  at the format boundary rather than normalized later, because one extraction path
  forgetting to re-check is all it takes.
- **Footer** (spec §8, rules F1–F9): commitment root, two signature slots, a
  `total_len` that must equal the real file length, and the repeated magic.
  Variable-width, because a signature's size is a property of the crypto suite and
  suite 3 roughly doubles it — so `footer_len` is *derived* from `file_len -
  footer_off` rather than stored, and MUST equal `56 + N + M` **exactly**. Padding
  inside the footer would be bytes covered by no commitment, which is §3's
  trailing-data ambiguity moved eight bytes to the left. A footer carrying one
  signature of the hybrid pair is rejected as a downgrade, not read as "classically
  signed".
- **Commitment root**, `BLAKE3("ctf/root/v1" ‖ header[0,64) ‖ section_table_bytes)`,
  computed over the bytes as they appear in the file rather than over a
  re-serialization of the parsed structs — which would make the check a tautology
  for any field the reader normalizes.
- **Signature transcript**, `"ctf/footer-sig/v1" ‖ u16_le(suite_id) ‖ root ‖
  u64_le(total_len)`, exactly 59 bytes, produced and pinned by a test now so phase
  2 has nothing left to decide.
- **Chunk index** (spec §9, rules C1–C7): a flat array of 32-byte BLAKE3 chaining
  values, one per chunk. See below.
- **External sections** end to end: mirror metadata in the manifest, with the
  record authoritative and a mismatch rejecting the file (M21). A bundle describing
  a 40 GB forensics image is under 8 KB and asserted to be so.
- **`Bundle::parse` and `write_bundle`** — the whole spec §10 conformance
  procedure in one call, and a writer that parses its own output before returning
  it. A writer that can emit a file its own reader rejects is a bug generator for
  every other implementation, and the check costs one pass over a file already in
  memory.
- **`ctf inspect`** (`crates/ctf-cli`): header, manifest, section table, chunk
  indices, mirrors, commitment root, `--verify` to re-hash every inline section,
  `--hex` for the annotated dump. It prints "NOT VERIFIED" next to any signature on
  every run, because one operator reading "signatures: 2" as "signed and checked"
  is the whole risk. It will not dump a sealed section in any mode.
- **Full-file golden vector** (spec §11): the minimal OSINT bundle, 4344 bytes,
  every region pinned byte-for-byte plus `BLAKE3(file)`. This is now the primary
  conformance target, because reproducing it from the spec text alone demonstrates
  agreement on the layout, the canonical CBOR key order, the section `root`, and
  the commitment construction at once.
- **`cargo-fuzz` targets** for the whole bundle, header, section table, manifest,
  and chunk index, with a seed corpus committed. Their oracle is round-trip
  stability, not merely absence of panics: an accepted file's structures must
  re-encode to exactly the bytes they came from.
- **`tests/mutation.rs`** — the same oracle on the pinned stable toolchain: single
  byte flips across every structure, truncation at every length, 40 000 randomly
  corrupted bundles, and 70 000 arbitrary inputs through the sub-parsers. The
  fuzzer finds things; this keeps them found without needing nightly.
- **`tests/fuzzmirror.rs`** compiles and runs each fuzz target's body on the pinned
  toolchain, so an API change cannot silently rot `fuzz/` between nightly runs.
- 69 new tests (124 total), still zero clippy warnings, still `unsafe_code =
  "forbid"`, one dependency.

### Added — `feat_ro_compat` bit 0, `CONTAINER_V1`

0.3 adds rules that reject files 0.2 would have accepted, so per the extension
policy it ships with a feature bit, and every 0.3 writer sets it. It is a
**read-only-compatible** bit, and the choice of word is the substance.

The criticality test decides it, clause by clause, for a 0.2 reader meeting a 0.3
file. It serves nothing new — no flag, kind, or record rule changed meaning. It
trusts nothing, because 0.2 forbids treating a parse as authentic. It reports
nothing as verified, having no verification. And it does not *mis-locate* the
chunk index: 0.2 §5.5 forbids dereferencing `chunk_index_off` at all, so the
region is never read. The 0.2 reader fails to **account** for bytes it never
touches, which is under-checking, not misreading. A valid 0.3 file also satisfies
every 0.2 rule, because R19, R20, T6 and T7 only narrow.

The hazard is entirely on the **rewriter** side, and it is severe: a 0.2 tool
re-emitting a 0.3 file drops the footer, the manifest, and every chunk index,
producing a bundle that no longer says what the author signed. That is spec §4.4's
definition of a read-only-compatible feature, word for word.

Result: a 0.3 file is **readable** by a 0.2 reader and **unrewritable** by it, and
a 0.3 reader reads everything a 0.2 file actually defines while naming what is
missing before attempting a whole-container read. Both directions are asserted by
tests. The 0.1 and 0.2 golden headers still parse and are still asserted.

An earlier draft of this release put the bit in `feat_incompat`, on a misreading of
criticality clause 4 that treated "does not check" as "mis-locates". That would
have made 0.3 files unreadable by every 0.2 reader — spending the
forward-compatibility mechanism on its own first use. Spec §15 now states the
lesson as a rule for editors: *"it needs a feature bit" does not mean "it needs an
incompatible one"*, and the two questions must be asked separately.

### Changed — `bao` audited and rejected; the chunk index that replaced it

`bao` 0.13.1 is BLAKE3 verified streaming by BLAKE3's own author, with a written
spec and test vectors. It is the wrong dependency here for a reason unrelated to
its quality: adopting it makes **its encoding** a normative part of `.ctf`, which
phase 8's independent Go implementation would then have to reproduce from a second
document with no Go `bao` to lean on. Pre-1.0 with a single maintainer was the
secondary concern.

The replacement is better than the roadmap's stated fallback of "per-chunk
BLAKE3". Independent per-chunk hashes would not reduce to the section's `root`, so
the index would have needed a commitment of its own — a new field in a frozen
record, and that one really would have been `feat_incompat`. Instead each entry is the chunk's
BLAKE3 **chaining value**, via the stable `blake3::hazmat` API. Because
`chunk_size` is a power of two of at least 4 KiB, every chunk boundary is also a
BLAKE3 subtree boundary, so merging the entries reproduces `BLAKE3(plaintext)`
exactly.

- **The index is committed by construction.** A forged index cannot reduce to the
  section root, which lives in the table, which the footer commits to. No new
  field, and nothing added to the root definition — which spec §15 now states
  outright is unchangeable without a major version, no feature bit sufficient.
- **Its length is derived**, `ceil(len_plain / chunk_size) × 32`, so
  `chunk_index_off` is finally bounds- and overlap-checked like every other region.
  That closes the `ponytail:` comment 0.2 left in `section.rs` and adds T6 and T7.
- **The cost is stated rather than discovered**: no interior tree nodes, so
  verifying a single chunk means reading the whole index. Kilobytes against
  gigabytes, and not something ingest or serving needs.

`blake3::hazmat` is marked hazardous material because a wrong tree shape yields a
plausible value that never matches `blake3::hash`. The merge is therefore checked
against `blake3::hash` directly across 48 input shapes — exact multiples, short
final chunks, and counts either side of every power of two — rather than argued
from the tree structure.

### Changed — new rules

- **R19**: `chunk_index_off ≠ 0` with fewer than two chunks is rejected. One
  chaining value carries no root finalization, so a one-entry index could not be
  checked against anything; zero entries describe an empty section.
  `chunk_index_off = 0` is how both say they have no index.
- **R20**: the manifest section must be neither encrypted nor compressed. It says
  which key opens every other section and where every external payload lives, so it
  has to be readable with no key and no codec — otherwise the file stops being
  self-describing, and a reader would have to decompress untrusted input to learn
  the decompression limits that make doing so safe.
- **T6, T7**: chunk index ranges are bounds-checked against `footer_off` and
  included in overlap detection, against payloads, the table, and each other.
- Footer checks are ordered so that the fields at fixed offsets from `footer_off`
  are read first. They are the only part of the footer whose position is unaffected
  by bytes being appended to or removed from the end of the file, which makes the
  exact-length rule the accurate diagnostic for exactly that tampering — reading the
  trailer first reports a magic mismatch, which is true but says nothing about what
  is wrong.
- `Error` gains `FeatureRequired`, `BadTotalLen`, `BadFooterLen`,
  `SignatureTooLong`, `RootMismatch`, `Manifest`, and eight `Cbor*` variants. All
  still carry static descriptions and offending numbers, never input bytes: a
  manifest is attacker-controlled text and an error string is not a place to echo
  it.

### Changed — spec restructured

`spec/SPEC.md` gains §7 manifest, §8 footer, §9 chunk index, and §11 the full-file
golden vector; reader conformance, constants, security considerations, the
extension policy, and the compatibility matrix move down accordingly. §14 "what is
not here yet" shrinks to signature verification, the suite registry, AEAD, zstd
limits, the later phases' manifest keys, and the entitlement record format.

`footer_off` deliberately keeps its lack of an alignment requirement. Adding one
would reject files that are legal under 0.2, and the footer is decoded through
alignment-independent little-endian reads regardless — so the rule would buy
nothing and cost a compatibility break. Recorded in the spec rather than left as an
apparent oversight.

### Fixed

- A chunk-swap test passed for the wrong reason: its filler was `(i * 31) as u8`,
  which repeats every 256 bytes, so every 4096-byte chunk was byte-identical and a
  "swapped" chunk genuinely was the same bytes. The filler is now a BLAKE3 XOF
  stream, and position binding is asserted separately by showing that two
  byte-identical chunks still get different chaining values.

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

[0.3.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.3.0
[0.2.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.2.0
[0.1.0]: https://github.com/EinsBackstein/sidequests/releases/tag/ctf-format-v0.1.0
