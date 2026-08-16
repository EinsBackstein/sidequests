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
every 0.2 rule, because R19, R20, R21, T6, T7 and T8 only narrow.

R21 and T8 differ from the others in that they constrain structures 0.2 already
defined, rather than ones it declared unspecified. They ride the same
`CONTAINER_V1` bit instead of taking one of their own because both were folded in
before 0.3 was ever tagged, so no file they would invalidate has ever existed —
spec §15's requirement exists to protect published files, and there were none.

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
- **R21**: `SEALED` with `enc = 0` is rejected. §5.3 defines `SEALED` as "the
  plaintext requires a key the platform does not hold during the event" — a
  statement about a key — so with no encryption there is no key and the flag asserts
  something the container does not carry. A reader that trusted the bit would serve
  the plaintext of a section labelled unservable, which is the failure R5 exists to
  make unrepresentable arriving by a second route. Now a sealed-yet-*readable*
  section cannot be expressed, just as a sealed-yet-*servable* one cannot.

  **The consequence is intended, not a side effect.** R6 requires `solver`,
  `writeup`, and `progress` to carry `SEALED`, and this version implements no
  encryption, so **a 0.3 writer cannot emit those kinds at all**. Refusing is the
  honest outcome; the alternative is a section that claims to be sealed and is not,
  which is worse than its absence because the claim is what a downstream serving
  layer reads. Asserted by
  `tests/bundle.rs::phase_1_cannot_write_a_kind_that_must_be_sealed`.
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

### Changed — T8: nothing in a bundle is uncommitted

Padding between structures was covered by no commitment. The root of §8.3 spans the
header and the section table; each section's `root` spans its own plaintext; nothing
spanned the gaps. A padding byte could therefore be changed in place without moving
the root and without moving `total_len` — two of the four fields in the §8.4
signature transcript — so **one signature would have verified two different files**.
That is signature malleability and a covert channel, and no amount of phase 2 crypto
would have closed it: the transcript is already correct, and those bytes were simply
never in scope of anything. 43% of the demo bundle and 93% of the minimal bundle were
mutable this way.

**T8** now requires every byte in `[64, footer_off)` claimed by no region to be zero,
and a reader rejects rather than normalizes — silently zeroing padding would change a
file a signature was computed over. New `Error::PaddingNotZero { at }` names the
offset; an offset is a number rather than attacker-controlled text, so it does not
turn the error into an oracle.

The spec had been arguing against itself. F5 forbids sixteen bytes of footer slack as
"bytes belonging to no structure and covered by no commitment", and §3 forbids bytes
after the footer as "the ambiguity behind a long line of archive-format
vulnerabilities" — then §3 permitted arbitrary padding between structures with only a
writer's SHOULD and no reader-side rule at all. The same argument won twice and lost
once, in one document. §3 is now a MUST, with the contradiction named rather than
quietly repaired.

Extending the commitment root to cover the padding was considered and rejected: §15
states the root definition is unchangeable below a major version, and requiring zero
buys the same guarantee — one canonical byte string per bundle — without touching it.

Enforcement reuses the sorted, non-overlapping range set `validate_layout` already
builds, so it is a walk over the gaps rather than new machinery. `validate_layout`
takes `file: &[u8]` in place of `file_len: u64`, which is one argument fewer: the
check needs the bytes, and the length was always `file.len()`. The cost is a pass
over unclaimed bytes, which alignment bounds at under 4096 per payload for a
conforming bundle.

Golden vectors did not move. `write_bundle` already zero-filled, and
`minimal_bundle_golden_vector` already asserted `file[64..4096]` was zero with the
message "padding must be zero" — the property was pinned by a test before it was
required by a rule. §11 now states that the vector's padding is normative rather than
incidental.

### Changed — the serving boundary enforces §10

`Bundle::section_bytes` is where bytes leave the crate, and it was enforcing fewer
of its own spec rules than anything else in the container. It now refuses two things
it previously returned.

- **A section whose kind this build does not implement.** Spec §10 is normative —
  "A reader MUST NOT serve, execute, decompress, or decrypt a section whose kind it
  does not implement" — and §5.2 adds that `PLAYER_VISIBLE` on an unknown kind
  "confers nothing on a reader that does not understand it". `SectionKind::is_known`
  existed for precisely this and had no caller outside tests, so an `OPTIONAL`
  section with a future kind, plain inline bytes and a matching root came straight
  back out.
- **A `SEALED` section**, as belt and braces behind R21. R21 makes the input
  unreachable through `Bundle::parse`, which is what makes the guard cheap to keep:
  it means a later relaxation of R21 cannot quietly turn this into a leak.

**Verification is deliberately *not* restricted the same way, and §10 now says so.**
The prohibition is a closed list of four acts, and hashing a section against the root
the footer already commits to is none of them. §5.2's promise is that a skipped
section is still bounds-checked, still overlap-checked, and still committed;
confirming the commitment holds is the follow-through, not a violation. So
`verify_inline_sections` verifies unknown-kind sections and counts them as verified,
while `section_bytes` refuses to hand them over. Restricting both would have left an
unimplemented section less checked than an implemented one for no gain in safety.
The carve-out is stated normatively so an independent implementation cannot guess
the other way.

### Changed — attacker-controlled text is handled at both ends

Manifest text is attacker-controlled, and the two halves of the problem need
different mechanisms — which is why both shipped rather than either alone.

- **`names` rejects the nine explicit Unicode bidi formatting characters**
  (U+202A–U+202E, U+2066–U+2069) at the format boundary. A name becomes a filename on
  extraction, and those characters reorder how surrounding text displays without
  changing it, so `chal\u{202e}gnp.exe` renders as `chal-exe.png` in a terminal, a
  file manager, and the phase 5 TUI alike. Display escaping cannot reach a name
  already written to disk. The byte tests already there could not see them either:
  every byte of their UTF-8 is `≥ 0x80`, so `c < 0x20` and `c == 0x7f` both miss.

  **Right-to-left script is unaffected.** Arabic and Hebrew names remain legal,
  because the characters that spell a word carry their direction implicitly; the nine
  rejected ones carry no content at all. Asserted in both directions.
- **`ctf inspect` escapes `category` and mirror URLs**, printing them through `{:?}`
  to match the challenge title on the adjacent line, which was already safe. These
  are free-form text that can never take a `check_name`-style rule — a description
  may legitimately contain anything — so escaping is the only mechanism available,
  and without it a crafted bundle could inject terminal escape sequences and spoof
  the tool's own output, including the lines stating what was verified.
- **`ctf inspect` errors on a second positional argument.** It previously assigned
  `path` on every one, so `ctf inspect a.ctf b.ctf` silently reported on `b.ctf`
  while the operator read the output as being about `a.ctf`.

Spec §7.2 states the name rule with its RTL carve-out and notes that a conforming
implementation must decode before checking; §13 states the display-escaping
requirement and why the two mechanisms are not alternatives.

### Fixed

- **`chunk_cv` panicked on public input.** Its guard checked that `chunk_size` was a
  power of two but never checked its range, so `chunk_size = 1` passed, `offset`
  became `index`, and `blake3::hazmat::set_input_offset` asserted:
  `offset (1) must be a chunk boundary (divisible by 1024)`. The function's own
  safety comment claimed "a power of two of at least 4096", which the code did not
  enforce — the comment is now true. `Bundle::parse` was never affected, because R14
  range-checks the record first, but `chunk_cv` is `pub` and reachable directly and
  `fuzz/fuzz_targets/chunk_index.rs` generates exactly that input. The crate's stated
  posture is that a panic on hostile input is *unrepresentable* rather than merely
  unreached, and clippy's `panic` lint cannot see into `blake3`.
- **A verify pass could report success it had not earned.**
  `verify_inline_sections` returned a single `usize` — the number of sections it
  *had* checked — after silently `continue`ing past everything it could not. A
  bundle with an inline encrypted artifact therefore printed
  `verified 1 inline section(s)` and exited 0 while that payload went unread, which
  is the one thing the project's own criticality test says must never happen.

  It now returns `VerifyReport { verified, external, unverifiable }`, and
  `ctf inspect --verify` exits non-zero when `unverifiable` is not zero.

  **The obvious fix would have been wrong, and the distinction is the point.**
  "Fail if anything was skipped" fails a bundle describing a 40 GB external image —
  which is *correct*, its bytes being elsewhere by design — so non-zero would have
  become the normal case and stopped carrying information. `EXTERNAL` sections are
  reported and never counted as failures. Only a section whose bytes are **present
  in this file** and unreadable by this build is a reason to fail.

  The policy stays with the caller: the library counts and returns, and only the CLI
  decides that `unverifiable` is fatal. A phase 2 caller holding the content key can
  verify precisely what this build counts as unverifiable, so a library-level hard
  error would have taken the decision away from the layer that will be able to act
  on it.
- A chunk-swap test passed for the wrong reason: its filler was `(i * 31) as u8`,
  which repeats every 256 bytes, so every 4096-byte chunk was byte-identical and a
  "swapped" chunk genuinely was the same bytes. The filler is now a BLAKE3 XOF
  stream, and position binding is asserted separately by showing that two
  byte-identical chunks still get different chaining values.

### Known issues

Found by a six-role multi-agent review of this release (`docs/reviews/0.3-phase1/`,
with the exact prompts committed alongside the reports) and a second verification
pass on 2026-08-16. What remains unfixed is listed here; what has been fixed is
described above, under *Changed* and *Fixed*, because 0.3 is not tagged and the
narrowings were folded in rather than deferred to a version with a feature bit of
its own. The full reasoning, evidence, blast radius, and fix for each lives in
[`TODO.md`](TODO.md); this section states what a reader of this release needs to
know before depending on it.

- **`verify_chunk` is callable without `verify_root`**, ordered by a doc comment
  rather than by a type, though C6 is normative. `ChunkIndex` also does not carry the
  `chunk_size` it was verified for, requiring the caller to re-supply a value the
  record already fixed. Both are the same footgun and close with the same change: a
  `VerifiedChunkIndex` that `verify_root` returns and that owns the chunk size.
- **`ChunkIndex::parse` accepts trailing bytes** past `count × 32` while `to_bytes`
  drops them, so the documented byte-for-byte round trip does not hold.
- **`ctf inspect` never prints a section's `root`**, so an operator fetching a 40 GB
  external payload cannot get the expected digest from the tool that describes it.
- **Manifest errors carry no index or `name_id`**, so "names entry is not text"
  means hand-decoding CBOR on a 50-artifact bundle. An index is a number rather than
  attacker-controlled text, so adding one does not violate the no-oracle rule.
- **§9.2's chunk merge is not implementable from the spec alone.** It defers to the
  BLAKE3 paper for parent-node compression without giving the key words, flag bytes,
  block construction, counter, block length, or root finalization. Measured against
  phase 8's actual acceptance criterion — a Go implementation reproducing §11's
  vector from `spec/SPEC.md` alone — that is a gap, since most Go BLAKE3 libraries do
  not expose subtree chaining values.
- **§7.3 overstates what `crit` does.** It claims a typo is caught because "the value
  the author meant to set is absent, which the schema check for that key catches",
  which holds only for *required* keys. `runtime`, `generate`, `sealed`, `verify`,
  `category`, and `description` are all optional, so a misspelled one is carried,
  ignored, and unnoticed — the exact incident design §10 names. `crit` provides
  reader forward compatibility, not typo detection; typo detection is `ctf pack`'s
  job and belongs in phase 3.
- **§8.2 cites "R1" for hybrid signing**, colliding with *record rule* R1. It means
  design requirement R1 and should cite F4. §8.2 also says key distribution "is
  specified with the suite registry (§14)" while §14 says the registry is
  unspecified.
- **Normative rules with no dedicated test**: R17, R20, T7, C7, M2–M6, M8, M11–M12,
  M14–M18, M20. 124 tests pass, so these can regress silently. Some existing
  rejection tests may also be vacuous, tripping an earlier check than the rule they
  name — the trap `HANDOFF.md` already warns about.
- **The `section_table` fuzz target never calls `validate_layout`**, so T1–T7 are
  entirely unfuzzed despite the target's doc claiming that coverage.
- **`Manifest::validate_against` is O(records × external entries)**, which at the
  4096-record cap is a lot of comparisons before a rejection.

Carried forward from earlier releases and still true: **no cryptography beyond
BLAKE3**, so this crate is not an authentication boundary; the byte layout is not
frozen while the major version is `0`; ML-DSA remains the least mature primitive in
the planned stack; the GPL-3 licence choice still sits awkwardly with design §13's
call for an independent second implementation; and `.ctf` still collides with
Compact C Type Format on extension though not on magic.

One review finding was **rejected and must not be re-raised**: the claim that §7.1's
M1g bytewise map-key ordering contradicts RFC 8949. It does not. RFC 8949 §4.2.1
requires bytewise lexicographic ordering of the encoded keys, which is what the spec
and `cbor.rs` do; §4.2.3 "Length-First Map Key Ordering" is the RFC 7049 compat
variant, offered as an alternative. The reviewer attributed §4.2.3's rule to §4.2.1.

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
