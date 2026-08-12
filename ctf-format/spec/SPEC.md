# The `.ctf` container format

**Version:** 0.2 (major 0, minor 2)
**Status:** Phase 0 — the header and section-record byte layouts specified here
are frozen. The manifest, chunk index, footer, and all cryptographic rules are
**not** specified yet; see §10.
**Reference implementation:** `crates/ctf-format`.
**Rationale, threat model, and design history:** `docs/FORMAT-DESIGN.md`. Where
that document and this one disagree, this one wins.

## 1. Scope

This document specifies the bytes of a `.ctf` file that a Phase 0 reader parses:
the fixed 64-byte header and the fixed-width 128-byte section table. It states
what a conforming writer MUST emit, what a conforming reader MUST reject, and how
both behave when they meet a file written against a different version of this
document (§2.3, §12).

It deliberately does **not** specify the manifest, the chunk index, the footer,
the crypto suite registry, or how a section's contents are verified. A reader
implementing only this document can determine a file's structure. It cannot
determine whether that file is authentic, and MUST NOT present it as such (§9).

Some rules here constrain structures this version does not yet parse — the
commitment root, the footer, external-section metadata. They are stated now
because they bind the *frozen* bytes: a writer that ignores them produces files
that a complete implementation must reject. §10.1 lists them together.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
MAY, and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119,
RFC 8174) when, and only when, they appear in all capitals.

- All multi-byte integers are **unsigned** and **little-endian**. This is
  normative, not host-dependent: a big-endian implementation MUST produce and
  consume the same bytes. An implementation MAY read the fixed-width structures
  by casting a mapped buffer instead of decoding field by field, but only through
  explicitly little-endian typed accessors — a native-endian cast is correct on a
  little-endian host by accident, and silently wrong elsewhere.
- All offsets and lengths are in bytes, measured from the first byte of the
  file, which is offset 0.
- `[a, b)` denotes the byte range starting at `a` and ending immediately before
  `b`. `[a, b)` is empty when `a == b`.
- "Aligned to *n*" means the value is an integer multiple of *n*. Zero is a
  multiple of every *n*; where zero is also a sentinel, the field's rule says so
  explicitly.
- KiB = 1024 bytes; MiB = 1048576 bytes.
- Every arithmetic operation a reader performs on a length or offset taken from
  the file MUST be overflow-checked. A computation that overflows a 64-bit
  unsigned integer MUST cause rejection, not wraparound.
- Every field marked *reserved* MUST be written as zero and MUST be rejected by
  a reader if any of its bytes is non-zero.
- Every flag bit and enumerated discriminant not assigned by this document MUST
  be rejected, never ignored, except through the mechanisms of §2.3. Silently
  ignoring an unknown bit is what lets two readers disagree about the same file.
- "Reject" means: stop, treat the file as invalid, and report an error. A
  rejecting reader MUST NOT return partial results that a caller could mistake
  for a valid parse.

### 2.1 Conformance and error identity

A reader MAY perform the checks in this document in any order, except where an
ordering is stated normatively (§4.3, H14). Error identity — which specific error
a reader reports — is **not** normative; only the accept or reject decision is.
Consequently, a conformance vector that asserts a *specific* rejection reason is
only meaningful when the input violates exactly one rule. Vectors that violate
several rules at once MUST assert rejection only.

### 2.2 Terminology

| Term | Meaning |
|---|---|
| Reader | Anything that parses a `.ctf` file |
| Writer | Anything that produces one |
| Rewriter | A writer that re-emits an existing file, preserving what it did not author — `ctf transfer`, seal release, re-signing |
| Inline section | A section whose bytes are stored in the file |
| External section | A section whose bytes are stored elsewhere (§5.3, `EXTERNAL`) |
| Understood | A section whose `kind` this reader implements (§5.2) |

### 2.3 Compatibility model

Strict rejection of the unknown is what stops two readers from disagreeing about
a file, and it is the default everywhere in this document. But a format that can
only ever reject the unknown cannot be extended at all. This version therefore
defines exactly three extension mechanisms, and no others.

| Mechanism | Old reader's behaviour | Use it for |
|---|---|---|
| **Major version** (§4.1) | Rejects the file | Anything that moves, resizes, or redefines a field |
| **`feat_incompat` bit** (§4.1) | Rejects the file, naming the missing feature | A structural or algorithmic change within the frozen layout |
| **`feat_ro_compat` bit** (§4.1) | Reads the file; refuses to rewrite it | Data a reader can safely ignore but a rewriter would destroy |
| **`OPTIONAL` section** (§5.3) | Skips the section; carries its bytes | Additive content in a new section kind |

**The criticality test.** An extension may be `ro_compat` or `OPTIONAL` **only
if** a reader that does not understand it cannot thereby be led to:

1. serve bytes to a player that should not be served,
2. execute or trust content it should not,
3. report content as verified when it was not, or
4. mis-locate any byte range in the file.

If any of the four is possible, the extension MUST be a `feat_incompat` bit or a
new major version. When in doubt, it is incompatible: the cost of that choice is
an old reader refusing a file it could have read, and the cost of the other
choice is an old reader being wrong about a file it thought it understood.

**Why ignoring is safe at all.** Because the footer commitment covers the header
and the whole section table (§10.1), bytes an old reader skips are still
authenticated by the author's signature. "Ignore" therefore never means "accept
unauthenticated data" — it means "do not interpret data that the signature
already vouches for".

**Minor versions.** `version_minor` is informational. A reader MUST NOT decide
what a file needs by comparing minor numbers; it decides from the feature words
and the `OPTIONAL` bit, which say what the file actually uses. This is what lets a
0.3 writer emit a file that a 0.2 reader accepts whenever the new capability
happens not to be exercised.

## 3. File layout

A file consists of, in address order but not necessarily in this arrangement:

| Structure | Location | Specified in |
|---|---|---|
| Header | `[0, 64)`, always | §4 |
| Section table | `[section_table_off, section_table_off + section_table_count × 128)` | §5 |
| Inline section payloads | anywhere in `[64, footer_off)` | §5, §6 |
| Chunk indices | starting at `chunk_index_off`, length unknown | Not yet specified (§5.5, §10) |
| Footer | `[footer_off, file end)` | Not yet specified (§10) |

Only the header's position is fixed. The section table, the payloads, and the
chunk indices MAY appear in any order and with any padding between them, subject
to the alignment, bounds, and non-overlap rules of §6. Chunk indices are the
exception to those rules only because their length is not yet defined (§5.5).

Section *records* MAY appear in the table in any order. A reader MUST NOT assume
the table is sorted by kind, `name_id`, or `offset`. **Record order carries no
meaning**: it MUST NOT be used to identify a section, and in particular a
section's index in the table MUST NOT be used as its identity. `name_id` is the
identity (§5.1).

The file MAY contain bytes belonging to no structure (padding). A reader MUST
NOT interpret them, and a writer SHOULD zero them.

**The file ends at the footer.** A writer MUST NOT emit any byte after the
footer, and the footer's `total_len` MUST equal the total length of the file. A
reader MUST reject a file with trailing bytes once the footer is specified
(§10.1). Trailing data would otherwise sit outside the commitment while leaving
the file valid, which is the ambiguity behind a long line of archive-format
vulnerabilities. The footer's repeated magic supports recovery scanning only;
`footer_off` in the header is always authoritative.

## 4. Header

The header is exactly 64 bytes and is present at offset 0 of every file. It is
plaintext in every file, including fully sealed ones.

### 4.1 Fields

| Offset | Size | Field | Type | Value / rule |
|---:|---:|---|---|---|
| 0 | 8 | `magic` | `u8[8]` | Exactly `89 43 54 46 0d 0a 1a 0a` |
| 8 | 2 | `version_major` | `u16` | `0` for this document |
| 10 | 2 | `version_minor` | `u16` | `2` for this document; readers accept any value |
| 12 | 4 | `header_len` | `u32` | Exactly `64` |
| 16 | 2 | `suite_id` | `u16` | Crypto suite selector; not interpreted in this version |
| 18 | 2 | `flags` | `u16` | Exactly `0`; no bits are assigned |
| 20 | 4 | `section_table_count` | `u32` | `0 ≤ n ≤ 4096` |
| 24 | 8 | `section_table_off` | `u64` | `≥ 64`, aligned to 8 |
| 32 | 8 | `footer_off` | `u64` | `≥ section_table_off + section_table_count × 128` |
| 40 | 4 | `feat_incompat` | `u32` | Features required to read the file at all |
| 44 | 4 | `feat_ro_compat` | `u32` | Features required to rewrite the file |
| 48 | 16 | `reserved` | `u8[16]` | All zero |

Every field is naturally aligned within the header, so the structure stays
castable (§2) if an implementation ever replaces field-by-field decoding with a
zero-copy view.

No bit is assigned in either feature word by this version: a conforming 0.2
writer emits zero in both. The words exist so that a later version has somewhere
to declare itself — a slot that cannot be added retroactively, because readers
of this version enforce zero across the rest of the header.

`flags` is a *separate* extension surface from the feature words and remains
entirely unassigned. A future version SHOULD prefer a feature bit: `flags` says
nothing about whether a reader that ignores a bit is still correct, while the
feature words say exactly that.

### 4.2 File signature

The 8-byte signature is PNG's construction with `CTF` as the three-character
tag. It MUST be checked byte-for-byte; a reader MUST NOT accept a case-folded,
truncated, or partially matching signature.

| Byte | Value | Purpose |
|---:|---|---|
| 0 | `0x89` | Non-ASCII: detects 7-bit stripping, marks the file binary |
| 1–3 | `C` `T` `F` | Legible in a hexdump and in `strings` |
| 4–5 | `0x0d 0x0a` | CRLF: detects CRLF→LF mangling by a text-mode transfer |
| 6 | `0x1a` | DOS EOF: stops `type file.ctf` dumping binary to a terminal |
| 7 | `0x0a` | LF: detects the reverse LF→CRLF mangling |

Its length is also load-bearing: 8 bytes leaves every following field naturally
aligned.

### 4.3 Validation rules

A reader MUST reject the file if any of the following holds. `file_len` is the
total length of the file in bytes.

| # | Rule |
|---:|---|
| H1 | Fewer than 64 bytes are available. |
| H2 | `magic` differs from §4.2 in any byte. |
| H3 | `version_major` is a major the reader does not implement. For this document, any value other than `0`. |
| H4 | `header_len ≠ 64`. |
| H14 | `feat_incompat` has any bit set that the reader does not implement. |
| H5 | Any byte of `reserved` is non-zero. |
| H6 | `flags ≠ 0`. |
| H7 | `section_table_count > 4096` (`MAX_SECTIONS`, §8). |
| H8 | `section_table_off < 64`. |
| H9 | `section_table_off` is not aligned to 8. |
| H10 | `section_table_off + section_table_count × 128` overflows `u64`. |
| H11 | `footer_off < section_table_off + section_table_count × 128`. |
| H12 | `section_table_off + section_table_count × 128 > file_len`. |
| H13 | `footer_off > file_len`. |

The table is in check order, which is why H14 appears where it does. **H14 MUST
be evaluated before H5, H6, and every structural rule.** A file built for a later
version may legitimately carry data where this version sees reserved space or an
unassigned bit; asking "do I implement what this file needs" first is what turns
a misleading `reserved not zero` into an accurate "this file requires feature *N*",
and stops a reader from reporting structural nonsense about a layout it was never
meant to parse. The remaining rules may be evaluated in any order (§2.1).

`feat_ro_compat` has no rule in this table on purpose: unknown bits there are
**not** an error. See §4.4.

Notes, all normative:

- **H3, minor versions.** `version_minor` is not validated. A reader that
  implements this major MUST accept any `version_minor`, and MUST decide what the
  file requires from the feature words rather than from the version number
  (§2.3).
- **`suite_id`.** A reader MUST NOT reject a file during header parsing solely
  because `suite_id` is unrecognized. The value is recorded verbatim and
  validated at the point a cryptographic primitive is actually needed, so an
  unknown suite fails where the diagnostic is useful. The registry is not yet
  defined (§10.2).
- **H7 and allocation.** The cap MUST be enforced *before* `section_table_count`
  is used to size any allocation. This is the single most common parser
  vulnerability in binary container formats, and the ordering is the whole
  mitigation.
- **`section_table_count = 0`** satisfies every rule in this section. Such a
  file is nonetheless invalid, because §6 requires exactly one manifest section.
  A reader that stops after header validation MUST NOT treat the file as valid.
- **H12 and H13** require knowledge of `file_len`. A reader that does not yet
  know it (for example, one streaming the first 64 bytes) MAY defer H12 and H13,
  but MUST apply them before acting on any section content.
- `footer_off` has no alignment requirement; the footer's own length is not yet
  specified (§10.2).

### 4.4 Read-only mode

A reader that meets an unimplemented bit in `feat_ro_compat` MUST still read the
file: by the criticality test (§2.3), nothing it already understands has changed
meaning. It MUST NOT rewrite it.

"Rewrite" means emitting a file that claims to be the same bundle — re-signing,
seal release, appending an entitlement record, re-packing. The danger is
specific: a rewriter that does not understand a feature cannot preserve what that
feature added, and since the commitment covers the whole file, dropping it
silently produces a bundle that no longer says what the author signed. Refusing
is the only safe response, and it must be automatic rather than left to the
operator.

A reader MAY expose this as a predicate; the reference implementation is
`Header::may_rewrite`.

### 4.5 Golden vectors

The complete, valid 64-byte 0.2 header for `suite_id = 1`, one section record at
offset 8192, `footer_off = 8320`, and no features in use:

```text
89 43 54 46 0d 0a 1a 0a  00 00 02 00 40 00 00 00
01 00 00 00 01 00 00 00  00 20 00 00 00 00 00 00
80 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

The same header as written by version **0.1**, which differs only at offset 10
and which every later reader MUST continue to accept:

```text
89 43 54 46 0d 0a 1a 0a  00 00 01 00 40 00 00 00
01 00 00 00 01 00 00 00  00 20 00 00 00 00 00 00
80 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

0.1 wrote zeros across `[40, 64)`, which is exactly what 0.2 reads as "no
features in use" — the reason the version could grow without moving a field.

Both are asserted byte-for-byte by the reference tests
`tests/container.rs::header_golden_vector` and `::header_golden_vector_v0_1`.
Any change to either is a format break.

## 5. Section record

The section table is an array of exactly `section_table_count` records, each
exactly 128 bytes, laid out contiguously from `section_table_off`. Fixed width
is what lets a reader seek to record *N* without parsing records `0..N`. A
reader MUST parse exactly `section_table_count` records and MUST reject the file
if fewer than `section_table_count × 128` bytes are available at
`section_table_off`.

### 5.1 Fields

| Offset | Size | Field | Type | Value / rule |
|---:|---:|---|---|---|
| 0 | 2 | `kind` | `u16` | `1`–`8` (§5.2); `0` is never valid; `> 8` only with `OPTIONAL` |
| 2 | 2 | `name_id` | `u16` | The section's identity; unique across the table |
| 4 | 2 | `flags` | `u16` | Bits 0–3 only (§5.3) |
| 6 | 1 | `enc` | `u8` | `0` = none, `1` = AEAD-STREAM |
| 7 | 1 | `comp` | `u8` | `0` = none, `1` = zstd |
| 8 | 8 | `offset` | `u64` | `0` if `EXTERNAL`; otherwise `≥ 64` and aligned to 4096 |
| 16 | 8 | `len_stored` | `u64` | Stored byte count, after compression and encryption; `0` if `EXTERNAL` |
| 24 | 8 | `len_plain` | `u64` | Plaintext byte count, before compression and encryption |
| 32 | 4 | `chunk_size` | `u32` | `0`, or a power of two in `[4096, 67108864]` |
| 36 | 4 | `reserved` | `u8[4]` | All zero |
| 40 | 8 | `chunk_index_off` | `u64` | `0`, or `≥ 64` and aligned to 8 |
| 48 | 32 | `root` | `u8[32]` | BLAKE3 root of the **plaintext** |
| 80 | 48 | `reserved` | `u8[48]` | All zero |

Every field is naturally aligned within the record.

**`name_id` is the section's identity, not a convenience.** It indexes the
manifest's name table, and phase 2 binds it into the AEAD nonce and additional
authenticated data (design §7). Three consequences are normative now, because
they constrain writers of files this version can already produce:

- It MUST be unique across the table (§6, T2).
- A rewriter MUST NOT reassign it. Re-encrypting a section's contents under an
  unchanged content key with the same `name_id` would repeat an AEAD nonce, which
  is a catastrophic failure rather than a degraded one.
- A section's position in the table MUST NOT be used as its identity anywhere,
  precisely because record order is free (§3) and a nonce derived from it would
  change every time a file was re-emitted.

`root` commits to the plaintext, not to the stored bytes, so the commitment is
independent of whether and how the section was compressed or encrypted. A writer
MUST set it to the BLAKE3 root of the section's plaintext. **A Phase 0 reader
does not verify it** (§10.2); the value is parsed and carried, nothing more.

### 5.2 Kinds

| Value | Kind | Meaning |
|---:|---|---|
| 0 | — | Never valid |
| 1 | `manifest` | Canonical CBOR manifest. Exactly one per file |
| 2 | `artifact` | A challenge artifact, player-facing or generator-internal |
| 3 | `generator` | `gen.wasm` |
| 4 | `solver` | `solver.wasm` |
| 5 | `writeup` | Author writeup |
| 6 | `entitlement` | Entitlement chain records |
| 7 | `keys` | Hybrid KEM key envelopes |
| 8 | `progress` | Sealed per-holder progress blob |
| > 8 | — | Defined by a later version; valid only with `OPTIONAL` (§5.3) |

`0` being invalid is what makes an all-zero record a hard reject rather than a
plausible manifest section.

There is no `external` kind. Whether a section's bytes live inside the file is
orthogonal to what the section *is* — an external artifact and an external
forensics image are both meaningful — so "external" is a flag (§5.3), and the
kind enum stays a statement of meaning only.

**A section whose kind this reader does not implement** (necessarily `> 8`, and
necessarily `OPTIONAL`) is *carried*, not *understood*. The reader MUST:

- include it in every bounds and overlap check, exactly like any other section —
  its bytes are real and committed, and "skip" means "do not interpret", never
  "pretend it is absent";
- preserve it byte-for-byte if it rewrites the file, or refuse to rewrite;
- never serve, execute, decompress, or decrypt its contents, whatever its other
  flags say. `PLAYER_VISIBLE` on an unknown kind is a statement about readers
  that understand it, and confers nothing on one that does not.

### 5.3 Flags

| Bit | Mask | Name | Meaning |
|---:|---|---|---|
| 0 | `0x0001` | `SEALED` | The plaintext requires a key the platform does not hold during the event |
| 1 | `0x0002` | `PLAYER_VISIBLE` | Eligible to be served to players |
| 2 | `0x0004` | `EXTERNAL` | The section's bytes live outside the file; mirror metadata is in the manifest |
| 3 | `0x0008` | `OPTIONAL` | A reader that does not implement this section's `kind` MUST skip it rather than reject the file |
| 4–15 | — | — | Unassigned. MUST be zero; a reader MUST reject any set bit |

**`SEALED`** is defined by *who cannot open it*, not by which recipient can. It
covers a section encrypted to the offline seal recipient (a `writeup` released at
event end) and equally one encrypted to a player's holder key (a `progress` blob,
design §9) — in both cases the platform cannot read it while the event runs, which
is the property the flag exists to assert. Defining it as "encrypted to the seal
recipient" would contradict R6, which requires `progress` sections to carry it.

**`PLAYER_VISIBLE`** is an allowlist bit, not the complement of `SEALED`. Three
states exist and all three are meaningful: sealed; player-visible; and neither,
meaning readable by the platform but never served. A section is never both sealed
and player-visible (R5).

**Stage-gated sections are not `SEALED`.** A section gated behind stage *N* is
encrypted (`enc = 1`) to a `stage:N` recipient and is `PLAYER_VISIBLE`, because it
is served — as ciphertext — to the player who has earned the previous stage. Since
R5 makes `SEALED` and `PLAYER_VISIBLE` mutually exclusive, marking such a section
`SEALED` would make it permanently unservable. Which key opens a section is
manifest data (§10.2), not a flag.

**`OPTIONAL`** on a kind the reader *does* implement is legal and has no effect.
This is required rather than tolerated: a kind that is unknown today becomes known
tomorrow, and every file written in between has to stay valid.

### 5.4 Encoding: `enc` and `comp`

| Field | Value | Meaning |
|---|---:|---|
| `enc` | 0 | No encryption |
| `enc` | 1 | AEAD-STREAM. Requires chunking (R15) |
| `comp` | 0 | No compression |
| `comp` | 1 | zstd |

Any other value of either field MUST be rejected, **including on an `OPTIONAL`
section**. This is a deliberate narrowing: a codec is not something a reader can
route around, and keeping the rule exception-free means "unknown discriminants are
rejected" holds everywhere without qualification. A writer using a new codec MUST
therefore also set a `feat_incompat` bit, so old readers fail with an accurate
diagnostic instead of a bare "unknown discriminant". A later version MAY relax
this to permit unknown codecs on skipped sections; doing so widens what readers
accept and so invalidates no existing file.

Both transforms apply to the plaintext in a fixed order: **compress, then
encrypt.** `len_plain` is the length before either; `len_stored` is the length
after both. When `comp = 1` and the section is chunked, a writer MUST emit zstd
frames aligned to chunk boundaries, so that a single chunk can be decompressed
without the preceding ones — this is what keeps a large section seekable.

The AEAD construction itself, its nonce and AAD derivation, and the zstd
decompression limits a reader must impose are not specified in this version
(§10.2).

### 5.5 Chunking

`chunk_size = 0` means the section is stored as a single unit. A non-zero
`chunk_size` MUST be a power of two in `[4096, 67108864]` (4 KiB through 64 MiB
inclusive). Powers of two only, so that chunk-index arithmetic is a shift.

`chunk_index_off` locates a chunk index for the section. `0` means no chunk
index is present. A non-zero value requires a non-zero `chunk_size` (R16): an
index is meaningless for a section that is not chunked. The converse does **not**
hold — a section MAY set `chunk_size` and leave `chunk_index_off = 0`, which is
the normal encoding for a chunked section that happens to fit in one chunk.

The chunk index's own record format and length are not specified in this
version. **Consequences a Phase 0 reader MUST be aware of:** the region a
non-zero `chunk_index_off` points at has no known length, is therefore not
bounds-checked against `footer_off`, and does not participate in the overlap
detection of §6. A Phase 0 reader MUST NOT dereference `chunk_index_off`.

### 5.6 Record validation rules

A reader MUST reject the file if any of the following holds for any record.

| # | Rule |
|---:|---|
| R1 | Fewer than 128 bytes are available for the record. |
| R2 | Any byte of either reserved field (`[36, 40)` or `[80, 128)`) is non-zero. |
| R3 | `kind = 0`. |
| R18 | `kind > 8` and `OPTIONAL` is not set. |
| R4 | Any bit above bit 3 is set in `flags`. |
| R5 | Both `SEALED` and `PLAYER_VISIBLE` are set. |
| R6 | `kind` is `solver`, `writeup`, or `progress` and `SEALED` is not set. |
| R7 | `kind` is `manifest` and `SEALED` is set. |
| R8 | `kind` is `manifest` and `PLAYER_VISIBLE` is set. |
| R9 | `kind` is `manifest` and `EXTERNAL` is set. |
| R10 | `enc` is not `0` or `1`; or `comp` is not `0` or `1`. |
| R11 | `EXTERNAL` is set and `offset ≠ 0`, or `EXTERNAL` is set and `len_stored ≠ 0`. |
| R12 | `EXTERNAL` is not set and: `offset < 64`, or `offset` is not aligned to 4096, or `offset + len_stored` overflows `u64`. |
| R13 | `enc = 0`, `comp = 0`, `EXTERNAL` is not set, and `len_stored ≠ len_plain`. |
| R14 | `chunk_size ≠ 0` and `chunk_size` is not a power of two in `[4096, 67108864]`. |
| R15 | `enc = 1` and `chunk_size = 0`. |
| R16 | `chunk_index_off ≠ 0` and `chunk_size = 0`. |
| R17 | `chunk_index_off ≠ 0` and: `chunk_index_off < 64`, or `chunk_index_off` is not aligned to 8. |

R4 MUST be evaluated before R3 and R18, since whether an undefined `kind` is a
rejection or a skippable section depends on a flag bit. Rules keep the numbers
they were given in 0.1 even where 0.2 inserted or narrowed one, so that a
conformance vector citing a rule keeps citing the same rule; see §11 and §13.

Notes, all normative:

- **R5** is the container's own enforcement of the leak invariant. A serving
  layer is expected to check independently; this check is the one a caller
  cannot forget.
- **R6** stops an author who forgets to seal a writeup at the format boundary
  rather than at the point someone reads it.
- **R7–R9.** The manifest is required to interpret anything else in the file, so
  it cannot wait on a seal key that is offline during the event; it carries the
  flag template for every other section, so it is never served to players; and
  it must be present to make the file self-describing, so it is never external.
- **R12.** Because a non-external `offset` must be both `≥ 64` and aligned to
  4096, the smallest legal value is 4096. Payloads start on a page boundary so a
  section can be memory-mapped without a misaligned first page.
- **R13.** With neither transform applied there is only one length. Allowing the
  two to disagree would let a writer park bytes outside what `root` commits to.
  The rule is deliberately not applied to an `EXTERNAL` section, whose
  `len_stored` is `0` by R11 while `len_plain` describes the external payload.
- **`len_plain` is otherwise unconstrained** by this version. In particular a
  reader cannot yet detect a `len_plain` that disagrees with the real plaintext;
  that is what `root` verification (§10.2) is for.
- An `EXTERNAL` section MAY set `chunk_size` and MAY set `chunk_index_off`;
  neither is constrained by `EXTERNAL` beyond R11, R14, R16, and R17.

### 5.7 External sections

An `EXTERNAL` section stores no bytes in the file. Its record still carries the
section's `root` and `len_plain`, and the manifest additionally carries mirror
metadata — a URL list and a copy of the payload's size and root (design §5).

**The section record is authoritative.** Where the manifest's copy of a root or
length disagrees with the record, the file MUST be rejected rather than resolved
in favour of either. Two carriers of the same fact, with no stated precedence, is
precisely the ambiguity that becomes a parser differential: one implementation
verifies the payload against the record, another against the manifest, and an
attacker who can edit one of them chooses which implementation is wrong.
Enforcement lands with the manifest (§10.1).

### 5.8 Golden vector

The complete, valid 128-byte record for the minimal bundle's manifest section:
`kind = manifest`, `name_id = 0`, no flags, no encryption, no compression,
`offset = 4096`, `len_stored = len_plain = 100`, unchunked, with `root` filled
with `0xab` as a placeholder for a real BLAKE3 root.

```text
01 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00
64 00 00 00 00 00 00 00  64 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
ab ab ab ab ab ab ab ab  ab ab ab ab ab ab ab ab
ab ab ab ab ab ab ab ab  ab ab ab ab ab ab ab ab
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

Unchanged from 0.1: no record field moved. Asserted byte-for-byte by the
reference test `tests/container.rs::record_golden_vector`.

## 6. Table-level rules

These rules constrain the table as a whole and cannot be checked one record at a
time. A reader MUST apply all of them after parsing every record and MUST reject
the file if any holds.

| # | Rule |
|---:|---|
| T1 | The number of records with `kind = manifest` is not exactly `1`. |
| T2 | Two records share a `name_id`. |
| T3 | For any record without `EXTERNAL`: `offset + len_stored > footer_off`. |
| T4 | Two non-empty inline payload ranges overlap. |
| T5 | A non-empty inline payload range overlaps the section table's own range, `[section_table_off, section_table_off + section_table_count × 128)`. |

Definitions and notes, all normative:

- An **inline payload range** is `[offset, offset + len_stored)` for a record
  without `EXTERNAL`. An `EXTERNAL` record has no inline payload range and is
  exempt from T3, T4, and T5 — an external section is unbounded in size by
  design, which is what lets a 40 GB forensics image be referenced by an 8 KB
  file.
- A range is **non-empty** when `len_stored > 0`. A zero-length inline payload
  occupies no bytes, cannot overlap anything, and is exempt from T4 and T5.
- Two ranges `[a₁, a₂)` and `[b₁, b₂)` overlap when `a₁ < b₂` and `b₁ < a₂`.
  Ranges that merely touch (`a₂ = b₁`) do not overlap.
- T3 and T5 together mean every inline payload lies wholly within
  `[64, footer_off)` and clear of the table. The lower bound comes from R12.
- **Sections of an unimplemented kind are included in all five rules.** They are
  ordinary sections that this reader cannot interpret, not absent ones.
- Overlap is a hard reject, not a warning: two sections sharing bytes is exactly
  the ambiguity that becomes a parser-differential exploit, where two conforming
  readers disagree about what a file contains.
- The rules of §4.3 that need `file_len` (H12, H13) MUST be applied no later
  than these.

## 7. Reader conformance

A conforming Phase 0 reader MUST perform these steps in this order and MUST stop
at the first failure. Steps within a rule set MAY be reordered subject to §2.1
and the two stated exceptions (H14 first, R4 before R3/R18); the *stages* MAY NOT,
because each depends on values the previous one validated.

1. Read 64 bytes at offset 0 and apply H1–H4, then **H14**, then H5–H11.
2. Apply H12 and H13 against the real file length.
3. Record whether the file is rewritable (§4.4).
4. Read `section_table_count × 128` bytes at `section_table_off` and apply
   R1–R18 to every record.
5. Apply T1–T5.
6. **Not implemented in this version:** verify the footer commitment root and
   both signatures.

Because step 6 does not exist yet, a Phase 0 reader MUST NOT represent a parsed
file as authentic, and MUST NOT execute, serve, or otherwise act on any section
content on the strength of a successful parse. A successful parse in this
version establishes structure only.

A reader MUST NOT dereference `chunk_index_off` (§5.5).

A reader MUST NOT serve, execute, decompress, or decrypt a section whose kind it
does not implement (§5.2).

A reader MUST NOT rewrite a file when §4.4 forbids it, or when it cannot preserve
every unimplemented section byte-for-byte.

A reader MUST NOT allocate memory proportional to any length field before that
field has passed its bounds check (H7 in particular).

## 8. Constants

| Name | Value | Meaning |
|---|---:|---|
| `MAGIC` | `89 43 54 46 0d 0a 1a 0a` | File signature |
| `VERSION_MAJOR` | `0` | Major version specified here |
| `VERSION_MINOR` | `2` | Minor version specified here |
| `HEADER_LEN` | `64` | Header size, fixed for this major |
| `SECTION_RECORD_LEN` | `128` | Section record size |
| `TABLE_ALIGN` | `8` | Alignment of `section_table_off` and `chunk_index_off` |
| `PAYLOAD_ALIGN` | `4096` | Alignment of an inline `offset` |
| `MAX_SECTIONS` | `4096` | Hard cap on `section_table_count` |
| `MIN_CHUNK_SIZE` | `4096` | Smallest legal non-zero `chunk_size` |
| `MAX_CHUNK_SIZE` | `67108864` | Largest legal `chunk_size` (64 MiB) |
| `SUPPORTED_INCOMPAT` | `0` | `feat_incompat` bits this version defines |
| `SUPPORTED_RO_COMPAT` | `0` | `feat_ro_compat` bits this version defines |

Every limit above is **normative, not an implementation detail**: a writer that
exceeds one produces a file that every conforming reader rejects. Raising any of
them is therefore an incompatible change (§11). At the cap the section table is
512 KiB, which is four orders of magnitude above what a real challenge uses.

`root` is 32 bytes in the frozen layout, so **every present and future crypto
suite MUST use a 32-byte digest.** A suite with a different digest size requires
a new major version, not a new `suite_id`.

The customary filename extension is `.ctf`. No media type is registered.

## 9. Security considerations

- **A parse is not an authentication.** See §7. Until footer verification exists,
  every field in this document is attacker-controlled input, including `root`.
- **Rejection is the only safe response to the unknown**, outside the three
  mechanisms of §2.3, each of which is safe only because the criticality test
  holds and because the commitment covers what is skipped.
- **Downgrade protection depends on the header being committed.** The feature
  words are the reader's instruction to refuse a file it cannot handle, so an
  attacker who could clear them would turn a refusal into a misparse. This is why
  the commitment root covers the header bytes (§10.1) and why that requirement is
  fixed in the same version that introduces the feature words.
- **Trailing data is excluded by construction** (§3). A file that stays valid with
  bytes appended after its commitment is the classic archive-format ambiguity, and
  the `total_len` equality rule is what closes it.
- **Allocation is gated before it happens.** H7 caps `section_table_count`
  before it can size a buffer; §7 generalizes the requirement.
- **Arithmetic is checked, never wrapped.** H10 and R12 exist because a wrapped
  offset computation turns a bounds check into a bypass.
- **The seal invariant is enforced in the container.** R5 and R6 mean a sealed
  section cannot be marked servable and an unsealed writeup cannot exist,
  independent of any policy layer above.
- **`name_id` reuse is a cryptographic failure, not a bookkeeping one** (§5.1).
  A rewriter that renumbers sections, or that re-encrypts under an unchanged key,
  risks repeating an AEAD nonce.
- **Error reporting must not become an oracle.** A reader's diagnostics SHOULD
  carry offending offsets and lengths, and MUST NOT carry bytes from a sealed
  section.
- **Decompression is unbounded in this version.** No limit on zstd output size or
  expansion ratio is specified yet (§10.2). A Phase 0 reader MUST NOT decompress
  untrusted input.

## 10. What is not here yet

### 10.1 Fixed by this version, implemented in phase 1

These rules constrain files that can be written today, so they are normative now
even though this version's reader cannot check them.

- **Commitment root.**
  `root = BLAKE3("ctf/root/v1" ‖ header[0, 64) ‖ section_table_bytes)`.
  Every section's own `root` already sits inside the table bytes, so hashing the
  table covers all of them; hashing the header is what makes the feature words
  and the layout unstrippable. The chunk index MUST also be committed; how is
  defined with its format.
- **Signature transcript.**
  `sig_input = "ctf/footer-sig/v1" ‖ u16_le(suite_id) ‖ root ‖ u64_le(total_len)`,
  with both the classical and post-quantum signature over the identical
  transcript. Binding `suite_id` is what stops a signature being replayed under a
  downgraded suite, and the domain label is what stops it being replayed against
  the entitlement chain, which shares the same keys.
- **`total_len` equals the file length, and no byte follows the footer** (§3).
- **The section record outranks the manifest** for an external section's root and
  length; a mismatch rejects the file (§5.7).
- **Every AEAD nonce derives from `name_id`, never from a record's position**
  (§5.1), and every re-encryption draws a fresh content key.

### 10.2 Not yet specified

An implementation MUST NOT invent behaviour for any of the following, and MUST
NOT claim conformance to a later version by guessing.

- The footer: its layout and its length.
- Verification of `root` per section, and the chunk index: entry format, length,
  and bounds.
- The manifest: canonical CBOR encoding (RFC 8949 §4.2 deterministic encoding),
  its schema, the name table that `name_id` indexes, and its own criticality
  mechanism for unknown keys (§11).
- The crypto suite registry that `suite_id` selects, the AEAD-STREAM
  construction, nonce and AAD derivation, and key management.
- Mirror metadata for `EXTERNAL` sections.
- Compression limits: absolute output cap and expansion ratio cap.
- A golden vector for a complete minimal `.ctf` file, which requires the
  manifest and the footer.

## 11. Extension policy

This section binds future editors of this document. Its purpose is that a change
which looks harmless in review cannot silently become a compatibility break.

| Change | Mechanism |
|---|---|
| Move, resize, or redefine an existing field | **New major version** |
| Grow the header beyond 64 bytes | **New major version** |
| Change the meaning of a value already assigned | **New major version** |
| Use a digest size other than 32 bytes | **New major version** |
| Add a header field inside `reserved` | `feat_incompat` bit |
| Add a value to `enc` or `comp` | `feat_incompat` bit (§5.4) |
| Change a layout, alignment, or ordering rule | `feat_incompat` bit |
| Raise or lower any limit in §8 | `feat_incompat` bit |
| Add data a reader may ignore but a rewriter would destroy | `feat_ro_compat` bit |
| Add a new section kind that must be understood | `feat_incompat` bit **and** a kind number |
| Add a new section kind that may be skipped | A kind number, used with `OPTIONAL` |
| Add a section flag bit | `feat_incompat` bit, unless ignoring it is provably safe |
| Relax a rule, so that more files are accepted | Nothing; old readers were merely stricter |
| Assign a manifest key that readers must understand | The manifest's own `crit` mechanism |

Rules for the editor, all normative:

- **Every new `enc`/`comp` value, section flag bit, and must-understand section
  kind ships with a `feat_incompat` bit**, so that an old reader fails with an
  accurate diagnostic rather than a structural one. The redundancy is deliberate:
  the reader still rejects the unknown value independently, so a writer that
  forgets the bit is caught anyway.
- **Rule numbers are stable.** A rule that is narrowed keeps its number; a new
  rule takes the next unused number regardless of where it belongs in check
  order. Conformance vectors cite numbers.
- **Relaxations are free, restrictions are not.** Widening what a reader accepts
  cannot invalidate an existing file. Narrowing can, and so needs a feature bit
  even when it looks like a bug fix — a file that was legal when written stays
  legal.
- **The manifest needs its own version of this policy.** CBOR keys are the
  natural growth surface, and §10.2 leaves the mechanism open deliberately: it
  should be an explicit criticality list (a COSE-style `crit` array naming keys a
  reader must understand, with unlisted unknown keys ignorable), not a bare
  "reject unknown keys", which would make the manifest the one unextendable part
  of an otherwise extensible format.
- The manifest's own `spec` number versions the CBOR schema and is **independent**
  of `version_major.minor`, which versions the bytes. Neither implies the other.

## 12. Compatibility matrix

| File | Reader | Result |
|---|---|---|
| 0.1 | 0.2+ | Accepted. `[40, 64)` reads as "no features in use", which is what 0.1 wrote |
| 0.2, no features, no unknown kinds | 0.1 | Accepted. `version_minor` is not validated and the feature words are zero |
| 0.2, `feat_incompat` set | 0.1 | Rejected, as `reserved not zero` — safe, but imprecise |
| 0.2, `feat_ro_compat` set | 0.1 | Rejected, as `reserved not zero` — safe, but stricter than necessary |
| 0.2, `OPTIONAL` unknown kind | 0.1 | Rejected: 0.1 knows neither the kind nor flag bit 3 |
| 0.3+, feature in use | 0.2 | Rejected, naming the feature |
| 0.3+, feature not in use | 0.2 | Accepted |
| 0.3+, `ro_compat` feature | 0.2 | Read-only (§4.4) |
| 0.3+, `OPTIONAL` unknown kind | 0.2 | Accepted; the section is carried, never interpreted |

Readers older than 0.2 are conservative in every case: they reject files they
could not have understood, and never accept one they would misread. **Graceful
forward compatibility begins at 0.2** and is not retroactive — which is the
reason for introducing it before the format is in use rather than after.

## 13. Version history

| Version | Change |
|---|---|
| 0.1 | Initial specification: header and section table frozen. |
| 0.2 | Compatibility model (§2.3): `feat_incompat` and `feat_ro_compat` carved from header reserved space, `OPTIONAL` section flag, extension policy (§11), compatibility matrix (§12). Adds H14, R18; narrows R3 to `kind = 0` and R4 to bits above 3. Redefines `SEALED` by who cannot open a section, so that R6 and sealed-to-holder `progress` sections agree. Names `name_id` the section's cryptographic identity. Fixes the commitment root, the signature transcript, the no-trailing-bytes rule, and record-over-manifest precedence (§10.1). No field moved; the section-record golden vector is unchanged and the 0.1 header remains valid. |
