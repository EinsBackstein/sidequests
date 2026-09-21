# The `.ctf` container format

**Version:** 0.3 (major 0, minor 3); document revision 0.12.0
**Status:** The container is complete and specified: header, section table,
manifest, chunk index, footer, zstd compression (§5.4), the entitlement record
format and chain validation (§18), the crypto suite registry (§19), the phase 2
constructions — the hybrid KEM combiner, the AEAD-STREAM construction, and hybrid
signature production and verification (§20) — the key-envelope construction (§21),
derived flags and stage keys (§22), the generator interface (§23), the sealed-
progress payload (§24), the offline solvability gate (§25), the seed/flag injection
ABI (§26), sealed release (§27), the serving manifest (§28), the platform ingest
descriptor (§29), the OCI artifact (§30), the base image contract (§31), the live
gate socket contract (§32), the WTFlag adapter (§33), and the trusted-key interface
(§34). Nothing in this version is left unspecified; §14 states what is specified but
not implemented in this repository.
**Reference implementation:** `crates/ctf-format`.
**Rationale, threat model, and design history:** `docs/FORMAT-DESIGN.md`. Where
that document and this one disagree, this one wins.

## 1. Scope

This document specifies every byte of a `.ctf` file: the fixed 64-byte header
(§4), the fixed-width 128-byte section table (§5, §6), the canonical CBOR
manifest (§7), the footer and its commitment root (§8), and the chunk index (§9).
It states what a conforming writer MUST emit, what a conforming reader MUST
reject, and how both behave when they meet a file written against a different
version of this document (§2.3, §16).

A reader implementing this document can determine a file's structure and can
establish that the file **commits to its own bytes** — that nothing has been
appended, moved, or flipped without detection. With a trusted public key supplied
out of band, it can also establish that the file is **authentic**, by verifying both
signatures of §20.3. The trusted key is not carried in the bundle (§8.2), and a
suite whose signature role is not implemented cannot authenticate at all. The
distinction between intact and authentic is normative and is stated again in §10
and §13.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
MAY, and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119,
RFC 8174) when, and only when, they appear in all capitals.

- All multi-byte integers are **unsigned** and **little-endian**. This is
  normative, not host-dependent: a big-endian implementation MUST produce and
  consume the same bytes. An implementation MAY read the fixed-width structures
  by casting a mapped buffer instead of decoding field by field, but only through
  explicitly little-endian typed accessors — a native-endian cast is correct on a
  little-endian host by accident, and silently wrong elsewhere. The one exception
  is CBOR (§7), which is big-endian by RFC 8949 and is decoded as such.
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
- `BLAKE3(x)` is the 32-byte BLAKE3 hash of `x` in unkeyed hash mode.

### 2.1 Conformance and error identity

A reader MAY perform the checks in this document in any order, except where an
ordering is stated normatively (§4.3, H14; §5.6, R4 and R16; §9, C6; §10). Error
identity — which specific error a reader reports — is **not** normative; only the
accept or reject decision is. Consequently, a conformance vector that asserts a
*specific* rejection reason is only meaningful when the input violates exactly
one rule. Vectors that violate several rules at once MUST assert rejection only.

### 2.2 Terminology

| Term | Meaning |
|---|---|
| Reader | Anything that parses a `.ctf` file |
| Writer | Anything that produces one |
| Rewriter | A writer that re-emits an existing file, preserving what it did not author — `ctf transfer`, seal release, re-signing |
| Inline section | A section whose bytes are stored in the file |
| External section | A section whose bytes are stored elsewhere (§5.3, `EXTERNAL`) |
| Understood | A section whose `kind` this reader implements (§5.2) |
| Intact | The file's commitment root matches its own header and section table (§8.3) |
| Authentic | Both signatures over the transcript verify with a trusted key (§20.3) |

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

The manifest has a fourth mechanism of its own, `crit` (§7.3), which governs CBOR
keys rather than bytes.

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
and the whole section table (§8.3), bytes an old reader skips are still
authenticated by the author's signature. "Ignore" therefore never means "accept
unauthenticated data" — it means "do not interpret data that the signature
already vouches for".

**Minor versions.** `version_minor` is informational. A reader MUST NOT decide
what a file needs by comparing minor numbers; it decides from the feature words
and the `OPTIONAL` bit, which say what the file actually uses. This is what lets a
0.4 writer emit a file that a 0.3 reader accepts whenever the new capability
happens not to be exercised.

## 3. File layout

A file consists of, in address order but not necessarily in this arrangement:

| Structure | Location | Specified in |
|---|---|---|
| Header | `[0, 64)`, always | §4 |
| Section table | `[section_table_off, section_table_off + section_table_count × 128)` | §5 |
| Inline section payloads | anywhere in `[64, footer_off)` | §5, §6 |
| Chunk indices | `[chunk_index_off, chunk_index_off + ceil(len_plain / chunk_size) × 32)` | §9 |
| Footer | `[footer_off, file end)` | §8 |

Only the header's position and the footer's terminal position are fixed. The
section table, the payloads, and the chunk indices MAY appear in any order and
with any padding between them, subject to the alignment, bounds, and non-overlap
rules of §6.

Section *records* MAY appear in the table in any order. A reader MUST NOT assume
the table is sorted by kind, `name_id`, or `offset`. **Record order carries no
meaning**: it MUST NOT be used to identify a section, and in particular a
section's index in the table MUST NOT be used as its identity. `name_id` is the
identity (§5.1).

The file MAY contain bytes belonging to no structure (padding). A writer MUST zero
them and a reader MUST reject any that is not zero (T8). Padding is permitted only
*between* structures; the footer itself admits none (F5). **T8 applies only to a
file that sets `CONTAINER_V1`** (§16): it is a statement about the commitment root
of §8.3 and the transcript of §8.4, and a 0.1 or 0.2 file has neither, so applying
it unconditionally would reject files its predecessors called valid.

Earlier drafts made zeroing a writer's SHOULD with no reader-side rule, which
contradicted the two paragraphs around it: F5 forbids footer slack, and the next
paragraph forbids trailing data, both because bytes belonging to no structure and
covered by no commitment are an ambiguity an attacker can use. Padding is the same
bytes with the same property. Since the commitment root covers the header and the
section table only, and `total_len` is a length rather than a digest, a mutated
padding byte moves nothing in the signature transcript of §8.4 — one signature over
two different files. T8 closes it by making the byte string of a bundle canonical.

**The file ends at the footer.** A writer MUST NOT emit any byte after the
footer, and the footer's `total_len` MUST equal the total length of the file
(F7, F9). Trailing data would otherwise sit outside the commitment while leaving
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
| 10 | 2 | `version_minor` | `u16` | `3` for this document; readers accept any value |
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

#### Assigned feature bits

| Word | Bit | Mask | Name | Meaning |
|---|---:|---|---|---|
| `feat_incompat` | 0–31 | — | — | Unassigned |
| `feat_ro_compat` | 0 | `0x00000001` | `CONTAINER_V1` | The file carries the manifest (§7), footer (§8), and chunk index (§9) of this version |
| `feat_ro_compat` | 1–31 | — | — | Unassigned |

**Every 0.3 writer MUST set `CONTAINER_V1`.**

It is a `feat_ro_compat` bit, and the criticality test (§2.3) is what decides
that. Take a 0.2 reader meeting a 0.3 file, clause by clause:

1. *Serve bytes it should not?* No. No flag, kind, or record rule changed meaning,
   so its serving decisions are the ones it always made.
2. *Execute or trust content it should not?* No. 0.2 forbids treating a parse as
   authentic, so it trusts nothing either way.
3. *Report content as verified when it was not?* No. It has no verification to
   report.
4. *Mis-locate a byte range?* No. 0.2 §5.5 forbids dereferencing
   `chunk_index_off` at all, so the index is never read. The 0.2 reader fails to
   *account* for bytes it never touches, which is under-checking, not misreading.

A valid 0.3 file also satisfies every 0.2 rule, because R19, R20, T6, and T7 only
narrow. So a 0.2 reader gets a correct answer about everything it checks — an
incomplete one, which is exactly the guarantee 0.2 offered: structure, and nothing
more.

The hazard is entirely on the **rewriter** side, and it is severe. A 0.2 tool
re-emitting a 0.3 file drops the footer, the manifest, and every chunk index,
producing a bundle that no longer says what the author signed. That is §4.4's
definition of a read-only-compatible feature, word for word.

So: a 0.3 file stays **readable** by a 0.2 reader and **unrewritable** by it,
which is what forward compatibility is for. A 0.3 reader still recognizes a file
that leaves the bit clear as one with no container to read (§10 step 2), so
backward compatibility keeps its accurate diagnostic at no cost to forward
compatibility.

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
| H7 | `section_table_count > 4096` (`MAX_SECTIONS`, §12). |
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
- **H14 and `CONTAINER_V1`.** `CONTAINER_V1` is in `feat_ro_compat`, so H14 never
  concerns it in either direction. A 0.2 reader meeting a 0.3 file finds
  `feat_incompat = 0` and reads on; a 0.3 reader meeting a 0.1 or 0.2 file finds
  the bit clear and still parses the header and section table, which is why the
  golden headers of both earlier versions remain valid. Such a file simply has no
  manifest, footer, or chunk index to interpret, and a reader that needs those
  MUST refuse it at §10 step 2 rather than improvising a footer. Note the
  direction: that refusal is about a bit the *file* lacks and the reader
  implements, which is the mirror image of H14 and MUST NOT be conflated with it.
- **`suite_id`.** A reader MUST NOT reject a file during header parsing solely
  because `suite_id` is unrecognized. The value is recorded verbatim and
  validated at the point a cryptographic primitive is actually needed, so an
  unknown suite fails where the diagnostic is useful. The registry is defined in
  §19.
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
- `footer_off` has **no alignment requirement**, because 0.2 froze it without
  one and narrowing it now would reject files that are legal today (§15). The
  footer's fields are consequently not naturally aligned in the file and MUST be
  decoded through alignment-independent little-endian reads. A writer SHOULD
  align `footer_off` to 8 regardless.

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

The complete, valid 64-byte 0.3 header of the minimal bundle in §11 —
`suite_id = 1`, one section record at offset 4160, `footer_off = 4288`, and
`CONTAINER_V1` in use:

```text
89 43 54 46 0d 0a 1a 0a  00 00 03 00 40 00 00 00
01 00 00 00 01 00 00 00  40 10 00 00 00 00 00 00
c0 10 00 00 00 00 00 00  00 00 00 00 01 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

The 0.2 header, which every later reader MUST continue to parse (§4.3 note on
H14). Its layout fields describe a different bundle; only the version and feature
words are the point:

```text
89 43 54 46 0d 0a 1a 0a  00 00 02 00 40 00 00 00
01 00 00 00 01 00 00 00  00 20 00 00 00 00 00 00
80 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

The same header as written by version **0.1**, which differs only at offset 10:

```text
89 43 54 46 0d 0a 1a 0a  00 00 01 00 40 00 00 00
01 00 00 00 01 00 00 00  00 20 00 00 00 00 00 00
80 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

0.1 wrote zeros across `[40, 64)`, which is exactly what 0.2 reads as "no
features in use" — the reason the version could grow without moving a field.

Each vector is asserted byte-for-byte by its own test, so a failure names the
version that moved: `tests/container.rs::header_golden_vector` (0.2),
`tests/container.rs::header_golden_vector_v0_1` (0.1), and
`tests/container.rs::header_golden_vector_v0_3` (the 0.3 header above — the minimal
bundle's layout offsets with `CONTAINER_V1` set). The whole-file
`tests/bundle.rs::minimal_bundle_golden_vector` pins the same 0.3 header among the
bytes it asserts. Any change to any of them is a format break.

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
| 48 | 32 | `root` | `u8[32]` | `BLAKE3` of the **plaintext** |
| 80 | 48 | `reserved` | `u8[48]` | All zero |

Every field is naturally aligned within the record.

**`name_id` is the section's identity, not a convenience.** It indexes the
manifest's name table (§7.2), and §20.2 binds it into the AEAD nonce and
additional authenticated data. Three consequences are normative:

- It MUST be unique across the table (T2).
- A rewriter MUST NOT reassign it. Re-encrypting a section's contents under an
  unchanged content key with the same `name_id` would repeat an AEAD nonce, which
  is a catastrophic failure rather than a degraded one.
- A section's position in the table MUST NOT be used as its identity anywhere,
  precisely because record order is free (§3) and a nonce derived from it would
  change every time a file was re-emitted.

**`root` is `BLAKE3(plaintext)` and nothing else.** It commits to the plaintext,
not to the stored bytes, so the commitment is independent of whether and how the
section was compressed or encrypted. Three things depend on that exact
definition:

- a reader verifies an inline plaintext section by hashing `[offset, offset +
  len_stored)` and comparing (§10 step 7);
- a chunk index is verified by merging its entries back into this value (§9);
- an external payload is verified by streaming it through BLAKE3 and comparing
  (§9.3).

A reader MUST NOT return a section's bytes to a caller before `root` verifies for
those bytes, whether whole or per chunk.

### 5.2 Kinds

| Value | Kind | Meaning |
|---:|---|---|
| 0 | — | Never valid |
| 1 | `manifest` | Canonical CBOR manifest (§7). Exactly one per file |
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
| 2 | `0x0004` | `EXTERNAL` | The section's bytes live outside the file; mirror metadata is in the manifest (§7.4) |
| 3 | `0x0008` | `OPTIONAL` | A reader that does not implement this section's `kind` MUST skip it rather than reject the file |
| 4–15 | — | — | Unassigned. MUST be zero; a reader MUST reject any set bit |

**`SEALED`** is defined by *who cannot open it*, not by which recipient can. It
covers a section encrypted to the offline seal recipient (a `writeup` released at
event end) and equally one encrypted to a player's holder key (a `progress` blob,
design §9) — in both cases the platform cannot read it while the event runs, which
is the property the flag exists to assert. Defining it as "encrypted to the seal
recipient" would contradict R6, which requires `progress` sections to carry it.

**`SEALED` requires `enc ≠ 0` (R21).** The definition above is a statement about a
key, so with `enc = 0` there is no key and the flag asserts something the container
does not carry. A reader that trusted the bit would then serve the plaintext of a
section labelled unservable — the failure R5 exists to make unrepresentable, arriving
by a different route. R21 closes it: a sealed-yet-readable section cannot be
expressed, just as a sealed-yet-servable one cannot.

R21 has a consequence a writer meets immediately. R6 requires `solver`, `writeup`,
and `progress` to carry `SEALED`, so a writer that implements no encryption cannot
emit those kinds at all. That is the intended outcome. The alternative is a section
that claims to be sealed and is not, which is worse than its absence, because the
claim is what a downstream serving layer reads.

**`PLAYER_VISIBLE`** is an allowlist bit, not the complement of `SEALED`. Three
states exist and all three are meaningful: sealed; player-visible; and neither,
meaning readable by the platform but never served. A section is never both sealed
and player-visible (R5).

**Stage-gated sections are not `SEALED`.** A section gated behind stage *N* is
encrypted (`enc = 1`) to a `stage:N` recipient and is `PLAYER_VISIBLE`, because it
is served — as ciphertext — to the player who has earned the previous stage. Since
R5 makes `SEALED` and `PLAYER_VISIBLE` mutually exclusive, marking such a section
`SEALED` would make it permanently unservable. Which key opens a section is
manifest data (§21), not a flag.

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

**The manifest section carries neither** (R20). It says which key opens every
other section and where every external payload lives, so it must be readable with
no key and no codec — otherwise the file stops being self-describing, and a reader
would have to decompress untrusted input in order to learn the decompression
limits that make doing so safe.

Both transforms apply to the plaintext in a fixed order: **compress, then
encrypt.** `len_plain` is the length before either; `len_stored` is the length
after both. The `comp = 1` framing and the decompression caps a reader must
enforce follow.

The AEAD construction, its nonce and AAD derivation, and the STREAM chunk framing are
specified in §20.2, including the composition of `comp = 1` with `enc = 1`.

#### zstd framing (`comp = 1`)

**Frames align to chunk boundaries.** When `comp = 1` and `chunk_size ≠ 0`, the
stored bytes are the concatenation of one zstd frame per chunk, in address order:
frame *i* covers `[i × chunk_size, min((i+1) × chunk_size, len_plain))` of the
plaintext and decodes without its predecessors. When `chunk_size = 0`, the stored
bytes are a single zstd frame covering the whole plaintext. `len_stored` is the
total stored length; `len_plain` is the total decompressed length.

#### Decompression caps

A reader MUST reject a `comp = 1` section if either of the following holds, and
MUST apply both checks **before invoking any decompressor**:

| # | Rule |
|---:|---|
| D1 | `len_plain > MAX_DECOMPRESSED_SECTION` (§12). |
| D2 | `len_plain > len_stored × MAX_DECOMPRESSION_RATIO` (§12). |

`len_plain` is authenticated twice over: it lives in the section table, which the
commitment root covers, and `root` is `BLAKE3` of exactly that many plaintext
bytes. A reader may therefore refuse an output it is not allowed to produce
without decoding a byte. The rule exists because a small stored size can otherwise
name an unbounded output — the classic decompression bomb — so checking the
declaration first bounds both the allocation and the work.

A reader MUST additionally reject a section whose decompressed output is not
exactly `len_plain` bytes, and MUST verify that plaintext against `root` before
returning any of it (§5.1, §10). Because the caps are checked first, a reader MAY
decompress an untrusted `comp = 1` section; that is a relaxation of the 0.3
position, which decompressed nothing.

The manifest is exempt from all of this rather than from the rule: R20 forbids it a
codec.

### 5.5 Chunking

`chunk_size = 0` means the section is stored as a single unit. A non-zero
`chunk_size` MUST be a power of two in `[4096, 67108864]` (4 KiB through 64 MiB
inclusive). Powers of two only, for two reasons: chunk-index arithmetic is a
shift, and every chunk boundary is thereby also a BLAKE3 subtree boundary, which
is what makes §9's index reduce to `root`.

`chunk_index_off` locates a chunk index for the section. `0` means no chunk
index is present. A non-zero value requires a non-zero `chunk_size` (R16) and at
least two chunks (R19). The converse does **not** hold — a section MAY set
`chunk_size` and leave `chunk_index_off = 0`, which is the normal encoding for a
chunked section that happens to fit in one chunk.

**The index's length is derived, never stored:**
`ceil(len_plain / chunk_size) × 32` bytes. It is therefore bounds-checked against
`footer_off` and included in overlap detection like every other region (T6, T7).
0.2 could do neither, because the entry format was undefined; that is the change
`CONTAINER_V1` announces.

**The formula is defined only for a non-zero `chunk_size`.** A `chunk_size = 0`
section is stored as a single unit and has no index. R16 therefore MUST be applied
before this formula is evaluated and before R19, T6, C1, and C3, each of which
divides by `chunk_size` or reuses the same count (§2.1). Without that ordering a
spec-faithful implementation evaluating R19 or T6 first would divide by zero on
hostile input.

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
| R20 | `kind` is `manifest` and `enc ≠ 0`, or `kind` is `manifest` and `comp ≠ 0`. **Applies only when `CONTAINER_V1` is set** (§16). |
| R21 | `SEALED` is set and `enc = 0`. **Applies only when `CONTAINER_V1` is set** (§16). |
| R22 | `EXTERNAL` is set and `enc ≠ 0`, or `EXTERNAL` is set and `comp ≠ 0`. **Applies only when `CONTAINER_V1` is set** (§16). |
| R10 | `enc` is not `0` or `1`; or `comp` is not `0` or `1`. |
| R11 | `EXTERNAL` is set and `offset ≠ 0`, or `EXTERNAL` is set and `len_stored ≠ 0`. |
| R12 | `EXTERNAL` is not set and: `offset < 64`, or `offset` is not aligned to 4096, or `offset + len_stored` overflows `u64`. |
| R13 | `enc = 0`, `comp = 0`, `EXTERNAL` is not set, and `len_stored ≠ len_plain`. |
| R14 | `chunk_size ≠ 0` and `chunk_size` is not a power of two in `[4096, 67108864]`. |
| R15 | `enc = 1` and `chunk_size = 0`. |
| R16 | `chunk_index_off ≠ 0` and `chunk_size = 0`. |
| R17 | `chunk_index_off ≠ 0` and: `chunk_index_off < 64`, or `chunk_index_off` is not aligned to 8. |
| R19 | `chunk_index_off ≠ 0` and `ceil(len_plain / chunk_size) < 2`. |

R4 MUST be evaluated before R3 and R18, since whether an undefined `kind` is a
rejection or a skippable section depends on a flag bit. R16 MUST be evaluated
before R19 (and before the §5.5 length formula), since both divide by
`chunk_size`. Rules keep the numbers they were given in 0.1 even where later
versions inserted or narrowed one, so that a conformance vector citing a rule
keeps citing the same rule; see §15 and §17.

Notes, all normative:

- **R5** is the container's own enforcement of the leak invariant. A serving
  layer is expected to check independently; this check is the one a caller
  cannot forget.
- **R6** stops an author who forgets to seal a writeup at the format boundary
  rather than at the point someone reads it.
- **R7–R9, R20.** The manifest is required to interpret anything else in the
  file, so it cannot wait on a seal key that is offline during the event, and it
  cannot be behind a codec; it carries the flag template for every other section,
  so it is never served to players; and it must be present to make the file
  self-describing, so it is never external.
- **R20 and R22 are gated on `CONTAINER_V1`** (§16), like R21 and T8. R20 forbids
  the manifest a codec so the file stays self-describing with no key and no
  decoder; 0.2 defined no manifest codec carve-out, and §10 step 2 refuses a
  whole-container read of a file without the bit before any manifest is read, so
  the rule protects nothing on the legacy path. R22 forbids an `EXTERNAL` record a
  codec because §5.7 and §9.4 verify an external payload against the record's
  plaintext `root` and `len_plain` and nothing states what a mirror serves
  otherwise — with `comp = 1` or `enc = 1` allowed, two implementations would
  disagree about the bytes behind `root`. 0.1 and 0.2 did not forbid the
  combination, and §10 step 2 refuses a legacy file before any payload is fetched.
- **R12.** Because a non-external `offset` must be both `≥ 64` and aligned to
  4096, the smallest legal value is 4096. Payloads start on a page boundary so a
  section can be memory-mapped without a misaligned first page.
- **R13.** With neither transform applied there is only one length. Allowing the
  two to disagree would let a writer park bytes outside what `root` commits to.
  The rule is deliberately not applied to an `EXTERNAL` section, whose
  `len_stored` is `0` by R11 while `len_plain` describes the external payload.
- **R19.** An index of one entry cannot be checked against anything — a single
  chaining value carries no root finalization (§9.2) — and an index of zero
  entries describes an empty section. `chunk_index_off = 0` is how both say they
  have no index.
- An `EXTERNAL` section MAY set `chunk_size` and MAY set `chunk_index_off`. Its
  payload lives elsewhere; the index that proves the payload does not.

### 5.7 External sections

An `EXTERNAL` section stores no bytes in the file. Its record still carries the
section's `root` and `len_plain`, and the manifest additionally carries mirror
metadata — a URL list and a copy of the payload's size and root (§7.4).

The mirror serves the payload's **plaintext**: `root` is `BLAKE3` of exactly
`len_plain` bytes, verified by streaming or per chunk (§9.4). An `EXTERNAL` record
therefore MUST NOT carry a codec (**R22**): `comp` and `enc` would describe a
transform over bytes that are not in the file, and no rule says the mirror applies
it, so the bytes behind `root` would be ambiguous.

**The section record is authoritative.** Where the manifest's copy of a root or
length disagrees with the record, the file MUST be rejected rather than resolved
in favour of either (M21). Two carriers of the same fact, with no stated
precedence, is precisely the ambiguity that becomes a parser differential: one
implementation verifies the payload against the record, another against the
manifest, and an attacker who can edit one of them chooses which implementation is
wrong.

### 5.8 Golden vector

The complete, valid 128-byte record for the minimal bundle's manifest section:
`kind = manifest`, `name_id = 0`, no flags, no encryption, no compression,
`offset = 4096`, `len_stored = len_plain = 62`, unchunked, with `root` the real
BLAKE3 of the manifest bytes in §11.

```text
01 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00
3e 00 00 00 00 00 00 00  3e 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
ae 64 30 d8 61 29 f6 3b  5a e6 39 4c 7f b9 93 17
1b 54 79 a8 7f e6 1d 0a  bf 64 3d 55 09 7d 5e 34
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

The record layout is unchanged since 0.1: no field has moved. The 0.1/0.2 record
vector, which differs only in `len_stored`, `len_plain`, and a placeholder `root`,
is asserted by `tests/container.rs::record_golden_vector`.

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
| T6 | A chunk index range extends beyond `footer_off`, or its end overflows `u64`. |
| T7 | A chunk index range overlaps another chunk index range, any non-empty inline payload range, or the section table. |
| T8 | Any byte in `[64, footer_off)` that lies in no inline payload range, no chunk index range, and not in the section table's own range is non-zero. **Applies only when `CONTAINER_V1` is set** (§16). |

Definitions and notes, all normative:

- An **inline payload range** is `[offset, offset + len_stored)` for a record
  without `EXTERNAL`. An `EXTERNAL` record has no inline payload range and is
  exempt from T3, T4, and T5 — an external section is unbounded in size by
  design, which is what lets a 40 GB forensics image be referenced by an 8 KB
  file.
- A **chunk index range** is `[chunk_index_off, chunk_index_off +
  ceil(len_plain / chunk_size) × 32)` for a record with `chunk_index_off ≠ 0`.
  It exists for `EXTERNAL` records too. R19 guarantees it is non-empty.
- A range is **non-empty** when its length is greater than zero. A zero-length
  inline payload occupies no bytes, cannot overlap anything, and is exempt from
  T4, T5, and T7.
- Two ranges `[a₁, a₂)` and `[b₁, b₂)` overlap when `a₁ < b₂` and `b₁ < a₂`.
  Ranges that merely touch (`a₂ = b₁`) do not overlap.
- A section's chunk index MUST NOT overlap that same section's payload. This is a
  case of T7, not an exception to it.
- **Unclaimed bytes are padding, and T8 requires them to be zero.** The bytes
  between structures belong to no region and are covered by no commitment: the root
  of §8.3 spans the header and the section table, and each section's `root` spans
  its own plaintext. Without T8 a padding byte could be changed in place without
  moving the root and without moving `total_len`, which are two of the four fields
  in the signature transcript of §8.4 — so a single signature would verify two
  distinct files. Requiring zero makes the byte string of a bundle canonical, which
  is the same guarantee, obtained without altering the root definition (§15 forbids
  altering it below a major version).

  This is the rule F5 and §3 already state for the footer and for trailing data,
  applied to the one remaining place where bytes belonged to no structure. A reader
  MUST reject rather than normalize: silently zeroing padding would change a file a
  signature was computed over.

  T8 costs a pass over the unclaimed bytes. Alignment bounds legitimate padding at
  under 4096 bytes before each payload, so a conforming bundle pays almost nothing;
  a file declaring a large gap pays in proportion to bytes it had to supply.
- T3, T5, T6, and T7 together mean every payload and every chunk index lies
  wholly within `[64, footer_off)` and clear of the table and of each other. The
  lower bounds come from R12 and R17.
- **Sections of an unimplemented kind are included in all seven rules.** They are
  ordinary sections that this reader cannot interpret, not absent ones.
- Overlap is a hard reject, not a warning: two structures sharing bytes is exactly
  the ambiguity that becomes a parser-differential exploit, where two conforming
  readers disagree about what a file contains.
- The rules of §4.3 that need `file_len` (H12, H13) MUST be applied no later
  than these.

## 7. Manifest

The manifest is the plaintext of the single section with `kind = manifest`. It is
one canonical CBOR map and nothing else: a reader MUST reject any byte after the
map's final byte.

The manifest's own bytes are covered by the record's `root`, which is covered by
the section table, which is covered by the commitment root. A reader MUST verify
that `root` **before** decoding the manifest (§10 step 7). CBOR decoding is
acting on content, and nothing acts on unauthenticated content.

### 7.1 Canonical CBOR

The encoding is RFC 8949 §4.2.1 *core deterministic encoding*, restricted to the
subset below, and **enforced on decode as well as on encode**. A general-purpose
CBOR library will decode more than this; that is precisely what must not happen
here. The commitment is over bytes, so an encoding a decoder tolerates but an
encoder would never produce is a second spelling of one manifest, and therefore a
second commitment root for one challenge.

Permitted major types:

| Major type | Contents |
|---:|---|
| 0 | Unsigned integer |
| 1 | Negative integer |
| 2 | Byte string |
| 3 | Text string, valid UTF-8 |
| 4 | Array |
| 5 | Map |
| 7 | Exactly `false` (`0xf4`), `true` (`0xf5`), and `null` (`0xf6`) |

A reader MUST reject:

| # | Rule |
|---:|---|
| M1a | An indefinite-length string, array, or map (additional information 31). |
| M1b | Additional information 28, 29, or 30, which are reserved. |
| M1c | An argument not in the shortest form that encodes it: `24` for values below 24, `25` for values at or below `0xff`, `26` for values at or below `0xffff`, `27` for values at or below `0xffffffff`. |
| M1d | Major type 6 (a tag). |
| M1e | Any major type 7 value other than `0xf4`, `0xf5`, `0xf6` — including every float width, `undefined`, and the one-byte simple-value escape. |
| M1f | A text string that is not valid UTF-8. |
| M1g | Map keys that are not strictly increasing in bytewise lexicographic order of their **encoded** form. Equal adjacent keys are a duplicate; a decreasing pair is unsorted. |
| M1h | Nesting deeper than 16 (`cbor::MAX_DEPTH`, §12). |
| M1i | Input that ends inside a value, or that has bytes after the outermost value. |

Rationale worth stating because it constrains future editors:

- **Floats are excluded deliberately**, not for want of a use. Deterministic float
  encoding is a known footgun — NaN payloads, and a shortest-form rule across
  three widths — and nothing in a challenge manifest is a real number. A manifest
  key that needs one needs a new major version, not a looser decoder.
- **Duplicate keys cannot occur** rather than being resolved. Last-wins and
  first-wins are both defensible, which is exactly why two conforming readers
  would otherwise disagree about a manifest they both accepted. M1g makes the
  question unaskable.
- **Negative integers are kept in CBOR's own representation** (`-1 - n`), so a
  value the reader only carries survives exactly, including `-1 - (2^64 - 1)`,
  which does not fit in a signed 64-bit integer.
- The subset is wide enough to hold a value this build has never seen, which §7.3
  requires: carrying an unknown key means decoding, holding, and re-encoding its
  value byte-for-byte without understanding it.

A reader MUST be able to re-encode any manifest it accepted and obtain the input
bytes exactly. This is testable and is the fuzzing oracle in design §14.

### 7.2 Schema

Keys defined by manifest `spec` 1. Every key is a text string.

| Key | Type | Required | Meaning |
|---|---|:-:|---|
| `spec` | uint ≥ 1 | ● | Manifest schema version |
| `id` | tstr | ● | Challenge identifier |
| `name` | tstr | ● | Human-readable title |
| `names` | array of tstr | ● | The name table; index is `name_id` |
| `paths` | map | | Section locations in a directory tree, keyed by `name_id` (§7.2) |
| `version` | uint | | Challenge version; absent means 0 |
| `category` | tstr | | Challenge category |
| `description` | tstr | | Markdown description |
| `crit` | array of tstr | | Keys a reader MUST understand (§7.3) |
| `external` | map | | Mirror metadata, keyed by `name_id` (§7.4) |
| `flag` | tstr or map | | Flag derivation rule; never a flag value (§7.6) |
| `generate` | map | | Deterministic generator declaration (§7.6) |
| `runtime` | map | | Runtime contract (§7.6) |
| `sealed` | map | | Sealed-release declaration (§7.6) |
| `verify` | map | | Solvability-gate declaration (§7.6) |
| `platform` | map | | Platform overlay, namespaced (§7.7) |

`id` MUST be 1 to 64 bytes of lowercase ASCII letters, ASCII digits, and hyphens,
and MUST NOT begin or end with a hyphen. It is an input to the seed derivation
(design §7) and appears in operator-facing output, so it is restricted to a shape
that is unambiguous in both.

**The name table.** `names[name_id]` is the section's human name. Every entry MUST
be 1 to 255 bytes, MUST NOT be `.` or `..`, MUST NOT contain `/`, `\`, a byte
below `0x20`, or `0x7f`, and MUST NOT contain any of the nine explicit Unicode
bidirectional formatting characters U+202A–U+202E and U+2066–U+2069. Entries MUST be
unique.

Names are checked for path shapes here rather than wherever a section is later
written to disk. A name containing a separator has no legitimate use, and one
extraction path forgetting to re-check is all it takes; separators are therefore
rejected outright at the format boundary rather than normalized (design §14).

The bidi rule follows from the same reasoning at one remove. A name becomes a
filename when a section is extracted, and those nine characters reorder how
surrounding text is displayed without changing it — so `chal\u{202e}gnp.exe` renders
as `chal-exe.png` in a terminal, a file manager, and an operator TUI alike. Escaping
at one display site does not help once the name is on disk, so the check belongs
here, where it covers every consumer including the ones not yet written.

**This rule does not restrict right-to-left script.** Arabic, Hebrew, and every
other RTL writing system remain legal, because the characters that spell a word
carry their direction implicitly. The nine forbidden characters carry no content at
all. Note also that a byte-level check cannot find them: every byte of their UTF-8
encoding is `≥ 0x80`, so the `< 0x20` and `0x7f` tests above do not apply and a
conforming implementation MUST decode before checking.

A reader MUST NOT apply this rule to `name`, `category`, or `description`. Those are
free-form human text where the characters may be legitimate, and a reader that
displays them MUST escape rather than reject (§13).

`names` MAY be longer than the number of sections — a generator declares output
names for artifacts that do not exist yet — but MUST NOT exceed 65536 entries,
which is the `name_id` space.

**Paths, for directory trees.** A name is flat and unique, so it cannot express
`src/main.c` and cannot distinguish two `main.c` files in different directories.
The optional `paths` key is the tree: a map from a `name_id` (unsigned integer,
≤ 65535) to a **relative POSIX path** naming where that section's payload belongs
when the challenge is unpacked.

A path is 1 to 4096 bytes, split on `/` into components. Every component MUST be 1
to 255 bytes and MUST satisfy the name-shape rule above — no `.`, no `..`, no `/`,
no `\`, no byte below `0x20` or `0x7f`, and none of the nine bidi formatting
characters. A leading, trailing, or doubled `/` therefore yields an empty component
and is rejected, as is an absolute path. Traversal is thus unrepresentable rather
than filtered: a component that could escape its directory fails the same check a
name fails.

Each key MUST name a section in the table (M25), and each path MUST be unique
across the map (M24) — two sections cannot extract to one file. A section with no
`paths` entry keeps its flat `names[name_id]` as its filename, so the key is
additive and a manifest that omits it behaves exactly as before. `paths` is an
ordinary manifest key: a reader that does not implement it MUST carry it
byte-for-byte (§7.3), and a writer that relies on the tree SHOULD list `paths` in
`crit` so a reader that would ignore it refuses the file cleanly instead of
unpacking the artifacts flat.

**`spec` versus the container version.** `spec` versions this schema and is
independent of `version_major.minor`, which versions the bytes. Neither implies
the other. A reader MUST NOT reject a manifest solely because `spec` is higher
than the one it implements — that is what `crit` decides — for the same reason
`version_minor` is not validated (§2.3).

### 7.3 Criticality: `crit`

Rejecting the unknown is the rule everywhere else in this document. It is wrong
for manifest keys, and only for manifest keys: the manifest is where the schema
grows, so a bare "reject unknown keys" would make it the one unextendable part of
an extensible format.

The mechanism is COSE's, and it is stronger than either extreme:

- An unknown key **named in `crit`** MUST be rejected. The writer has declared
  that a reader which does not understand it will get the file wrong.
- An unknown key **not named in `crit`** MUST be carried and ignored. Carried
  means byte-exact: it survives a decode/encode round trip unchanged, so a
  rewriter cannot destroy what it does not understand.
- Every entry of `crit` MUST name a key present in the manifest, and MUST name a
  key the reader implements — a `crit` entry naming an unimplemented key is the
  rejection above.

**Criticality is reader forward compatibility, not typo detection.** An unknown key
`crit` does not name is carried and ignored, so a misspelled *optional* key —
`visibilty` for `visibility`, say — is not rejected here: it is carried, the value
the author meant to set is absent, and nothing at this layer notices. That is
exactly the failure design §10 cares about, an author silently publishing a hidden
challenge. It is the **authoring tool's** job to catch it, not the reader's: the
YAML front end (`ctf pack`, phase 3) MUST reject unknown keys against its fixed
schema, where a typo is visible. The two mechanisms answer different questions —
`crit` answers "can an older reader correctly interpret this newer manifest?", not
"did the author spell this key right?" — and a reader MUST NOT be relied on for the
latter. A misspelled *required* key is still caught, because the required key is
then absent (M4, M9, M10, M13).

### 7.4 External metadata

`external` maps a `name_id` (unsigned integer, ≤ 65535) to a map:

| Key | Type | Required | Meaning |
|---|---|:-:|---|
| `size` | uint | ● | Plaintext size of the payload |
| `root` | bstr, exactly 32 bytes | ● | `BLAKE3` of the payload |
| `mirrors` | array of tstr, non-empty | ● | Where the payload can be fetched |

Each mirror MUST be 1 to 2048 bytes. This document does not constrain the URL
scheme; who serves an external payload is a downstream concern (design §2).

The `external` map's key set MUST be exactly the set of `name_id`s of sections
carrying `EXTERNAL` — no more, no fewer (M20) — and `size` and `root` MUST equal
the record's `len_plain` and `root` (M21). **The record wins**, and a mismatch
rejects the file rather than resolving in favour of either (§5.7).

### 7.5 Manifest validation rules

A reader MUST reject the file if any of the following holds.

| # | Rule |
|---:|---|
| M1 | The bytes are not canonical CBOR per §7.1 (M1a–M1i). |
| M2 | The outermost value is not a map. |
| M3 | A top-level key is not a text string. |
| M4 | `spec` is absent, or is not an unsigned integer. |
| M5 | `spec = 0`. |
| M6 | `crit` is present and is not an array of text strings. |
| M7 | A `crit` entry names a key this reader does not implement. |
| M8 | A `crit` entry names a key not present in the manifest. |
| M9 | `id` is absent, is not text, or violates the shape in §7.2. |
| M10 | `name` is absent, or is not text. |
| M11 | `category` or `description` is present and is not text. |
| M12 | `version` is present and is not an unsigned integer. |
| M13 | `names` is absent, or is not an array. |
| M14 | `names` has more than 65536 entries. |
| M15 | A `names` entry is not text, or violates the shape in §7.2. |
| M16 | `names` contains a duplicate. |
| M17 | `external` is present and is not a map, or one of its keys is not an unsigned integer, or a key exceeds 65535. |
| M18 | An `external` entry is missing `size`, `root`, or `mirrors`, or one of them has the wrong type, or `root` is not exactly 32 bytes, or `mirrors` is empty, or a mirror is empty or longer than 2048 bytes. |
| M19 | A section's `name_id` is greater than or equal to the number of entries in `names`. |
| M20 | A section carries `EXTERNAL` and has no `external` entry; or a section without `EXTERNAL` has one; or an `external` entry names a `name_id` that no `EXTERNAL` section uses. |
| M21 | An `external` entry's `size` or `root` disagrees with the record's `len_plain` or `root`. |
| M22 | `paths` is present and is not a map, or one of its keys is not an unsigned integer, or a key exceeds 65535. |
| M23 | A `paths` value is not text, or is not a valid relative path per §7.2 (empty, too long, absolute, a `.`/`..` component, an empty component, or a forbidden byte or bidi control). |
| M24 | Two `paths` entries name the same path. |
| M25 | A `paths` key names a `name_id` that no section uses. |

M7 SHOULD be evaluated before M9–M18: if the manifest requires an understanding
this reader does not have, every other diagnostic is noise about a schema that was
never meant for it. M19–M21 and M25 need the section table and are therefore
evaluated after it (§10 step 8); M22–M24 are manifest-local and evaluated with the
rest of the schema. The list rules — M6–M8, M15, M17, M18, M22–M24 — SHOULD
identify the offending entry by its position, a number, and MUST NOT echo the entry
text (§13).

### 7.6 Declaration keys for the later phases

Five keys declare behaviour the container itself does not perform: `flag`,
`generate`, `runtime`, `sealed`, and `verify` (design §10). They are carried,
committed, and re-emitted byte-for-byte like any other key; the platform consumes
them. This section fixes their shapes so two authors, and two implementations,
agree about them.

| Key | Type | Required sub-keys | Optional sub-keys |
|---|---|---|---|
| `flag` | tstr **or** map | — (a tstr is a derivation name, e.g. `derived`) | `derive` tstr, `template` tstr, `scope` tstr, `stage_gate` bool |
| `generate` | map | `determinism` tstr | `wasm` tstr, `outputs` array, `interface` uint, `profile` uint |
| `runtime` | map | `image` tstr, `ports` array, `resources` map, `instancing` tstr, `ttl` tstr, `readiness` map | — |
| `sealed` | map | `release` tstr, `members` array of tstr | — |
| `verify` | map | `solver` tstr, `expect` tstr, `offline` bool | `live` map with `interval` tstr |

Within `generate.outputs`, each entry is a map with `name` (tstr) and
`player_visible` (bool). Within `runtime.ports`, each entry is a map with
`container` (uint) and `protocol` (tstr). `runtime.resources` is a map with `cpu`
(tstr), `memory` (tstr), and `pids` (uint). `runtime.readiness` is a map with `tcp`
(uint) and `timeout` (tstr). `flag.scope`, when present, is one of `player`,
`team`, or `event`; `generate.determinism` is one of `strict`, `flag_only`, or
`none`; `runtime.instancing` is `shared` or `per_team`; `sealed.release` is
`event_end`, `manual`, or `stage:<id>`.

`flag.stage_gate`, when true, declares that a later stage's key derives from this
flag (spec §22.4). It is valid **only** on a derived flag: a stage gate on a static
flag MUST be rejected by the validator (DF5, §22.5), because a stage key must derive
from something with entropy, not from a guessable string. `derive` names the
derivation; `derived` and `hkdf-sha256` are the derivations this version implements,
and `static`/`none` name a literal. The key is an ordinary carried declaration like
the rest of this section: a reader that does not act on it preserves it byte-for-byte
and MUST NOT reject the file for carrying it.

`generate` declares the deterministic generator (§23, design §8). `determinism` is
required and is one of `strict`, `flag_only`, or `none`. `wasm` and `outputs` are
required when `determinism` is `strict` or `none`, and MUST be absent when it is
`flag_only`: the flag-only path needs no generator at all (§23.5). `outputs` is an
array whose entries each name a generated byte stream and say whether it may be
served to a player. Every output name MUST be an entry of the manifest's `names`
table, because a generator's output becomes a section and a section's identity is
its `name_id` (§7.2); a generator output with no name entry is rejected by the
authoring tool (§7.8). `interface` is the generator interface version (§23.3),
absent meaning `1`; `profile` is the WASM feature profile (§23.4), absent meaning
`1`. Neither is validated by the container reader — the host that runs a generator
is the only component that acts on them (G9).

**The container carries these keys; it does not act on them.** A reader of this
version MUST preserve them byte-for-byte (they are ordinary manifest keys) and MUST
NOT reject a file because one is present. It MUST also reject one named in `crit`
only if it does not understand the key — and this version *does* understand these
five, so a writer that needs them interpreted may list them in `crit` and rely on a
reader that predates this section to refuse the file cleanly (M7). That is the
`crit` mechanism working, not an exception to it.

### 7.7 Platform overlay

The format does not own platform concepts such as track level or scoring weights.
They travel in a single top-level key, `platform`, whose value is a map from a
**namespace** (a non-empty text string naming the owning platform, by convention a
reversed domain such as `example.org`) to that platform's opaque data.

- The overlay is an ordinary manifest key. A reader that does not understand any of
  it MUST carry it and re-emit it byte-for-byte (§7.3).
- The format MUST NOT interpret or validate the namespaced values beyond the
  canonical-CBOR subset of §7.1. A platform may add a field inside its namespace
  without a format change and without a feature bit, because it is adding data to a
  key the format already treats as opaque.
- The container MUST NOT require `crit` for a `platform` field, and a reader MUST
  NOT reject a `platform` key merely for carrying a namespace it does not know.
  Platform data is not format semantics, so it is exactly the kind of unknown a
  reader is supposed to carry.

### 7.8 Authoring surface

Authors do not write canonical CBOR by hand; they write YAML and `ctf pack`
compiles it (design §10). The YAML schema is independent of this document and of
`MANIFEST_SPEC`, but two properties are normative for the authoring front end:

- **Unknown keys are rejected.** Every structure in the authoring schema MUST
  reject a key it does not define, at every nesting level. This is the typo guard
  §7.3 assigns to the authoring tool: a misspelled *optional* key (`visibilty` for
  `visibility`) is carried silently by a reader and must be caught here, before a
  byte is packed.
- **The error names the offending key.** Authoring input is the author's own file,
  not a hostile byte stream, so the diagnostic MUST name the key rather than
  restating the rule abstractly.

`crit` is *reader* forward compatibility and is not a substitute for this; the two
mechanisms answer different questions (§7.3).

## 8. Footer

The footer runs from `footer_off` to the end of the file. Unlike the header and
the section record it is **variable width**, because a signature's size is a
property of the crypto suite and suite 3 (design §7) roughly doubles it.

### 8.1 Fields

| Offset from `footer_off` | Size | Field | Type | Value / rule |
|---:|---:|---|---|---|
| 0 | 32 | `root` | `u8[32]` | The commitment root (§8.3) |
| 32 | 4 | `sig_classical_len` | `u32` | `0 ≤ n ≤ 65536` |
| 36 | 4 | `sig_pq_len` | `u32` | `0 ≤ n ≤ 65536` |
| 40 | *N* | `sig_classical` | `u8[N]` | `N = sig_classical_len` |
| 40 + *N* | *M* | `sig_pq` | `u8[M]` | `M = sig_pq_len` |
| `footer_len` − 16 | 8 | `total_len` | `u64` | Equals the real file length |
| `footer_len` − 8 | 8 | `magic` | `u8[8]` | The file signature, repeated |

`footer_len` is `file_len − footer_off`. It is **not** a field: the footer runs to
the end of the file, so its length is already determined, and storing it as well
would be a second carrier of one fact — the ambiguity §5.7 rules out. The fact it
would duplicate, `total_len`, is in the signed transcript and cannot be dropped.

**`footer_len` MUST equal `56 + N + M` exactly** (F5). No padding, no slack.
Padding inside the footer would be bytes belonging to no structure and covered by
no commitment, which is the trailing-data ambiguity of §3 moved eight bytes to the
left.

**The two length fields locate the signature slots, and both the suite and the
transcript constrain them.** For a reader that implements `suite_id`'s suite, the
signature sizes are a property of the suite (§8.1's opening paragraph); a declared
length that disagrees with the suite MUST be rejected rather than used, and a
verifier MUST derive the slot boundaries from the suite rather than from the
fields. §20.3 fixes the slot lengths for suites 1, 2, and 3. The §8.4 transcript
additionally covers both declared lengths, so any change
to the split between the slots is detectable even without a suite registry. The
fields are therefore a bounded declaration, never the sole authority for where the
signatures begin and end.

The footer's fields are **not** naturally aligned in the file, because
`footer_off` carries no alignment requirement (§4.3). They MUST be decoded through
alignment-independent little-endian reads.

### 8.2 Validation rules

A reader MUST reject the file if any of the following holds.

| # | Rule |
|---:|---|
| F1 | `file_len − footer_off < 56` (`MIN_FOOTER_LEN`, §12). |
| F2 | `footer_off < 64`, or `footer_off > file_len`. |
| F3 | `sig_classical_len > 65536`, or `sig_pq_len > 65536` (`MAX_SIG_LEN`, §12). |
| F4 | Exactly one of `sig_classical_len` and `sig_pq_len` is zero. |
| F5 | `file_len − footer_off ≠ 56 + sig_classical_len + sig_pq_len`. |
| F6 | The last 8 bytes of the file are not the signature of §4.2. |
| F7 | `total_len ≠ file_len`. |
| F8 | `root` differs from the commitment recomputed per §8.3. |
| F9 | Any byte follows the footer. |

F3, F4, and F5 SHOULD be evaluated before F6 and F7. Those three read fields at
fixed offsets from `footer_off`, so they are the only part of the footer whose
position is unaffected by bytes being appended to or removed from the end of the
file — which makes F5 the accurate diagnostic for exactly that tampering. Reading
the trailer first would instead report a magic mismatch, which is true but says
nothing about what is wrong. This is a SHOULD, per §2.1; the accept/reject
decision is identical either way.

Notes, all normative:

- **F4 is the downgrade check.** Hybrid signing is mandated: both the classical and
  the post-quantum signature must verify. A footer carrying one of the pair is
  rejected by F4 rather than read as "classically signed".
- **F9 is implied by F5 and F7 together** and is stated separately because it is
  the rule a writer must obey, and because it is the property a security reviewer
  looks for by name.
- **`sig_classical_len = sig_pq_len = 0` is legal** and means the bundle is
  unsigned. Such a bundle authenticates nothing and MUST NOT be served, executed,
  or trusted. It is a valid intermediate state — a writer produces the file, a
  signer adds the signatures — and it is what this version's writer emits; signing
  is specified in §20.3.
- The signature *verification* keys are not carried in the footer. Bundles are
  authored by a single trusted org (design §2), whose keys the platform holds out of
  band. **Key distribution is an interface, not a container structure:** §34 fixes
  the shape of the verifier's trust input, and a reader MUST NOT infer a
  distribution scheme from `suite_id`. Verification (§20.3) takes the trusted key as
  an input; it is never read from the file.

### 8.3 The commitment root

```text
root = BLAKE3("ctf/root/v1" ‖ header[0, 64) ‖ section_table_bytes)
```

`"ctf/root/v1"` is the 11 ASCII bytes with no terminator and no length prefix;
`header[0, 64)` is the header exactly as it appears in the file;
`section_table_bytes` is `[section_table_off, section_table_off +
section_table_count × 128)` exactly as it appears in the file. Only the last
element is variable-length and it is last, so the concatenation is unambiguous
without length prefixes.

A reader MUST hash the bytes as they appear in the file, not a re-serialization of
its parsed structures. Hashing what the reader believes rather than what is there
would make the check a tautology for any field the reader normalizes.

Three properties, all load-bearing:

- **The header is inside the root.** Otherwise the feature words are strippable:
  an attacker clears the bits that tell an old reader to refuse the file, and the
  refusal becomes a misparse. A compatibility signal outside the commitment is not
  a signal.
- **The section table is hashed as bytes, once.** Every section's own `root`
  already lives inside those bytes, so this covers all of them without a second
  pass whose ordering would have to be defined — and two conforming writers
  disagreeing about that ordering is enough to produce two roots for one bundle.
- **The chunk indices are not hashed here, and MUST NOT be.** An index is
  verified by reducing it to its section's `root` (§9.2), which is already inside
  the table bytes. Adding them to this construction would be a second carrier of
  one fact, and the root definition is as load-bearing as the byte layout: nothing
  may be added to it without a major version.

What the root does **not** cover: inline payload bytes and external payload
bytes. Those are covered by their sections' `root` fields, which are inside the
table. The chain is `payload → section root → table bytes → commitment root →
signature`, and a reader MUST verify each link before relying on the next.

### 8.4 The signature transcript

```text
sig_input = "ctf/footer-sig/v2" ‖ u16_le(suite_id)
            ‖ u32_le(sig_classical_len) ‖ u32_le(sig_pq_len)
            ‖ root ‖ u64_le(total_len)
```

`"ctf/footer-sig/v2"` is 17 ASCII bytes; `suite_id` is the header's; the two
lengths are the footer's; `root` is the 32 bytes of §8.3; `total_len` is the
footer's. The transcript is **67 bytes** and every element after the label is
fixed-width, so no length prefixes are needed (design §7's `LP` rule applies to
constructions with a variable-width element).

Both the classical and the post-quantum signature are computed over this identical
transcript, and **both MUST verify**. Binding `suite_id` is what stops a signature
being replayed under a downgraded suite; the domain label is what stops it being
replayed against an entitlement record, which is signed with the same keys
(design §9). Binding `total_len` is what makes F9 enforceable rather than
advisory.

**Binding the two slot lengths is the v2 change, and it closes a real gap.** F3–F5
bound each length, require both-or-neither, and fix their sum, but they leave the
split between the two slots free; §8.1 locates the slots from those very fields.
Nothing else commits to the split — not the §8.3 root, which covers the header and
the section table only. An attacker could therefore exchange `sig_classical_len`
and `sig_pq_len` while preserving their sum, and two readers that trusted the fields
would slice the slot bytes differently. Signing both lengths removes the ambiguity:
any change to the split changes the transcript and fails both signatures. A verifier
of this version MUST NOT accept a transcript bearing the v1 label, and MUST NOT
locate the slots from the fields alone (§8.1).

Producing and checking the signatures is specified in §20.3. A reader MUST NOT
report a bundle as authentic unless both components verify over this transcript with
a trusted public key (§8.2). An unsigned bundle authenticates nothing and MUST NOT
be reported as authentic on any grounds.

## 9. Chunk index

A chunk index is a flat array of 32-byte BLAKE3 **chaining values**, one per
chunk, in address order, at `chunk_index_off`. Entry *i* is the chaining value of
the subtree covering `[i × chunk_size, min((i+1) × chunk_size, len_plain))` of the
section's plaintext.

### 9.1 Layout

| Field | Size | Value |
|---|---:|---|
| entry *i*, for *i* in `[0, count)` | 32 | Chaining value of chunk *i* |

`count = ceil(len_plain / chunk_size)` and the index occupies `count × 32` bytes.
Nothing about the index's extent is read from the file, so there is no length
field here for an attacker to inflate.

### 9.2 Verification

Because `chunk_size` is a power of two of at least 4096, every chunk boundary is
also a BLAKE3 subtree boundary, and merging the entries back up BLAKE3's tree
reproduces `BLAKE3(plaintext)` — which is the section's `root` (§5.1).

The merge is BLAKE3's own tree shape, not a Merkle tree defined here. It is pinned
to the **BLAKE3 specification revision `20211102173700`** (the BLAKE3 team's
`blake3.pdf`) and to the reference implementation of that revision, the `blake3`
crate 1.8.x, whose `hazmat` module exposes the subtree operations named below.
§2.4 and §2.5 of that revision define the chunk and parent chaining values; this
section restates the parent-node and root operations in full so an implementation
can reproduce the merge without reading reference code.

Each index entry `cv(i)` is the **non-root** chaining value of the aligned subtree
covering chunk *i*. That subtree spans at least 4096 bytes — four BLAKE3 1024-byte
chunks, since `MIN_CHUNK_SIZE` is 4096 — and is built by combining those chunk
chaining values (§2.4 of the pinned revision) with `parent_cv` at every level and
**no** `parent_root` finalization: the `ROOT` flag is set only at the top of the
whole section tree. Note that this is not a by-product of `BLAKE3(plaintext)`, which
yields only the final root; an implementation without a BLAKE3 subtree API must
build each `cv(i)` as described.

At every level, the left subtree covers the largest power-of-two number of chunks
strictly less than the total and the right subtree covers the rest; the top merge
is the root finalization. With `cv(i)` the *i*th entry:

```text
merge(a..b):                       # non-root, b - a >= 1
    if b - a == 1: return cv(a)
    k = largest power of two strictly less than (b - a)
    return parent_cv(merge(a..a+k), merge(a+k..b))

root(count):                       # count >= 2
    k = largest power of two strictly less than count
    return parent_root(merge(0..k), merge(k..count))
```

`parent_cv(left, right)` and `parent_root(left, right)` are each **one call to
BLAKE3's compression function**, with every argument fixed. The two 32-byte child
chaining values are the 64-byte message block, each half parsed as eight
little-endian 32-bit words:

```text
parent_cv(left, right):            # non-root parent node
    compress(
        h     = IV,                # the 8 unkeyed key words
        m     = left ‖ right,      # 64 bytes = 16 little-endian words
        t     = 0,                 # 64-bit counter
        b     = 64,                # block length in bytes
        flags = PARENT,            # 0x04
    )[0..8]                        # first 8 output words, little-endian = 32 bytes

parent_root(left, right):          # the root of the tree
    compress(h = IV, m = left ‖ right, t = 0, b = 64,
             flags = PARENT | ROOT)[0..8]   # 0x04 | 0x08
```

`IV` is SHA-256's initial value — `0x6a09e667`, `0xbb67ae85`, `0x3c6ef372`,
`0xa54ff53a`, `0x510e527f`, `0x9b05688c`, `0x1f83d9ab`, `0x5be0cd19` — which is
the unkeyed key for both operations. The compression function itself (its seven
rounds of eight `G` calls, the message permutation, and the final
`v[i] ^= v[i+8]; v[i+8] ^= h[i]`) is specified in §2.2 and §3.3 of the pinned
revision and is not restated here.

**Worked example.** Three chunks, `chunk_size = 4096`, `len_plain = 12288`, each
chunk 4096 bytes of `0x00`. The index's three entries, read as `cv(0)`, `cv(1)`,
`cv(2)`, are:

```text
cv(0) = 3694b08b169d1c322ef5e9d4dee1a3d2536233851fffd7977a8c1b5a0d51628f
cv(1) = 64b687935a6f38f68a040817d157412bf934ec48790e6b34d85825252979e5be
cv(2) = e7a0e6d9923560f45e51bacc92be096e061c088fec2667c6fb68b86b02059847
```

`count = 3`, so `k = 2`: the tree is one interior parent over the first two chunks,
merged with the third.

```text
parent_cv(cv(0), cv(1)) = 8f1dc9cbc6a28285f11e986c79ba3a41b85c219111c034740eda6d95b8302850
root(3)                 = parent_root(8f1d…2850, cv(2))
                        = 819ad8f20ee2578f84eeb28b4aa852458c066911cce810767021030961e43e60
```

That root equals `BLAKE3` of the 12288 zero bytes, which is the section's `root`.
The first value is the interior chaining value `merge(0..2)`; the second is the
root finalization of §9.2.

**The index is committed by construction.** It carries no commitment of its own
and needs none: a forged index cannot reduce to the section's `root`, the root
lives in the section table, and the table is inside the commitment root. This is
why §8.3 forbids adding the index to the root construction.

### 9.3 Validation rules

| # | Rule |
|---:|---|
| C1 | The index has exactly `ceil(len_plain / chunk_size)` entries of 32 bytes each, in address order, at `chunk_index_off`. |
| C2 | An index of fewer than two entries MUST be rejected. Such a section carries `chunk_index_off = 0` instead (R19). |
| C3 | Fewer than `count × 32` bytes available at `chunk_index_off` MUST be rejected. |
| C4 | An index whose merge (§9.2) does not equal the section's `root` MUST be rejected. |
| C5 | A chunk whose plaintext does not reproduce its entry MUST be rejected. |
| C6 | **C4 MUST be checked before C5.** Per-chunk checks against an unverified index prove only that the payload matches whatever the attacker wrote there. |
| C7 | A reader MUST NOT expose a chunk's bytes to a caller before that chunk passes C5. |
| C8 | A reader MUST NOT expose the chunk index of a `SEALED` section, nor of a section whose `kind` it does not implement. |

C1 and C3 divide by `chunk_size` and are therefore defined only for a non-zero
value: R16 MUST be applied first (§5.5, §5.6). A `chunk_size = 0` section has no
index.

**C1–C7 are on-use rules, not parse-time rules** (§10). A reader MUST evaluate them
when it hands out or relies on an index — that is, when it performs the §9.4
verification or returns the index to a caller — and MUST NOT reject the file at
`Bundle::parse` time merely because an index is malformed. C6's ordering and C8's
serving boundary are the parts that carry the security weight; C1–C5 are what a
verification performs once it has the index.

**C8 is the serving boundary applied to the index.** An entry is a chaining value of
the section's **plaintext** (§9.1), so the index is information about contents the
reader must not serve: exposing it for a `SEALED` section, or for a kind this reader
does not implement, would leak a plaintext-derived guess-confirmation oracle while
§10 forbids serving the section itself. It is a rule a reader applies when it hands
an index to a caller, not a parser rule; the reference implementation enforces it in
`Bundle::chunk_index`. An `EXTERNAL` section's index is unaffected — external
verification is what the index is for (§9.4) — provided the section is neither
sealed nor of an unimplemented kind.

### 9.4 External payloads

An external payload is verified against the section's `root` and `len_plain`, not
against the manifest's copies (§5.7). A reader MAY verify it in either of two
ways:

- **Streaming**, in bounded memory: hash the payload with BLAKE3 and compare to
  `root`. The length MUST be checked as well as the hash — BLAKE3 over a prefix
  is a perfectly good hash *of that prefix*, so a truncated payload is caught by
  the length check and by nothing else.
- **Per chunk**, via the chunk index, when the section has one. This is what lets
  a broken transfer resume rather than restart, and what lets bytes be verified
  as they arrive.

This index proves each chunk against the root but carries no interior tree nodes,
so verifying a *single* chunk requires reading the whole index — kilobytes,
against a payload measured in gigabytes. Random access into a payload without the
full index is not a capability this version provides, and is not one ingest or
serving needs. Stated rather than left to be discovered.

## 10. Reader conformance

A conforming reader MUST perform these steps in this order and MUST stop at the
first failure. Steps within a rule set MAY be reordered subject to §2.1 and the
stated exceptions (H14 first; R4 before R3 and R18; C4 before C5); the *stages*
MAY NOT, because each depends on values the previous one validated.

1. Read 64 bytes at offset 0 and apply H1–H4, then **H14**, then H5–H11. Apply
   H12 and H13 against the real file length.
2. If the reader needs the manifest, footer, or chunk index, require
   `feat_ro_compat & CONTAINER_V1 ≠ 0`; refuse the file otherwise. This is the
   mirror of H14 — a bit the file lacks and the reader has — not H14 itself. A
   reader that
   only wants the structure of a 0.1 or 0.2 file MAY skip this and stop after
   step 4. The refusal SHOULD name what is absent — no footer, manifest, or chunk
   index — and MAY report the file's `version_minor`; the bit, never the minor
   number, decides whether the read proceeds (§2.3).
3. Record whether the file is rewritable (§4.4).
4. Read `section_table_count × 128` bytes at `section_table_off` and apply
   R1–R22 to every record; then apply T1–T8. **R20, R21, R22 and T8 are applied
   only if the header sets `CONTAINER_V1`** (§16); every other rule applies to
   every file. R4 MUST precede R3 and R18, and R16 MUST precede R19.
5. Parse the footer and apply F1–F7 and F9.
6. Recompute the commitment root per §8.3 and apply F8.
7. Locate the manifest section, verify its `root` against its stored bytes, then
   decode it and apply M1–M18 and M22–M24.
8. Apply M19–M21 and M25 against the section table.
9. If the caller supplies a trusted public key and needs authenticity, verify both
   signatures over the transcript of §8.4 (§20.3). A reader that does not take this
   step, or that takes it without a trusted key, has established only that the file
   is intact.

**The chunk-index rules C1–C7 are on-use, not parse-time, and are deliberately
absent from the ordered steps above.** They are evaluated when a reader hands out
or relies on an index — §9.4's verification, or a call that returns the index to a
caller — because an index is not needed to open a bundle and a bundle referencing
gigabytes of payload should not read its indices merely to parse. This placement is
normative so two conforming readers do not disagree about whether a malformed index
rejects the *file*: it does not. The reference implementation's whole-file
verification pass therefore reports the number of indices it did **not** evaluate
rather than implying it checked them, and [`Bundle::chunk_index`] is where C4 (and
C8's serving boundary) is applied.

A reader that completes steps 1–8 has established that the file is **intact**. It
has *not* established that the file is **authentic** unless it also completes step 9
with a trusted public key. A reader MUST NOT represent a bundle as authentic on any
other basis, and MUST NOT execute, serve, or otherwise act on section content on the
strength of an intact parse alone.

Further requirements, all normative:

- A reader MUST NOT return any section's bytes to a caller before that section's
  `root` verifies for those bytes, whole or per chunk (§5.1, C7).
- A reader MUST apply D1 and D2 (§5.4) to a `comp = 1` section before invoking a
  decompressor, and MUST reject a decompressed output that is not exactly
  `len_plain` bytes.
- A reader MUST NOT serve, execute, decompress, or decrypt a section whose kind it
  does not implement (§5.2). This list is exhaustive and deliberately excludes
  hashing: a reader MAY verify such a section's stored bytes against its `root`, and
  SHOULD do so when verifying the file as a whole. Checking a commitment is not one
  of the four prohibited acts, the section is committed whether or not it is
  understood (§5.2), and treating verification as forbidden would leave an
  unimplemented section less checked than an implemented one for no gain in safety.
- A reader MUST NOT return a `SEALED` section's plaintext to a caller. R21 makes an
  unencrypted sealed section unrepresentable, so a conforming file cannot reach this
  case; the requirement is stated separately because the serving boundary must not
  depend on a record rule having been applied upstream.
- A reader MUST NOT expose a `SEALED` section's chunk index, nor the chunk index of
  a section whose kind it does not implement (C8). An entry is a chaining value of
  the plaintext (§9.1), so the index is information about the section's contents even
  though it is not the contents.
- A reader MUST NOT rewrite a file when §4.4 forbids it, or when it cannot
  preserve every unimplemented section and every carried manifest key
  byte-for-byte.
- A reader MUST NOT allocate memory proportional to any length field before that
  field has passed its bounds check (H7 in particular; also M1i, C3).
- A writer SHOULD parse its own output before emitting it. The reference
  implementation does, unconditionally: a writer that can emit a file its own
  reader rejects is a bug generator for every other implementation.

## 11. Golden vector: the minimal bundle

The smallest thing that is a valid `.ctf`: an OSINT challenge with no artifacts,
manifest only, unsigned. Total length **4344 bytes**. Every byte not shown below
is zero padding between structures, and that is normative rather than incidental:
T8 requires it, so a reproduction of this vector with any non-zero padding byte is
not a valid `.ctf` and its bytes will not match.

```text
id       whos-that-bird
name     Who's That Bird
names    ["manifest"]
spec     1
```

Layout: header at 0, manifest payload at 4096, section table at 4160, footer at
4288.

**Header, `[0, 64)`:**

```text
89 43 54 46 0d 0a 1a 0a  00 00 03 00 40 00 00 00
01 00 00 00 01 00 00 00  40 10 00 00 00 00 00 00
c0 10 00 00 00 00 00 00  00 00 00 00 01 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

**Manifest, `[4096, 4158)`, 62 bytes of canonical CBOR.** Keys are in
encoded-byte order — `id`, `name`, `spec`, `names` — which is *not* alphabetical
order of the key text: `0x62 "id"` sorts before `0x64 "name"` before `0x64 "spec"`
before `0x65 "names"`, because the length is part of the encoded key.

```text
a4 62 69 64 6e 77 68 6f  73 2d 74 68 61 74 2d 62
69 72 64 64 6e 61 6d 65  6f 57 68 6f 27 73 20 54
68 61 74 20 42 69 72 64  64 73 70 65 63 01 65 6e
61 6d 65 73 81 68 6d 61  6e 69 66 65 73 74
```

**Section table, `[4160, 4288)`,** one record. `root` is
`BLAKE3` of the 62 manifest bytes above:

```text
01 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00
3e 00 00 00 00 00 00 00  3e 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
ae 64 30 d8 61 29 f6 3b  5a e6 39 4c 7f b9 93 17
1b 54 79 a8 7f e6 1d 0a  bf 64 3d 55 09 7d 5e 34
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

**Footer, `[4288, 4344)`,** 56 bytes: the commitment root, two zero signature
lengths, `total_len = 4344` (`0x10f8`), and the repeated magic:

```text
20 e7 bc 2b fd 39 64 51  e6 59 68 16 1d 6a ce e9
49 39 44 d8 b8 f1 0c 68  0c 2f 43 d2 07 a0 57 bb
00 00 00 00 00 00 00 00  f8 10 00 00 00 00 00 00
89 43 54 46 0d 0a 1a 0a
```

**Whole file:**

```text
BLAKE3(file) = e4411ccb6b947f9bc4978299213c795ddf9680e56303f8196e69651365b07fae
```

Asserted byte-for-byte by `tests/bundle.rs::minimal_bundle_golden_vector`. An
independent implementation that reproduces these bytes from this document alone
has demonstrated agreement on the layout, the canonical CBOR key order, the
`root` construction, and the commitment construction at once — which is why this
vector, not the header vector, is the one design §13's second implementation is
measured against.

## 12. Constants

| Name | Value | Meaning |
|---|---:|---|
| `MAGIC` | `89 43 54 46 0d 0a 1a 0a` | File signature |
| `VERSION_MAJOR` | `0` | Major version specified here |
| `VERSION_MINOR` | `3` | Minor version specified here |
| `HEADER_LEN` | `64` | Header size, fixed for this major |
| `SECTION_RECORD_LEN` | `128` | Section record size |
| `TABLE_ALIGN` | `8` | Alignment of `section_table_off` and `chunk_index_off` |
| `PAYLOAD_ALIGN` | `4096` | Alignment of an inline `offset` |
| `MAX_SECTIONS` | `4096` | Hard cap on `section_table_count` |
| `MIN_CHUNK_SIZE` | `4096` | Smallest legal non-zero `chunk_size` |
| `MAX_CHUNK_SIZE` | `67108864` | Largest legal `chunk_size` (64 MiB) |
| `ROOT_LEN` | `32` | Size of every `root` and every chunk index entry |
| `MIN_FOOTER_LEN` | `56` | Footer size with no signatures |
| `MAX_SIG_LEN` | `65536` | Cap on either signature |
| `MAX_DECOMPRESSED_SECTION` | `68719476736` | Absolute cap on a compressed section's plaintext (D1), 64 GiB |
| `MAX_DECOMPRESSION_RATIO` | `65536` | Cap on `len_plain / len_stored` for a compressed section (D2) |
| `MAX_DEPTH` (`cbor`) | `16` | Manifest nesting cap |
| `MAX_NAME_LEN` | `255` | Longest name table entry |
| `MAX_PATH_LEN` | `4096` | Longest `paths` entry |
| `MAX_ID_LEN` | `64` | Longest challenge `id` |
| `MAX_MIRROR_LEN` | `2048` | Longest mirror URL |
| `MAX_NAMES` | `65536` | Entries in the name table; the `name_id` space |
| `MANIFEST_SPEC` | `1` | Manifest schema version specified here |
| `FEAT_RO_COMPAT_CONTAINER_V1` | `0x00000001` | The feature bit of §4.1 |
| `SUPPORTED_INCOMPAT` | `0` | `feat_incompat` bits this version implements |
| `SUPPORTED_RO_COMPAT` | `0x00000001` | `feat_ro_compat` bits this version implements |

Every limit above is **normative, not an implementation detail**: a writer that
exceeds one produces a file that every conforming reader rejects. The two directions
are not symmetric, and §15's table is the authority:

- **Lowering** a limit rejects files that were legal when written, so a lower limit
  needs a `feat_incompat` bit.
- **Raising** a limit is a relaxation: a reader with the higher limit accepts
  strictly more files, and accepts every file the lower limit accepted. It needs no
  bit for the reader. A writer that emits a file *beyond* the old limit SHOULD set a
  `feat_incompat` bit, so an old reader names the missing feature rather than
  reporting a structural error about a range it never expected.

At the cap the section table is 512 KiB, which is four orders of magnitude above
what a real challenge uses.

`MAX_DECOMPRESSED_SECTION` and `MAX_DECOMPRESSION_RATIO` are the same rule in a
different direction: they bound what a *reader* will expand rather than what a writer
may emit, so **raising** either accepts more files and is a relaxation (§15's
"relaxations are free"), while lowering either rejects files that were legal and
needs a feature bit.

`root` is 32 bytes in the frozen layout, so **every present and future crypto
suite MUST use a 32-byte digest.** A suite with a different digest size requires
a new major version, not a new `suite_id`. The chunk index inherits the same
constraint, since its entries are chaining values of the same hash.

The customary filename extension is `.ctf`. A bundle is distributed as an OCI image
with media type `application/vnd.ctf.bundle.v1` (§30).

## 13. Security considerations

- **Intact is not authentic.** A file whose commitment root matches its own bytes
  has proven internal consistency, nothing more. An attacker who rewrites a
  bundle and recomputes the root produces a perfectly intact file. Only the
  signatures distinguish the author's bundle from anyone else's, and verifying them
  (§20.3) needs a trusted public key the file does not carry. Every field in this
  document is attacker-controlled input until that step is taken.
- **Manifest text is attacker-controlled, and displaying it is an output-encoding
  problem.** `name`, `category`, `description`, and every mirror URL are free-form
  text that no schema rule constrains, because a description may legitimately
  contain anything. A tool that writes them to a terminal MUST escape control
  characters; otherwise a crafted bundle injects escape sequences and spoofs the
  tool's own output, including the parts stating what was and was not verified. The
  name table is handled at the other end — §7.2 rejects path shapes, control bytes,
  and bidi controls outright — because a name becomes a filename, where no amount of
  display escaping reaches. The two mechanisms are not alternatives: each covers a
  case the other cannot.
- **The verification chain has an order, and skipping a link breaks it.**
  `payload → section root → table bytes → commitment root → signature`. In
  particular a chunk index MUST be reduced to its section's root before any chunk
  is checked against it (C6), and the manifest's root MUST be verified before the
  manifest is decoded (§10 step 7).
- **Rejection is the only safe response to the unknown**, outside the four
  mechanisms of §2.3 and §7.3, each of which is safe only because the criticality
  test holds and because the commitment covers what is skipped.
- **Downgrade protection depends on the header being committed.** The feature
  words are the reader's instruction to refuse a file it cannot handle, so an
  attacker who could clear them would turn a refusal into a misparse. This is why
  the commitment root covers the header bytes (§8.3).
- **A half-signed footer is a downgrade**, not a partial file, and F4 rejects it.
- **Trailing data is excluded by construction** (§3, F5, F7, F9). A file that
  stays valid with bytes appended after its commitment is the classic
  archive-format ambiguity.
- **The canonical encoding is a security property, not a style choice.** One
  manifest has exactly one byte encoding (§7.1), so "same manifest" and "same
  commitment root" are the same statement. Tolerating a non-canonical encoding on
  decode would let a rewriter change a bundle's identity without changing anything
  an author wrote, and duplicate map keys would let two conforming readers
  disagree about a file both accepted.
- **Allocation is gated before it happens.** H7 caps `section_table_count`
  before it can size a buffer; C3 bounds the chunk index by a derived length
  rather than a stored one; the CBOR decoder MUST NOT size an allocation from a
  declared array, map, or string length before consuming the bytes behind it.
  §10 generalizes the requirement.
- **Arithmetic is checked, never wrapped.** H10, R12, T6 and the chunk index
  length computation exist because a wrapped offset turns a bounds check into a
  bypass.
- **Nesting is capped** (M1h). Unbounded recursion over attacker-supplied CBOR
  nesting is a stack-overflow denial of service.
- **The seal invariant is enforced in the container.** R5 and R6 mean a sealed
  section cannot be marked servable and an unsealed writeup cannot exist,
  independent of any policy layer above.
- **Path shapes are rejected, not normalized** (§7.2). A name that could escape a
  directory is refused at the format boundary, so no extraction path has to
  remember to re-check.
- **`name_id` reuse is a cryptographic failure, not a bookkeeping one** (§5.1).
  A rewriter that renumbers sections, or that re-encrypts under an unchanged key,
  risks repeating an AEAD nonce.
- **Error reporting must not become an oracle.** A reader's diagnostics SHOULD
  carry offending offsets, lengths, and `name_id`s — all numbers — and MUST NOT
  carry bytes from a sealed section, from the manifest, or from the input at all.
  A bad magic, an unsupported CBOR item, and a section root mismatch are therefore
  reported by position or by category, never by echoing what was read; a
  `name_id` is safe to name because it is the identity of the section whose root
  failed, not any of its content. A whole-file verification pass that finds more
  than one bad section SHOULD report every one rather than stopping at the first,
  so an operator is not left to bisect a large bundle by hand.
- **Decompression is bounded before it runs.** A compressed section's declared
  plaintext is checked against an absolute cap and an expansion-ratio cap (D1, D2)
  before any decoder is invoked, so a decompression bomb is refused rather than
  expanded. The declaration is authenticated — `len_plain` is in the committed
  section table and `root` covers exactly that many plaintext bytes — which is what
  makes checking it first sound. The decoded output is then length-checked and
  hashed against `root` before a caller sees it. The manifest is exempt from the
  problem rather than from the rule: R20 forbids it a codec.
- **An unsigned bundle authenticates nothing** and MUST NOT be served, executed,
  or trusted, however intact it is.

## 14. What is specified but not implemented here

Every structure and procedure this document describes is specified: an
implementation does not have to guess at any behaviour. Three items are
**specified but not implemented in this repository**, and an implementation that
lacks them MUST report that honestly rather than approximate them:

- **Trusted-key distribution.** §34 fixes the shape of the verifier's trust input
  and the holder-hash construction, but the reference tooling ships no
  key-management service: obtaining and provisioning the keys is a deployment
  concern. Verification takes the trust set as an input; it is never read from the
  file (§8.2).
- **Suite 3's SLH-DSA signature role.** §20.3 fixes its parameter set and slot
  layout, but the reference implementation resolves that role to `NotImplemented`
  at the point of use rather than silently reducing the hybrid signature to two of
  its three components.
- **The live solvability gate's implementation.** Its socket contract is specified
  in §32, but no implementation of it ships in this repository; until one does, a
  `runtime`-bearing bundle is recorded `unverified` (§25.6).

An implementation MUST NOT claim conformance to a later version by guessing at
behaviour this document does not specify, and MUST NOT report a role it did not
implement, or a gate that did not run, as if it had succeeded.

## 15. Extension policy

This section binds future editors of this document. Its purpose is that a change
which looks harmless in review cannot silently become a compatibility break.

| Change | Mechanism |
|---|---|
| Move, resize, or redefine an existing field | **New major version** |
| Grow the header beyond 64 bytes | **New major version** |
| Change the meaning of a value already assigned | **New major version** |
| Use a digest size other than 32 bytes | **New major version** |
| Change the commitment root or the signature transcript construction | **New major version** |
| Add a CBOR major type or simple value to the manifest subset | **New major version** |
| Add a header field inside `reserved` | `feat_incompat` bit |
| Add a value to `enc` or `comp` | `feat_incompat` bit (§5.4) |
| Add a field to the footer | `feat_incompat` bit |
| Change a layout, alignment, or ordering rule | `feat_incompat` bit |
| **Lower** a limit in §12, so files that were legal are rejected | `feat_incompat` bit |
| **Raise** a limit in §12, so a reader accepts more | Nothing for the reader; old readers were merely stricter. A writer emitting a file beyond the old limit SHOULD set a `feat_incompat` bit, so an old reader names the feature rather than failing structurally |
| Add data a reader may ignore but a rewriter would destroy | `feat_ro_compat` bit |
| Define a structure a previous version left unspecified | Run the criticality test; `feat_ro_compat` if old readers still answer correctly about what they do check, `feat_incompat` otherwise |
| Add a new section kind that must be understood | `feat_incompat` bit **and** a kind number |
| Add a new section kind that may be skipped | A kind number, used with `OPTIONAL` |
| Add a section flag bit | `feat_incompat` bit, unless ignoring it is provably safe |
| Add a manifest key readers must understand | The key, plus `crit` (§7.3) |
| Add a manifest key readers may ignore | The key alone |
| Relax a rule, so that more files are accepted | Nothing; old readers were merely stricter |

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
- **"It needs a feature bit" does not mean "it needs an incompatible one."** The
  two questions are separate and must be asked separately: *does this narrow what
  is legal?* decides whether a bit is needed at all; the criticality test decides
  which word it goes in. Reaching for `feat_incompat` because a change feels
  significant is how a forward-compatibility mechanism gets spent on its own first
  use. `CONTAINER_V1` is the worked example (§4.1): a large addition, and still
  `ro_compat`, because an old reader is merely incomplete about it while an old
  *rewriter* would destroy it.
- **The commitment root construction is as load-bearing as the byte layout.**
  Nothing may be added to it, removed from it, or reordered within it without a
  major version, and no feature bit is sufficient. If a future structure needs
  committing, commit it the way §9 commits the chunk index: by reducing it to
  something already inside the root.

## 16. Compatibility matrix

| File | Reader | Result |
|---|---|---|
| 0.1 | 0.2+ | Header and table accepted. `[40, 64)` reads as "no features in use", which is what 0.1 wrote |
| 0.2, no features, no unknown kinds | 0.1 | Header and table accepted. `version_minor` is not validated and the feature words are zero |
| 0.2 | 0.3 | Header and table accepted in full; a whole-container read is refused at §10 step 2, because a 0.2 file has no footer or manifest to read. The refusal SHOULD name the older format and what is absent rather than reading as a feature-negotiation failure. R20, R21, R22 and T8 are **not** applied — see below |
| **0.3** | **0.2** | **Accepted, read-only.** `feat_incompat` is zero, so nothing stops the read; `CONTAINER_V1` is an unimplemented `ro_compat` bit, so the file MUST NOT be rewritten (§4.4) |
| 0.3 | 0.1 | Rejected, as `reserved not zero`. 0.1 predates the feature words entirely; see below |
| 0.3, plus a `ro_compat` bit from a later version | 0.3 | Accepted, read-only (§4.4) |
| 0.4+, `feat_incompat` feature in use | 0.3 | Rejected, naming the feature (H14) |
| 0.4+, `feat_incompat` feature not in use | 0.3 | Accepted |
| 0.4+, `OPTIONAL` unknown kind | 0.3 | Accepted; the section is carried, never interpreted |
| Manifest `spec` 2+, no `crit` | 0.3 | Accepted; unknown keys carried byte-for-byte |
| Manifest `spec` 2+, unknown key in `crit` | 0.3 | Rejected (M7). The diagnostic may identify the entry's position — a number — but MUST NOT echo the key text, which is attacker-controlled manifest content (§13) |

**R20, R21, R22 and T8 are conditional on `CONTAINER_V1`, and this is what the bit
is for.** Each narrows what a 0.1 or 0.2 file could legally contain, so applying
them unconditionally would make a 0.3 reader reject files its predecessors called
valid — breaking the row above rather than honouring it. A reader MUST determine
the rule set from the file's own header and MUST NOT apply any of them to a file
that does not set the bit.

None of the exemptions weakens a 0.3 file, and none is a concession:

- **R20** forbids the manifest a codec so the file stays self-describing with no key
  and no decoder. 0.2 defined no manifest codec carve-out, and §10 step 2 refuses a
  whole-container read of a file without `CONTAINER_V1` before any manifest is read,
  so the rule protects nothing on the legacy path.
- **R21** rejects `SEALED` with `enc = 0` because the flag then claims a key that
  does not exist. 0.2 specified no encryption at all, so *every* sealed section a 0.2
  writer could produce carried `enc = 0`. Enforcing R21 on such a file would reject
  the only form `solver`, `writeup`, and `progress` could take, not an abuse of it.
- **R22** forbids an `EXTERNAL` record a codec because §5.7 and §9.4 verify an
  external payload against the record's plaintext `root` and `len_plain`. 0.1 and
  0.2 did not forbid the combination, and §10 step 2 refuses a legacy file before any
  external payload is fetched, so the mirror bytes were never interpreted on the
  legacy path.
- **T8** requires unclaimed bytes to be zero because a mutable padding byte is a
  channel that survives signing. It is a statement about the commitment root of §8.3
  and the transcript of §8.4. A 0.2 file has no footer, no root, and no signature, so
  there is nothing for the rule to protect.

Nothing is served on the legacy path regardless. §10 step 2 refuses a whole-container
read of a file without `CONTAINER_V1`, so a reader never reaches the point of
returning section bytes from one; the most a legacy parse yields is a record
describing a section, and §10 already forbids acting on it.

Readers older than 0.2 are conservative in every case: they reject files they
could not have understood, and never accept one they would misread. **Graceful
forward compatibility begins at 0.2** and is not retroactive — which is the
reason for introducing it before the format was in use rather than after. 0.3 is
the first version to exercise it, and the exercise is the point: had
`CONTAINER_V1` been made `feat_incompat`, the mechanism's first use would have
been to break the compatibility it exists to provide.

Both directions across the 0.2/0.3 boundary are asserted by the reference tests
`tests/bundle.rs::a_0_2_reader_can_read_a_0_3_file_but_not_rewrite_it` and
`::a_0_3_reader_reads_a_0_2_file_and_names_what_is_missing`.

## 17. Version history

| Version | Change |
|---|---|
| 0.1 | Initial specification: header and section table frozen. |
| 0.2 | Compatibility model (§2.3): `feat_incompat` and `feat_ro_compat` carved from header reserved space, `OPTIONAL` section flag, extension policy (§15), compatibility matrix (§16). Adds H14, R18; narrows R3 to `kind = 0` and R4 to bits above 3. Redefines `SEALED` by who cannot open a section. Names `name_id` the section's cryptographic identity. Fixes the commitment root, the signature transcript, the no-trailing-bytes rule, and record-over-manifest precedence. No field moved; the section-record golden vector is unchanged and the 0.1 header remains valid. |
| 0.3 | Completes the container. Adds the manifest (§7, M1–M21), the footer (§8, F1–F9), and the chunk index (§9, C1–C7); adds R19, R20, **R21**, T6, T7, **T8**; narrows the `names` shape rule (§7.2) to reject the explicit Unicode bidi formatting characters (a manifest-level rule, so no 0.1 or 0.2 file is affected — neither version defined a manifest); R21 and T8 apply only to files setting `CONTAINER_V1`, so the §16 guarantee to 0.2 files is preserved rather than narrowed; assigns `feat_ro_compat` bit 0, `CONTAINER_V1` — `ro_compat` rather than `incompat` because a 0.2 reader gets a correct if incomplete answer about a 0.3 file, while a 0.2 *rewriter* would silently drop the footer, so 0.3 files stay readable by 0.2 readers and unrewritable by them. The full-file golden vector (§11) replaces the header and record vectors as the primary conformance target. **No field moved** and no existing rule changed meaning — R19, R20, T6 and T7 constrain structures 0.2 declared unspecified and forbade writing, which is why the narrowing is announced by a feature bit rather than a major version, and why that bit does not have to be incompatible. R21 and T8 do narrow structures 0.2 defined, and ride the same `CONTAINER_V1` bit rather than taking one of their own: both were folded in before 0.3 was ever tagged, so no file they would invalidate has ever existed. §15's requirement protects published files, and there were none. T8 in particular could not wait: it closes a signature malleability that phase 2 cannot close, because the transcript is already correct and the padding was never in scope of anything. `footer_off` keeps its lack of an alignment requirement, so the footer is decoded through alignment-independent reads. |
| 0.3.1 | Review-debt release. **No byte-layout change:** `version_minor` stays `3` and every 0.3 file is byte-identical. Corrects false claims (§7.3's `crit`-typo claim, §8.2's F4 citation and key-distribution statement), pins §9.2's merge to BLAKE3 specification revision `20211102173700` with full parent-node pseudocode and a worked example, and states that `cv(i)` is a **non-root** subtree chaining value. Reference implementation: chunk-verification ordering is type-enforced (`VerifiedChunkIndex`), manifest diagnostics carry an entry index/`name_id`, `ctf inspect` prints each section's `root`, `ChunkIndex::parse` requires its exact derived length, and `Manifest::validate_against` is linear. Closes every first-review finding; the post-fix re-review's new findings are recorded as tickets 70–97 and deferred. |
| 0.4.0 | Closes post-fix tickets 70 and 71. **No byte-layout change:** `version_minor` stays `3` and every `.ctf` file is byte-identical; this is a version break only because §15 reserves a change to the signature transcript for one. Adds **C8**: a reader MUST NOT expose a `SEALED` section's chunk index, nor one for a section whose `kind` it does not implement, because an entry is a chaining value of the plaintext (§9.1). Changes the §8.4 transcript from `v1` (59 bytes) to `v2` (67 bytes), adding `u32_le(sig_classical_len) ‖ u32_le(sig_pq_len)` after `suite_id`: F3–F5 left the split between the two signature slots free while §8.1 located the slots from those fields, so neither signature covered the split. A verifier MUST NOT accept a `v1` transcript and MUST NOT locate the slots from the fields alone (§8.1). Producing and checking signatures remains unspecified (§14), so no signed bundle exists for the change to invalidate. |
| 0.5.0 | Phase 2 groundwork and the authoring surface. **No byte-layout change:** `version_minor` stays `3` and every existing `.ctf` file is byte-identical. Defines zstd framing and the two decompression caps (§5.4, D1–D2), adds `MAX_DECOMPRESSED_SECTION` and `MAX_DECOMPRESSION_RATIO` to §12, and implements compression in the reference reader and writer. Specifies the five declaration keys `flag`, `generate`, `runtime`, `sealed`, `verify` (§7.6) and the namespaced `platform` overlay (§7.7), and makes strict key rejection normative for the authoring front end (§7.8). Specifies the entitlement record format, ordering, genesis binding, and signature transcript (§18), and the crypto suite registry with its failure timing (§19); only the BLAKE3 hash role is implemented. Nothing here narrows what is legal — each change either defines a structure a previous version left unspecified or widens what a reader accepts — so no feature bit is spent. |
| 0.6.0 | Phase 2 constructions. **No byte-layout change:** `version_minor` stays `3` and every existing `.ctf` file is byte-identical. Specifies and implements the hybrid KEM combiner (§20.1), the AEAD-STREAM construction with its nonce, AAD, and per-chunk length framing (§20.2) — including the composition of `comp = 1` with `enc = 1` — and hybrid signature production and verification over the §8.4 transcript (§20.3), for suites 1 and 2; suite 3's SLH-DSA signature role remains unimplemented. Nothing here narrows what is legal: it defines structures 0.5 left unspecified, and the 0.5 writer emits `enc = 0` only, so no feature bit is spent (§15). §14 shrinks accordingly — key envelopes, derived flags, entitlement signatures, key distribution, and the live gate remain unspecified. |
| 0.7.0 | Key envelopes, derived flags, and the review-debt tickets 72–97. **No byte-layout change:** `version_minor` stays `3` and every `.ctf` file this version's writer produces is byte-identical to a 0.6 file's for the same inputs. Specifies the key-envelope construction (§21) and the derived-flag and stage-key derivations (§22), and the production side of the hybrid signature — signing a bundle in place, changing no byte outside the footer (§20.3). Adds **R22** (an `EXTERNAL` record carries no codec) and gates **R20** on `CONTAINER_V1`; both ride the existing bit rather than spending a new one, because the mirror bytes R22 rules out were never well-defined (§5.7, §9.4) and no writer has produced the combination, while R20 on the legacy path protects nothing (§16). Places the C1–C7 chunk-index rules explicitly **on-use** in §10, and states `chunk_size ≠ 0` as a precondition of the §5.5 index-length formula, R19, T6, C1, and C3, with R16 ordered before them (§2.1, §5.6). §14 shrinks to entitlement signatures, key distribution, and the live gate. |
| 0.8.0 | Encrypted sections end to end, the entitlement chain, and stage gating. **No byte-layout change:** `version_minor` stays `3`, and the header, section table, footer, commitment root, and signature transcript are untouched. Adds **`name_id`** to the key-envelope map (§21.3, EN5), which is what lets one `keys` section deliver the content keys of every encrypted section; no writer has ever emitted a `keys` section, so no existing file carries the old three-key form. The reference writer now emits `enc = 1` — compress, then encrypt, with `comp = 1` framing one zstd frame per STREAM chunk (§5.4, §20.2) — and a reader recovers a section's key from its envelope and decrypts it. A **stage-gated** section's content key is `stage_key(flag(N−1), N)` rather than random (§20.2, §22.4); the derivation is the gate and no envelope carries it. Implements the entitlement chain's E1–E9 (§18): the record format was specified in 0.5.0, and **E9** now verifies `sig_platform` always and a `transfer`'s `sig_holder` given trusted keys, so §14 shrinks to key distribution and the live gate. Adds the optional `flag.stage_gate` declaration (§7.6) and enforces **DF5**: a stage gate on a static flag is rejected, and a static flag is `static`/`none` or any derivation this version does not implement. Closes the review-debt tickets 75, 77, 78, 79, and 82: §15's limit row is split by direction and §12 reconciled with it; §3's padding clause is gated on `CONTAINER_V1`; §16's M7 cell no longer claims to name the key; §4.5 names the test that asserts each header vector, with a dedicated **0.3 header vector test** added; and `ctf` gains argument parsing, shell completions, and CLI integration tests. Every change either defines what a previous version left unspecified or *widens* what a reader accepts, so no feature bit is spent (§15). |
| 0.9.0 | Review-debt tickets 81, 83, 86–88, 90–92, 95–97. **No byte-layout change:** `version_minor` stays `3` and every existing `.ctf` file is byte-identical. Adds the optional **`paths`** manifest key and rules M22–M25 (§7.2, §7.5), so a directory tree is representable without widening `names`: a relative POSIX path per `name_id`, checked component-by-component against the name rule so `.`, `..`, an absolute path, and a `\` are unrepresentable rather than filtered; unique across the map; and naming a real section. It is an ordinary manifest key, so no feature bit is spent — a reader that does not implement it carries it byte-for-byte (§7.3). The rest are diagnostic and reference-implementation changes with no format effect: a section root mismatch carries the section's `name_id` and the whole-file verification pass reports every mismatch instead of aborting on the first; `crit` list errors (M6–M8) carry an entry index like the sibling list rules; `ExceedsFile` reports the real file length and names `footer_off` as the bound when that is what fired; a pre-0.3 file is diagnosed as an older format with no container rather than as a feature-negotiation failure; `BadMagic` and `CborUnsupported` no longer echo input bytes; `ctf inspect` prints each section's full name so truncated labels cannot collide; the unused `Bundle::sig_input` is deleted and `Manifest::description` is pinned by a test. The design note's thread-parallel BLAKE3 claim is corrected to state the reference implementation hashes single-threaded. |
| 0.10.0 | Phase 3: the deterministic generator, and the progress payload of a handoff. **No byte-layout change:** `version_minor` stays `3`, the header, section table, footer, commitment root, and signature transcript are untouched, and every `.ctf` file this version's writer produces is byte-identical to a 0.9 file's for the same inputs. Adds **§23**, fixing the generator interface (a core WebAssembly module with no imports, exporting `memory`, `ctf_alloc`, `ctf_generate`, and `ctf_output_len`), the canonical output block, the output root, the interface version and WASM profile, the three determinism modes (`strict`, `flag_only`, `none`), and rules G1–G12 — including fuel rather than epochs, forced deterministic relaxed-SIMD, NaN canonicalization, and a cross-engine cross-check, which is how §23.6's settings are validated rather than trusted. Adds **§24**, fixing the sealed-progress payload a `progress` record carries across a handoff (P1–P4): a `holder`-context envelope and an AEAD ciphertext whose AAD binds suite, challenge, and subject. §7.6 gains `generate.interface` and `generate.profile`, makes `wasm` and `outputs` conditional on a non-`flag_only` determinism mode, and states that the container reader carries these declarations without acting on them; the output-to-`names` mapping is enforced by the authoring tool (§7.8), not the reader. Every change either defines a structure a previous version left unspecified or relaxes a rule, so no feature bit is spent (§15). Reference implementation: the `ctf-generator` crate (Wasmtime host with a `wasmi` cross-check and the determinism gate), the Rust and C guest SDKs, `ctf init` archetype scaffolds, the sealed-progress helpers, and `ctf transfer`. |
| 0.11.0 | Phase 4 and the platform interfaces. **No byte-layout change:** `version_minor` stays `3`, the header, section table, footer, commitment root, and signature transcript are untouched, and every `.ctf` file this version's writer produces is byte-identical to a 0.10 file's for the same inputs. Adds **§25**, the offline solvability gate: the `solver.wasm` ABI (a core module with no imports exporting `memory`, `ctf_alloc`, `ctf_solve`, and `ctf_output_len`), the artifact block that deliberately omits the flag, the flag output block, the gate procedure, the tri-state `passed`/`failed`/`unverified` status, and rules S1–S8. Adds **§26** (seed and flag injection: `CTF_SEED`/`/ctf/seed`, `CTF_FLAG`/`/ctf/flag`, `/ctf/data`, and the no-guessing rule I1–I5), **§27** (sealed release and its audit record, L1–L4), **§28** (the static artifact serving manifest and its two independent checks, V1–V5), **§29** (the platform ingest descriptor and the digest-pinning and referrer/origin policy checks, P1–P3 and O1–O3), **§30** (the bundle as an OCI image, media type `application/vnd.ctf.bundle.v1`, X1–X3), **§31** (the challenge base image contract, B1–B3), **§32** (the live gate socket contract, N1–N4 — specified, not implemented), and **§33** (the WTFlag adapter, W1–W3). Registers the bundle media type in §12 and removes the live gate from §14's unspecified list. Every addition defines a structure a previous version left unspecified, adds a platform-side policy that is not a container rule, or relaxes nothing; no feature bit is spent (§15). Reference implementation: `ctf-generator`'s solver host and offline gate, the `ctf-generator` container binary, and the `ctf` subcommands `run`, `serving-manifest`, `oci-export`, `oci-import`, and `release`. |
| 0.12.0 | Fills the last specification gaps (ticket 55). **No byte-layout change:** `version_minor` stays `3`, the header, section table, footer, commitment root, and signature transcript are untouched, and every `.ctf` file this version's writer produces is byte-identical to a 0.11 file's for the same inputs. Adds **§34**, the trusted-key interface: the trust set a verifier is supplied (`root`, `platform`, `holder`), the **holder public-key hash** `BLAKE3("ctf/holder-hash/v1" ‖ pk_classical ‖ pk_pq)` that E9 resolves a `transfer` against, the rule that a key trusted for one role is not accepted for another, and the separation of the §24 progress recipient KEM key from the holder signature key. Completes **§20.3** for suite 3 by fixing its parameter set (`SLH-DSA-SHA2-128s`, FIPS 205) and slot layout (`sig_pq = ML-DSA-65 ‖ SLH-DSA-SHA2-128s`, 11165 bytes), so a suite-3 verifier need not guess. Adds **S9–S10** to §25.7, requiring a gate to name each §25.5 stage it ran (with the §25.6 condition behind a non-passed outcome) and to persist a `ctf/verification/v1` record. Rewrites §14 to state that nothing is left unspecified and to list the three items specified but not implemented here. Every change defines a structure a previous version left unspecified and narrows nothing, so no feature bit is spent (§15). |

## 18. Entitlement records

An `entitlement` section (kind `6`, §5.2) carries an append-only, hash-chained,
hybrid-signed log (design §9). Its plaintext is a single canonical CBOR **array**
(§7.1) of record maps, so it is one CBOR value decoded under the same rules as the
manifest; a reader MUST reject any byte after the array.

### 18.1 Fields

| Key | Type | Required | Meaning |
|---|---|---|---|
| `seq` | uint | ● | Sequence number; the authoritative ordering |
| `type` | tstr | ● | `grant`, `transfer`, `revoke`, or `progress` |
| `challenge` | tstr | ● | Challenge `id` the record is about |
| `subject` | tstr | ● | Subject the record binds |
| `holder` | bstr, 32 bytes | ● | Holder public-key hash (§34.1) |
| `prev` | bstr, 32 bytes | ● | Record id of the previous record; 32 zero bytes at genesis |
| `root` | bstr, 32 bytes | ● at genesis only | Commitment root (§8.3) of the bundle the genesis grant was issued for |
| `timestamp` | int (uint or nint) | | Platform-issued; **advisory only** |
| `payload` | bstr | | Opaque bytes, e.g. a `progress` blob sealed to the new holder |
| `sig_holder` | map | required for `transfer`, absent otherwise | Current holder's hybrid signature |
| `sig_platform` | map | ● | Platform's hybrid signature |

A signature map has exactly two keys, `classical` and `pq`, each a byte string.

`holder` is the 32-byte **holder public-key hash** of §34.1: `BLAKE3` over a domain
label and the holder's hybrid signature public key. It names the holder whose
signature a `transfer` requires (E9); it is not the holder's KEM key, which is a
separate key used only by the §24 progress envelope and is supplied out of band
(§34.2).

### 18.2 Chaining and ordering

- `seq` MUST start at `0` and increase by exactly one per record, in array order.
  Ordering is by `seq`; `timestamp` MUST NOT be used for ordering or validation —
  clocks drift and clients lie, and the field exists for human audit display only.
- The **record id** of record *n* is
  `BLAKE3("ctf/entitlement/record/v1" ‖ cbor)`, where `cbor` is the canonical
  encoding of the record map with both `sig_*` keys removed.
  `"ctf/entitlement/record/v1"` is the 25 ASCII bytes, with no terminator.
- `prev` of record *n* (n > 0) MUST equal the record id of record *n−1*; `prev` of
  the genesis record (n = 0) MUST be 32 zero bytes.
- The genesis record MUST be a `grant` and MUST carry `root` equal to the
  commitment root of the bundle version it was issued for. This is what stops a
  grant for challenge version 3 being replayed as one for version 4 (design §9). No
  later record may carry `root`.

### 18.3 Signatures

Both signatures cover the identical transcript:

```text
sig_input = "ctf/entitlement-sig/v1" ‖ u16_le(suite_id) ‖ u32_le(seq) ‖ record_id
```

`"ctf/entitlement-sig/v1"` is 22 ASCII bytes. `suite_id` is the enclosing bundle's
header field, and both components of that suite's hybrid signature MUST verify
(§19). Every element after the label is fixed width, so the transcript is
`22 + 2 + 4 + 32 = 60` bytes and needs no length prefixes (design §7's `LP` rule
applies to inputs with a variable-width element). The label differs from §8.4's, so a
footer signature can never be replayed as an entitlement signature even though the
two share keys (design §9). `sig_holder` is required only for `transfer`, which is
what makes a handoff non-repudiable: the current holder cannot later claim another
player took the challenge.

### 18.4 Validation rules

A reader that understands entitlement records MUST reject the section if any of the
following holds.

| # | Rule |
|---:|---|
| E1 | The plaintext is not canonical CBOR per §7.1, or is not an array, or has bytes after it. |
| E2 | A record is not a map, a field has the wrong type, a required field is absent, or a 32-byte field is not exactly 32 bytes. |
| E3 | `seq` values are not exactly `0, 1, …, count−1` in array order. |
| E4 | `type` is not one of the four names. |
| E5 | The genesis record is not a `grant`, does not carry `root`, or has a non-zero `prev`. |
| E6 | A non-genesis record carries `root`. |
| E7 | `prev` of a record does not equal the record id of its predecessor. |
| E8 | `sig_platform` is absent; or `type` is `transfer` and `sig_holder` is absent; or `type` is not `transfer` and `sig_holder` is present. |
| E9 | A `sig_platform` signature, or a `transfer`'s `sig_holder` signature, does not verify under a trusted key. |

E9 needs trusted public keys the bundle does not carry, supplied as the trust set of
§34: the platform's public key always, and for a `transfer` the public key of the
holder named by the previous record. Both components of the suite's hybrid
signature MUST verify over the §18.3 transcript (§20.3); a failure of either is a
failure of the whole.
E1–E8 establish structure and the genesis binding, **not** authenticity: a reader
MUST NOT report a chain as authenticated until E9 has run with trusted keys.

### 18.5 Offline validation

Everything except E9 is checkable with no platform reachable: the records are
inside the bundle, the chain is a hash chain, and the genesis binds the bundle's
commitment root. E9 needs trusted public keys, but it needs no network either — the
signature primitive is local and the keys are an input (§34). That is why the chain
lives in the format rather than in a database table — an air-gapped forensics
workstation on USB media has to validate it, and it has to stay auditable even if
the platform's database is later found to be wrong (design §9).

## 19. Crypto suite registry

`suite_id` (§4.1) selects one crypto suite. A suite provides one implementation of
each primitive role, and a file MUST NOT mix primitives from different suites. The
registry is what lets a suite be retired — if ML-DSA's youth becomes a problem, for
example (design §7) — without moving a field or changing a record.

### 19.1 Roles and suites

| Role | Meaning |
|---|---|
| `hash` | Content hashing and the commitment |
| `kdf` | Key derivation |
| `kem` | Key encapsulation |
| `aead` | Authenticated encryption |
| `signature` | Digital signatures |

| `suite_id` | `kem` | `aead` | `hash` | `kdf` | `signature` |
|---:|---|---|---|---|---|
| 1 (default) | X25519 + ML-KEM-768 | AES-256-GCM | BLAKE3 | HKDF-SHA-256 | Ed25519 + ML-DSA-65 |
| 2 | X25519 + ML-KEM-768 | XChaCha20-Poly1305 | BLAKE3 | HKDF-SHA-256 | Ed25519 + ML-DSA-65 |
| 3 (archive) | X25519 + ML-KEM-768 | AES-256-GCM | BLAKE3 | HKDF-SHA-256 | Ed25519 + ML-DSA-65 + SLH-DSA |

Suite 3 is for the long-term archive copy only; its signature is larger and slower
to verify (design §7). §20.3 fixes the parameter set (`SLH-DSA-SHA2-128s`) and the
exact slot lengths for all three suites, so the registry is complete even for the
suite this version does not implement.

### 19.2 Rules

| # | Rule |
|---:|---|
| S1 | A reader MUST NOT reject a file during header parsing because `suite_id` is unrecognized (§4.3). |
| S2 | A reader MUST resolve `suite_id` through the registry at the first point a primitive is needed. |
| S3 | An id absent from the registry MUST be rejected at that point, naming the suite. |
| S4 | A suite's `hash` MUST produce 32 bytes; `root` and the chunk-index entries are fixed at 32 bytes (§12). |
| S5 | A suite selects **all** roles; mixing roles across suites MUST be rejected. |

This section specifies the registry and its failure timing. The `hash`, `kdf`,
`kem`, `aead`, and `signature` roles are implemented for suites 1 and 2 (§20). Suite
3's signature role includes SLH-DSA, which is not implemented, so resolving it
reports that the role is not implemented at the point of use — a suite is not
silently reduced to a subset of its hybrid signature.

## 20. Cryptographic constructions

This section specifies the phase 2 constructions behind the suite roles of §19: the
hybrid KEM combiner (§20.1), the chunked AEAD (§20.2), and the hybrid signature
(§20.3). They are normative for `suite_id` 1 and 2. Suite 3's signature is specified
by §19 as adding SLH-DSA; that role is not implemented in this version (§14).

Every `‖` below joins **fixed-width fields only**, except where `LP` length-prefixes
a variable-length input:

```text
LP(x) = u32_le(len(x)) ‖ x
```

Without the prefix, concatenation is ambiguous — in `a ‖ b` the pairs `("ab","c")`
and `("a","bc")` are the same bytes — so two different inputs would derive the same
key. The failure is silent and fails open, which is why the rule is stated before any
construction that uses it.

### 20.1 Hybrid KEM combiner

Suites 1 and 2 use X25519 + ML-KEM-768 (FIPS 203). The hybrid public key is
`pk_x25519 ‖ ek_mlkem`, the hybrid secret key is `sk_x25519 ‖ dk_mlkem`, and the
hybrid ciphertext is `ct_x25519 ‖ ct_mlkem`, where `ct_x25519` is the sender's
ephemeral X25519 public key.

| Component | Size (bytes) |
|---|---:|
| `pk_x25519`, `sk_x25519`, `ct_x25519` | 32 |
| `ek_mlkem` (ML-KEM-768 encapsulation key) | 1184 |
| `dk_mlkem` (decapsulation key seed, `d ‖ z`) | 64 |
| `ct_mlkem` (ML-KEM-768 ciphertext) | 1088 |

The combiner MUST be an HKDF-SHA-256 over **both** shared secrets **and the full
transcript** — never XOR, never a bare concatenation of the secrets:

```text
content_key = HKDF-SHA-256(
    ikm  = ss_x25519 ‖ ss_mlkem,
    salt = "ctf/kem/v1" ‖ u16_le(suite_id) ‖ u16_le(version_major),
    info = LP(ct_x25519) ‖ LP(ct_mlkem) ‖ LP(pk_x25519) ‖ LP(pk_mlkem)
           ‖ LP(context_label) )
```

`content_key` is 32 bytes. `context_label` is one of `storage`, `seal`, `stage:N`, or
`holder` (design §7). The salt binds `version_major` only, never `version_minor`
(§2.3): binding the minor would re-key every bundle on a spec bump that moved no
field. Binding both ciphertexts and both public keys into `info` is what stops an
attacker who controls one component's ciphertext from steering the derived key.

A decapsulating recipient reconstructs `pk_x25519` from `sk_x25519` and `pk_mlkem`
from `dk_mlkem`, so the transcript is identical on both sides.

### 20.2 AEAD-STREAM

A section with `enc = 1` — with or without `comp = 1` — is encrypted with the STREAM
construction (Hoang–Reyhanitabar–Rogaway–Vizár), not naive per-chunk AEAD. Naive
per-chunk AEAD is reorderable and truncatable: each chunk is individually authentic
and nothing binds its position. STREAM binds position and a final flag into the
nonce, and position and total length into the AAD.

`section_id` is the record's `name_id`, never its index in the section table (§5.1,
§3). Record order is free, so an index-derived nonce would change on every re-emit.

```text
nonce_prefix(section_id) = u16_le(section_id) ‖ 0x00 × (nonce_len − 7)
nonce = nonce_prefix(section_id) ‖ u32_be(chunk_index) ‖ final_flag
aad   = "ctf/stream/v1" ‖ u16_le(section_id) ‖ u32_le(chunk_index)
        ‖ u64_le(len_plain) ‖ u16_le(suite_id)
```

`nonce_len` is the suite's AEAD nonce size: 12 for AES-256-GCM (suite 1) and 24 for
XChaCha20-Poly1305 (suite 2). `final_flag` is `0x01` on the last chunk and `0x00`
otherwise. `len_plain` is the record's `len_plain`. The tag length is 16 for both
suites.

The stored body is a sequence of chunks, each framed as `u32_le(ct_len) ‖ ct`, where
`ct_len` is that chunk's ciphertext length including its tag and MUST be at least the
tag length (16). The last chunk in the body carries `final_flag = 0x01` and every
other `0x00`. A reader walks the prefixes from the start; the chunk whose `ct_len`
reaches the end of the body is the final one. A body whose last chunk was not sealed
as final fails its tag, which is what makes truncation detectable.

For `comp = 0`, the AEAD plaintext is the section plaintext, divided into
`ceil(len_plain / chunk_size)` chunks of at most `chunk_size` bytes in address order.
Chunk *i* is sealed with `chunk_index = i`, and
`len_stored = len_plain + count × (16 + 4)`.

For `comp = 1`, the AEAD plaintext is the concatenation of the zstd frames of §5.4,
and **each frame is one chunk**, so `chunk_index` is the frame index. `len_plain` in
the AAD remains the record's field — the total *decompressed* length — and frame *i*
MUST decompress to exactly `min(chunk_size, len_plain − i × chunk_size)` bytes. The
per-frame compressed lengths are not stored separately: they are the `ct_len`
prefixes, which is what lets a reader walk the body without knowing the compressed
length. This is the composition of `comp = 1` with `enc = 1`.

**Every encryption MUST draw a fresh random 32-byte `content_key`.** With a
per-encryption key, re-encrypting the same section under the same `name_id` is safe,
because it is a different keystream. Re-encrypting under a reused key is forbidden,
and no field exists that would make it safe. A rewriter MUST NOT reassign `name_id`
(§5.1).

**One exception, for stage gating.** A stage-gated section's content key is not
random: it is `stage_key(flag(N−1), N)` (§22.4). The derivation *is* the gate, so the
key must be recomputable by whoever submits the previous stage's flag, and it is
never delivered by an envelope. This is the only case in which a content key is not
drawn fresh, and it is safe for the same reason a fresh key is: the flag that derives
it is per-subject and per-stage, so two encryptions under one `name_id` still use
different keys unless the same flag is submitted twice for the same stage — which the
platform's one-shot stage progression forbids.

A reader MUST reject a body whose framing is malformed, whose last chunk was not
sealed as final, that has bytes beyond the body, or any chunk whose tag does not
verify, and MUST NOT return plaintext before every chunk has been authenticated
(C7).

### 20.3 Hybrid signature

Suites 1 and 2 sign with Ed25519 + ML-DSA-65 (FIPS 204); suite 3 adds SLH-DSA
(FIPS 205). Every component MUST verify over the identical §8.4 transcript. The two
components occupy the footer's two slots, so no in-slot encoding is needed:

| Slot | Primitive | Length (bytes) |
|---|---|---:|
| `sig_classical` | Ed25519 signature | 64 |
| `sig_pq` | ML-DSA-65 signature | 3309 |

The corresponding public keys are 32 and 1952 bytes. They are not carried in the
bundle (§8.2); a verifier is supplied them out of band (§34).

Verification succeeds only when **both** components verify over the same transcript.
A failure of either is a failure of the whole: there is no half-authentic result. A
bundle whose signature slots are empty authenticates nothing and MUST NOT be reported
as authentic, however intact it is. A verifier MUST NOT locate the slots from the
length fields alone (§8.1); the lengths are the suite's.

Suite 3 adds SLH-DSA-SHA2-128s (FIPS 205) as a third component. The footer has two
slots, so the two post-quantum components share `sig_pq` in a fixed order:

| Suite | `sig_classical` length | `sig_pq` contents | `sig_pq` length |
|---|---:|---|---:|
| 1, 2 | 64 | ML-DSA-65 | 3309 |
| 3 | 64 | ML-DSA-65 ‖ SLH-DSA-SHA2-128s | 3309 + 7856 = 11165 |

The corresponding public keys are Ed25519 32 bytes, ML-DSA-65 1952 bytes, and
SLH-DSA-SHA2-128s 32 bytes. `SLH-DSA-SHA2-128s` is FIPS 205's small-signature
parameter set; the archive suite is its only consumer and its signature is already
the dominant cost of a bundle, which is the whole reason the suite is separate.
A suite-3 verifier MUST split `sig_pq` at the ML-DSA-65 length and verify all three
components; a failure of any is a failure of the whole, exactly as for suites 1
and 2. Section §19.1's suite table assigns the `signature` role; this section fixes
the bytes that role produces, so a suite-3 verifier need not guess them.

SLH-DSA is not implemented in this version, so a suite-3 file cannot be
authenticated by the reference implementation; resolving the role reports the suite
and the role rather than silently reducing the hybrid to two of its three
components.

## 21. Key envelopes

A section's `content_key` is a fresh random 32-byte key, drawn per encryption
(§20.2). It is delivered to a named recipient by a **key envelope**: the hybrid KEM
of §20.1 establishes a per-envelope key-encryption key, and that key wraps the
content key. One envelope carries one recipient context; a section readable by
several contexts carries one envelope per context.

### 21.1 Construction

`context` is one of `storage`, `seal`, `stage:N` (with `N` in decimal), or
`holder` (design §7). `LP(x) = u32_le(len(x)) ‖ x` (§20).

```text
(ct, kek) = KEM.encapsulate(recipient_public_key,
                            KemContext { suite_id, version_major, label = context })

aad       = "ctf/envelope/v1" ‖ u16_le(suite_id) ‖ LP(context)
wrapped   = AEAD.seal(kek, nonce, aad, content_key)      # content_key is 32 bytes
```

`"ctf/envelope/v1"` is 15 ASCII bytes with no terminator. `nonce` is
`AEAD.nonce_len()` **zero** bytes.

**A zero nonce is safe here, and the reason is the construction, not an
assumption.** The AEAD requires a nonce unique under its key; `kek` is fresh for
every envelope, because every `KEM.encapsulate` draws new randomness, so no two
envelopes ever share a `(kek, nonce)` pair. Reusing an envelope's `ct` under a
different `wrapped` would repeat a nonce, which is why a rewriter MUST NOT
re-encapsulate under an unchanged `ct`.

### 21.2 Unwrapping

A recipient holding the matching hybrid secret key recovers the content key by
reversing §21.1, with four checks, all required:

| # | Rule |
|---|---|
| EN1 | `context` MUST equal the caller's expected context. |
| EN2 | `ct` MUST be exactly the suite's `kem.ciphertext_len()`. |
| EN3 | `kek = KEM.decapsulate(secret_key, ct, KemContext { suite_id, version_major, label = context })` MUST be derived over the *same* transcript. |
| EN4 | `AEAD.open(kek, nonce, aad, wrapped)` MUST authenticate, and MUST yield exactly 32 bytes. |

EN1 and EN3 are independent, and that is deliberate. EN1 refuses an envelope whose
declared context is not the one the caller wants, before any key is derived. EN3
binds the label into the KEM combiner's `info` (§20.1), so even an envelope that
passed a laxer EN1 derives a different `kek` and EN4 fails. A recipient without the
matching secret key fails EN4 as well: decapsulation yields a different `kek`, and
the tag does not verify.

### 21.3 `keys` section encoding

A `keys` section (kind 7, §5.2) carries envelopes as the plaintext of a single
canonical CBOR **array** (§7.1), one element per envelope, with no bytes after it.
Each element is a map with exactly four keys:

| Key | Type | Meaning |
|---|---|---|
| `name_id` | uint | The identity (§5.1) of the section whose `content_key` this envelope wraps |
| `context` | tstr | The recipient context, carried verbatim; §21.1 names the contexts in use |
| `ct` | bstr | The hybrid KEM ciphertext |
| `wrapped` | bstr | The content key sealed under the KEM-derived key |

`name_id` is what lets one `keys` section serve every encrypted section in a bundle:
a recipient finds the envelope addressed to the section it holds. It is the section's
own identity — the value the STREAM nonce and AAD already bind (§20.2) — so an
envelope whose `name_id` is swapped is not a forgery of a key; the recovered content
key is then used to decrypt a different section, whose STREAM AAD binds its own
`name_id`, and the tag does not verify.

A reader MUST reject a `keys` section whose plaintext is not canonical CBOR, is not
an array, has bytes after it, or contains an element that is not a map, is missing
one of the four keys, carries an extra key, has a field of the wrong type, or has a
`name_id` outside the `u16` section identity space (**EN5**). The `keys` section is
not `SEALED` by construction: an envelope is ciphertext, and hiding it would prevent
the recipient from finding it.

## 22. Derived flags

A bundle MUST NOT carry a flag value or the event secret. It carries a derivation
rule, and the platform derives the per-subject flag from an `event_secret` that
never enters a bundle, never enters git, and lives in a KMS or HSM (design §4, §7).
This section fixes the derivations, so two implementations agree on the flag a
subject receives.

### 22.1 Encoding

`LP(x) = u32_le(len(x)) ‖ x` (§20). Every variable-length input is length-prefixed
so that, for example, `("ab", "c")` and `("a", "bc")` cannot derive the same flag.

### 22.2 The per-subject seed

```text
seed(challenge, subject) = HKDF-SHA-256(
    ikm  = event_secret,
    salt = "ctf/seed/v1",
    info = LP(chal_id) ‖ u64_le(chal_version) ‖ LP(subject_id) )
```

`"ctf/seed/v1"` is 11 ASCII bytes. `chal_id` is the manifest `id` (§7.2) as UTF-8,
and `subject_id` is the subject's identifier as UTF-8; both are length-prefixed.
`chal_version` is the manifest `version` (§7.2) as a **fixed-width** `u64`
little-endian, and is therefore **not** length-prefixed — the design sketch wrote
`LP(chal_version)` for a variable-width reading, and this document fixes the
unambiguous fixed-width encoding instead. `seed` is 32 bytes.

### 22.3 The flag

```text
flag(seed) = base32_lower( HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..10] )
```

`"ctf/flag/v1"` is 11 ASCII bytes, the HMAC message; `seed` is the key. The first
10 bytes are 80 bits and encode to exactly 16 base32 symbols. `base32_lower` is
RFC 4648 §6 with the alphabet `abcdefghijklmnopqrstuvwxyz234567`, lowercase, and
**no** `=` padding.

The flag's length is a per-challenge choice, not a format constant: the default
10-byte prefix of the tag yields 80 bits and 16 symbols, while a challenge that needs
a 128-bit boundary keeps 16 bytes, which base32 renders as 26 characters. The
ceiling is the HMAC-SHA-256 tag itself — 32 bytes, or 52 symbols — because a flag can
never carry more entropy than the tag it is truncated from. §22.5 states the
consequence.

### 22.4 Stage keys

```text
stage_key(flag(N-1), N) = HKDF-SHA-256(
    ikm  = flag(N-1).as_bytes(),
    salt = "ctf/stage/v1",
    info = u32_le(N) )
```

`"ctf/stage/v1"` is 12 ASCII bytes. The key for stage *N* derives from the **flag**
of stage *N-1*, so unlocking order is enforced by the derivation, not by platform
logic. The resulting 32 bytes are a `content_key` that a section's `stage:N`
envelope (§21) delivers, so a stage-gated section is `enc = 1` and
`PLAYER_VISIBLE`, never `SEALED` (§5.3).

### 22.5 Rules and the entropy ceiling

| # | Rule |
|---|---|
| DF1 | A bundle MUST NOT contain the flag, the event secret, or any stage key. It carries only the derivation rule. |
| DF2 | `chal_version` is `u64_le` and is not length-prefixed; `chal_id` and `subject_id` are length-prefixed. |
| DF3 | `flag` is 16 lowercase base32 characters for the default derivation, with no padding. |
| DF4 | A stage key derives from the previous stage's flag, never from the stage number alone. |
| DF5 | A validator MUST reject a `stage_gate` declared on a **static** flag: an 80-bit derived flag is an acceptable key, a guessable static string is not. |

A stage gate is declared by `flag.stage_gate` (§7.6). A flag is **derived** when
`flag` is the shorthand `derived`, or its `derive` is `derived` or `hkdf-sha256`; it
is **static** otherwise — `static`, `none`, or any derivation name this version does
not implement, because an unknown derivation cannot be assumed to contribute
entropy.

**The 80-bit ceiling is real and inherent.** A stage key must be derivable from the
flag a player submits and nothing else, so stage gating's strength is exactly the
entropy of that flag: 2^80 against an attacker who holds the bundle offline and
wants to open stage *N* without solving stage *N-1*. That is far out of reach for a
48-hour event and far short of the 128-bit floor the rest of the stack targets. A
challenge that needs a real cryptographic boundary uses a longer derived flag
(§22.3); the length is a per-challenge choice.

## 23. Generator interface and determinism

A `generator` section (kind `3`, §5.2) carries `gen.wasm` — the deterministic
challenge function of design §8. The premise of the format is that a challenge is
a *pure* function `challenge(seed) -> (artifacts, flag)`, and this section fixes
the interface and the sandbox that make "pure" enforceable rather than promised.

### 23.1 The sandbox

The plaintext is a **core** WebAssembly module (not a component). It MUST have no
imports: the host provides no WASI, clock, network, filesystem, randomness, or any
other capability, so a conforming module cannot observe one, and a module that
imports anything MUST be rejected before it runs. Determinism is a property of the
sandbox, not of author discipline (design §8).

### 23.2 Exports — the ABI

The module MUST export `memory` and exactly these three functions, with these
signatures. A module missing one, or exporting one with a different signature, is
rejected.

| Export | Signature | Meaning |
|---|---|---|
| `memory` | linear memory | The address space for seed and output |
| `ctf_alloc` | `(len: u32) -> u32` | Allocate `len` zeroed bytes; returns the pointer, `0` on failure |
| `ctf_generate` | `(seed_ptr: u32, seed_len: u32) -> u32` | Run the generator on the seed; returns a pointer to the output block, `0` on failure |
| `ctf_output_len` | `() -> u32` | Byte length of the block the last `ctf_generate` produced |

The host writes the seed into `ctf_alloc(seed_len)` and calls `ctf_generate`; it
then reads `ctf_output_len()` bytes at the returned pointer. Every pointer and
length is bounds-checked against the module's current memory before a byte is read.

### 23.3 Output block

The output block is little-endian, with no padding and no alignment requirement:

```text
u32_le count
count × { u32_le name_len; name bytes (UTF-8); u32_le data_len; data bytes }
u32_le flag_len; flag bytes (UTF-8)
```

`count` is the number of named outputs; the flag follows the last output. A block
that ends early, has trailing bytes, names a duplicate output, names an output not
declared by `generate.outputs` (§7.6), or carries invalid UTF-8 is rejected. The
encoding is canonical: one value has exactly one byte string, so the output root
below is injective.

### 23.4 Output root

```text
output_root = BLAKE3("ctf/generator-output/v1" ‖ output block bytes)
```

`"ctf/generator-output/v1"` is 24 ASCII bytes applied as the BLAKE3 prefix. The
output root is the value the determinism gate compares; two runs that produce
different bytes have different roots by the injectivity of §23.3.

### 23.5 Interface version and WASM profile

Two declarations version the interface independently of the container and of the
manifest `spec` (§7.2), for the reason design §8 gives: a determinism guarantee is
only meaningful relative to a pinned feature set, and tying that set to
`version_minor` would mean a spec bump that touches nothing about WASM silently
changes what a generator may do.

- `generate.interface` (§7.6) is the **interface version**. This document defines
  interface **1**. A host MUST reject an interface version it does not implement
  before running the module, and MUST NOT guess at a later one.
- `generate.profile` (§7.6) is the **WASM feature profile**. Profile **1** enables
  multi-value, bulk-memory, reference-types, sign-extension, mutable-globals,
  saturating-float-to-int, SIMD, and relaxed-SIMD (with the deterministic
  lowering below), and floats; it disables threads, memory64, tail-call, GC,
  exceptions, wide-arithmetic, custom-page-sizes, stack-switching, and
  multi-memory. A host MUST reject an unknown profile number rather than run it
  under a different feature set.

### 23.6 Determinism

A profile-1 host MUST configure the engine so that all of the following hold:

- **Relaxed SIMD is forced deterministic** (`relaxed_simd_deterministic`): one
  defined behaviour on every architecture, rather than banning the feature.
- **Float NaN bits are canonicalized**, so a NaN payload cannot vary by codegen.
- **Threads are disabled**, so no shared state or scheduling can be observed.
- **CPU limits use fuel, not wall-clock interruption.** Fuel traps at a fixed
  count, so the limit is part of the deterministic result; an epoch or timeout is
  wall-clock driven and would make a near-limit generator pass ingest and fail in
  production.

### 23.7 Determinism modes

`generate.determinism` (§7.6) is one of:

| Mode | Meaning |
|---|---|
| `strict` | A generator is required and MUST pass the gate below. |
| `flag_only` | No generator exists. `wasm` and `outputs` MUST be absent. Per-subject flags still derive from the event secret (§22); this is the default path and covers most challenges (design §8). |
| `none` | A generator is declared, but reproducibility is not required and the gate is not run. Used for one-shot artifact generation. |

### 23.8 Rules

| # | Rule |
|---|---|
| G1 | The `generator` section's plaintext is a core WebAssembly module. |
| G2 | The module MUST have no imports; a host MUST reject one that does. |
| G3 | The module MUST export `memory`, `ctf_alloc`, `ctf_generate`, and `ctf_output_len` with the signatures of §23.2. |
| G4 | Every pointer and length the host reads MUST be bounds-checked against the module's current memory. |
| G5 | A resource limit bounds guest execution (fuel) and guest memory; exceeding it rejects the run. |
| G6 | `generate.interface` MUST be a version the host implements (§23.5). |
| G7 | `generate.profile` MUST be a profile the host implements (§23.5). |
| G8 | The output block MUST be canonical per §23.3, and every named output MUST be declared in `generate.outputs`. |
| G9 | `determinism: strict` MUST run the generator **twice in one process with the reference seed** and reject if the two output roots differ. |
| G10 | The determinism cross-check MUST also run the same module on a second engine (§23.6's settings are validated by agreement, not trusted), and reject a disagreement. |
| G11 | The conformance suite MUST run the same module on x86-64 and aarch64 and reject a difference. |
| G12 | A host MUST NOT expose a section's plaintext, or any other capability, to the guest; the only inputs are the seed and the module's own bytes. |

### 23.9 Testing

A module importing any capability is rejected by G2 before it runs. A module that
observes its own call count, reads a global that changes between calls, or
otherwise varies across two `ctf_generate` calls in one instance is rejected by
G9. Cross-engine disagreement is rejected by G10.

## 24. Sealed progress payloads

A `progress` record's `payload` (§18.1) is opaque to the chain, but a handoff mid
multi-stage challenge needs it to carry the stages already earned, sealed to the
**new** holder's key (design §9). This section fixes its shape when it is present;
a reader that does not understand it carries the record and does not reject the
chain, because the chain's structure (E1–E8) does not depend on the payload.

### 24.1 Shape

`payload`, when present on a `progress` record, is one canonical CBOR map (§7.1)
with exactly two keys:

| Key | Type | Meaning |
|---|---|---|
| `envelope` | map | A key envelope (§21.3) whose `context` is `holder` |
| `ct` | bstr | The progress plaintext sealed under the envelope's content key |

The envelope's `name_id` is `0`: a progress payload wraps a content key rather
than a section's, and `0` is not a valid section identity for this purpose because
no section carries it. The content key is a fresh 32-byte key delivered to the new
holder's hybrid KEM public key.

### 24.2 The progress ciphertext

```text
ct = AEAD.seal(
       key   = content_key,
       nonce = 0,
       aad   = "ctf/progress/v1" ‖ u16_le(suite_id) ‖ LP(challenge) ‖ LP(subject),
       plaintext )
```

`"ctf/progress/v1"` is 16 ASCII bytes. The all-zero nonce is safe for the same
reason an envelope's is (§21.1): every payload draws a fresh content key, so no
`(key, nonce)` pair repeats. `challenge` and `subject` are length-prefixed because
they are variable width (design §7's `LP` rule); binding them into the AAD stops a
payload being replayed under a different challenge or subject.

### 24.3 Rules

| # | Rule |
|---|---|
| P1 | A `progress` payload, when present, MUST be a canonical CBOR map with exactly `envelope` and `ct`. |
| P2 | The envelope's `context` MUST be `holder`. |
| P3 | `ct` MUST open under the content key the envelope yields, with the §24.2 AAD. |
| P4 | A reader without the new holder's hybrid KEM secret key MUST NOT recover the plaintext. |

A `progress` payload is present in the bundle and is therefore covered by the
commitment root and the record id; it is not a `SEALED` section, so the container
does not require it to be encrypted — the chain distinguishes a progress record by
its `type`, and the payload's confidentiality is the envelope's job.

## 25. Offline solvability gate

Pillar 5's implementable half (design §3): a bundle that cannot be solved cannot be
published. A `solver` section (kind `4`, §5.2) carries `solver.wasm`, the author's
proof that the challenge is solvable from the generated artifacts alone. This
section fixes the solver interface and the gate procedure.

The solver is the author's own program, not a format-defined one: the format fixes
only the sandbox it runs in, the block it receives, the block it returns, and what
the gate does with the result.

### 25.1 The sandbox

A solver's plaintext is a **core** WebAssembly module (not a component). Like a
generator (§23.1) it MUST have no imports: the host provides no WASI, clock,
network, filesystem, randomness, or any other capability, so a conforming solver
cannot observe one, and a module that imports anything MUST be rejected before it
runs. A solver therefore has exactly two inputs: its own bytes and the artifact
block (§25.3).

### 25.2 Exports — the ABI

The module MUST export `memory` and exactly these three functions, with these
signatures. A module missing one, or exporting one with a different signature, is
rejected.

| Export | Signature | Meaning |
|---|---|---|
| `memory` | linear memory | The address space for input and output |
| `ctf_alloc` | `(len: u32) -> u32` | Allocate `len` zeroed bytes; returns the pointer, `0` on failure |
| `ctf_solve` | `(input_ptr: u32, input_len: u32) -> u32` | Run the solver on the input block; returns a pointer to the output block, `0` on failure |
| `ctf_output_len` | `() -> u32` | Byte length of the block the last `ctf_solve` produced |

The host writes the artifact block into `ctf_alloc(input_len)` and calls
`ctf_solve`; it then reads `ctf_output_len()` bytes at the returned pointer. Every
pointer and length is bounds-checked against the module's current memory before a
byte is read.

### 25.3 The artifact block (input)

The input block is little-endian, with no padding and no alignment requirement:

```text
u32_le count
count × { u32_le name_len; name bytes (UTF-8); u32_le data_len; data bytes }
```

It is exactly the generator output block of §23.3 **without the trailing flag**. The
solver MUST NOT receive the flag: handing it the generator's flag would make the
gate vacuous, because a solver could echo it without solving anything. A block that
ends early, has trailing bytes, names a duplicate output, or carries invalid UTF-8
is rejected by the host.

### 25.4 The flag block (output)

The solver's output block is little-endian:

```text
u32_le flag_len; flag bytes (UTF-8)
```

`flag_len` is bounded, the bytes MUST be valid UTF-8, and trailing bytes are
rejected. The block carries nothing else: the solver's entire result is the flag it
recovered.

### 25.5 The gate procedure

A conforming gate MUST, in order:

1. Run the generator at the reference seed under the determinism gate (§23.8,
   rules G9 and G10), obtaining the named outputs.
2. Build the artifact block (§25.3) from those outputs.
3. Run the solver on the artifact block in the same capability-free sandbox
   (§25.1).
4. Compare the solver's flag (§25.4) to the **derived flag** for the reference
   subject (§22.3).

A solver that does not recover the derived flag blocks publication.

### 25.6 Tri-state status

| Status | Meaning |
|---|---|
| `passed` | The solver recovered the derived flag. |
| `failed` | The solver ran but produced a different flag. |
| `unverified` | The gate could not be run. |

A bundle is `unverified`, never `passed`, when any of the following holds: it
declares `runtime` (solving needs a booted instance, §32); its `verify.offline`
declaration is false or absent; or it declares no generator or no solver. An honest
`unverified` is a usable state; a false `passed` is worse than no gate at all
(design §3).

A conforming gate MUST name each stage of §25.5 that it ran, and for a `failed` or
`unverified` outcome MUST name the stage or the condition that produced it, so a
caller can tell a flag mismatch from a module that could not be sandboxed.

The reference tooling persists the outcome as a **verification record**: a JSON
object written alongside the bundle it describes, never inside one. It is derived
data about a run, not a container structure, and it is not covered by the
commitment root.

```json
{
  "schema": "ctf/verification/v1",
  "challenge": "<manifest id>",
  "version": 0,
  "subject": "reference",
  "status": "passed",
  "reason": "the solver recovered the derived flag",
  "generator_root": "<64 lowercase hex, or null>",
  "cross_engine": true,
  "runs": 2
}
```

`generator_root`, `cross_engine`, and `runs` are `null` when the gate did not run;
`challenge` and `subject` are JSON strings with `"` and `\` escaped.

### 25.7 Rules

| # | Rule |
|---|---|
| S1 | A `solver` section's plaintext is a core WebAssembly module. |
| S2 | The module MUST have no imports; a host MUST reject one that does. |
| S3 | The module MUST export `memory`, `ctf_alloc`, `ctf_solve`, and `ctf_output_len` with the signatures of §25.2. |
| S4 | Every pointer and length the host reads MUST be bounds-checked against the module's current memory. |
| S5 | A resource limit bounds guest execution (fuel) and guest memory; exceeding it rejects the run. |
| S6 | The input block MUST be the canonical artifact block of §25.3 and MUST NOT carry the flag. |
| S7 | The output block MUST be canonical per §25.4, and its flag MUST be valid UTF-8. |
| S8 | A bundle whose gate does not run MUST be reported `unverified` (§25.6), never `passed`. |
| S9 | A gate MUST name each §25.5 stage it ran, and MUST name the stage or §25.6 condition behind a `failed` or `unverified` outcome. |
| S10 | A persisted verification record MUST carry the `ctf/verification/v1` schema, the `status`, and the `challenge` it describes. |

## 26. Seed and flag injection

A generator-based challenge starts inside the platform with the **per-subject seed**
and the **derived flag** injected, so `ctf_generate(seed)` is reproducible and the
challenge service knows what a player must submit. This section fixes the injection
mechanism for authors and for the platform.

### 26.1 The mechanism

| Value | Environment | Mount | Encoding |
|---|---|---|---|
| seed | `CTF_SEED` | `/ctf/seed` | 64 lowercase hex digits, or 32 raw bytes in the file |
| flag | `CTF_FLAG` | `/ctf/flag` | the flag text |
| generated artifacts | — | `/ctf/data` | written by the generator host |

The environment variable wins over the mount, so an orchestrator may inject without
a volume. The host MUST read the seed through this mechanism and write it into
guest memory; it MUST NOT read the seed from anywhere else.

### 26.2 Rules

| # | Rule |
|---|---|
| I1 | The seed is 32 bytes, injected as 64 lowercase hex digits (`CTF_SEED`) or as a 32-byte file (`/ctf/seed`). |
| I2 | A container with no injected seed MUST fail to start. It MUST NOT default, derive, or guess a seed. |
| I3 | The environment variable takes precedence over the mount when both are present. |
| I4 | When `CTF_FLAG` (or `/ctf/flag`) is injected, the flag the generator computes MUST equal it; a mismatch MUST fail the start. |
| I5 | Generated artifacts are written under the data mount; a generated name that is path-like MUST be rejected (a name becomes a filename). |

The seed is a secret in the same sense `event_secret` is (§22): it is injected at
runtime and never written into a bundle.

## 27. Sealed release

A `solver`, `writeup`, or `progress` section is `SEALED` (§5.3): its plaintext needs
a key the platform does not hold while the event runs (design §4). At event end the
**offline seal key** is brought back and the sections are released.

### 27.1 The release

A bundle's `sealed` declaration (§7.6) names a `release` mode — `event_end`,
`manual`, or `stage:<id>` — and the `members` it covers. A release at event end:

1. decrypts each covered `SEALED` section with the `seal` recipient's secret key
   (the envelope of §21 carries its `content_key` under context `seal`);
2. verifies each recovered plaintext against its section `root` before writing it;
3. emits an audit record.

A bundle with no `sealed` declaration releases every `SEALED` section. A declaration
whose `release` is not `event_end` MUST NOT be released by the event-end operation:
a `manual` or `stage:<id>` release is a different authorization.

### 27.2 The audit record

The release record carries the bundle's commitment root, the challenge `id` and
`version`, the release mode, and for each released member its `name_id`, name, size,
and `root`. It MUST NOT contain any released plaintext, so it can be published or
archived without leaking a writeup or solver.

### 27.3 What it does not protect against

The scheme protects against storage theft and pre-release leaks only if the seal key
is **not resident on the platform during the event** (design §4). If the platform
holds the seal key anyway, release is policy, not cryptography. Sealed sections are
encrypted to the seal recipient only, never additionally wrapped to the platform's
storage key.

| # | Rule |
|---|---|
| L1 | An event-end release MUST use the `seal` recipient's secret key and MUST NOT proceed without it. |
| L2 | A recovered plaintext MUST verify against its section `root` before it is written out. |
| L3 | A release whose declared mode is not `event_end` MUST be refused by the event-end operation. |
| L4 | The audit record MUST NOT contain released plaintext. |

## 28. Static artifact serving manifest

A platform serving a challenge's player-visible artifacts needs each artifact's
name, size, and root so it can verify bytes as it hands them out, without
re-deriving the commitment or trusting a client-supplied list. The serving manifest
is that projection of a parsed bundle.

### 28.1 Shape

The serving manifest is one canonical CBOR map (§7.1):

| Key | Type | Meaning |
|---|---|---|
| `challenge_id` | tstr | The manifest `id` |
| `version` | uint | The manifest `version` |
| `artifacts` | array | The servable artifacts |

Each entry of `artifacts` is a map:

| Key | Type | Required | Meaning |
|---|---|:-:|---|
| `name_id` | uint | ● | The section's identity (§5.1) |
| `name` | tstr | ● | The name table entry |
| `size` | uint | ● | The record's `len_plain` |
| `root` | bstr, 32 bytes | ● | The record's `root` |
| `external` | bool | ● | Whether the bytes live outside the bundle |
| `path` | tstr | | The `paths` entry, when the manifest declares one |
| `mirrors` | array of tstr | | Present only for an external artifact |

### 28.2 Rules

| # | Rule |
|---|---|
| V1 | Only sections carrying `PLAYER_VISIBLE` appear. |
| V2 | A `SEALED` section MUST NOT appear, whatever its flags (§5.3, design §10). |
| V3 | Each artifact's `size` and `root` are the record's `len_plain` and `root`. |
| V4 | Bytes MUST NOT be served before they verify against the artifact's `size` and `root`. Both are checked: BLAKE3 over a prefix is a valid hash of that prefix, so a truncated payload is caught only by the length. |
| V5 | An external artifact's bytes are fetched and verified against its `root`; they are not in the bundle. |

The two checks of V1 and V2 are independent on purpose (design §10): the container
makes the pair unrepresentable (R5), but a serving manifest is exactly the artifact
a leak would flow through, so it re-states the rule rather than assuming it.

## 29. Platform ingest descriptor and policy checks

The platform's challenge and runtime records are not the manifest's shape. Packing a
bundle produces a JSON **ingest descriptor** projected from the manifest, and two
policy checks that are the platform's, not the container's.

### 29.1 The descriptor

| Field | Source |
|---|---|
| `slug` | manifest `id` |
| `name` | manifest `name` |
| `category` | manifest `category`, when present |
| `version` | manifest `version` |
| `level` | platform overlay (`platform.<namespace>.level`) |
| `image` | `runtime.image` |
| `port` | `runtime.ports[0].container` |
| `resources` | `runtime.resources` |
| `storage_size` | platform overlay |
| `read_only` | platform overlay |
| `ttl` | `runtime.ttl` |
| `readiness` | `runtime.readiness` |
| `referrer_policy` | always `no-referrer` (§29.3) |

An absent field is omitted rather than emitted as `null`. The descriptor is derived
data: it MUST be projected from the manifest that was packed, so it cannot disagree
with the bundle's committed bytes.

### 29.2 Digest-pinned images

A `runtime.image` MUST be a digest, never a tag: `name@sha256:` followed by exactly
64 lowercase hex digits. A tag — including a name that carries one alongside a
digest — MUST be rejected. The image is an ordinary manifest key and is therefore
inside the commitment root and the author's signature; this rule is what keeps a
mutable reference from being committed to at all.

The check MUST run at authoring time (`ctf pack`) and again as a read-time policy
pass over the parsed manifest. It is **not** a container rule: §7.6 makes the
container carry `runtime` without acting on it, so a tagged image is a readable
bundle and a policy failure, not a parse failure.

| # | Rule |
|---|---|
| P1 | `runtime.image` MUST end with `@sha256:` and 64 lowercase hex digits. |
| P2 | A tag on the name portion MUST be rejected. |
| P3 | The check MUST be applied at authoring time and at read time. |

### 29.3 Third-party origins and the referrer policy

A challenge frontend that loads an external asset sends the challenge's capability
URL in its `Referer` header, handing a third party access. The format cannot rewrite
a frontend, so the policy is:

- The descriptor's `referrer_policy` defaults to `no-referrer` and is not an
  authoring choice in this version.
- An absolute `http(s)` URL in the manifest `description` MUST be reported at
  authoring time. It is a warning, not an error: a description may legitimately
  contain a hyperlink. A challenge that vendors its assets references them relatively
  and produces no warning.

| # | Rule |
|---|---|
| O1 | The descriptor's `referrer_policy` is `no-referrer`. |
| O2 | An absolute `http(s)` origin in `description` is reported at authoring time. |
| O3 | Relative references are not reported. |

## 30. Bundle as an OCI artifact

A `.ctf` is distributed as an **OCI image** (OCI Image Spec v1.1) so a registry
gains digests, immutability, and replication without knowing the format.

### 30.1 Media types

| Media type | Blob |
|---|---|
| `application/vnd.ctf.bundle.v1` | the `.ctf` bundle (the layer) |
| `application/vnd.ctf.bundle.config.v1+json` | an empty image config |
| `application/vnd.oci.image.manifest.v1+json` | the image manifest |
| `application/vnd.oci.image.index.v1+json` | the image index |

### 30.2 The layout

An OCI image layout: `oci-layout` (version `1.0.0`), `index.json`, and
`blobs/sha256/<hex>`. The index references one image manifest; the manifest's single
layer is the bundle with media type `application/vnd.ctf.bundle.v1`.

### 30.3 Round-trip and digest

The layer blob is the bundle, unmodified: there is no re-serialization step, so a
push/pull round trip is byte-for-byte. The registry digest is `sha256` of the bundle
and is independent of the format's BLAKE3 commitment; both are checked, and the OCI
digest is a transport address, never a substitute for the commitment.

| # | Rule |
|---|---|
| X1 | The bundle layer's media type is `application/vnd.ctf.bundle.v1`. |
| X2 | Export then import MUST reproduce the bundle byte-for-byte. |
| X3 | The content address MUST be `sha256` of the bundle bytes. |

## 31. Challenge base image contract

A challenge that declares `runtime` runs on the challenge base image. The image
carries the generator host (§23) and nothing else; the orchestrator boots it.

| Mount | Contents | Direction |
|---|---|---|
| `/ctf/data` | generated artifacts | written |
| `/ctf/seed` | the injected seed (§26) | read-only |
| `/ctf/flag` | the injected derived flag (§26) | read-only, optional |

The image MUST default to a **non-root** user and the orchestrator MUST run it with
a **read-only root filesystem**, so only the data mount is writable. The generator
needs no network.

| # | Rule |
|---|---|
| B1 | The image MUST include the generator host and run a declared `gen.wasm`. |
| B2 | The data mount and the seed/flag mount paths are fixed as in the table. |
| B3 | The default user is non-root and the root filesystem is read-only. |

## 32. The live solvability gate contract

The offline gate (§25) covers artifact-only challenges. A challenge that declares
`runtime` is solved against a **booted instance**, which the orchestrator project
provides (design §2). This section is the socket contract the orchestrator MUST
satisfy; it is specified here so the platform side does not have to guess.

### 32.1 Connection

1. The orchestrator boots the instance from `runtime.image` and waits for
   `runtime.readiness` to succeed.
2. It opens exactly one TCP connection to the instance at `runtime.readiness.tcp`
   on the orchestrator's side of the network.
3. It hands the solver that one connection and **no other network capability**.

### 32.2 The solve exchange

The solver speaks its own protocol over the connection; the format does not fix it,
because only the author knows what the instance speaks. The format fixes the
transport: one connected socket, no other capability, bounded by the same fuel and
memory limits as §25.1.

### 32.3 The result

The solver's result is the flag block of §25.4. The gate compares it to the derived
flag for the subject, exactly as §25.5 step 4, and reports the tri-state of §25.6.

### 32.4 Until it exists

No implementation of this section ships in this repository. Until an orchestrator
implements it, a `runtime`-bearing bundle MUST be recorded `unverified`, never
`passed` (§25.6).

| # | Rule |
|---|---|
| N1 | The orchestrator provides one connected TCP socket to the readiness port and no other network capability. |
| N2 | The solver's result is the §25.4 flag block, compared to the derived flag. |
| N3 | The status is tri-state per §25.6. |
| N4 | A `runtime`-bearing bundle is `unverified` until an implementation of this section exists. |

## 33. The WTFlag adapter

The platform mints flags from a per-challenge key and a team; the format mints them
from a challenge `id`/`version` and a subject (§22). This section is the documented
adapter between the two, so the platform does not have to invent a second derivation
or protect a second secret.

| Platform concept | Format concept |
|---|---|
| challenge key | manifest `id` (`chal_id`) |
| challenge revision | manifest `version` (`chal_version`) |
| **team** | **`subject_id`** |
| the signing pod's secret | `event_secret` |

Team maps to subject one-to-one. With `subject_scope: team` (the default, §7.6)
every member of a team derives the same flag, and a handoff between teammates is
free because it is not a subject change (design §9).

`event_secret` lives in exactly one place — the signing pod — and every flag is
minted by that one holder. The format never carries the secret or a flag (DF1), so
the bundle a player downloads leaks nothing and the platform does not gain a second
secret to protect.

| # | Rule |
|---|---|
| W1 | The adapter's subject id is the team identifier, verbatim. |
| W2 | Its seed and flag are exactly §22.2 and §22.3 with that mapping. |
| W3 | `event_secret` is held by a single oracle and is never written into a bundle. |

## 34. Trusted keys (interface)

The container never carries a verification key (§8.2). Verification is therefore an
operation with two inputs: the file, and a **trust set** the verifier is supplied
out of band. This section fixes the shape of that input so a verifier does not have
to invent one, in the same spirit as §32's socket contract. It is an interface, not
a container structure: nothing here appears in a bundle or inside the commitment
root.

### 34.1 The holder hash

An entitlement record names its holder by the 32-byte `holder` field (§18.1), not by
a public key. The field is the holder's **holder public-key hash**:

```text
holder = BLAKE3("ctf/holder-hash/v1" ‖ pk_classical ‖ pk_pq)
```

`"ctf/holder-hash/v1"` is the 18 ASCII bytes with no terminator and no length
prefix. `pk_classical` is the holder's Ed25519 public key (32 bytes) and `pk_pq` is
the holder's post-quantum signature public key in the slot order of §20.3
(ML-DSA-65, 1952 bytes; for suite 3, ML-DSA-65 ‖ SLH-DSA-SHA2-128s, §20.3). The
hash is over the **signature** public key — the one that verifies `sig_holder` — not
over the KEM key of §24.

A verifier resolves a `holder` by hashing each trusted holder signature key and
comparing. A `holder` with no matching trusted key is an E9 failure, not a
structural error: E1–E8 do not depend on key distribution.

### 34.2 The trust set

A trust set binds three key roles. Each public key is a hybrid signature public key
per §20.3: the classical component and the post-quantum component(s).

| Role | Verifies | Key |
|---|---|---|
| `root` | the footer signature (§8.4, §20.3) | the authoring org's hybrid signature public key |
| `platform` | `sig_platform` on every entitlement record (§18.3, E9) | the platform's hybrid signature public key |
| `holder` | a `transfer`'s `sig_holder` (§18.3, E9) | the current holder's hybrid signature public key, resolved through §34.1 |

`root` and `platform` may be the same key; the format neither requires nor forbids
their separation. A verifier MUST NOT treat a key it was not given as trusted; the
trust set is the whole of its authority, and a key presented by the file is never
one of them.

The **progress recipient key** of §24 is a fourth, separate input: the new holder's
hybrid KEM public key. It is not named by the `holder` field (§34.1); a caller that
constructs a progress envelope resolves it out of band.

### 34.3 Provisioning

How a verifier obtains a trust set, and how keys are rotated or retired, are
deployment concerns deliberately outside this document, exactly as the live gate's
implementation is outside it (§32.4). What this document fixes is that such a set
exists, what each role means, and how a holder is resolved from it.

| # | Rule |
|---|---|
| KD1 | A verifier MUST take its trusted public keys as an input, never read them from the file. |
| KD2 | `holder` MUST be `BLAKE3("ctf/holder-hash/v1" ‖ pk_classical ‖ pk_pq)` over the signature public key, per §34.1. |
| KD3 | A `transfer`'s `sig_holder` MUST be verified against the key the previous record's `holder` resolves to; an unresolved `holder` fails E9. |
| KD4 | A key trusted for one role MUST NOT be accepted for another role. |
| KD5 | The §24 progress recipient KEM key is a separate input, distinct from the `holder` field's signature key. |
