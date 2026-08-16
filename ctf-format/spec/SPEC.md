# The `.ctf` container format

**Version:** 0.3 (major 0, minor 3)
**Status:** The container is complete and specified: header, section table,
manifest, chunk index, and footer. The crypto suite registry, the AEAD
construction, key management, and signature *verification* are **not** specified
yet; see §14.
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
appended, moved, or flipped without detection. It cannot determine whether the
file is **authentic**: the signature slots in the footer are located and bounded
here, but the suite registry needed to verify them is not (§14). The distinction
is normative and is stated again in §10 and §13.

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
ordering is stated normatively (§4.3, H14; §5.6, R4; §9, C6; §10). Error
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
| Authentic | Both signatures over the transcript verify — **not specified here** (§14) |

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
*between* structures; the footer itself admits none (F5).

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
  unknown suite fails where the diagnostic is useful. The registry is not yet
  defined (§14).
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

All three are asserted byte-for-byte by the reference tests
`tests/container.rs::header_golden_vector`, `::header_golden_vector_v0_1`, and
`tests/bundle.rs::minimal_bundle_golden_vector`. Any change to any of them is a
format break.

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
manifest's name table (§7.2), and phase 2 binds it into the AEAD nonce and
additional authenticated data (design §7). Three consequences are normative:

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
manifest data (§14), not a flag.

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
after both. When `comp = 1` and the section is chunked, a writer MUST emit zstd
frames aligned to chunk boundaries, so that a single chunk can be decompressed
without the preceding ones — this is what keeps a large section seekable.

The AEAD construction itself, its nonce and AAD derivation, and the zstd
decompression limits a reader must impose are not specified in this version
(§14).

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
| R20 | `kind` is `manifest` and `enc ≠ 0`, or `kind` is `manifest` and `comp ≠ 0`. |
| R21 | `SEALED` is set and `enc = 0`. **Applies only when `CONTAINER_V1` is set** (§16). |
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
rejection or a skippable section depends on a flag bit. Rules keep the numbers
they were given in 0.1 even where later versions inserted or narrowed one, so that
a conformance vector citing a rule keeps citing the same rule; see §15 and §17.

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
| `version` | uint | | Challenge version; absent means 0 |
| `category` | tstr | | Challenge category |
| `description` | tstr | | Markdown description |
| `crit` | array of tstr | | Keys a reader MUST understand (§7.3) |
| `external` | map | | Mirror metadata, keyed by `name_id` (§7.4) |

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

A typo is still caught, because a typo appears in neither place: `visibilty` is
not a known key and not in `crit`, so it is carried and ignored — and the value
the author meant to set is absent, which the schema check for that key catches.
This is the failure design §10 cares about, an author silently publishing a hidden
challenge.

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

M7 SHOULD be evaluated before M9–M18: if the manifest requires an understanding
this reader does not have, every other diagnostic is noise about a schema that was
never meant for it. M19–M21 need the section table and are therefore evaluated
after it (§10 step 8).

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

- **F4 is a downgrade check.** R1 mandates hybrid signing: both the classical and
  the post-quantum signature must verify. A footer carrying one of the pair is
  rejected rather than read as "classically signed".
- **F9 is implied by F5 and F7 together** and is stated separately because it is
  the rule a writer must obey, and because it is the property a security reviewer
  looks for by name.
- **`sig_classical_len = sig_pq_len = 0` is legal** and means the bundle is
  unsigned. Such a bundle authenticates nothing and MUST NOT be served, executed,
  or trusted. It is a valid intermediate state — a writer produces the file, a
  signer adds the signatures — and it is what this version's writer emits, since
  signing is not specified here (§14).
- The signature *verification* keys are not carried in the footer. R10 puts
  bundles under a single trusted author org, whose keys the platform holds out of
  band. Key distribution is specified with the suite registry (§14).

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
sig_input = "ctf/footer-sig/v1" ‖ u16_le(suite_id) ‖ root ‖ u64_le(total_len)
```

`"ctf/footer-sig/v1"` is 17 ASCII bytes; `suite_id` is the header's; `root` is the
32 bytes of §8.3; `total_len` is the footer's. The transcript is 59 bytes and every
element after the label is fixed-width, so no length prefixes are needed (design
§7's `LP` rule applies to constructions with a variable-width element).

Both the classical and the post-quantum signature are computed over this identical
transcript, and **both MUST verify**. Binding `suite_id` is what stops a signature
being replayed under a downgraded suite; the domain label is what stops it being
replayed against an entitlement record, which is signed with the same keys
(design §9). Binding `total_len` is what makes F9 enforceable rather than
advisory.

Producing and checking the signatures is not specified in this version (§14). A
reader of this version MUST NOT report a bundle as authentic on any grounds.

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

The merge is BLAKE3's own tree shape (BLAKE3 paper §2.1), not a Merkle tree
defined here. At every level, the left subtree covers the largest power-of-two
number of chunks strictly less than the total and the right subtree covers the
rest; the top merge is the root finalization. In pseudocode, with `cv(i)` the
*i*th entry:

```text
merge(a..b):                       # non-root, b - a >= 1
    if b - a == 1: return cv(a)
    k = largest power of two strictly less than (b - a)
    return parent_cv(merge(a..a+k), merge(a+k..b))

root(count):                       # count >= 2
    k = largest power of two strictly less than count
    return parent_root(merge(0..k), merge(k..count))
```

`parent_cv` and `parent_root` are BLAKE3's parent node compression, non-root and
root respectively.

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
   step 4.
3. Record whether the file is rewritable (§4.4).
4. Read `section_table_count × 128` bytes at `section_table_off` and apply
   R1–R21 to every record; then apply T1–T8. **R21 and T8 are applied only if the
   header sets `CONTAINER_V1`** (§16); every other rule applies to every file.
5. Parse the footer and apply F1–F7 and F9.
6. Recompute the commitment root per §8.3 and apply F8.
7. Locate the manifest section, verify its `root` against its stored bytes, then
   decode it and apply M1–M18.
8. Apply M19–M21 against the section table.
9. **Not implemented in this version:** verify both signatures over the
   transcript of §8.4.

A reader that completes steps 1–8 has established that the file is **intact**. It
has *not* established that the file is **authentic**, because step 9 does not
exist yet. A reader MUST NOT represent a bundle as authentic, and MUST NOT
execute, serve, or otherwise act on section content on the strength of an intact
parse alone.

Further requirements, all normative:

- A reader MUST NOT return any section's bytes to a caller before that section's
  `root` verifies for those bytes, whole or per chunk (§5.1, C7).
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
| `MAX_DEPTH` (`cbor`) | `16` | Manifest nesting cap |
| `MAX_NAME_LEN` | `255` | Longest name table entry |
| `MAX_ID_LEN` | `64` | Longest challenge `id` |
| `MAX_MIRROR_LEN` | `2048` | Longest mirror URL |
| `MAX_NAMES` | `65536` | Entries in the name table; the `name_id` space |
| `MANIFEST_SPEC` | `1` | Manifest schema version specified here |
| `FEAT_RO_COMPAT_CONTAINER_V1` | `0x00000001` | The feature bit of §4.1 |
| `SUPPORTED_INCOMPAT` | `0` | `feat_incompat` bits this version implements |
| `SUPPORTED_RO_COMPAT` | `0x00000001` | `feat_ro_compat` bits this version implements |

Every limit above is **normative, not an implementation detail**: a writer that
exceeds one produces a file that every conforming reader rejects. Raising any of
them is therefore an incompatible change (§15). At the cap the section table is
512 KiB, which is four orders of magnitude above what a real challenge uses.

`root` is 32 bytes in the frozen layout, so **every present and future crypto
suite MUST use a 32-byte digest.** A suite with a different digest size requires
a new major version, not a new `suite_id`. The chunk index inherits the same
constraint, since its entries are chaining values of the same hash.

The customary filename extension is `.ctf`. No media type is registered.

## 13. Security considerations

- **Intact is not authentic.** A file whose commitment root matches its own bytes
  has proven internal consistency, nothing more. An attacker who rewrites a
  bundle and recomputes the root produces a perfectly intact file. Only the
  signatures distinguish the author's bundle from anyone else's, and verifying
  them is not specified here (§14). Every field in this document is
  attacker-controlled input until that step exists.
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
  carry offending offsets and lengths, and MUST NOT carry bytes from a sealed
  section — nor from the manifest, whose text is attacker-controlled.
- **Decompression is unbounded in this version.** No limit on zstd output size or
  expansion ratio is specified yet (§14). A reader MUST NOT decompress untrusted
  input. The manifest is exempt from the problem rather than from the rule: R20
  forbids it a codec.
- **An unsigned bundle authenticates nothing** and MUST NOT be served, executed,
  or trusted, however intact it is.

## 14. What is not here yet

An implementation MUST NOT invent behaviour for any of the following, and MUST
NOT claim conformance to a later version by guessing.

- **Signature production and verification.** The footer's slots are located and
  bounded (§8.1, §8.2) and the transcript is fixed (§8.4), but the algorithms,
  the encoding of a signature within its slot, and key distribution are not
  specified.
- **The crypto suite registry** that `suite_id` selects.
- **The AEAD-STREAM construction**, nonce and AAD derivation, key envelopes, and
  every rule for `enc = 1`. Consequently a reader of this version cannot read the
  plaintext of an encrypted section at all, and MUST NOT try.
- **zstd rules for `comp = 1`**: framing details beyond the chunk-alignment
  requirement of §5.4, an absolute output cap, and an expansion ratio cap.
- **Manifest keys for the later phases** — `flag`, `generate`, `runtime`,
  `sealed`, `verify` (design §10). They are unknown keys under this version and
  are therefore carried and ignored unless a writer lists them in `crit`, which
  makes a file requiring them fail cleanly against a reader that does not
  implement them. This is the extension mechanism working, not a gap.
- **The entitlement chain record format** for `kind = entitlement`, and the
  progress blob for `kind = progress`.
- **The live solvability gate's socket contract** (design §3, pillar 5).

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
| Raise or lower any limit in §12 | `feat_incompat` bit |
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
| 0.2 | 0.3 | Header and table accepted in full; a whole-container read is refused at §10 step 2, because a 0.2 file has no footer or manifest to read. R21 and T8 are **not** applied — see below |
| **0.3** | **0.2** | **Accepted, read-only.** `feat_incompat` is zero, so nothing stops the read; `CONTAINER_V1` is an unimplemented `ro_compat` bit, so the file MUST NOT be rewritten (§4.4) |
| 0.3 | 0.1 | Rejected, as `reserved not zero`. 0.1 predates the feature words entirely; see below |
| 0.3, plus a `ro_compat` bit from a later version | 0.3 | Accepted, read-only (§4.4) |
| 0.4+, `feat_incompat` feature in use | 0.3 | Rejected, naming the feature (H14) |
| 0.4+, `feat_incompat` feature not in use | 0.3 | Accepted |
| 0.4+, `OPTIONAL` unknown kind | 0.3 | Accepted; the section is carried, never interpreted |
| Manifest `spec` 2+, no `crit` | 0.3 | Accepted; unknown keys carried byte-for-byte |
| Manifest `spec` 2+, unknown key in `crit` | 0.3 | Rejected, naming the key (M7) |

**R21 and T8 are conditional on `CONTAINER_V1`, and this is what the bit is for.**
Both narrow rules a 0.1 or 0.2 file could satisfy legally, so applying them
unconditionally would make a 0.3 reader reject files its predecessors called valid —
breaking the row above rather than honouring it. A reader MUST determine the rule set
from the file's own header and MUST NOT apply either rule to a file that does not set
the bit.

Neither exemption weakens a 0.3 file, and neither is a concession:

- **R21** rejects `SEALED` with `enc = 0` because the flag then claims a key that
  does not exist. 0.2 specified no encryption at all, so *every* sealed section a 0.2
  writer could produce carried `enc = 0`. Enforcing R21 on such a file would reject
  the only form `solver`, `writeup`, and `progress` could take, not an abuse of it.
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
