# Audit — parser hardening checklist (design §14)

**Date:** 2026-09-21
**Format version:** 0.3 (`version_minor` 3) · **Release:** 0.12.0
**Source checklist:** `docs/FORMAT-DESIGN.md` §14, lines 777–803.
**Method:** every claim below was verified by reading the enforcement site and the
tests that pin it in the current tree, not inferred from the design text. Line
numbers are against this commit.

## Verdicts

| # | Checklist item | Where enforced | Test(s) | Verdict | Ticket |
|---:|---|---|---|---|---|
| 1 | Never allocate from a length field before validating it against remaining bytes | `header.rs:134-141` (`TooManySections`, `MAX_SECTIONS` at `lib.rs:180`); `section.rs:694-713` (`count × 128` checked before `with_capacity`); `cbor.rs:321-358` (array/map grow by consumed bytes, never `with_capacity(arg)`); `chunk.rs:194-239` (`count` derived, never read); `footer.rs:74-77,154-161` (`MAX_SIG_LEN` before slot lengths); `compress.rs:114-124` (declared length bounded by `take`, no `with_capacity`) | `container.rs:288` `header_rejects_section_count_over_cap`; `cbor.rs:237` `a_huge_length_field_does_not_allocate`; `container.rs:656` `record_rejects_range_overflow`; `container.rs:328` `header_rejects_table_overflowing_u64` | Satisfied | — |
| 2 | Bounds-check every offset; reject backwards, into the header, or overlapping | `header.rs:143-226` (`section_table_off ≥ HEADER_LEN`, alignment, `footer_off ≥ table_end`, `check_file_len`); `section.rs:501-520` (`offset ≥ HEADER_LEN`, alignment, `offset + len_stored` overflow); `section.rs:570-598` (index offset bounds, R19); `section.rs:727-798` `validate_layout` (payload/index past `footer_off`, pairwise overlap, table overlap); `bundle.rs:509-523` `slice` | `container.rs:298` `header_rejects_table_inside_header`; `container.rs:637` `record_rejects_misaligned_payload_offset`; `container.rs:647` `record_rejects_payload_inside_header`; `container.rs:969,988,1027,1050` overlap/bounds; `container.rs:1006` unknown-optional participation | Satisfied | — |
| 3 | Reject trailing bytes; file ends at the footer; `total_len` equals real length | `footer.rs:20-26,170-199` (F5 exact `footer_len`, F6 magic, F7 `total_len`); `bundle.rs:90-91` (footer parsed against whole file); `cbor.rs:80-90` (`CborTrailing`); `chunk.rs:202-224` (exact `count × 32`) | `bundle.rs:546` `rejects_trailing_bytes`; `bundle.rs:586` `rejects_footer_slack`; `bundle.rs:573` `rejects_a_wrong_total_len`; `cbor.rs:189` `rejects_trailing_bytes`; `chunk.rs:217` `index_rejects_trailing_bytes` | Satisfied | — |
| 4 | Depth cap on nested CBOR | `cbor.rs:45-51` (`MAX_DEPTH = 16`), `cbor.rs:154-157` (encode), `cbor.rs:304-307` (decode) | `cbor.rs:220` `rejects_nesting_past_the_depth_cap` (both encoder and decoder) | Satisfied | — |
| 5 | Absolute output cap and ratio cap on zstd decompression, checked before decode | `compress.rs:27-70` (`MAX_DECOMPRESSED_SECTION`, `MAX_DECOMPRESSION_RATIO`, `check_caps`); `compress.rs:114-135` (`check_caps` first, then bounded `take`, exact-length check) | `compression.rs:108` `caps_reject_a_bomb_before_decompression`; `compression.rs:128` `a_wrong_declared_length_is_rejected` | Satisfied | — |
| 6 | Reject duplicate section IDs and duplicate manifest keys | `section.rs:740-746` (T2 duplicate `name_id`); `cbor.rs:175-190` (encode) and `cbor.rs:333-358` (decode strictly-increasing keys ⇒ `CborDuplicateKey`/`CborUnsortedKeys`); `manifest.rs:267-277` (`names`), `manifest.rs:311-321` (`paths`) | `container.rs:951` `layout_rejects_duplicate_name_id`; `cbor.rs:92` `encoder_rejects_duplicate_keys`; `cbor.rs:175` `rejects_unsorted_and_duplicate_map_keys`; `bundle.rs:1285` `m16_duplicate_names_are_rejected`; `bundle.rs:906` `paths_reject_traversal_and_duplicates` | Satisfied | — |
| 7 | Normalize and reject path-like names (`../`, absolute, symlink-shaped) | `manifest.rs:701-738` (`check_name`/`check_path`: separators, `.`/`..`, control and bidi chars, empty components); applied at `manifest.rs:252-322`; authoring side `pack.rs:143-151` | `bundle.rs:1027` `manifest_rejects_path_like_names`; `bundle.rs:1064` `manifest_rejects_bidi_controls_in_names`; `bundle.rs:1099` `manifest_accepts_right_to_left_script_in_names`; `bundle.rs:906` `paths_reject_traversal_and_duplicates` | Satisfied | — |
| 8 | Verify signatures and the commitment root before interpreting the manifest semantically | Commitment root: `bundle.rs:90-112` (footer → root recomputed → `verified_bytes` over the manifest record) and `bundle.rs:441-469`; signatures: deliberately a separate caller step, `bundle.rs:132-143` `Bundle::verify_signatures` | Commitment: `bundle.rs:365` `section_bytes_are_verified_before_they_are_returned`; `bundle.rs:452,481` byte-flip breaks root; `bundle.rs:497` `commitment_root_is_the_documented_construction`; `bundle.rs:2131` `t8_does_not_reach_into_claimed_regions` (manifest payload byte fails at parse with `SectionRootMismatch { name_id: 0 }`). Signatures: `bundle.rs:2254,2289,2328,2340` | Satisfied by design | — |
| 9 | Verify chunk authenticity before exposing chunk bytes | `chunk.rs:255-362` (`ChunkIndex::verify_root` consumes the index and yields `VerifiedChunkIndex`; no method returns chunk bytes), `compile_fail` doctests at `chunk.rs:274-280,321-326`; serving boundary `bundle.rs:231-250` (C8) | `chunk.rs:116` `a_chunk_cannot_be_checked_against_an_unverified_index`; `chunk.rs:137,155,183` tamper/swap/forge; `chunk.rs:350` `c7_chunk_bytes_are_never_exposed_without_passing_c5`; `bundle.rs:1962,1979` C8 | Satisfied | — |
| 10 | Fuzz from day one (header, section table, manifest, chunk index, entitlement chain); oracle no panic, no OOM, round-trip stable | `fuzz/fuzz_targets/{bundle,header,section_table,manifest,chunk_index}.rs`; `fuzz/Cargo.toml:27-59`; stable-toolchain mirror `tests/fuzzmirror.rs:114-145`; mutation oracle `tests/mutation.rs:110-147,221-239`. **No `entitlement` target exists** (see Gaps). No-OOM oracle is not a fuzzer memory cap; see Notes | `fuzzmirror.rs:115` `fuzz_targets_still_compile_and_run`; `mutation.rs:152,174,188,205,221` flips/truncation/corruption/arbitrary/sub-parsers | Gap | #107 |
| 11 | Write an independent second implementation from the spec text alone | Absent: no `go/` directory; planned at `docs/ROADMAP.md:372` | — | Gap | #53 |

## Gaps

### 10 — no `entitlement` fuzz target

The checklist names five targets: header, section table, manifest, chunk index, and
**entitlement chain**. The first four exist (`fuzz/Cargo.toml:27-59`). There is no
`fuzz/fuzz_targets/entitlement.rs` and no `[[bin]] name = "entitlement"` entry, so
`Entitlement` parsing is fuzzed only indirectly through the whole-bundle target and
the stable-toolchain mutation pass. No existing issue tracks this.

**Tracked by issue #107** ("Fuzz the entitlement chain"). A target that
parses an entitlement record, checks it re-encodes byte-for-byte, and exercises its
signature/validation paths, with the same oracle as the other targets.

### 11 — no independent second implementation

`docs/FORMAT-DESIGN.md` §14 requires a second implementation written from
`spec/SPEC.md` alone. There is no `go/` directory (`docs/ROADMAP.md:19` reserves it;
`docs/ROADMAP.md:372` still has it unchecked). Tracked by issue **#53**, "Go second
implementation".

## Notes

### Bullet 8 splits into two halves, and only one is parse-time

The checklist line reads as one rule but names two checks, and the reference reader
puts them in different places on purpose:

- **Commitment root** is verified during `Bundle::parse`: after parsing the footer
  (`bundle.rs:91`) the root is recomputed over the file's own header and table bytes
  (`bundle.rs:93-101`), then the manifest record's stored bytes are hashed against
  its section `root` by `verified_bytes` (`bundle.rs:441-469`) **before** `Manifest::decode`
  runs (`bundle.rs:110-111`). Spec §10 step 7 fixes this order: "verify its `root`
  against its stored bytes, then decode it". Nothing acts on unauthenticated content.
- **Signature verification** is deliberately *not* part of `Bundle::parse`. Keys are
  out of band and never carried in the bundle (spec §8.2: "The signature *verification*
  keys are not carried in the footer"), so authenticity is a separate caller step,
  `Bundle::verify_signatures` (`bundle.rs:132-143`), corresponding to spec §10 step 9:
  "If the caller supplies a trusted public key and needs authenticity, verify both
  signatures". Until that step runs, a parsed bundle is *intact* only, and `Signing`
  reports `Present`/`Unsigned`, never "verified". Signature production and checking are
  specified in §20.3; the transcript is §8.4.

The verdict is therefore **Satisfied by design**, not a gap: the second half is
caller-gated by the spec, not omitted.

### Bullet 10's "no OOM" oracle is not yet a fuzzer memory cap

The checklist's oracle is "no panic, no OOM, and round-trip stability". In this tree:

- **No panic / round-trip stability** are the oracles of every `fuzz/` target and of
  the stable-toolchain mirror/mutation pass (`tests/mutation.rs:110-147`, and the
  canonicality assertion at `tests/mutation.rs:235-237`).
- **No OOM** is *currently* enforced by construction and by bounded-allocation tests
  rather than by a `cargo-fuzz -rss_limit_mb`-style cap: `cbor.rs:321-358` sizes from
  consumed input, `chunk.rs:194-239` derives the count, `footer.rs:154-161` caps the
  signature lengths, and `compress.rs:114-135` grows under a `take` limit. The pinned
  tests are `tests/cbor.rs:237` `a_huge_length_field_does_not_allocate` (array and byte
  string claiming `u64::MAX` are rejected as `CborTruncated` without allocating) and
  the mutation suite (`tests/mutation.rs`), which drives the same `oracle` over flips,
  truncations, corruption, and arbitrary bytes.

This is adequate today — every length field is bounded before it can size an
allocation — but it is an enforced-by-construction property, not a fuzzer memory cap.
Adding `-rss_limit_mb` to CI is part of the phase-8 "Fuzzing in CI" item
(`docs/ROADMAP.md:360`) rather than a new gap.

### Scope

This audit reflects the tree at release 0.12.0. It records gaps as tickets; no code
was changed. Trailing-byte rejection, the CBOR depth cap, the zstd caps, and the
`VerifiedChunkIndex` type were all confirmed against their implementations and tests,
not against the design text.
