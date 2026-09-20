# Post-fix re-review — format 0.3

**Date:** 2026-09-20
**Tree:** all of tickets 01–06 landed (`cargo test` 161 pass, `cargo clippy
--all-targets` 0 warnings, `cargo fmt --check` clean).

## How this review ran

The committed prompts under `prompts/` were re-run against the current tree, plus a
seventh lane, `r7_artifact.md`, partitioned by artifact rather than by role.

**The Codex CLI could not be used.** `codex exec` authenticates locally but every
lane failed with `Connection failed … waiting for network` — there is no network
egress from the sandbox. Rather than skip the lane, the seven prompts were run as
seven parallel **read-only agent sessions** using `_common_postfix.md` and the role
prompts verbatim. Each reviewer verified its claims by reading the tree. The
sessions share a model, so the independence is weaker than seven different
reviewers; treat agreement between lanes as corroboration, not as separate
evidence. The BLAKE3-independent claims (the §9.2 worked example, the §11 golden
vector) were checked by reimplementing BLAKE3 from the pinned spec, which is a
genuinely independent check.

## Verdicts by lane

| Lane | Verdict | Ship-blocking |
|---|---|---|
| r1 security | chain sound; B1/B2/B4/H1/L1/L8 fixed | no |
| r2 rust correctness | all parsers sound; no reachable panic | no |
| r3 rust quality | tests real; prior gaps closed; residual coverage | no |
| r4 spec document | implementable except three underspecified points | no |
| r5 spec conformance | all rules enforced except parse-time C4 | no |
| r6 challenge-dev | container sound; authoring surface incomplete | no |
| r7 artifact | every byte claimed **except the footer's two length words** | no |

## Prior findings re-checked

| # | Finding | Result |
|---|---|---|
| B1 | `SEALED` with `enc = 0` representable | fixed — R21 in `section.rs`; `section_bytes` refuses sealed |
| B2 | `section_bytes` serves unknown kinds | fixed — guard in the serving boundary, verification still counts them |
| B3 | `chunk_cv` panic on public input | fixed — range check; no reachable hazmat panic (r2 independently confirmed) |
| B4 | inter-structure padding uncommitted | fixed — T8, gated on `CONTAINER_V1` |
| H1 | verify pass silently skips | fixed — `VerifyReport`; `external` vs `unverifiable` |
| H2 | `verify_chunk` callable unverified | fixed — `VerifiedChunkIndex`; C6/C7 unwritable, pinned by `compile_fail` doctests |
| H3 | crit-typo claim false | fixed — §7.3 rewritten; ROADMAP phase-3 requirement recorded |
| H4 | BLAKE3 merge not implementable | fixed — pinned to revision `20211102173700`, full parent pseudocode, worked example (r4 reproduced it independently) |
| H5 | untested rules | fixed — R17, R20, T7, C7, M2–M6, M8, M11–M18, M20 now tested |
| H6 | fuzz target misses layout validator | fixed — target and mirror call `validate_layout`; padding seed asserts T8 |
| L1, L8 | CLI escaping; two positionals | fixed |
| L2 | inspector never prints section root | fixed — root printed per section, external marked |
| L3 | manifest errors carry no entry id | fixed — `Error::ManifestEntry` with index/`name_id` |
| L4, L5 | false spec claims | fixed |
| **L6** | `ChunkIndex::parse` accepts trailing bytes | **fixed in this pass** — exact-length `parse`, new `Error::TrailingBytes`, fuzz oracles tightened, test added |
| **L7** | `validate_against` is quadratic | **fixed in this pass** — `BTreeMap`/`BTreeSet` built once, O(records + entries) |

Every prior committed finding is closed.

## New findings → tickets

Recorded as tickets (70+), **not** fixed inline, per the seventh-lane contract.

| Ticket | Severity | Finding |
|---|---|---|
| 70 | MEDIUM | **Fixed in 0.4.0 (C8).** `Bundle::chunk_index` served a `SEALED` (or unknown-kind) section's plaintext chaining values without the `section_bytes` guard |
| 71 | MEDIUM | **Fixed in 0.4.0 (transcript v2).** footer `sig_classical_len` / `sig_pq_len` lay outside the commitment root **and** the signature transcript, so the slot split was unauthenticated |
| 72 | MEDIUM | R20 applies to legacy files, contradicting §16's "0.2 accepted in full" |
| 73 | MEDIUM | `EXTERNAL` sections may carry `comp`/`enc` while external verification is defined over plaintext |
| 74 | MEDIUM | §5.5/R19/T6 divide by `chunk_size` with no stated non-zero precondition |
| 75 | MEDIUM | §15's "raise or lower any limit → `feat_incompat`" contradicts the relaxation rule |
| 76 | LOW | §10's ordered procedure omits C1–C7, leaving parse-time vs on-use undefined |
| 77 | LOW | §3 states the padding rule unconditionally though T8 is gated |
| 78 | LOW | §16 says M7 "names the key"; the diagnostic deliberately does not |
| 79 | LOW | §4.5 attributes the 0.3 header vector to a test that asserts the 0.2 vector |
| 80 | LOW | `ctf inspect` reads the whole file into memory; no mmap despite the alignment rationale |
| 81 | LOW | section-root mismatch carries no `name_id`; `--verify` aborts on the first |
| 82 | MEDIUM | `ctf-cli` has no tests, including the `--verify` exit path |
| 83 | MEDIUM | `a_flipped_header_byte_breaks_the_commitment` is near-vacuous |
| 84 | LOW | footer F2–F4 and header H13 have no parse-side test |
| 85 | LOW | `write_bundle` hashes chunked inline payloads twice |
| 86 | LOW | BLAKE3 built without `rayon` while the design claims thread-parallel verification |
| 87 | NIT | dead public API (`Bundle::sig_input`, `Footer::sig_input`, `Manifest::description`) |
| 88 | MEDIUM | directory trees cannot be represented; flattening collides on duplicate basenames |
| 89 | MEDIUM | the reference writer cannot emit a chunk index for an `EXTERNAL` section |
| 90 | NIT | `Error::ExceedsFile.file_len` reports `footer_off` |
| 91 | NIT | `crit` errors carry no entry index, unlike the other list rules |
| 92 | LOW | `section_bytes`/`chunk_index` do not check the record belongs to the bundle |
| 93 | LOW | `ctf inspect --verify`'s exit code cannot distinguish intact from authentic |
| 94 | NIT | stale spec cross-references in module docs (`footer.rs`, `section.rs`, a test) |
| 95 | NIT | `BadMagic`/`CborUnsupported` echo input bytes in `Display` |
| 96 | LOW | a pre-0.3 file is reported as a feature-bits problem rather than a version one |
| 97 | NIT | long names truncate to indistinguishable 20-char labels in `inspect` |

**GitHub issue numbering is offset for tickets 72–97.** GitHub shares its number
space between issues and pull requests, and **PR #72** consumed the number 72. Tickets
70 and 71 are issues
[#70](https://github.com/EinsBackstein/sidequests/issues/70) and
[#71](https://github.com/EinsBackstein/sidequests/issues/71); local ticket *N* for *N*
in 72–97 is issue *N*+1 — [#73](https://github.com/EinsBackstein/sidequests/issues/73)
through [#98](https://github.com/EinsBackstein/sidequests/issues/98). Each synced issue
title carries the local number in brackets, e.g. `[72] Gate R20 on CONTAINER_V1`.

None is ship-blocking for phase 1. The two that phase 2 would have had to settle
before building on them — **70** and **71** — were fixed in **0.4.0**: C8 withholds
a sealed or unimplemented-kind section's chunk index, and the signature transcript
moved to `v2`, which binds both slot lengths. The rest remain deferred.
