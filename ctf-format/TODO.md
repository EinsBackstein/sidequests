# TODO — post-review work on 0.3

**Created:** 2026-08-13, immediately after the phase 1 / format 0.3 multi-agent review.
**Read first:** [`HANDOFF.md`](HANDOFF.md) for what the project is, then this file for
what is outstanding.

Nothing in this file has been applied. The tree is exactly as the review found it:
`cargo test` 124 pass, `cargo clippy --all-targets` 0 warnings, `cargo fmt --check`
clean.

---

## ⚠ Read before anything else

**All of phase 1 is uncommitted.** `git log` still ends at `ec98681` (the 0.2
release). Everything below — the manifest, footer, chunk index, `Bundle`, the CLI
crate, the fuzz targets, the 0.3 spec rewrite — exists only in the working tree.

```
 M ctf-format/{CHANGELOG,HANDOFF}.md  ctf-format/spec/SPEC.md  docs/ROADMAP.md
 M crates/ctf-format/src/{error,lib,section}.rs  tests/container.rs
 M Cargo.toml  Cargo.lock  .gitignore
?? crates/ctf-format/src/{bundle,cbor,chunk,footer,manifest}.rs
?? crates/ctf-format/tests/{bundle,cbor,chunk,fuzzmirror,mutation}.rs
?? crates/ctf-cli/  crates/ctf-format/examples/  fuzz/  docs/reviews/  .mcp.json
```

Decide whether to commit 0.3 as-is first, or fold the Tier 1 fixes in before the
commit. **Recommendation: commit 0.3 as-is first**, so the review findings land as
a separate, reviewable diff rather than being invisible inside the feature commit.

---

## Where the review came from

Six independent reviewers, run through Codex (`gpt-5.6-luna`, reasoning `medium`),
read-only sandbox, one role each. Raw reports and the exact prompts are committed:

```
docs/reviews/0.3-phase1/
  1-security-crypto.md      4-spec-document.md
  2-rust-correctness.md     5-spec-conformance.md
  3-rust-quality.md         6-challenge-dev.md
  prompts/_common.md        prompts/r{1..6}_*.md
```

Reproduce or re-run after fixes:

```bash
cd ctf-format
cat docs/reviews/0.3-phase1/prompts/_common.md \
    docs/reviews/0.3-phase1/prompts/r1_security.md \
  | codex exec -m gpt-5.6-luna -c model_reasoning_effort="medium" \
      -c 'notify=[]' -s read-only --color never -o /tmp/out.md -
```

Cost was ~541k Codex tokens for all six (59k–112k each) against the ChatGPT Plus
subscription. `.mcp.json` now registers `codex mcp-server` at project scope, so a
future session gets Codex as MCP tools rather than a shell-out.

**The signal worth remembering:** three reviewers in different lanes (security,
spec-conformance, challenge-dev), explicitly told not to overlap, independently
landed on `Bundle::verified_bytes` / `verify_inline_sections`. That is the serving
boundary, and it enforces fewer of its own spec rules than anything else in the
crate. Treat it as the weakest surface until Tier 1 is done.

---

## Tier 1 — blockers

These three are the format failing to enforce its own stated invariants. Do these
before phase 2 touches anything.

### [ ] B1 — `SEALED` with `enc = 0` is representable, and its plaintext is served

- **Source:** Security & Cryptography reviewer. **Status:** confirmed by reading
  `section.rs` record validation and `bundle.rs::verified_bytes`.
- **Where:** `crates/ctf-format/src/section.rs` (record validation, the
  `must_be_sealed` block) and `crates/ctf-format/src/bundle.rs::verified_bytes`.
- **Evidence:** R6 forces `solver`/`writeup`/`progress` to carry `SEALED`, but no
  rule anywhere ties `SEALED` to `enc ≠ 0`. `verified_bytes` rejects only
  `EXTERNAL` and non-plain records — never `SEALED`.
- **Why it matters:** spec §5.3 defines `SEALED` as "the plaintext requires a key
  the platform does not hold during the event." With `enc = 0` there *is* no key.
  The flag is a claim the container does not back, and `section_bytes` will hand
  the "sealed" writeup to any caller that trusts it. This is precisely the class of
  bug the design claims to eliminate ("a sealed-yet-servable section cannot be
  expressed").
- **Fix:** add record rule **R21** — `SEALED` set and `enc = 0` MUST be rejected.
  Enforce in `SectionRecord::parse`. Add the belt-and-braces guard in
  `verified_bytes` too (reject `SEALED` outright there — a phase 1 reader can never
  legitimately return sealed plaintext).
- **Consequence, and it is the right one:** with R21, **phase 1 can no longer write
  a `solver`, `writeup`, or `progress` section at all**, because R6 forces them
  `SEALED` and the phase 1 writer has no encryption. That is honest. Today it can
  emit a *fake*-sealed section, which is strictly worse than refusing.
- **Blast radius (measured):** three test sites touch `SEALED`.
  `container.rs:356` uses `Encryption::AeadStream`, so it survives.
  `container.rs:419` (R5) and `container.rs:452` (R7) are rejected by earlier rules
  and assert the generic `Inconsistent`, so they survive too. **No existing test
  breaks.** Golden vectors unaffected — the minimal bundle has no sealed section.
- **Also update:** spec §5.6 rule table, §5.3 prose, §17 version history,
  `CHANGELOG.md`.

### [ ] B2 — `section_bytes` returns sections whose kind this reader does not implement

- **Source:** Spec-conformance reviewer. **Status:** confirmed —
  `grep -rn is_known crates/` returns its own definition at `section.rs:179` and
  two *test* call sites. **Zero callers in `src/`.**
- **Where:** `crates/ctf-format/src/bundle.rs::verified_bytes`.
- **Evidence:** spec §10 states, normatively: "A reader MUST NOT serve, execute,
  decompress, or decrypt a section whose kind it does not implement (§5.2)."
  `SectionKind::is_known()` exists for exactly this and is never called outside
  tests.
- **Why it matters:** an `OPTIONAL` section with `kind > 8`, plain inline bytes and
  a valid root parses fine, and `section_bytes` returns its contents. Spec §5.2 is
  explicit that `PLAYER_VISIBLE` on an unknown kind "confers nothing on a reader
  that does not understand it" — the code does not know that.
- **Fix:** guard `!record.kind.is_known()` in `verified_bytes`, before the root
  check. Also skip unknown kinds in `verify_inline_sections` (and count them as
  skipped — see H1).
- **Blast radius:** none expected; no test currently calls `section_bytes` on an
  unknown kind. Add one that does, asserting rejection.

### [ ] B3 — `chunk_cv` panics on public input

- **Source:** Rust correctness reviewer. **Status:** confirmed **by execution**, not
  by reading:

  ```
  chunk_cv(&[0], 1, 1)
  -> panicked at blake3-1.8.6/src/hazmat.rs:232:
     assertion `left == right` failed: offset (1) must be a chunk boundary
     (divisible by 1024)
  ```

- **Where:** `crates/ctf-format/src/chunk.rs::chunk_cv`, the guard near the top.
- **Evidence:** the guard is `chunk_size == 0 || !chunk_size.is_power_of_two()`. It
  never checks `MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE`, so `chunk_size = 1` passes,
  `offset = index * 1 = 1`, and `blake3::hazmat::set_input_offset` asserts.
- **Why it matters:** the crate's whole hardening posture is that a panic on
  hostile input is *unrepresentable*, not merely absent. Clippy's `panic`/`unwrap`
  lints do not see into `blake3`. `Bundle::parse` is safe because R14 range-checks
  first — but `chunk_cv` is `pub` and reachable directly.
  **`fuzz/fuzz_targets/chunk_index.rs` already passes `cs = 1`**, so
  `cargo +nightly fuzz run chunk_index` would hit this on the first run.
- **Fix:** range-check in `chunk_cv`: reject unless
  `(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)` *and* power-of-two.
  The doc comment already claims "a power of two of at least 4 KiB" — the code just
  never enforced it.
- **Add:** a test asserting `chunk_cv(&[0], 1, 1)` returns `Err(BadChunkSize)`, and
  the same through `ChunkIndex::verify_chunk`.

---

## Tier 2 — high value, not blocking

### [ ] H1 — `verify_inline_sections` reports success while silently skipping

- **Source:** Challenge-dev reviewer. Confirmed at `bundle.rs:156-166`.
- The loop `continue`s past `EXTERNAL` and non-plain records, returns only the
  count it *did* check, and `ctf inspect --verify` prints
  `verified N inline section(s)` and exits 0.
- A bundle with an inline `enc = 1` artifact therefore reports success while that
  payload was never verified. This trips **my own criticality clause 3** — "report
  content as verified when it was not."
- **Fix:** return verified *and* skipped counts (or a small struct); make the CLI
  print skipped sections explicitly and exit non-zero if anything was skipped under
  `--verify`. Do not silently succeed.

### [ ] H2 — `verify_chunk` is callable without `verify_root`

- **Source:** Security reviewer. Confirmed: both are `pub` on `ChunkIndex`; only a
  doc comment orders them. `Bundle::chunk_index` does the right thing, but the raw
  API does not force it.
- Spec **C6** is normative: "C4 MUST be checked before C5." Enforced by prose only.
- **Fix (preferred):** make the ordering unrepresentable — have `verify_root`
  consume the parsed index and return a distinct `VerifiedChunkIndex` type that is
  the only thing carrying `verify_chunk`. Same trick as `FutureKind`: turn a
  convention into a type.

### [ ] H3 — spec §7.3's typo claim is false for optional keys

- **Source:** Challenge-dev reviewer. Confirmed in `spec/SPEC.md:812-816`.
- Current text: *"A typo is still caught … the value the author meant to set is
  absent, which the schema check for that key catches."* That only holds for
  **required** keys. `runtime`, `generate`, `sealed`, `verify`, `category`,
  `description` are all optional — a misspelled one is carried, ignored, and
  nothing notices.
- Design §10 calls this exact failure out by name: *"A typo'd `visibility` silently
  publishing a hidden challenge mid-event is a real incident."* The mechanism as
  documented does not stop it.
- **Fix:** correct the spec claim — `crit` provides *reader forward compatibility*,
  not typo detection. State plainly that typo detection is `ctf pack`'s job
  (reject unknown YAML keys at authoring time, phase 3) and record it as a phase 3
  requirement in `docs/ROADMAP.md`.

### [ ] H4 — spec §9.2's chunk merge is not implementable from the document alone

- **Source:** Spec-document reviewer (rated HIGH). Not a defect in running code.
- §9.2 says `parent_cv`/`parent_root` are "BLAKE3's parent node compression,
  non-root and root respectively" and defers to the BLAKE3 paper §2.1. It omits the
  key words, flag bytes, block construction, counter, block length, and root
  finalization.
- This is measured against phase 8's actual acceptance criterion: *a Go
  implementation, from `spec/SPEC.md` alone, reproducing §11's vector*. Most Go
  BLAKE3 libraries do not expose subtree chaining values, so the implementer has to
  build it from the primitive.
- **Fix:** add normative pseudocode for parent-node compression to §9.2, pin the
  BLAKE3 version/spec revision it is defined against, and add a worked
  two-chunk example with intermediate chaining values.

### [ ] H5 — normative rules with no dedicated test

- **Source:** Rust quality reviewer. Uncovered: **R17, R20, T7, C7, M2–M6, M8,
  M11–M12, M14–M18, M20.**
- 124 tests pass, so these can regress silently. The reviewer also flags that some
  existing rejection tests may be vacuous because an earlier check fires first —
  the exact trap `HANDOFF.md` already warns about.
- **Fix:** one minimal fixture per rule, each mutating exactly one property from a
  valid baseline, in the established style. While doing it, re-verify that each
  existing rejection test trips the rule it names and not an earlier one.

### [ ] H6 — the `section_table` fuzz target never calls `validate_layout`

- **Source:** Rust quality reviewer. Confirmed by reading
  `fuzz/fuzz_targets/section_table.rs`.
- It calls `parse_table` and `index_range` only, so **T1–T7 are entirely unfuzzed**
  despite the target's doc claiming that coverage.
- **Fix:** synthesize a `Header` and `file_len` from the fuzz input and call
  `section::validate_layout`. Mirror the change into `tests/fuzzmirror.rs`.

---

## Tier 3 — low severity, all confirmed

| # | Finding | Where |
|---|---|---|
| [ ] L1 | CLI prints `category` and mirror URLs unescaped — a crafted bundle can inject terminal escape sequences and spoof output | `crates/ctf-cli/src/main.rs` |
| [ ] L2 | `ctf inspect` never prints a section's `root`; an operator fetching a 40 GB external payload cannot get the expected digest from the tool | `crates/ctf-cli/src/main.rs` |
| [ ] L3 | Manifest errors carry no index or `name_id`, so "names entry is not text" means hand-decoding CBOR on a 50-artifact bundle. An index is a number, not attacker text, so this does not violate the no-oracle rule | `src/manifest.rs`, `src/error.rs` |
| [ ] L4 | §8.2 note says "R1 mandates hybrid signing" — collides with *record rule* R1. It means *design requirement* R1. Cite **F4** instead | `spec/SPEC.md` §8.2 |
| [ ] L5 | §8.2 says key distribution "is specified with the suite registry (§14)" while §14 says the registry is unspecified. State plainly that it is not specified in this version | `spec/SPEC.md` §8.2, §14 |
| [ ] L6 | `ChunkIndex::parse` accepts trailing bytes past `count × 32` but `to_bytes` drops them, breaking the documented byte-for-byte round trip. Require `b.len() == need` | `src/chunk.rs` |
| [ ] L7 | `Manifest::validate_against` is O(records × external entries) — 4096 records against many entries is a lot of comparisons before rejection. Build a lookup set once | `src/manifest.rs` |

---

## Rejected — do not re-raise

### ✗ "Canonical CBOR ordering contradicts RFC 8949" (spec-document reviewer, MEDIUM)

**Claim:** M1g requires bytewise ordering of encoded keys, but RFC 8949 deterministic
encoding is length-first, so two implementers would produce different bytes.

**Verdict: wrong.** Verified against the RFC text itself
(`https://www.rfc-editor.org/rfc/rfc8949.txt`):

- **§4.2.1** (Core Deterministic Encoding Requirements), line 1416:
  *"The keys in every map MUST be sorted in the bytewise lexicographic order of
  their deterministic encodings."* ← what `spec/SPEC.md` §7.1 M1g and `cbor.rs` do.
- **§4.2.3** is titled *"Length-First Map Key Ordering"* and opens: *"The core
  deterministic encoding requirements (Section 4.2.1) sort map keys in a different
  order from the one suggested by Section 3.9 of [RFC7049]"*. It is the RFC 7049
  "Canonical CBOR" compat variant, offered as an alternative.

The reviewer attributed §4.2.3's rule to §4.2.1. Spec and implementation are correct
as written; **no change**. Its other three findings (H4, L4, L5 above) stand.

---

## Deferred — decisions, not defects

- **Flat name table cannot express `src/main.c`.** Names forbid `/` and `\` (spec
  §7.2). Real consequence: authors must flatten names or ship an archive artifact.
  This is a phase 3 authoring-surface question, not a phase 1 bug. Revisit when
  `ctf pack` is designed; if directory trees are needed, add a separate
  path-typed manifest field with traversal checks rather than loosening `names`.
- **The 4096-byte alignment tax.** A minimal bundle is 4344 bytes of which 4032 is
  zero padding (93%), because R12 forces payloads to a page boundary. Accepted:
  mmap alignment is the stated reason and a 6 KB floor is already expected once PQ
  signatures land (design §12). Revisit only if a real deployment complains.
- **`SectionRecord`'s public fields allow constructing invalid records.**
  `to_bytes` is deliberately a low-level serializer; `parse` is the validating
  boundary. Reviewer raised it as an open question, not a finding. Leave as is,
  but do not add a public constructor that looks validating and is not.

---

## Verification checklist after each tier

```bash
cd ctf-format
cargo test                    # was 124 before any fix
cargo clippy --all-targets    # must stay at 0 warnings
cargo fmt --all -- --check
cargo run --example demo -- /tmp/demo.ctf
cargo run --bin ctf -- inspect --verify --hex /tmp/demo.ctf
```

**Golden vectors:** Tier 1 should not move them — the minimal bundle has no sealed
section, no unknown kind, and no chunk index. If `tests/bundle.rs::minimal_bundle_golden_vector`
starts failing, something changed the header, the manifest encoding, or the
commitment, and that is a format break needing a deliberate decision plus updates to
`spec/SPEC.md` §4.5, §5.8, §11 and `CHANGELOG.md`.

**Re-run the reviewers** after Tier 1 and Tier 2 land, using the committed prompts.
The security and spec-conformance roles are the two worth re-running first.

---

## Open questions for the user

1. Commit 0.3 as-is before fixing, or fold Tier 1 into the 0.3 commit? (Recommend:
   commit first.)
2. Does R21 (`SEALED` ⇒ `enc ≠ 0`) need a `feat_incompat` bit? It narrows what is
   legal, and spec §15 says narrowings need a bit — **but** no 0.3 file has been
   published yet, so there is nothing in the wild to invalidate. Cheapest honest
   answer: fold R21 into 0.3 before release and treat it as never having existed
   otherwise. Decide before the first tagged release, not after.
3. Should `ctf inspect --verify` exit non-zero when it skips an unverifiable
   section (H1), or just report it? Non-zero is safer for CI; report-only is
   friendlier for humans.
