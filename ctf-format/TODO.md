# TODO — post-review work on 0.3

**Created:** 2026-08-13, immediately after the phase 1 / format 0.3 multi-agent review.
**Updated:** 2026-08-16 — phase 1 committed, second audit pass added B4 and L8.
**Read first:** [`HANDOFF.md`](HANDOFF.md) for what the project is, then this file for
what is outstanding.

**Progress:** H1, B1, B2, B3 done. B4 and the bidi work outstanding, then Tier 2 and
Tier 3. Checkboxes below are accurate; each closed item keeps its original text and
gains a note saying what actually shipped, because in two cases what shipped is not
what the entry proposed.

Current tree: `cargo test` 132 pass (was 124 at `9f50d84`), `cargo clippy
--all-targets` 0 warnings, `cargo fmt --check` clean.

---

## ⚠ Read before anything else

**Phase 1 is committed** as `9f50d84`, unchanged from the tree the reviewers read.
That was deliberate: the fixes below land as a separate, reviewable diff instead of
being invisible inside the feature commit. `git log` now runs
`ec98681` (0.2) → `9f50d84` (0.3, phase 1) → this file's documentation commit.

So the baseline for every "blast radius" note below is exactly `9f50d84`. If
`cargo test` does not report 124 passing before you start, something else moved
first and the measurements are stale.

**Four blockers, not three.** The original review found B1–B3. A second audit pass
on 2026-08-16 confirmed all three independently — B3 *by execution* — and found
**B4**, which is the most consequential of the four because it survives phase 2 by
construction. Read B4 before planning any crypto work.

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

## The second pass, 2026-08-16

A single reviewer re-read the committed tree with two goals: verify the six
reviewers' claims rather than relay them, and look where six lanes of review had
*collectively* not looked. Method and result, so the next pass can be aimed rather
than repeated:

- **B1 and B2 confirmed by reading**, at the sites the reports name.
- **B3 confirmed by execution**, not by reading — a scratch test calling
  `chunk_cv(&[0], 1, 1)` reproduces
  `assertion left == right failed: offset (1) must be a chunk boundary` verbatim
  from `blake3-1.8.6/src/hazmat.rs:232`.
- **B4 found**, by asking a question none of the six roles owned: *which bytes of a
  valid file does nothing commit to?* Each reviewer checked the structures; nobody
  checked the space between them.
- **L6 confirmed** at `chunk.rs:200` (`if b.len() < need`, so trailing bytes pass).
- **L8, and the L1 sharpening**, from reading `crates/ctf-cli/src/main.rs` end to
  end. The CLI got the least attention of any file — one reviewer, two findings —
  because it is the newest and least normative part of the tree. It is also the
  only part an operator ever looks at.

**The lesson worth carrying to the next pass:** the six prompts partition the work
by *role* (security, correctness, quality, spec, conformance, challenge-dev), and a
role-partitioned review has seams. B4 lives in the seam between "security" (which
checked the crypto constructions) and "spec conformance" (which checked the rules as
written) — it is a gap in what the spec *says*, so conformance could not see it, and
it is not a flaw in any construction, so security did not look. When re-running the
reviewers, add a seventh prompt that partitions by *artifact* instead: hand it the
byte layout and ask what is not covered by anything.

---

## Tier 1 — blockers

These four are the format failing to enforce its own stated invariants. Do these
before phase 2 touches anything.

### [x] B1 — `SEALED` with `enc = 0` is representable, and its plaintext is served

**Done 2026-08-16.** R21 added to `SectionRecord::parse`; `section_bytes` refuses a
`SEALED` record outright as belt and braces. Spec §5.3, §5.6, §10, §17 updated. No
existing test broke, exactly as the blast-radius note predicted.


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

### [x] B2 — `section_bytes` returns sections whose kind this reader does not implement

**Done 2026-08-16, but not where this entry said to put it** — see the correction
below, which is the part worth reading.


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

> **Correction, 2026-08-16 — the fix above is in the wrong place, and following it
> would have made the bundle less verified.**
>
> `verified_bytes` has two callers with opposite jobs: `section_bytes`, which *serves*
> bytes to a caller, and `verify_inline_sections`, which *hashes* them against a root.
> Putting the guard in the shared helper applies it to both.
>
> §10's prohibition is a closed list — "serve, execute, decompress, or decrypt" — and
> hashing a section against the root the footer already commits to is none of the
> four. It is the opposite: §5.2's whole promise is that a skipped section is still
> bounds-checked, still overlap-checked, and **still committed**, and verifying that
> the commitment holds is the follow-through. Skipping unknown kinds during
> verification would leave them less checked than implemented ones, buying no safety.
>
> **What shipped:** the guard lives in `section_bytes` (the serving boundary), and
> `verified_bytes` stays a pure integrity helper. So an unknown-kind section is
> verified and counted as `verified` in the `VerifyReport`, and is refused by the
> serving API. Spec §10 now states the carve-out normatively, so the Go
> implementation cannot guess the other way.
>
> This also means H1's "count unknown kinds as skipped" is withdrawn — there is
> nothing to skip.

### [x] B3 — `chunk_cv` panics on public input

**Done 2026-08-16.** `chunk_cv` now range-checks
`(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)` as well as power-of-two,
which also makes its own safety comment true for the first time.


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

### [ ] B4 — inter-structure padding is uncommitted, so a signed bundle is malleable

- **Source:** second audit pass, 2026-08-16. Not found by any of the six reviewers.
- **Status:** confirmed **by execution** against `9f50d84`.
- **Where:** `spec/SPEC.md` §3 (the padding paragraph), and the absence of any check
  in `crates/ctf-format/src/section.rs::validate_layout` /
  `crates/ctf-format/src/bundle.rs::parse`.

**Reproduction**, start to finish:

```bash
cd ctf-format
cargo run --example demo -- /tmp/demo.ctf     # 18328 bytes
python3 - <<'PY'
d = bytearray(open('/tmp/demo.ctf', 'rb').read())
d[3000] = 0x41   # padding between the section table and the first payload
d[5000] = 0x42   # padding between the manifest and notes.md
open('/tmp/tampered.ctf', 'wb').write(bytes(d))
PY
cargo run --bin ctf -- inspect --verify /tmp/tampered.ctf
```

Observed: byte-different file, same length, **identical commitment root**
`ca81744bdca2d76bb566b47538d716893de7b439d2c0124fb7eeab630178f9ed`,
`verified 2 inline section(s) against their roots`, **exit 0**.

- **Why it matters, and why it is a blocker rather than a tidiness complaint:** the
  signed transcript is `SIG_LABEL ‖ suite_id ‖ root ‖ total_len`. Padding appears in
  none of the four, and mutating it in place leaves `total_len` unchanged. So **one
  phase 2 signature verifies both files.** This is signature malleability and a
  covert channel, and phase 2 cannot fix it — the transcript is already fixed and
  correct; the gap is that the bytes were never in scope of anything. It has to be
  closed in the container, in phase 1.
- **The spec contradicts itself here**, and that is the tell. §8 F5 forbids *sixteen
  bytes* of footer slack on the grounds that padding would be "bytes belonging to no
  structure and covered by no commitment." §3's trailing-data paragraph forbids
  bytes after the footer as "the ambiguity behind a long line of archive-format
  vulnerabilities." Then §3 permits arbitrary padding *between* structures with only
  *"a writer SHOULD zero them"* and no reader-side rule at all. The same argument
  wins twice and loses once, in one document.
- **Scale:** demo bundle, 7862 of 18328 bytes (43%) freely mutable. Minimal golden
  bundle, 4032 of 4344 (93%) — spec §11 says outright that "every byte not shown
  below is zero padding between structures."
- **Fix:** promote SHOULD to MUST. A reader rejects any non-zero byte in
  `[HEADER_LEN, footer_off)` that no region claims. **The machinery already exists**:
  `validate_layout` builds `ranges: Vec<(u64, u64, Region)>` and sorts it, so this is
  a walk over the gaps between adjacent entries plus the head and tail gaps — no new
  structure, no new field, no format break. Add rule **T8** and a new
  `Error::PaddingNotZero { at: u64 }` carrying the offset (a number, not attacker
  text, so the no-oracle rule holds).
- **Cost to weigh:** it makes `Bundle::parse` touch every padding byte, which on a
  bundle whose payloads are inline is a scan proportional to file size rather than to
  structure count. Bounded by `footer_off` and skippable for a 40 GB external-only
  bundle, which has almost no inline padding by construction. Take the scan; the
  alternative is an unauthenticated region inside a signed file.
- **Alternative considered and rejected:** extending the commitment root to cover
  the padding. That changes the root definition, which spec §15 states outright is
  unchangeable without a major version, no feature bit sufficient. Rejecting non-zero
  padding gets the same guarantee — one canonical byte string per bundle — without
  touching the root.
- **Blast radius:** none expected. `write_bundle` zero-fills, so every file this
  crate has ever produced already conforms, including both golden vectors. Confirm
  by re-running `tests/bundle.rs::minimal_bundle_golden_vector` — it must **not**
  move. If it does, the writer is emitting non-zero padding and that is a separate
  bug.
- **Supersedes** the "4096-byte alignment tax" entry under *Deferred* below, which
  treated padding purely as a file-size question and never asked what commits to it.
- **Also update:** spec §3 (the padding paragraph, SHOULD → MUST), §6 rule table
  (add T8), §11 (state that the golden vector's padding is normative, not
  incidental), §17 version history, `CHANGELOG.md`.
- **Decide with question 2 below:** like R21, this narrows what is legal. Same
  answer, same reasoning — fold it into 0.3 before the first tagged release, while
  nothing is in the wild to invalidate.

---

## Tier 2 — high value, not blocking

### [x] H1 — `verify_inline_sections` reports success while silently skipping

**Done 2026-08-16.** `verify_inline_sections` now returns `VerifyReport { verified,
external, unverifiable }` instead of `usize`, and `ctf inspect --verify` exits
non-zero when `unverifiable != 0`.

- **Source:** Challenge-dev reviewer. Confirmed at `bundle.rs:156-166`.
- The loop `continue`d past `EXTERNAL` and non-plain records, returned only the
  count it *did* check, and `ctf inspect --verify` printed
  `verified N inline section(s)` and exited 0. A bundle with an inline `enc = 1`
  artifact therefore reported success while that payload was never verified —
  tripping **criticality clause 3**, "report content as verified when it was not."
- **The fix as first written would have been wrong, and this is the part worth
  keeping.** "Exit non-zero if anything was skipped" fails the demo bundle, which is
  *correct* — it describes a 40 GB external image whose bytes are elsewhere by
  design. Making non-zero the normal case destroys the signal. So the report splits
  the two meanings of "not verified":
  - `external` — bytes absent by design. Reported, never a failure.
  - `unverifiable` — bytes are **right here** and this build cannot read them
    (encrypted or compressed). A real reason to fail.
- **The policy stays with the caller.** The library counts and returns; only the CLI
  decides that `unverifiable != 0` is an error. A phase 2 caller holding the content
  key can verify exactly what this build counts as unverifiable, so hard-erroring in
  the library would have taken that decision away from the layer that will be able
  to act on it.
- **Verified both directions.** `external_bundle` → `verified 1, external 1,
  unverifiable 0`, CLI exits 0. A hand-built bundle with `enc = 1` on an inline
  artifact → `verified 1, external 0, unverifiable 1`, CLI prints the count and
  exits 1.
- **New in `tests/bundle.rs`:** `mark_encrypted`, which flips a record's `enc` byte
  and repairs the commitment root so the file still opens. The phase 1 writer cannot
  emit `enc != 0`, so this fixture has to be built by hand; re-rooting is the trick,
  because changing a record changes the table and therefore the root, and without it
  the file would fail on the commitment and never reach the code under test. **B1
  needs the same helper** for its `SEALED`-with-`enc = 0` cases.

### [ ] H2 — `verify_chunk` is callable without `verify_root`

- **Source:** Security reviewer. Confirmed: both are `pub` on `ChunkIndex`; only a
  doc comment orders them. `Bundle::chunk_index` does the right thing, but the raw
  API does not force it.
- Spec **C6** is normative: "C4 MUST be checked before C5." Enforced by prose only.
- **Fix (preferred):** make the ordering unrepresentable — have `verify_root`
  consume the parsed index and return a distinct `VerifiedChunkIndex` type that is
  the only thing carrying `verify_chunk`. Same trick as `FutureKind`: turn a
  convention into a type.
- **Fold in, found 2026-08-16:** `ChunkIndex` does not carry `chunk_size` —
  `struct ChunkIndex { cvs: Vec<ChainingValue> }` at `chunk.rs:263`, while
  `verify_chunk(&self, index, data, chunk_size)` takes it per call. So the caller
  must re-supply, from memory, a value the record already fixed. It fails safe (a
  wrong `chunk_size` yields a wrong offset and the chaining value mismatches), so
  this is a footgun rather than a hole — but it is the *same* footgun as the
  ordering one, and the same fix closes both: give `VerifiedChunkIndex` a private
  `chunk_size` field populated from the record, and let `verify_chunk(index, data)`
  take no size argument at all. One type change, two convention-only rules retired.

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
| [ ] L1 | CLI prints `category` and mirror URLs unescaped — a crafted bundle can inject terminal escape sequences and spoof output. See the note below; the fix is already sitting two lines away | `crates/ctf-cli/src/main.rs:106-108`, `137` |
| [ ] L2 | `ctf inspect` never prints a section's `root`; an operator fetching a 40 GB external payload cannot get the expected digest from the tool | `crates/ctf-cli/src/main.rs` |
| [ ] L3 | Manifest errors carry no index or `name_id`, so "names entry is not text" means hand-decoding CBOR on a 50-artifact bundle. An index is a number, not attacker text, so this does not violate the no-oracle rule | `src/manifest.rs`, `src/error.rs` |
| [ ] L4 | §8.2 note says "R1 mandates hybrid signing" — collides with *record rule* R1. It means *design requirement* R1. Cite **F4** instead | `spec/SPEC.md` §8.2 |
| [ ] L5 | §8.2 says key distribution "is specified with the suite registry (§14)" while §14 says the registry is unspecified. State plainly that it is not specified in this version | `spec/SPEC.md` §8.2, §14 |
| [ ] L6 | `ChunkIndex::parse` accepts trailing bytes past `count × 32` but `to_bytes` drops them, breaking the documented byte-for-byte round trip. Require `b.len() == need` | `src/chunk.rs` |
| [ ] L7 | `Manifest::validate_against` is O(records × external entries) — 4096 records against many entries is a lot of comparisons before rejection. Build a lookup set once | `src/manifest.rs:347-386` |
| [ ] L8 | `ctf inspect a.ctf b.ctf` silently inspects `b.ctf` — the arg loop assigns `path` on every positional, so the last one wins with no warning. Error on a second positional | `crates/ctf-cli/src/main.rs:47` |

### L1 in detail — the fix is an asymmetry, not a new escaping layer

Found 2026-08-16, sharpening what the reviewer reported.

Two adjacent lines in `inspect()` treat attacker-controlled text differently:

```rust
println!("              {:?}", b.manifest.name());   // :106 — Debug, control chars escaped
println!("              category {c}");              // :108 — Display, raw
```

`{:?}` on a `&str` escapes control characters, so the challenge *title* is already
safe. `category`, `description`, and mirror URLs (`:137`) go out through `Display`
and are not. The cheapest correct fix is to make `:108` and `:137` match `:106`,
not to write an escaping helper.

**`names` is *mostly* covered but not fully.** `check_name` (`manifest.rs:478`)
rejects `/`, `\`, bytes `< 0x20`, and `0x7f`, so ASCII `ESC` cannot reach the
terminal through a name. It does **not** reject U+202E RIGHT-TO-LEFT OVERRIDE,
whose UTF-8 is `E2 80 AE` — every byte `≥ 0x80`, so every one of those four tests
passes. A name can therefore visually reorder the `flags` column in `ctf inspect`
and in any future TUI. Whether to reject bidi controls in `check_name` or to escape
at every display site is a real decision: rejecting at the format boundary matches
the module's stated reasoning ("one extraction path forgetting to re-check is all
it takes"), but it narrows what is legal and so wants the same release timing as
R21 and T8.

**Not a finding, recorded so it is not re-raised:** `id` is already safe by
`check_id` (lowercase ASCII, digits, interior hyphens only), and `--hex` renders
bytes outside `0x20..0x7f` as `.`, so the hexdump path is clean.

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
  zero padding (93%), because R12 forces payloads to a page boundary. Accepted *as a
  size question*: mmap alignment is the stated reason and a 6 KB floor is already
  expected once PQ signatures land (design §12). Revisit only if a real deployment
  complains.
  **Superseded in part by B4.** This entry asked only "is the padding too big" and
  never "what commits to it". The size verdict stands; the authentication verdict
  does not, and B4 is the live item. Keeping the alignment *and* requiring the
  padding be zero costs nothing extra — a page of zeros compresses and dedupes to
  nothing, and it is already what the writer emits.
- **`SectionRecord`'s public fields allow constructing invalid records.**
  `to_bytes` is deliberately a low-level serializer; `parse` is the validating
  boundary. Reviewer raised it as an open question, not a finding. Leave as is,
  but do not add a public constructor that looks validating and is not.

---

## Verification checklist after each tier

```bash
cd ctf-format
cargo test                    # was 124 at 9f50d84, before any fix
cargo clippy --all-targets    # must stay at 0 warnings
cargo fmt --all -- --check
cargo run --example demo -- /tmp/demo.ctf
cargo run --bin ctf -- inspect --verify --hex /tmp/demo.ctf
```

**B4 regression, once T8 lands.** The repro in B4 must start failing, and must fail
with the *padding* error rather than a root mismatch — a root mismatch would mean
something else changed and the check is not the thing catching it:

```bash
cargo run --bin ctf -- inspect --verify /tmp/tampered.ctf   # expect: non-zero exit
```

This one belongs in `tests/bundle.rs` as well as here: build a valid bundle, flip
one byte in a known gap, assert `Bundle::parse` returns `PaddingNotZero`. Per the
fixture discipline in `HANDOFF.md`, mutate exactly one byte from a known-good
bundle, and pick a gap offset that no earlier rule reaches first.

**Golden vectors:** Tier 1 should not move them — the minimal bundle has no sealed
section, no unknown kind, and no chunk index. If `tests/bundle.rs::minimal_bundle_golden_vector`
starts failing, something changed the header, the manifest encoding, or the
commitment, and that is a format break needing a deliberate decision plus updates to
`spec/SPEC.md` §4.5, §5.8, §11 and `CHANGELOG.md`.

**Re-run the reviewers** after Tier 1 and Tier 2 land, using the committed prompts.
The security and spec-conformance roles are the two worth re-running first.

---

## Open questions for the user

1. ~~Commit 0.3 as-is before fixing, or fold Tier 1 into the 0.3 commit?~~
   **Answered 2026-08-16: committed as-is, `9f50d84`.** The reviewed tree is now a
   fixed point every finding below is measured against.
2. ~~Do the narrowings need their own feature bit, or do they fold into 0.3?~~
   **Answered 2026-08-16: fold all three into 0.3, before it is ever tagged.**

   Covers R21 (B1), T8 (B4), and the `check_name` bidi rejection (question 4). One
   decision, three rules, taken together on purpose — deciding them separately is how
   one of them ends up published and unfixable.

   The reasoning, so it is not relitigated: spec §15 says a narrowing needs a bit,
   and that rule exists to protect files already in the wild. There are none. 0.3 is
   committed but untagged and unpublished, `feat_ro_compat` bit 0 (`CONTAINER_V1`)
   already stops a 0.2 rewriter, and a *narrower* file still satisfies every rule a
   0.3-without-these reader would check — so the only hazard a new bit could address
   is a 0.3-without-these **writer**, which has never produced an artifact. Spending
   `feat_ro_compat` bit 1 here would defend against readers that do not exist and set
   the precedent that every narrowing costs a bit, which is how a 32-bit word runs
   out on bookkeeping rather than on features.

   **Consequence:** `9f50d84` is now a version that was committed but is not the 0.3
   anyone should implement. The 0.3.0 changelog entry must be rewritten rather than
   appended to, `spec/SPEC.md` §17's version history must describe 0.3 as containing
   R21, T8, and the name rule from the start, and the *Known issues* section added in
   `b1e265c` shrinks to the findings that remain unfixed. **Do not tag anything until
   Tier 1 lands.** A tag is the moment this option stops being available.
3. ~~Should `ctf inspect --verify` exit non-zero when it skips an unverifiable
   section (H1), or just report it?~~
   **Answered 2026-08-16: non-zero, but only for the skips that mean something.**

   The question as posed had a false premise, and finding it is the useful part. A
   plain "non-zero on any skip" fails the demo bundle — which is a *correct* bundle
   describing a 40 GB external image — so non-zero becomes the normal case and stops
   carrying information. `EXTERNAL` sections are reported and never counted as
   failures; only sections whose bytes are present and unreadable by this build make
   the command exit 1. See H1 for the implementation and both verified directions.
4. ~~Reject bidi controls at the format boundary, or escape at every display site?~~
   **Answered 2026-08-16: both.** The two halves close different holes, and neither
   subsumes the other.

   - **`check_name` rejects the nine explicit bidi formatting characters**,
     U+202A–U+202E and U+2066–U+2069. Add them to the existing reject list in
     `manifest.rs:478`; this is the narrowing folded into 0.3 under question 2.
     Legitimate right-to-left *script* is unaffected — Arabic and Hebrew challenge
     names stay legal, because only the explicit override and isolate controls are
     rejected, never the characters that actually spell a word.
   - **The CLI escapes on output.** `category`, `description`, and mirror URLs go
     through `Display` today and are free-form text that can never get a
     `check_name`-style rule — a description may legitimately contain anything. Switch
     them to `{:?}` to match the title line at `main.rs:106`, which is already safe.

   **Why both, and why this is not defensive over-building:** a name becomes a
   filename on extraction, so a bidi-carrying name is a filename-spoofing vector
   (`…gnp.exe` rendering as `…exe.png`) that exists with no terminal in the picture
   at all — display escaping cannot reach it. Conversely, boundary rejection cannot
   reach `description`, which is not name-shaped. Two holes, two fixes. This is the
   same two-independent-checks pattern the container already uses for
   `SEALED`/`PLAYER_VISIBLE`, applied for the same reason.

   **Not in scope of this answer:** whether `description` and `category` should also
   reject ASCII control characters at the format boundary. They currently accept any
   text CBOR admits. Escaping makes that safe to *print*; it does not make it
   sensible to *store*. Left open deliberately — decide it with `ctf pack` in phase 3,
   where authoring-time validation belongs.
