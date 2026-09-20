# Engagement brief — post-fix re-review

You are one of seven independent reviewers auditing the `.ctf` challenge transport
format and its Rust reference implementation. Repo root for this review:
`/Users/0xjvl1an/.t3/worktrees/project-p4ssive/t3code-f96790a3/ctf-format`.

The other six reviewers cover different angles. Stay in YOUR role. Do not try to
cover everything; depth in your lane beats breadth.

## What this project is

A single-file container carrying ONE CTF challenge from an author to a platform
and into an archive. Premise: a challenge is a pure deterministic function
`challenge(seed) -> (artifacts, flag, oracle)` plus a verifiable commitment to it.

Format version **0.3**, phase 1: header, section table, canonical CBOR manifest,
chunk index, footer + commitment root. NOT yet implemented and deliberately out of
scope: signature verification, crypto suite registry, AEAD, KEM, zstd, WASM
generator, solver gate. Do not report those as missing.

## Since the first review

The first review's Tier 1 blockers (B1-B4), H1, L1, L8 have landed, as have a
further round of fixes: chunk-verification ordering is now type-enforced
(`VerifiedChunkIndex`), manifest diagnostics carry entry indices/`name_id`,
false spec claims were corrected, previously untested rules now have tests, the
section-table fuzz target reaches `validate_layout`, and the BLAKE3 merge is
pinned to a named spec revision with a worked example. `cargo test` is 160 tests,
`cargo clippy --all-targets` and `cargo fmt --check` are clean. Toolchain pinned
1.97.1, edition 2024, `unsafe_code = "forbid"`, one dependency (`blake3`).

Re-check the prior findings against the CURRENT tree (by reading or execution) and
look for what they missed. Do not assume a prior fix is correct because it landed.

## Orientation (read what your role needs, not everything)

- `spec/SPEC.md`          — NORMATIVE. Wins over every other doc. ~1600 lines.
- `docs/FORMAT-DESIGN.md` — rationale and threat model
- `docs/ROADMAP.md`       — phases, deliberate simplifications
- `HANDOFF.md`            — cold-start context, gotchas
- `TODO.md`               — the first review's findings and dispositions
- `CHANGELOG.md`          — what 0.3 changed and why
- `crates/ctf-format/src/{lib,error,header,section,cbor,manifest,footer,chunk,bundle}.rs`
- `crates/ctf-format/tests/{container,cbor,chunk,bundle,mutation,fuzzmirror}.rs`
- `crates/ctf-cli/src/main.rs`
- `fuzz/fuzz_targets/*.rs`

You have READ-ONLY access. You cannot and must not modify files. You MAY run
read-only shell commands (`rg`, `cat`, `cargo tree`, etc.). Do not run `cargo
test` unless you truly need it — it is already known green at 160 tests.

## Standing design decisions — do NOT relitigate these, they were deliberate

- Canonical CBOR is hand-written rather than a dependency, because no mainstream
  crate REJECTS non-canonical input on decode.
- `bao` was audited and rejected; the chunk index stores BLAKE3 chaining values.
- `clap` is deliberately absent while the CLI has one subcommand.
- The writer emits only `enc=0, comp=0`.
- "Intact" (commitment matches) is deliberately distinguished from "authentic"
  (signatures verify), and there is intentionally no API reporting authenticity.

You MAY challenge these if you find a concrete defect they cause. Do not
challenge them on taste.

## Output contract — follow exactly

Write a report with these sections and nothing else:

```
## VERDICT
One paragraph. Is this sound in your lane? Ship-blocking issues yes/no.

## FINDINGS
Repeat this block per finding, most severe first. Max 12 findings.

### [CRITICAL|HIGH|MEDIUM|LOW|NIT] Short title
- where: path:line (or spec section)
- claim: what is wrong, stated as a fact
- evidence: the specific code/text you read that proves it
- impact: concrete failure scenario — inputs/state -> wrong outcome
- fix: the smallest change that resolves it
- confidence: high | medium | low

## VERIFIED SOUND
Bullet list, max 8. Things you specifically checked and found correct. Be
specific ("R5/R6 enforced in SectionRecord::parse, not just documented"), not
vague ("code looks good").

## OPEN QUESTIONS
Max 5. Things you could not resolve from the repo alone.
```

Rules for findings:
- A finding must be a DEFECT, not a preference. If you cannot state a concrete
  failure scenario, it is not a finding — put it in OPEN QUESTIONS or drop it.
- Verify before you claim. Read the actual code. Do not infer from names.
- If you claim something is missing, grep for it first.
- Severity: CRITICAL = exploitable or data-destroying. HIGH = wrong behaviour on
  realistic input. MEDIUM = wrong on adversarial/edge input, or a spec
  contradiction. LOW = correct but fragile. NIT = cosmetic.
- No praise padding. No summary of what the code does. Findings only.
