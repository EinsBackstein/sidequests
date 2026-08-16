## VERDICT

Phase 1 is sound for static OSINT, text-only, external forensics payloads, and many-artifact bundles. RE/pwn sealed solvers, generators, runtimes, and stage gating are correctly deferred. Ship-blocking issues: no, but the manifest criticality contradiction and operator diagnostics should be fixed before the authoring surface is built.

## FINDINGS

### MEDIUM `crit` does not catch typos

- where: spec/SPEC.md:803-815; docs/FORMAT-DESIGN.md:645-655
- claim: Unknown keys outside `crit` are explicitly carried and ignored, so misspelled future authoring keys are silently accepted.
- evidence: The spec says `visibilty` is “not in `crit`” and “is carried and ignored,” while simultaneously claiming the typo is caught.
- impact: An author writes `visibility`, `runtime`, or `generate` incorrectly; packing succeeds, the intended behavior is absent, and the challenge may be published with incorrect serving or execution semantics.
- fix: Make `ctf pack` reject unknown YAML keys before encoding, and clarify that `crit` provides reader compatibility—not typo detection.
- confidence: high

### MEDIUM `inspect --verify` can report success without verifying all inline sections

- where: crates/ctf-format/src/bundle.rs:151-165; crates/ctf-cli/src/main.rs:150-155
- claim: Verification silently skips inline sections with encryption or compression and reports only the count it checked.
- evidence: `verify_inline_sections` skips `!is_plain(r)`, while the CLI prints “verified N inline section(s)” without reporting skipped sections.
- impact: A bundle containing an inline `enc=1` or `comp=1` section exits successfully and can appear verified even though that payload was not checked.
- fix: Report skipped sections explicitly or fail verification when any inline section is not verifiable by this build.
- confidence: high

### LOW Flat names cannot represent ordinary challenge file trees

- where: spec/SPEC.md:775-782
- claim: Section names cannot contain `/` or `\`, so `src/main.c` and `dist/chal.zip` cannot be represented as named sections.
- evidence: Both separators are mandatory rejection cases.
- impact: Authors must flatten names or wrap the tree in one archive, losing direct per-file artifact identity and individual serving/verification.
- fix: Add a distinct safe relative-path field or permit normalized relative paths with strict traversal checks before the path-consuming phase.
- confidence: high

### LOW External inspection omits the payload root

- where: crates/ctf-cli/src/main.rs:116-138
- claim: `ctf inspect` prints external size and mirrors but not the external section’s BLAKE3 root.
- evidence: The section table output includes `len_plain`; the external branch prints only mirror URLs. `r.root` is never printed.
- impact: An operator fetching a 40 GB E01 from a mirror cannot obtain the expected digest from the primary inspection output and must write separate tooling.
- fix: Print each section’s root, especially for `EXTERNAL` sections.
- confidence: high

### LOW Manifest errors lack the offending field or entry index

- where: crates/ctf-format/src/manifest.rs:145-226; crates/ctf-format/src/error.rs:170-183
- claim: Several author-facing schema errors identify only a generic condition, not which name, mirror, or external entry failed.
- evidence: Errors such as “manifest `names` entry is not text,” “manifest `names` contains a duplicate,” and “manifest external metadata disagrees with the section record” carry only static text.
- impact: A 50-artifact bundle or multi-mirror forensics bundle requires manual binary/CBOR inspection to locate the bad entry.
- fix: Include the array index or `name_id` in the diagnostic while continuing to avoid echoing sealed payload bytes.
- confidence: high

## VERIFIED SOUND

- OSINT with no artifacts is expressible as a manifest-only bundle; the tested minimum is 4344 bytes.
- External 40 GB payloads are expressible with `EXTERNAL`, plaintext size, BLAKE3 root, and mirrors, without embedding the image.
- Fifty artifacts fit comfortably: the section cap is 4096 and `name_id` supports 65536 names.
- Reverse-engineering binaries can be carried as artifacts today; sealed solver and generator behavior are phase 2/3 work.
- Runtime-backed pwn challenges and multi-stage gating are explicitly phase 2–7 work, not accidental phase-1 omissions.
- `SEALED` and `PLAYER_VISIBLE` are mutually exclusive, and solver/writeup/progress sections require sealing in `SectionRecord::parse`.
- External metadata is cross-checked against section size and root in `Manifest::validate_against`.
- The 4096 alignment tax is real and intentional: payloads are page-aligned for mmap, though disproportionately expensive for tiny bundles.

## OPEN QUESTIONS

- Whether phase-2 manifest keys will define explicit section references by `name_id`, rather than relying on human names.
- Whether the eventual `ctf pack` tool will reject unknown YAML keys independently of the CBOR `crit` mechanism.
- Whether downstream serving supports archive artifacts when authors need directory trees.
- Whether operators are expected to verify external payloads through a future CLI command or separate tooling.