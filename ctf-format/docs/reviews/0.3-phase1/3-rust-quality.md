## VERDICT

The Rust implementation is generally sound in this lane, with no immediate ship-blocking quality or performance defect. However, important rule coverage gaps exist, and manifest/table validation can become unnecessarily expensive on adversarial inputs.

## FINDINGS

### MEDIUM Manifest cross-validation is quadratic

- where: `crates/ctf-format/src/manifest.rs:347-385`
- claim: External metadata validation repeatedly linearly scans both the records and external-entry arrays.
- evidence: Each record searches `entries.iter().find(...)`, then each external entry searches `records.iter().any(...)`.
- impact: A manifest with thousands of external entries and up to 4096 records can force hundreds of millions of comparisons before rejection.
- fix: Build a `HashSet<u16>`/`HashMap<u16, ...>` of record IDs and external IDs once, then perform constant-time or sorted lookups.
- confidence: high

### MEDIUM Fuzz section-table target does not fuzz table validation

- where: `fuzz/fuzz_targets/section_table.rs:15-21`
- claim: The target exercises only `parse_table` and `index_range`; it never calls `validate_layout`, despite claiming coverage of T1–T7.
- evidence: The target returns after per-record round-trip checks and has no `Header`, `file_len`, or `validate_layout` call.
- impact: Fuzzing cannot discover regressions in manifest count, duplicate IDs, payload overlap, table overlap, footer bounds, or chunk-index overlap.
- fix: Construct a valid header/file-length context from the fuzz input and call `section::validate_layout`.
- confidence: high

### MEDIUM Several normative rules have no dedicated rejection coverage

- where: `crates/ctf-format/tests/container.rs`, `crates/ctf-format/tests/bundle.rs`, `crates/ctf-format/tests/chunk.rs`
- claim: The suite has no focused tests for R17, R20, T7, C7, M2–M6, M8, M11–M12, M14–M18, and M20.
- evidence: Existing tests cover aligned/low chunk-index offsets only through the earlier R16 path, unknown manifest encoding values rather than manifest-specific R20, and chunk-index/table overlap but not index-versus-payload or index-versus-index overlap. Manifest tests do not construct the listed malformed schema cases.
- impact: Changes can break these rules while all 124 tests remain green; in particular, rejection-order regressions may be hidden by an earlier validation error.
- fix: Add one minimal fixture per uncovered rule, mutating exactly one property from a valid baseline.
- confidence: high

### LOW Fuzz mirrors are compile checks, not ongoing target-equivalence checks

- where: `crates/ctf-format/tests/fuzzmirror.rs:17-90`
- claim: The mirror bodies are manually duplicated and run only against three inputs, so they can drift semantically while the compile test still passes.
- evidence: The test invokes each copied function with the corpus file, empty input, and 200 zero bytes; it does not compare the mirror source or execute the actual fuzz targets.
- impact: A later change to a fuzz target can leave the stable mirror testing an older oracle, falsely suggesting nightly fuzz targets remain covered.
- fix: Keep the mirror minimal and add a CI command that actually compiles all `fuzz` targets, or generate/share target bodies from one source.
- confidence: medium

## VERIFIED SOUND

- `validate_layout` uses `sort_unstable` over at most `2 * records + 1` ranges, so overlap checking is `O(n log n)`, not quadratic.
- `parse_table` checks the complete byte requirement before allocating and receives a header-capped count through normal bundle parsing.
- `ChunkIndex::parse` checks `count × 32` before allocation; `root_from_cvs` is linear in the number of entries.
- The Cargo.lock dependency graph has no `rayon` feature enabled for `blake3`.
- Chunk tests use non-periodic BLAKE3 XOF filler, so swapped-chunk detection is meaningful.
- Header tests cover H1–H14 with order-sensitive cases for H14-before-reserved and overflow-after-alignment.
- Section tests isolate most rejection rules correctly, including R16 versus later chunk-index checks.
- All five fuzz-target bodies match the corresponding mirror bodies in the reviewed paths and use current public API signatures.

## OPEN QUESTIONS

- Whether CI outside the repository runs `cargo +nightly fuzz build` and all fuzz targets.
- Whether expected manifests can contain tens of thousands of external entries in production.
- Whether downstream callers rely on `ChunkIndex::entries()` for incremental exposure semantics covered by C7.