## VERDICT

The implementation is sound in the container parsing path. No ship-blocking correctness issue found. Two public chunk/API edge cases should be fixed before treating the library API as fully robust.

## FINDINGS

### MEDIUM `chunk_cv` can panic on invalid public input

- where: `crates/ctf-format/src/chunk.rs:85-112`
- claim: `chunk_cv` accepts power-of-two chunk sizes that are not BLAKE3 chunk-aligned.
- evidence: validation checks only zero and power-of-two at lines 86-87, then passes `index * chunk_size` to `set_input_offset`; BLAKE3 requires offsets divisible by 1024 and panics otherwise.
- impact: `chunk_cv(&[0], 1, 1)` computes offset `1` and reaches BLAKE3's assertion, causing a panic instead of returning `Err`.
- fix: enforce the format bounds (`MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE`) or at minimum `chunk_size >= blake3::CHUNK_LEN`.
- confidence: high

### LOW `ChunkIndex::parse` violates its byte-for-byte round-trip contract

- where: `crates/ctf-format/src/chunk.rs:191-225`
- claim: `ChunkIndex::parse` silently ignores trailing bytes.
- evidence: it rejects only when `b.len() < need` at line 205, parses exactly `need` bytes, and `to_bytes` emits only those entries.
- impact: `ChunkIndex::parse(index_bytes_with_extra_data, count)?.to_bytes()` drops the extra bytes despite the documented round-trip guarantee.
- fix: require `b.len() == need`, or revise the API documentation to explicitly permit trailing data.
- confidence: high

## VERIFIED SOUND

- Header table arithmetic uses checked multiplication and addition in `Header::table_range`.
- Section-record offset-plus-length overflow is checked during parsing before layout validation.
- Section table and chunk-index regions are checked for bounds and overlap.
- `SectionRecord::parse` enforces R4–R20, including flags-before-kind ordering.
- Footer signature lengths are capped before integer conversion; footer length is checked exactly.
- `Bundle::parse` verifies the manifest section root before decoding CBOR.
- CBOR decoding rejects non-shortest integers, unsorted/duplicate map keys, trailing bytes, invalid UTF-8, and excessive nesting.
- BLAKE3 hazmat calls used by valid container inputs satisfy the required subtree shape and offset preconditions.

## OPEN QUESTIONS

- Whether `SectionRecord::to_bytes` is intentionally a low-level serializer that may emit invalid records, since its public fields permit invalid states.
- Whether callers are expected to pass only records obtained from the same `Bundle` to `section_bytes` and `chunk_index`; the methods do not enforce record ownership.