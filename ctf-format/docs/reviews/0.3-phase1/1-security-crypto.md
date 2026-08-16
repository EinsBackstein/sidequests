## VERDICT

The verification and commitment chain is sound for intactness, but there is one ship-blocking confidentiality defect: `SEALED` plaintext sections are accepted and returned by the public API. Two lower-severity security footguns remain.

## FINDINGS

### HIGH Sealed plaintext is exposed as readable content

- where: `crates/ctf-format/src/section.rs:384-393`, `crates/ctf-format/src/bundle.rs:168-189`
- claim: A section marked `SEALED` with `enc = 0` and `comp = 0` is accepted, and `section_bytes` returns its plaintext.
- evidence: Record validation only requires sealing for solver/writeup/progress kinds; it does not require encryption. `verified_bytes` rejects only `EXTERNAL` or non-plain sections, never `SEALED`.
- impact: An author creates a sealed writeup or solver with plaintext bytes. `Bundle::parse` succeeds and `section_bytes` exposes the supposedly sealed content to any consumer that trusts the flag.
- fix: Reject `SEALED` records with `enc == Encryption::None`, or make all plaintext-returning APIs reject `SEALED`.
- confidence: high

### MEDIUM Chunk verification can be used without root verification

- where: `crates/ctf-format/src/chunk.rs:238-267`
- claim: `ChunkIndex::verify_chunk` is independently callable after parsing an attacker-controlled index.
- evidence: `ChunkIndex::parse` and `verify_chunk` are public; `verify_root` is a separate method whose ordering is enforced only by documentation. The code explicitly states that skipping `verify_root` checks payloads against an attacker’s index.
- impact: A caller parses an untrusted index and calls `verify_chunk` without first checking the committed section root. Forged index entries then validate attacker-selected chunks.
- fix: Expose only a root-verified index to callers, or make chunk verification require the expected section root and perform root verification before accepting any chunk.
- confidence: high

### LOW CLI emits unescaped attacker-controlled manifest text

- where: `crates/ctf-cli/src/main.rs:107-109`, `crates/ctf-cli/src/main.rs:135-138`
- claim: `category` and mirror strings are printed directly and may contain terminal control sequences or newlines.
- evidence: Manifest validation only checks mirror emptiness and length; the CLI uses `println!("... {c}")` and `println!("... {m}")` without escaping.
- impact: Inspecting a crafted unsigned or unauthenticated bundle can inject terminal output, spoof lines, or alter terminal state.
- fix: Print attacker-controlled text with `Debug` escaping or sanitize control characters before output.
- confidence: high

## VERIFIED SOUND

- `Bundle::parse` verifies header length, table layout, footer structure, commitment root, and manifest section root before decoding the manifest.
- `commitment_root` includes the fixed 64-byte header and exact section-table bytes; header count fixes the table boundary.
- Footer parsing enforces exact footer length, repeated magic, real `total_len`, and no trailing bytes.
- Canonical CBOR enforces shortest arguments, UTF-8, depth 16, strict encoded-key ordering, supported major types, and trailing-data rejection.
- CBOR sequence/map allocations grow from consumed values rather than attacker-supplied capacity fields.
- Section layout rejects duplicate `name_id`s, integer-overflowed ranges, out-of-file ranges, and overlaps with payloads, indices, or the table.
- `Bundle::chunk_index` derives the index length, parses the exact range, and calls `verify_root` before returning the index.
- Unsigned and merely signature-present bundles are clearly distinguished in `Signing` and CLI output.

## OPEN QUESTIONS

- Phase-2 consumers are not present, so it is unresolved whether they will reject or decrypt `SEALED` sections before exposing plaintext.
- No extraction or serving implementation exists to assess filesystem handling beyond manifest name validation.
- Signature verification behavior cannot be assessed because the suite registry and verifiers are explicitly phase 2.