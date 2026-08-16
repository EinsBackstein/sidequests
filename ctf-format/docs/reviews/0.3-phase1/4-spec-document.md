## VERDICT

The document is mostly precise on layout, rule numbering, and commitment construction, but it is not independently implementable without guessing: the chunk merge algorithm is materially underspecified, and canonical CBOR ordering contradicts its cited RFC rule. Ship-blocking issues: yes.

## FINDINGS

### HIGH Chunk merge is not fully specified
- where: §9.2
- claim: `parent_cv` and `parent_root` are not defined sufficiently to reproduce BLAKE3 output from SPEC.md alone.
- evidence: The spec only says they are “BLAKE3's parent node compression, non-root and root respectively,” while omitting the exact key words, flags, block construction, counter, block length, endianness, and root-output procedure; it additionally relies on “BLAKE3 paper §2.1.”
- impact: A Go implementation can choose different BLAKE3 compression/finalization details and produce a different section root or reject the §11 vector.
- fix: Add normative pseudocode or reference the exact BLAKE3 version and define parent block, flags, compression inputs, and root finalization.
- confidence: high

### MEDIUM CBOR ordering contradicts RFC 8949
- where: §7.1, M1g
- claim: The spec simultaneously requires RFC 8949 core deterministic encoding and a different map-key ordering rule.
- evidence: M1g requires bytewise lexicographic ordering of encoded keys; RFC 8949 deterministic map ordering is encoded-key length first, then bytewise order. Both permitted key types can expose the difference, such as a 23-byte byte-string key versus a 1-byte text key in an unknown nested map.
- impact: Two conforming implementers can order the same accepted map differently and produce different bytes and commitment roots.
- fix: Explicitly choose RFC length-first ordering or replace the RFC claim and define bytewise ordering as the format’s canonical rule.
- confidence: high

### LOW Incorrect rule reference for hybrid signing
- where: §8.2, note after F9
- claim: The note says R1 mandates hybrid signing, but R1 is the section-record short-record rule.
- evidence: §5.6 defines R1 as “Fewer than 128 bytes are available for the record”; §8.2 F4 is the rule requiring both signature lengths to be zero or non-zero.
- impact: An implementer following cross-references is directed to an unrelated rule, weakening confidence in the normative signing requirement.
- fix: Replace “R1 mandates hybrid signing” with “F4 mandates hybrid signing.”
- confidence: high

### MEDIUM §14 contradicts the suite-registry statement
- where: §8.2 final note; §14
- claim: The footer note says key distribution is specified in the suite registry, while §14 explicitly says the crypto suite registry is not specified.
- evidence: §8.2: “Key distribution is specified with the suite registry (§14).” §14: “The crypto suite registry that `suite_id` selects” is not yet specified.
- impact: An independent implementer may invent suite/key-distribution behavior that the phase explicitly leaves undefined.
- fix: State that key distribution is not specified in this version.
- confidence: high

## VERIFIED SOUND

- H1–H14, R1–R20, T1–T7, M1–M21, F1–F9, and C1–C7 are each present exactly once; M1a–M1i are explicitly scoped as CBOR subrules.
- H14 is explicitly required before reserved, flag, and structural checks.
- R4 is explicitly required before R3/R18, resolving unknown-kind versus OPTIONAL handling.
- C4 is explicitly required before C5.
- §8.3 defines the commitment input as the exact header bytes followed by exact section-table bytes.
- §11 supplies complete header, manifest, record, footer, and whole-file golden-vector data.
- `feat_ro_compat` unknown bits are consistently described as readable but non-rewritable.
- §3, F5, and F7 consistently prohibit trailing bytes.

## OPEN QUESTIONS

- Whether the intended BLAKE3 merge semantics are documented in an external normative design reference unavailable from SPEC.md.
- Whether the 0.2 compatibility claims depend on behavior defined only in historical versions of the specification.
- Whether the reference tests enforce RFC deterministic ordering or the explicit M1g bytewise ordering for nested unknown maps.