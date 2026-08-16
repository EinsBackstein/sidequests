## VERDICT

The implementation is largely sound in spec-to-code conformance. One ship-blocking issue exists in the public section-access API: optional unknown-kind sections can be returned as plaintext bytes, violating the mandatory “never serve” rule.

## FINDINGS

### HIGH Unknown sections can be exposed through `section_bytes`

- where: `crates/ctf-format/src/bundle.rs:131-132`, `crates/ctf-format/src/bundle.rs:168-189`
- claim: `Bundle::section_bytes` does not reject sections whose kind is unknown to this reader.
- evidence: §5.2 and §10 require unknown kinds to be carried but never served, executed, decompressed, or decrypted. `section_bytes` only rejects `EXTERNAL`, encrypted, and compressed records; it never checks `record.kind.is_known()`.
- impact: A valid `OPTIONAL` section with kind `> 8`, plain inline bytes, and a valid root can be passed to `section_bytes`; the API returns its bytes, allowing a caller to serve or process content this reader explicitly does not understand.
- fix: Reject `!record.kind.is_known()` before returning bytes; apply the same guard to any future API exposing unknown-kind content.
- confidence: high

## VERIFIED SOUND

- H14 is checked before header reserved bytes, flags, and structural validation in `Header::parse`.
- H7 caps `section_table_count` before table allocation.
- H10, R12, T6, and chunk-index length arithmetic use checked operations.
- R5–R9 and R20 are enforced in `SectionRecord::parse`.
- R19, T6, and T7 are enforced through derived chunk-index ranges.
- M1a–M1i canonical CBOR restrictions are enforced by `cbor::Decoder`.
- M19–M21 are enforced in `Manifest::validate_against`.
- `Bundle::parse` follows the required header → table → footer → commitment → manifest order.

## OPEN QUESTIONS

- Whether callers are expected to treat `section_bytes` as the sole serving boundary for unknown section kinds.
- Whether the planned second-language implementation will expose equivalent safeguards for optional unknown sections.