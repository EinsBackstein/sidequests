# Spec ambiguities and the readings chosen here

This implementation was written from `spec/SPEC.md` and the files the spec
points at. The container is byte-exact only where the spec is; the list below
records every place where the text admits more than one reasonable reading, the
reading chosen, and why. None of these is a licence to reject a file the
reference reader accepts or to accept one it rejects: the conformance suite
under `spec/vectors/conformance` is the arbiter, and all 35 of its fixtures pass.

## A1. §8.2 F4 and the unsigned footer (a first misreading, kept as a warning)

**Text.** Rule F4 says "Exactly one of `sig_classical_len` and `sig_pq_len` is
zero" is a rejection. The note immediately below says
"`sig_classical_len = sig_pq_len = 0` is legal and means the bundle is
unsigned", that this is what "this version's writer emits", and that a signer
adds the pair later.

A first reading took "exactly one is zero" as "at most one is zero" and therefore
as contradicting the note (and rejecting the unsigned `golden/minimal.ctf`). That
reading is wrong: "exactly one" is exact, so both zero is not a violation. The
spec now states that explicitly in the F4 note.

**Chosen reading.** Reject only a **half-signed** pair: one length zero and the
other non-zero. Accept both zero (legal unsigned bundle) and both non-zero (signed
pair). F4 is the downgrade check that stops a one-signature footer being read as
"classically signed".

**Consequence.** An unsigned footer is 56 bytes; a signed one is
`56 + sig_classical_len + sig_pq_len`, matching F5. The minimal golden parses
and rewrites; no signature is treated as present.

## A2. §7.1 M1h: is the outermost value depth 1?

"M1h" says "Nesting deeper than 16" without saying whether the outermost value
counts as depth 1 or whether depth counts only container children.

**Chosen reading (superseded).** This implementation originally counted the
outermost value as depth 1 and each contained value as one deeper. Sixteen
nested containers were accepted; the seventeenth was rejected with M1h. That
reading rejected a manifest the reference implementation and its writer accept
at the boundary.

**Resolved reading.** §7.1 now defines the count normatively: depth counts from
0 at the outermost value, so 17 nested containers are accepted and a scalar
inside them is rejected. `decodeCBOR` starts at `value(0)` and `appendValue`
checks the same cap, matching `ctf_format::cbor`. Tested by `TestCBORDepthCap`
(both the byte and value forms) and the Rust `rejects_nesting_past_the_depth_cap`.

## A3. §9: when a writer must emit a chunk index

§9 makes the index optional in some encodings (`chunk_index_off = 0` is normal
for `chunk_size = 0`), and R19 rejects an index with fewer than two entries,
but it does not say when a writer *should* emit one.

**Chosen reading.** `WriteBundle` emits an index whenever the author sets
`chunk_size != 0` and the section has at least two chunks. `EmitChunkIndex`
overrides the default in either direction; a nil pointer keeps it. With
`chunk_size = 0` or one chunk no index is emitted, because R19 forbids one.
This reproduces the demo golden (three 4096-byte chunks → three CVs) and the
minimal golden (no chunked section).

## A4. §5.4 D1/D2: which sections, checked when

D1 and D2 are stated for "a `comp = 1` section" and "before invoking any
decompressor". For `enc = 1, comp = 1`, decryption necessarily precedes
decompression, so "before any decompressor" is compatible with checking after
decryption.

**Chosen reading.** `SectionPlaintext` checks both caps whenever `comp = 1`,
before it does any decryption or decompression. The checks use only
`len_plain` and `len_stored` from the authenticated table, so their position
relative to decryption cannot change the outcome; checking first is the stronger
ordering. `comp = 0` sections are unaffected. D2 uses an overflow-checked
product: an overflowing `len_stored × ratio` is larger than any `uint64`
`len_plain` and therefore cannot violate the cap.

## A5. §7.4: unknown keys inside `external` entries

The `external` table names `size`, `root`, and `mirrors` as required. It does
not say whether an entry carrying an additional key is invalid. §7.3 requires
unknown *manifest* keys to be carried and ignored, but is phrased around
top-level keys, and its strictness belongs to the authoring front end (§7.8).

**Chosen reading.** Required keys are enforced for presence and type (M18);
additional keys inside an `external` entry are carried, not rejected. This
follows "carry what you do not understand" and leaves typo detection to the
authoring tool, as §7.8 requires. There is no counterpart for `paths`: its
values are plain text, so M23 rejects anything that is not a valid relative path
and no extra structure can be carried there.

## A6. §8: signature lengths vs. suite slot lengths (resolved by F10)

F3 caps each length at 65536 and F4 forbids a lone length; §20.3 fixes the slot
layout per suite. Written before F10 existed, this entry read the text as leaving
it open whether a footer whose two lengths are non-zero but disagree with its
suite's slots is rejected at parse time.

**Chosen reading (now normative).** The spec resolved this by adding **F10** to
§8.2: for a suite the reader implements, a declared length that disagrees with
§20.3's slot lengths is a parse rejection. §8.1 already said the lengths are the
suite's, so F10 states what the text implied rather than narrowing what a reader
accepts. An unsigned footer has no slots to locate and is outside F10; an
unrecognized `suite_id` is still not a header rejection (§19.1 S1) and its slots
are checked when the primitive is resolved. This implementation checks F10 in
`parseFooter` and reports it under rule tag `F10`.

## A7. Error identity and rule tags

§2.1 makes accept/reject normative and error identity non-normative. Several
fixtures can trigger more than one rule (for example, zeroing the manifest
record's kind would violate both R3 and T1, so the unknown-kind vector mutates the
artifact record instead; a byte flip in a payload is reported as a root mismatch,
while the fixture cites §10 step 7).

**Chosen reading.** The parser reports the most specific rule it applied, in
the order §5.6/§4.3 require where an order is normative. A named-error vector is
built so its first failure in that order is the named rule and no second rule
fails at the same step: moving a payload also zeroes the bytes it orphaned, so
T8 is not violated too, and an unknown kind is put on an ordinary section rather
than the manifest, so T1 is not violated too. A later step may also be
unreachable-but-violated (a moved payload no longer matches its `root`); the
reader stops at the first failing step, so the named rule is the determined one.

The conformance runner compares a rule tag only for an `error` vector whose
`rules` names exactly one tag. `rejects` vectors, and `error` vectors citing a
section instead of a tag (the manifest root is reported with an empty tag), assert
rejection only; `TestNamedRuleIsAssertedOnlyForSingleRuleVectors` keeps that
distinction from silently degrading into "no rule is ever checked". The Go runner
compares the rule tag, not the Rust error variant's name — error identity is not
normative, so matching a rule string exactly is not part of conformance.

## A8. The conformance corpus index is not specified

`spec/vectors/conformance/corpus.json` is not described by `SPEC.md` and was
added to the spec tree while this implementation was in progress. It carries
`vectors[].expectation.kind` (`parses`, `parses_read_only`,
`parses_unknown_optional`, `rejects`, `error`, `rejects_on_serve`,
`serve_error`, `rejects_chunk_index`, `chunk_index_error`), an optional
`name_id`, and `rules`.

**Chosen reading.** The runner prefers the corpus when present and fails
loudly if any `.ctf` file on disk is not listed, so a new fixture cannot be
silently skipped. `rejects` and `error` both mean "`Parse` must fail";
`rejects_on_serve` and `serve_error` mean "`Parse` succeeds and serving
`name_id` must fail"; `chunk_index_error` means "`Parse` succeeds and
`VerifyChunkIndex(name_id)` must fail". If no index is present the runner falls
back to sidecars and the `golden/` / `hostile/` directory convention, and
refuses to guess about any file it cannot classify.

## A9. §10 step 8 versus C8: parse-time and use-time split

`Parse` accepts a bundle with an unknown optional section (kind > 8) and with a
chunk index whose contents are wrong. C8 and C4 are use-time rules.

**Chosen reading.** `Parse` validates structure only. `SectionBytes`,
`SectionPlaintext`, and `VerifyChunkIndex` refuse to serve an unknown kind, and
`VerifyChunkIndex` verifies the index against the record's root on demand. This
is why `parses_unknown_optional` and `chunk_index_error` are distinct
expectation kinds in the corpus.

## A11. §5.4/§10: where the zstd decoder sits relative to D1, D2, and the kind gate

**Text.** §5.4 and §10 say a reader MUST apply D1 and D2 "before invoking a
decompressor" and MUST reject output that is not exactly `len_plain`. §10 also
says a reader MUST NOT decompress a section "whose kind it does not implement".
The two requirements meet on a `comp = 1` section of an unknown kind: the caps
are stated for every compressed section, but the decoder may never run for that
one.

**Chosen reading.** The two rules have different subjects and compose without
conflict. `decompressionCaps` is a pure function of the authenticated section
record (`len_plain`, `len_stored`) and is applied before anything else, including
before reading stored bytes, on every non-external `comp = 1` section.
Decompression is a *later* step and is skipped entirely when the kind is not
implemented. So `VerifyAll` reports a D1/D2 violation on an unknown-kind
compressed section but does not report "unverifiable-but-possibly-corrupt" for
one that passes the caps; §10 forbids the decode, and `root` commits to the
plaintext the reader may not produce. `SectionPlaintext`/`SectionBytes` refuse
the unknown kind before any decode, as C8 requires.

**Consequence.** The decoder itself is additionally defensive: it is read through
`io.LimitReader(len_plain+1)` and configured with `WithDecoderMaxMemory`, so even a
frame that lies about its decoded size cannot expand past the declaration, and an
output shorter or longer than `len_plain` is rejected rather than truncated. No
allocation is ever sized from the declared length. D2's product is checked for
overflow: an overflowing `len_stored × ratio` is larger than any `uint64`
`len_plain` and so cannot be a violation. Compression level is a writer choice,
not a format rule: zstd frames are self-describing, and the default (`Comp: 0`)
path is unchanged, so the goldens stay byte-identical.

## A12. §20.3: suite 3's two-in-one `sig_pq` slot and F10

**Text.** §20.3 gives the footer two slots and says suite 3 puts
`ML-DSA-65 ‖ SLH-DSA-SHA2-128s` in `sig_pq`, "split at the ML-DSA-65 length".
§8.2 F10 rejects a declared length that disagrees with §20.3's slot lengths.
At the time this reading was chosen, §19.2 and §20.3's trailing note said SLH-DSA
"is not implemented in this version", which described the reference build at the
time, not a prohibition on another implementation. Those status notes were removed
in 1.0.0, when both implementations began resolving suite 3.

**Chosen reading.** §20.3's tables are the normative bytes; the "not implemented"
sentences were status notes and did not narrow what a reader may accept. For
`suite_id = 3`, `sig_pq_len` must be exactly `3309 + 7856 = 11165`, and F10
enforces that like any other slot length. `sig_pq` is split at 3309; all three
components (Ed25519, ML-DSA-65, SLH-DSA-SHA2-128s) verify over the identical
§8.4 transcript, and a failure of any one is a failure of the whole. The suite-3
public key is `Ed25519 (32) ‖ ML-DSA-65 (1952) ‖ SLH-DSA pk (32)`, and the holder
hash of §34.1 hashes exactly those bytes in that order.

**Consequence.** `Suite.ImplementsSignatureRole()` is true for suites 1, 2, and 3,
so F10 applies to suite 3 too. Length errors name the role and the expected and
got lengths (e.g. `pq: expected 11165 bytes, got N`), never the input bytes.
Suite 3's SLH-DSA secret key is a different width from its public key; it is held
as an opaque suite-specific key, not a container structure.

## A13. §18: "canonical CBOR per §7.1" for records, and the record-id preimage

**Text.** §18 says an `entitlement` section's plaintext is "a single canonical
CBOR array ... decoded under the same rules as the manifest", and the record id is
`BLAKE3(label ‖ cbor)` where `cbor` is "the canonical encoding of the record map
with both `sig_*` keys removed". §7.1's canonical form fixes key ordering, and
§7.3 elsewhere lets the manifest carry unknown keys. §18.4 E2, by contrast,
explicitly rejects "a field not listed in §18.1". The text does not spell out how
removing two keys interacts with key ordering, nor whether an unknown record key
is carried (manifest-style) or rejected (E2-style).

**Chosen reading.** E2 is specific to records and wins: an unknown record key is a
rejection, unlike the manifest's carried-unknown rule. Canonicality is checked the
manifest way — decode, re-encode, and require the bytes to match — because §18
says "same rules as the manifest"; a value that decodes but does not round-trip is
E1. For the record id, the preimage is the canonical encoding of the map built
*without* `sig_holder`/`sig_platform`. Canonical CBOR sorts keys, and deleting
entries cannot disturb the relative order of the survivors, so this is identical
to deleting the two keys from the full canonical map; the implementation does the
former, which cannot depend on how a caller ordered the input.

**Consequence.** `timestamp` is preserved with its sign (major type 0 or 1) so it
round-trips, but it is never compared, subtracted, or used for ordering — E3 and
§18.2 make `seq` authoritative. `payload` is opaque bytes and presence is tracked
separately from emptiness, so an absent payload and a present zero-length payload
do not collapse and the record id stays stable.

## A14. §18.5/§34: validating an embedded chain against its own file's root

**Text.** §18.2 says the genesis `root` is "the commitment root of the bundle
version it was issued for", and §18.5 explains that a chain embedded in a bundle
"can never name that bundle's own root", because the root covers the table, which
covers the section root, which covers the plaintext carrying the genesis root. It
does not say what the validator should do when it is handed the containing file's
root.

**Chosen reading.** `EntitlementChain.Validate` applies E1–E8 only; it cannot know
which version the grant was issued for and must not invent one. A separate
`ValidateAgainstRoot(commitmentRoot)` exists for a caller that holds the issued
version, and it compares the genesis `root` to *that* root with E5. The section
helper `Bundle.EntitlementSection` deliberately uses the E1–E8 path, because
applying `ValidateAgainstRoot` to the containing bundle's own commitment root
would demand the hash fixed point §18.5 says is impossible. `VerifySignatures`
runs E9 and is separate from both, so "passed E1–E8" is never reported as
"authentic".

## A15. §34.2/§34.3: role separation and holder lookup

**Text.** §34.2 says `root` and `platform` "may be the same key", and KD4 says a
key trusted for one role "MUST NOT be accepted for another role". KD2 says
`holder` is computed from the holder's signature public key, and KD3 says a
transfer's `sig_holder` verifies against "the key the previous record's `holder`
resolves to". The text does not prescribe a data structure for the trust set.

**Chosen reading.** `TrustSet` keeps one lookup per role: `Root` for footer
signatures, `Platform` for `sig_platform`, and a private map keyed by the
*computed* §34.1 holder hash for holders. The two may hold the same key material,
but a caller must register it under each role it should serve; a platform key is
never consulted for a holder and vice versa. `AddHolder` computes the hash from
the key it is given (KD2), so a caller cannot register a key under a hash it does
not produce. A `transfer` resolves the *predecessor's* `holder` (KD3), so a
missing or untrusted predecessor key is an E9 failure, not E2/E5; a chain whose
genesis `holder` is unknown can still pass, because the genesis record carries no
`sig_holder`.

## A10. Writer option defaults (API convention, not a container rule)

The zero value of `WriteOptions` cannot express `suite_id = 0` or
`version_minor = 0`; it is interpreted as suite 1 / minor 3 / manifest
`name_id` 0. This is a Go API convenience, not a claim about the format:
`suite_id = 0` is not in the registry, and `version_minor` is deliberately
unvalidated (§4.3 note), so this API simply cannot express minor 0; a caller
that needs it must extend `WriteOptions`. That is a limitation of this writer
surface, not a constraint on the container.
