# Spec ambiguities and the readings chosen here

This implementation was written from `spec/SPEC.md` and the files the spec
points at. The container is byte-exact only where the spec is; the list below
records every place where the text admits more than one reasonable reading, the
reading chosen, and why. None of these is a licence to reject a file the
reference reader accepts or to accept one it rejects: the conformance suite
under `spec/vectors/conformance` is the arbiter, and all 34 of its fixtures pass.

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

## A2. §7.1 M1h: what is depth 1?

" Nesting deeper than 16" does not say whether the outermost value counts as
depth 1 or whether depth counts only container children.

**Chosen reading.** The outermost value is depth 1 and each contained value is
one deeper. Sixteen nested containers are accepted; the seventeenth is rejected
with M1h. This is the inclusive reading of "16 levels" and keeps the cap a
property of the document rather than of the caller's entry point. Tested by
`TestCBORDepthCap` (17 nested arrays plus a scalar is rejected).

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
fixtures can trigger more than one rule (for example, an unknown `enc`
discriminant on the manifest is rejected by R20 because the manifest forbids a
codec, while the fixture cites R10; a byte flip in a payload is reported as a
root mismatch, while the fixture cites §10 step 7).

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

## A10. Writer option defaults (API convention, not a container rule)

The zero value of `WriteOptions` cannot express `suite_id = 0` or
`version_minor = 0`; it is interpreted as suite 1 / minor 3 / manifest
`name_id` 0. This is a Go API convenience, not a claim about the format:
`suite_id = 0` is not in the registry, and `version_minor` is deliberately
unvalidated (§4.3 note), so this API simply cannot express minor 0; a caller
that needs it must extend `WriteOptions`. That is a limitation of this writer
surface, not a constraint on the container.
