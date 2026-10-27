# Conformance corpus

Byte-exact vectors for the `ctf-format` reader, plus the machine-readable index
that says what each one proves. The runner lives in
[`crates/ctf-conformance`](../../../crates/ctf-conformance); it evaluates the
committed bytes, it does not generate them at test time.

```
conformance/
  golden/    known-good bundles (inputs, never emitted)
  hostile/   deterministic mutations of a golden, each expected to be refused
  future/    synthetic later-version files from the spec §16 matrix
  corpus.json
```

## Running

```sh
# Evaluate the committed corpus; prints PASS/FAIL per vector and a summary.
cargo run -p ctf-conformance

# Regenerate every non-golden fixture and corpus.json from the goldens.
cargo run -p ctf-conformance -- --emit spec/vectors/conformance
```

`--emit` is the only writer. A test asserts that every committed fixture and
`corpus.json` are byte-for-byte what it produces, so regeneration is how you
change the corpus — never edit a `.ctf` file by hand.

## `corpus.json`

`format` is `ctf-conformance-corpus/1`; `goldens` lists the input bundles;
`vectors` is one entry per fixture. Each vector carries:

| field | meaning |
| --- | --- |
| `name` | stable vector name, also used in runner output |
| `file` | path relative to this directory |
| `kind` | `golden`, `hostile`, or `future` |
| `hardening` | §14 bullet numbers from `docs/HARDENING-AUDIT.md` it covers |
| `rules` | rule identifiers the fixture exercises (`M1i`, `T4`, `§16`, …) |
| `matrix_row` | the exact §16 matrix row, for `future/` vectors only |
| `proves` | what a pass demonstrates, in one sentence |
| `expectation` | the API result the runner asserts (see below) |

`not_file_shaped` records §14 bullets that cannot be a byte string, with the
reason and where the check actually lives. The audit coverage test requires
every row of the §14 table to appear either in some vector's `hardening` list or
in `not_file_shaped`.

## Expectations

The runner calls only the public API: `Bundle::parse`,
`Bundle::verify_inline_sections`, `Bundle::section_bytes`,
`Bundle::chunk_index`, and `Header::may_rewrite`. It re-implements no container
rule.

| `expectation.kind` | assertion |
| --- | --- |
| `parses` | parse succeeds, footer commitment verifies, inline sections hash correctly |
| `parses_read_only` | the above, **and** `Header::may_rewrite()` is false |
| `parses_unknown_optional` | the named section is an unknown kind; `section_bytes` and `chunk_index` refuse it; `verify_inline_sections` still counts it |
| `rejects` | parse fails; used where the bytes necessarily violate more than one rule |
| `error` | parse fails with the named error variant; the named rule is the file's first failure in §10's check order, with no second rule failing at that step |
| `rejects_on_serve` | parse succeeds; serving the named section fails |
| `serve_error` | parse succeeds; `section_bytes` fails with the named error |
| `rejects_chunk_index` | parse succeeds; `chunk_index` for the named section fails |
| `chunk_index_error` | parse succeeds; `chunk_index` fails with the named error |

Named errors are preferred where the order is determined. A `rejects` vector is
a deliberate admission that the mutation breaks several rules at once — or that
the first failure depends on an order §10 leaves open — so asserting one name
would claim more than the bytes support. `truncated-footer` is the second case:
an unsigned footer shorter than 56 bytes necessarily violates F1 *and* F5, so no
reader order makes F1 the sole failure and the vector asserts rejection.

`rules` records what a fixture exercises. An `error` vector cites the rule that
must fire first, and the fixture is built so the mutation leaves no second
violation in that step — moving a payload also zeroes the bytes it orphaned, or
T8 would fire alongside R12. A `rejects` vector cites several, or cites a rule
whose check order is not fixed, and only rejection is asserted, per §2.1's
condition for requiring a specific reason. Later steps may also be
unreachable-but-violated: a moved payload no longer hashes to its `root`, and the
reader stops before §10 step 7.

## Future vectors

These make the §16 compatibility matrix executable, and each names its matrix
row in `corpus.json`:

- `future/incompat-feature.ctf` — invented `feat_incompat` bit: parse is refused
  with `UnsupportedFeature` before any structural rule.
- `future/ro-compat-bit.ctf` — invented `feat_ro_compat` bit: parses, but
  `may_rewrite()` is false.
- `future/unknown-optional-section.ctf` — `OPTIONAL` section of an undefined
  kind: the section is carried, the serving APIs refuse it, and inline
  verification still hashes and counts it.

## Adding a vector

1. Add a `case(...)` to `catalog()` in `crates/ctf-conformance/src/lib.rs`,
   deriving the bytes from a golden with a single-field mutation where possible.
2. Run `--emit`, then `cargo test -p ctf-conformance` and
   `cargo clippy -p ctf-conformance --all-targets -- -D warnings`.
3. If you add a §14 bullet, update `HARDENING_BULLETS` only when the audit table
   itself changes.
