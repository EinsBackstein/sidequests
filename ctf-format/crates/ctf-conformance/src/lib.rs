//! Conformance vector runner (roadmap phase 8).
//!
//! The corpus is committed under `spec/vectors/conformance/` and indexed by
//! `corpus.json`:
//!
//! - **Golden bundles** (`golden/`) — known-good `.ctf` files. Each must parse,
//!   the footer commitment must verify, and every inline section must hash to its
//!   record's `root`.
//! - **Hostile inputs** (`hostile/`) — deterministic mutations of a golden. Each
//!   must be rejected. A vector asserts a *named* error only when the mutated
//!   file's first failure, in the check order §10 fixes, is that rule and no
//!   second rule fails at the same step (see [`Expectation::Error`]); a vector
//!   whose bytes break several rules at once, or whose first failure depends on
//!   an order the spec leaves free, asserts only that the file is refused
//!   ([`Expectation::Rejects`]).
//!   Rules that the spec makes *on-use* rather than parse-time (C1–C8, D1–D2) are
//!   asserted where they fire, through the serving API ([`Expectation::ServeError`],
//!   [`Expectation::ChunkIndexError`]).
//! - **Synthetic future files** (`future/`) — the §16 compatibility matrix made
//!   executable: an invented `feat_incompat` bit, an invented `feat_ro_compat`
//!   bit, and an `OPTIONAL` section of an undefined kind. These assert API results
//!   (`Header::may_rewrite`, `Bundle::section_bytes`, `Bundle::chunk_index`,
//!   `Bundle::verify_inline_sections`), not merely that a parse returned `Ok`.
//!
//! Every fixture is generated from the committed goldens by the same builder that
//! `--emit <dir>` runs. A test asserts each committed byte string is exactly what
//! the builder produces, so the corpus is reproducible rather than opaque.
//!
//! The runner is deliberately thin. It calls [`Bundle::parse`],
//! [`Bundle::verify_inline_sections`], [`Bundle::section_bytes`] and
//! [`Bundle::chunk_index`] and compares what comes back against the vector's
//! expectation; it re-implements no container rule, so a vector passing is
//! evidence about the reference implementation rather than about the runner.
//!
//! A failure names the vector and the observed result, which is what makes the
//! output usable in CI: `FAIL non-zero-padding: expected error PaddingNotZero,
//! observed ReservedNotZero { at: "section" }` says both what was wanted and what
//! actually happened.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ctf_format::compress::MAX_DECOMPRESSED_SECTION;
use ctf_format::{
    Bundle, HEADER_LEN, Header, MAGIC, Manifest, SECTION_RECORD_LEN, SUPPORTED_RO_COMPAT,
    SectionFlags, SectionKind, SectionSpec, footer::commitment_root, write_bundle,
};

/// Fixtures live under the workspace `spec/` tree, relative to this crate's
/// manifest directory (`crates/ctf-conformance`).
const FIXTURE_REL: &str = "../../spec/vectors/conformance";

/// The §14 hardening checklist this corpus covers (design §14, audited in
/// `docs/HARDENING-AUDIT.md`).
pub const HARDENING_BULLETS: u32 = 11;

/// Section-record field offsets, mirrored from `ctf_format::section` so a hostile
/// mutation can name the field it changes rather than a magic number.
const REC_KIND: usize = 0;
const REC_NAME_ID: usize = 2;
const REC_FLAGS: usize = 4;
const REC_ENC: usize = 6;
const REC_COMP: usize = 7;
const REC_OFFSET: usize = 8;
const REC_LEN_PLAIN: usize = 24;
const REC_CHUNK_SIZE: usize = 32;
const REC_CHUNK_INDEX_OFF: usize = 40;
const REC_ROOT: usize = 48;

/// Header field offsets.
const HDR_SECTION_TABLE_COUNT: usize = 20;
const HDR_FEAT_INCOMPAT: usize = 40;
const HDR_FEAT_RO_COMPAT: usize = 44;
const HDR_RESERVED: usize = 48;

/// The invented bit the future-file vectors use. Deliberately not a value this
/// build assigns: the point is that the reader has never seen it.
const INVENTED_FEATURE_BIT: u32 = 0x8000_0000;

/// What a vector asserts about the reference reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// [`Bundle::parse`] must succeed, the footer commitment must re-verify against
    /// the file's own header and table bytes, and [`Bundle::verify_inline_sections`]
    /// must report no mismatches.
    Parses,
    /// [`Bundle::parse`] must succeed and every structural check above must pass,
    /// **and** [`Header::may_rewrite`] must be false. A synthetic `feat_ro_compat`
    /// bit from a later version: readable, never rewritable (spec §4.4, §16).
    ParsesReadOnly,
    /// [`Bundle::parse`] must succeed, the section named by `name_id` must be of a
    /// kind this build does not implement, [`Bundle::section_bytes`] and
    /// [`Bundle::chunk_index`] must refuse it, and
    /// [`Bundle::verify_inline_sections`] must still hash it and count it as
    /// verified. A synthetic `OPTIONAL` section from a later version (spec §5.2,
    /// §10, §16).
    ParsesUnknownOptional { name_id: u16 },
    /// [`Bundle::parse`] must fail. Used where the file necessarily violates more
    /// than one rule, so asserting one named error would claim more than the bytes
    /// support.
    Rejects,
    /// [`Bundle::parse`] must fail with an error whose [`std::fmt::Debug`] name
    /// starts with this string — the variant name, e.g. `"PaddingNotZero"`.
    /// Reserved for a vector whose first failure this is: no rule that §10
    /// evaluates earlier is violated, and no second rule fails in the same step.
    /// Error identity is not normative (§2.1), so the assertion is that the
    /// *rule* is determined by the check order, not that every reader spells the
    /// variant identically. A later step may also be unreachable-but-violated — a
    /// moved payload no longer hashes to its `root` — and the reader never gets
    /// there.
    Error(&'static str),
    /// [`Bundle::parse`] must fail. Used where an on-use rule (D1/D2, C1–C8) is
    /// violated and several checks apply; the file is still refused.
    RejectsOnServe { name_id: u16 },
    /// [`Bundle::parse`] must succeed and [`Bundle::section_bytes`] for `name_id`
    /// must fail with this named error. On-use rules that fire at the serving
    /// boundary (D1/D2).
    ServeError { name_id: u16, error: &'static str },
    /// [`Bundle::parse`] must succeed and [`Bundle::chunk_index`] for `name_id`
    /// must fail. C4 runs before any entry is exposed (C6/C7).
    RejectsChunkIndex { name_id: u16 },
    /// [`Bundle::parse`] must succeed and [`Bundle::chunk_index`] for `name_id`
    /// must fail with this named error.
    ChunkIndexError { name_id: u16, error: &'static str },
}

/// Whether a vector is a known-good bundle, a deliberately hostile mutation, or a
/// synthetic file from a later version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorKind {
    /// A committed valid bundle, expected to parse.
    Golden,
    /// A mutation expected to be rejected.
    Hostile,
    /// A compatible file from a later version, expected to parse with the
    /// documented restriction.
    Future,
}

impl VectorKind {
    /// The name used in `corpus.json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Golden => "golden",
            Self::Hostile => "hostile",
            Self::Future => "future",
        }
    }
}

/// One conformance vector: a name, the bytes, and what parsing them must do.
#[derive(Debug, Clone)]
pub struct Vector {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expectation,
}

/// One committed fixture plus the index metadata that explains it.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: &'static str,
    /// Path relative to the fixtures root, e.g. `hostile/bad-magic.ctf`.
    pub file: &'static str,
    pub kind: VectorKind,
    /// The design §14 checklist bullets this fixture covers, if any.
    pub hardening: &'static [u32],
    /// The rule ids the fixture exercises (`H7`, `R12`, `T4`, `M1g`, `C4`, …).
    pub rules: &'static [&'static str],
    /// The spec §16 compatibility-matrix row, for `future/` vectors.
    pub matrix_row: Option<&'static str>,
    /// One sentence stating what a pass proves.
    pub proves: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expectation,
}

/// Metadata for a catalog entry, kept separate so each fixture's construction is
/// one readable expression.
struct Meta {
    name: &'static str,
    file: &'static str,
    kind: VectorKind,
    hardening: &'static [u32],
    rules: &'static [&'static str],
    matrix_row: Option<&'static str>,
    proves: &'static str,
}

/// What one vector established.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub name: &'static str,
    pub kind: VectorKind,
    pub passed: bool,
    /// On failure, `expected <x>, observed <y>`; a human-readable note on success.
    pub detail: String,
}

/// The result of a whole run.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub outcomes: Vec<Outcome>,
}

impl Report {
    /// Every vector passed.
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.passed)
    }

    /// Number of vectors that failed.
    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| !o.passed).count()
    }
}

/// The directory holding the committed fixtures.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL)
}

/// Build the committed minimal golden bundle through the public API.
///
/// This is the same 4344-byte fixture the crate's `minimal_bundle_golden_vector`
/// pins; a test asserts the committed `golden/minimal.ctf` is byte-for-byte this,
/// so the fixture is reproducible rather than opaque.
pub fn build_minimal_golden() -> ctf_format::Result<Vec<u8>> {
    let manifest =
        Manifest::minimal("whos-that-bird", "Who's That Bird", &["manifest"])?.encode()?;
    write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest,
        )],
    )
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// Run every committed vector.
///
/// A missing fixture is reported as a single failing outcome rather than a panic:
/// a runner that cannot even read its inputs should still say so in the same
/// shape as every other failure.
pub fn run() -> Report {
    match catalog() {
        Ok(cases) => Report {
            outcomes: cases.into_iter().map(evaluate_committed).collect(),
        },
        Err(detail) => Report {
            outcomes: vec![Outcome {
                name: "fixtures",
                kind: VectorKind::Hostile,
                passed: false,
                detail,
            }],
        },
    }
}

/// Run an arbitrary vector set, exposed so a test can drive a deliberately wrong
/// expectation and check that the failure names the vector.
pub fn run_vectors(vectors: Vec<Vector>) -> Report {
    Report {
        outcomes: vectors.into_iter().map(evaluate).collect(),
    }
}

/// Evaluate the **committed** bytes, not the builder's in-memory copy: a run must
/// exercise the artifact under version control, while the reproducibility test
/// separately proves the two agree.
fn evaluate_committed(case: Case) -> Outcome {
    match read_fixture(&fixtures_root(), case.file) {
        Ok(bytes) => {
            let mut outcome = evaluate(Vector {
                name: case.name,
                bytes,
                expect: case.expect,
            });
            outcome.kind = case.kind;
            outcome
        }
        Err(detail) => Outcome {
            name: case.name,
            kind: case.kind,
            passed: false,
            detail,
        },
    }
}

fn evaluate(v: Vector) -> Outcome {
    let kind = kind_of(v.expect);
    match v.expect {
        Expectation::Parses => evaluate_parses(v.name, kind, &v.bytes, Extra::None),
        Expectation::ParsesReadOnly => evaluate_parses(v.name, kind, &v.bytes, Extra::ReadOnly),
        Expectation::ParsesUnknownOptional { name_id } => {
            evaluate_parses(v.name, kind, &v.bytes, Extra::UnknownOptional(name_id))
        }
        Expectation::Rejects => evaluate_rejects(v.name, kind, &v.bytes),
        Expectation::Error(expected) => evaluate_error(v.name, kind, &v.bytes, expected),
        Expectation::RejectsOnServe { name_id } => {
            evaluate_serve(v.name, kind, &v.bytes, name_id, None)
        }
        Expectation::ServeError { name_id, error } => {
            evaluate_serve(v.name, kind, &v.bytes, name_id, Some(error))
        }
        Expectation::RejectsChunkIndex { name_id } => {
            evaluate_chunk_index(v.name, kind, &v.bytes, name_id, None)
        }
        Expectation::ChunkIndexError { name_id, error } => {
            evaluate_chunk_index(v.name, kind, &v.bytes, name_id, Some(error))
        }
    }
}

fn kind_of(expect: Expectation) -> VectorKind {
    match expect {
        Expectation::Parses => VectorKind::Golden,
        Expectation::ParsesReadOnly | Expectation::ParsesUnknownOptional { .. } => {
            VectorKind::Future
        }
        _ => VectorKind::Hostile,
    }
}

/// Extra assertions a `Parses`-shaped expectation adds after the baseline checks.
enum Extra {
    None,
    ReadOnly,
    UnknownOptional(u16),
}

fn evaluate_parses(name: &'static str, kind: VectorKind, bytes: &[u8], extra: Extra) -> Outcome {
    let bundle = match Bundle::parse(bytes) {
        Ok(bundle) => bundle,
        Err(e) => {
            return Outcome {
                name,
                kind,
                passed: false,
                detail: format!("expected parse to succeed, observed error {e:?}"),
            };
        }
    };
    // `parse` recomputes the commitment, but the runner re-derives it from the
    // file's own header and table bytes so "the commitment verifies" is checked by
    // the vector, not taken on trust from the code under test.
    if !commitment_verified(bytes, &bundle) {
        return Outcome {
            name,
            kind,
            passed: false,
            detail: "expected the footer commitment to verify, observed a root mismatch".into(),
        };
    }
    // This second pass is what proves every inline section hashes to the `root`
    // its record claims.
    let report = match bundle.verify_inline_sections() {
        Ok(report) => report,
        Err(e) => {
            return Outcome {
                name,
                kind,
                passed: false,
                detail: format!("expected inline sections to verify, observed error {e:?}"),
            };
        }
    };
    if !report.mismatches.is_empty() {
        return Outcome {
            name,
            kind,
            passed: false,
            detail: format!(
                "expected no section root mismatches, observed mismatches {:?}",
                report.mismatches
            ),
        };
    }
    let mut detail = String::new();
    let _ = write!(
        detail,
        "parses, commitment verified; verified={}, external={}, unverifiable={}, chunk_indices={}",
        report.verified, report.external, report.unverifiable, report.chunk_indices
    );
    match extra {
        Extra::None => {}
        Extra::ReadOnly => {
            if bundle.header.feat_ro_compat & !SUPPORTED_RO_COMPAT == 0 {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail:
                        "expected an unimplemented ro_compat bit, observed only implemented bits"
                            .into(),
                };
            }
            if bundle.header.may_rewrite() {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail:
                        "expected the file to be read-only, observed Header::may_rewrite() == true"
                            .into(),
                };
            }
            detail.push_str("; unknown ro_compat bit is set and may_rewrite() is false");
        }
        Extra::UnknownOptional(name_id) => {
            let Some(record) = bundle.section(name_id) else {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail: format!("expected a section with name_id {name_id}, observed none"),
                };
            };
            if record.kind.is_known() {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail: format!(
                        "expected section {name_id} to have an unknown kind, observed {:?}",
                        record.kind
                    ),
                };
            }
            let record = *record;
            if bundle.section_bytes(&record).is_ok() {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail: format!(
                        "expected Bundle::section_bytes to refuse unknown kind section {name_id}, observed plaintext"
                    ),
                };
            }
            if bundle.chunk_index(&record).is_ok() {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail: format!(
                        "expected Bundle::chunk_index to refuse unknown kind section {name_id}, observed an index"
                    ),
                };
            }
            if report.verified != bundle.sections.len() || report.unverifiable != 0 {
                return Outcome {
                    name,
                    kind,
                    passed: false,
                    detail: format!(
                        "expected every section to be verified, observed verified={} of {} (unverifiable={})",
                        report.verified,
                        bundle.sections.len(),
                        report.unverifiable
                    ),
                };
            }
            let _ = write!(
                detail,
                "; unknown kind section {name_id} is carried, refused by the serving APIs, and verified"
            );
        }
    }
    Outcome {
        name,
        kind,
        passed: true,
        detail,
    }
}

fn evaluate_rejects(name: &'static str, kind: VectorKind, bytes: &[u8]) -> Outcome {
    match Bundle::parse(bytes) {
        Ok(_) => Outcome {
            name,
            kind,
            passed: false,
            detail: "expected rejection, observed parse succeeded".into(),
        },
        Err(e) => Outcome {
            name,
            kind,
            passed: true,
            detail: format!("rejected with {e:?}"),
        },
    }
}

fn evaluate_error(
    name: &'static str,
    kind: VectorKind,
    bytes: &[u8],
    expected: &'static str,
) -> Outcome {
    match Bundle::parse(bytes) {
        Ok(_) => Outcome {
            name,
            kind,
            passed: false,
            detail: format!("expected error {expected}, observed parse succeeded"),
        },
        Err(e) => {
            let observed = format!("{e:?}");
            let passed = observed.starts_with(expected);
            Outcome {
                name,
                kind,
                passed,
                detail: if passed {
                    format!("observed error {observed}")
                } else {
                    format!("expected error {expected}, observed {observed}")
                },
            }
        }
    }
}

fn evaluate_serve(
    name: &'static str,
    kind: VectorKind,
    bytes: &[u8],
    name_id: u16,
    expected: Option<&'static str>,
) -> Outcome {
    let bundle = match Bundle::parse(bytes) {
        Ok(bundle) => bundle,
        Err(e) => {
            return Outcome {
                name,
                kind,
                passed: false,
                detail: format!(
                    "expected parse to succeed before the serving boundary, observed error {e:?}"
                ),
            };
        }
    };
    let Some(record) = bundle.section(name_id).copied() else {
        return Outcome {
            name,
            kind,
            passed: false,
            detail: format!("expected a section with name_id {name_id}, observed none"),
        };
    };
    match bundle.section_bytes(&record) {
        Ok(_) => Outcome {
            name,
            kind,
            passed: false,
            detail: "expected Bundle::section_bytes to refuse, observed plaintext".into(),
        },
        Err(e) => {
            let observed = format!("{e:?}");
            let passed = expected.is_none_or(|want| observed.starts_with(want));
            Outcome {
                name,
                kind,
                passed,
                detail: if passed {
                    format!("parse succeeded; section_bytes refused with {observed}")
                } else {
                    format!(
                        "expected section_bytes error {}, observed {observed}",
                        expected.unwrap_or_default()
                    )
                },
            }
        }
    }
}

fn evaluate_chunk_index(
    name: &'static str,
    kind: VectorKind,
    bytes: &[u8],
    name_id: u16,
    expected: Option<&'static str>,
) -> Outcome {
    let bundle = match Bundle::parse(bytes) {
        Ok(bundle) => bundle,
        Err(e) => {
            return Outcome {
                name,
                kind,
                passed: false,
                detail: format!(
                    "expected parse to succeed before chunk-index use, observed error {e:?}"
                ),
            };
        }
    };
    let Some(record) = bundle.section(name_id).copied() else {
        return Outcome {
            name,
            kind,
            passed: false,
            detail: format!("expected a section with name_id {name_id}, observed none"),
        };
    };
    match bundle.chunk_index(&record) {
        Ok(Some(_)) => Outcome {
            name,
            kind,
            passed: false,
            detail: "expected Bundle::chunk_index to refuse the index, observed a verified index"
                .into(),
        },
        Ok(None) => Outcome {
            name,
            kind,
            passed: false,
            detail: "expected Bundle::chunk_index to refuse the index, observed none".into(),
        },
        Err(e) => {
            let observed = format!("{e:?}");
            let passed = expected.is_none_or(|want| observed.starts_with(want));
            Outcome {
                name,
                kind,
                passed,
                detail: if passed {
                    format!("parse succeeded; chunk_index refused with {observed}")
                } else {
                    format!(
                        "expected chunk_index error {}, observed {observed}",
                        expected.unwrap_or_default()
                    )
                },
            }
        }
    }
}

/// Re-derive the commitment root from the file's own header and table bytes, the
/// way spec §8.3 defines it, and compare it to the footer's.
fn commitment_verified(bytes: &[u8], bundle: &Bundle<'_>) -> bool {
    let Ok((start, end)) = bundle.header.table_range() else {
        return false;
    };
    let (Ok(s), Ok(e)) = (usize::try_from(start), usize::try_from(end)) else {
        return false;
    };
    let Some(header_bytes) = bytes.get(..HEADER_LEN as usize) else {
        return false;
    };
    let Some(table_bytes) = bytes.get(s..e) else {
        return false;
    };
    commitment_root(header_bytes, table_bytes) == bundle.footer.root
}

// ---------------------------------------------------------------------------
// The catalog: the single source of truth for every committed fixture
// ---------------------------------------------------------------------------

/// Build the whole catalog from the committed goldens.
///
/// The goldens are inputs; every other fixture is derived here and written by
/// [`emit`]. Mutations change one declared field where the layout allows it. Where
/// a mutation changes the header or the section table, the commitment root is
/// recomputed through the library's own [`commitment_root`], so the fixture differs
/// from the golden only in the rule under test rather than also being accidentally
/// tampered.
pub fn catalog() -> Result<Vec<Case>, String> {
    let root = fixtures_root();
    let goldens = Goldens {
        minimal: read_fixture(&root, "golden/minimal.ctf")?,
        demo: read_fixture(&root, "golden/demo.ctf")?,
    };
    build_cases(&goldens)
}

struct Goldens {
    minimal: Vec<u8>,
    demo: Vec<u8>,
}

fn build_cases(g: &Goldens) -> Result<Vec<Case>, String> {
    let mh = Header::parse(&g.minimal).map_err(|e| format!("golden/minimal.ctf: {e}"))?;
    let dh = Header::parse(&g.demo).map_err(|e| format!("golden/demo.ctf: {e}"))?;
    let mrec = |i: usize| -> usize { mh.section_table_off as usize + i * SECTION_RECORD_LEN };
    let drec = |i: usize| -> usize { dh.section_table_off as usize + i * SECTION_RECORD_LEN };

    let demo_bundle =
        Bundle::parse(&g.demo).map_err(|e| format!("golden/demo.ctf does not parse: {e}"))?;
    let demo_artifact = *demo_bundle
        .section(1)
        .ok_or_else(|| "golden/demo.ctf has no section 1".to_string())?;
    let demo_index = usize::try_from(demo_artifact.chunk_index_off)
        .map_err(|_| "demo chunk index offset does not fit usize".to_string())?;
    let demo_payload = usize::try_from(demo_artifact.offset)
        .map_err(|_| "demo payload offset does not fit usize".to_string())?;
    let demo_payload_len = usize::try_from(demo_artifact.len_stored)
        .map_err(|_| "demo payload length does not fit usize".to_string())?;
    let demo_chunks = usize::try_from(demo_artifact.len_plain)
        .map_err(|_| "demo plaintext length does not fit usize")?
        .div_ceil(demo_artifact.chunk_size as usize);
    let demo_index_len = demo_chunks * 32;
    let minimal_bundle =
        Bundle::parse(&g.minimal).map_err(|e| format!("golden/minimal.ctf does not parse: {e}"))?;
    let minimal_manifest = *minimal_bundle
        .section(0)
        .ok_or_else(|| "golden/minimal.ctf has no section 0".to_string())?;
    let min_payload = usize::try_from(minimal_manifest.offset)
        .map_err(|_| "minimal payload offset does not fit usize".to_string())?;
    let min_payload_len = usize::try_from(minimal_manifest.len_stored)
        .map_err(|_| "minimal payload length does not fit usize".to_string())?;

    let mut cases = Vec::new();

    // ---- Goldens ----------------------------------------------------------
    cases.push(case(
        Meta {
            name: "golden-minimal",
            file: "golden/minimal.ctf",
            kind: VectorKind::Golden,
            hardening: &[],
            rules: &["§11"],
            matrix_row: None,
            proves: "the minimal bundle of spec §11 is byte-for-byte reproducible through the public writer and parses",
        },
        build_minimal_golden().map_err(|e| format!("build minimal golden: {e}"))?,
        Expectation::Parses,
    ));
    cases.push(case(
        Meta {
            name: "golden-demo",
            file: "golden/demo.ctf",
            kind: VectorKind::Golden,
            hardening: &[],
            rules: &["§11"],
            matrix_row: None,
            proves: "a multi-section bundle with a chunk index and an external section parses and verifies",
        },
        g.demo.clone(),
        Expectation::Parses,
    ));

    // ---- 1. No allocation from an unvalidated length ----------------------
    // H7 is checked before the count can size a table allocation. A count above
    // the cap necessarily also breaks H11/H12, so the fixture asserts rejection
    // rather than one named error.
    cases.push(case(
        Meta {
            name: "section-count-over-cap",
            file: "hostile/section-count-over-cap.ctf",
            kind: VectorKind::Hostile,
            hardening: &[1],
            rules: &["H7", "H11", "H12"],
            matrix_row: None,
            proves: "section_table_count above MAX_SECTIONS is refused before the table can size an allocation",
        },
        mutated(&g.minimal, |b| set_u32(b, HDR_SECTION_TABLE_COUNT, u32::MAX)),
        Expectation::Rejects,
    ));
    // The same bullet at the CBOR layer: a declared array length near u64::MAX is
    // never used to size an allocation; decoding stops when the input runs out.
    cases.push(case(
        Meta {
            name: "manifest-huge-length",
            file: "hostile/manifest-huge-length.ctf",
            kind: VectorKind::Hostile,
            hardening: &[1],
            rules: &["M1i"],
            matrix_row: None,
            proves: "a CBOR array claiming u64::MAX elements is refused as CborTruncated without allocating for the claim",
        },
        replace_manifest(&g.minimal, &huge_length_manifest())?,
        Expectation::Error("CborTruncated"),
    ));

    // ---- 2. Bounds-check every offset -------------------------------------
    cases.push(case(
        Meta {
            name: "payload-inside-header",
            file: "hostile/payload-inside-header.ctf",
            kind: VectorKind::Hostile,
            hardening: &[2],
            rules: &["R12"],
            matrix_row: None,
            proves: "an inline payload offset below HEADER_LEN is refused (R12), not read",
        },
        committed(&g.minimal, |b| {
            // Moving the range orphans the bytes it came from; zero them so T8 is
            // not violated too. The only numbered rule left broken is R12.
            if let Some(old) = b.get_mut(min_payload..min_payload + min_payload_len) {
                old.fill(0);
            }
            set_u64(b, mrec(0) + REC_OFFSET, 0);
        })?,
        Expectation::Error("BadOffset"),
    ));
    cases.push(case(
        Meta {
            name: "overlapping-payloads",
            file: "hostile/overlapping-payloads.ctf",
            kind: VectorKind::Hostile,
            hardening: &[2],
            rules: &["T4"],
            matrix_row: None,
            proves: "two non-empty inline payload ranges that share bytes are refused (T4)",
        },
        committed(&g.demo, |b| {
            // The old artifact bytes become unclaimed when the record moves; zero
            // them so T4 is the only rule the file violates.
            if let Some(old) = b.get_mut(demo_payload..demo_payload + demo_payload_len) {
                old.fill(0);
            }
            set_u64(b, drec(1) + REC_OFFSET, ctf_format::PAYLOAD_ALIGN);
        })?,
        Expectation::Error("OverlappingSections"),
    ));
    cases.push(case(
        Meta {
            name: "misaligned-payload-offset",
            file: "hostile/misaligned-payload-offset.ctf",
            kind: VectorKind::Hostile,
            hardening: &[2],
            rules: &["R12"],
            matrix_row: None,
            proves: "an inline payload offset that is not page-aligned is refused (R12)",
        },
        committed(&g.demo, |b| {
            if let Some(old) = b.get_mut(demo_payload..demo_payload + demo_payload_len) {
                old.fill(0);
            }
            // 4401 is above the manifest payload's end and inside the file, so the
            // only rule broken is alignment.
            set_u64(b, drec(1) + REC_OFFSET, 4401);
        })?,
        Expectation::Error("Misaligned"),
    ));
    cases.push(case(
        Meta {
            name: "payload-beyond-footer",
            file: "hostile/payload-beyond-footer.ctf",
            kind: VectorKind::Hostile,
            hardening: &[2, 3],
            rules: &["T3"],
            matrix_row: None,
            proves: "an inline payload that runs past footer_off is refused (T3)",
        },
        committed(&g.minimal, |b| {
            // As above: the old range is orphaned, so zero it rather than leave T8
            // broken as well.
            if let Some(old) = b.get_mut(min_payload..min_payload + min_payload_len) {
                old.fill(0);
            }
            set_u64(b, mrec(0) + REC_OFFSET, 8192);
        })?,
        Expectation::Error("ExceedsFile"),
    ));

    // ---- 3. The file ends at the footer -----------------------------------
    cases.push(case(
        Meta {
            name: "trailing-byte-after-footer",
            file: "hostile/trailing-byte-after-footer.ctf",
            kind: VectorKind::Hostile,
            hardening: &[3],
            rules: &["F5", "F7"],
            matrix_row: None,
            proves: "a byte appended after the footer is refused; no structure may follow it",
        },
        mutated(&g.minimal, |b| b.push(0)),
        Expectation::Rejects,
    ));
    cases.push(case(
        Meta {
            name: "truncated-footer",
            file: "hostile/truncated-footer.ctf",
            kind: VectorKind::Hostile,
            hardening: &[3],
            rules: &["F1", "F5"],
            matrix_row: None,
            proves: "a footer shorter than MIN_FOOTER_LEN is refused rather than padded. F1 always implies F5 (an unsigned footer must be exactly 56 bytes), so no reader order can make F1 the sole violation; this vector asserts rejection, not a reason",
        },
        truncate(&g.minimal, g.minimal.len().saturating_sub(1)),
        Expectation::Rejects,
    ));
    cases.push(case(
        Meta {
            name: "wrong-total-len",
            file: "hostile/wrong-total-len.ctf",
            kind: VectorKind::Hostile,
            hardening: &[3],
            rules: &["F7"],
            matrix_row: None,
            proves: "footer total_len must equal the real file length (F7)",
        },
        mutated(&g.minimal, |b| {
            let n = b.len();
            set_u64(b, n.saturating_sub(16), n as u64 + 1);
        }),
        Expectation::Error("BadTotalLen"),
    ));
    cases.push(case(
        Meta {
            name: "signature-slot-length-mismatch",
            file: "hostile/signature-slot-length-mismatch.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["F10"],
            matrix_row: None,
            proves: "a suite-1 footer declaring 1-byte signature slots is refused (F10, §8.1, §20.3): \
                     the slot lengths are the suite's, so the file cannot be authenticated as itself",
        },
        forged_signature_lengths(&g.minimal)?,
        Expectation::Error("SignatureSlotLength"),
    ));
    cases.push(case(
        Meta {
            name: "truncated-body",
            file: "hostile/truncated-body.ctf",
            kind: VectorKind::Hostile,
            hardening: &[2, 3],
            rules: &["H12", "H13"],
            matrix_row: None,
            proves: "a file shorter than its own table and footer is refused before any of it is read",
        },
        truncate(&g.minimal, 1000),
        Expectation::Rejects,
    ));

    // ---- 4. CBOR depth cap ------------------------------------------------
    cases.push(case(
        Meta {
            name: "manifest-cbor-too-deep",
            file: "hostile/manifest-cbor-too-deep.ctf",
            kind: VectorKind::Hostile,
            hardening: &[4],
            rules: &["M1h"],
            matrix_row: None,
            proves: "a manifest nested past cbor::MAX_DEPTH is refused as CborTooDeep",
        },
        replace_manifest(&g.minimal, &nested_manifest())?,
        Expectation::Error("CborTooDeep"),
    ));

    // ---- 5. Decompression caps, checked before decode ---------------------
    let compressed = compressed_section_bundle()?;
    let ch = Header::parse(&compressed).map_err(|e| format!("compressed base: {e}"))?;
    let crec = |i: usize| -> usize { ch.section_table_off as usize + i * SECTION_RECORD_LEN };

    cases.push(case(
        Meta {
            name: "compressed-ratio-cap",
            file: "hostile/compressed-ratio-cap.ctf",
            kind: VectorKind::Hostile,
            hardening: &[5],
            rules: &["D2"],
            matrix_row: None,
            proves: "a declared plaintext above MAX_DECOMPRESSION_RATIO times len_stored is refused before zstd runs (D2)",
        },
        committed(&compressed, |b| {
            // Equal to D1's cap, so D1 passes and only the ratio rule fires.
            set_u64(
                b,
                crec(1) + REC_LEN_PLAIN,
                MAX_DECOMPRESSED_SECTION,
            );
        })?,
        Expectation::ServeError {
            name_id: 1,
            error: "CompressionRatioExceeded",
        },
    ));
    cases.push(case(
        Meta {
            name: "compressed-output-cap",
            file: "hostile/compressed-output-cap.ctf",
            kind: VectorKind::Hostile,
            hardening: &[5],
            rules: &["D1", "D2"],
            matrix_row: None,
            proves: "a declared plaintext above MAX_DECOMPRESSED_SECTION is refused before zstd runs; a small stored section also exceeds the ratio, so the fixture asserts refusal rather than one name",
        },
        committed(&compressed, |b| {
            set_u64(
                b,
                crec(1) + REC_LEN_PLAIN,
                MAX_DECOMPRESSED_SECTION + 1,
            );
        })?,
        Expectation::RejectsOnServe { name_id: 1 },
    ));

    // ---- 6. Duplicate section IDs and duplicate manifest keys -------------
    cases.push(case(
        Meta {
            name: "duplicate-name-id",
            file: "hostile/duplicate-name-id.ctf",
            kind: VectorKind::Hostile,
            hardening: &[6],
            rules: &["T2"],
            matrix_row: None,
            proves: "two records sharing a name_id are refused (T2), because name_id is identity",
        },
        committed(&g.demo, |b| set_u16(b, drec(1) + REC_NAME_ID, 0))?,
        Expectation::Error("DuplicateSectionName"),
    ));
    cases.push(case(
        Meta {
            name: "duplicate-manifest-key",
            file: "hostile/duplicate-manifest-key.ctf",
            kind: VectorKind::Hostile,
            hardening: &[6],
            rules: &["M1g"],
            matrix_row: None,
            proves: "a manifest map with an adjacent duplicate key is refused, never last-wins resolved",
        },
        replace_manifest(&g.minimal, &duplicate_key_manifest())?,
        Expectation::Error("CborDuplicateKey"),
    ));

    // ---- 7. Path-like and bidi names --------------------------------------
    cases.push(case(
        Meta {
            name: "manifest-name-traversal",
            file: "hostile/manifest-name-traversal.ctf",
            kind: VectorKind::Hostile,
            hardening: &[7],
            rules: &["M15"],
            matrix_row: None,
            proves: "a name table entry containing a path separator is refused, so traversal is unrepresentable",
        },
        replace_manifest(&g.minimal, &manifest_with_name(b"../aaaaa")?)?,
        Expectation::Error("ManifestEntry"),
    ));
    cases.push(case(
        Meta {
            name: "manifest-name-bidi-control",
            file: "hostile/manifest-name-bidi-control.ctf",
            kind: VectorKind::Hostile,
            hardening: &[7],
            rules: &["M15"],
            matrix_row: None,
            proves: "a name table entry containing U+202E is refused after UTF-8 decoding, not byte-masked",
        },
        replace_manifest(&g.minimal, &manifest_with_name("chal\u{202e}x".as_bytes())?)?,
        Expectation::Error("ManifestEntry"),
    ));

    // ---- 8. Commitment verified before the manifest is interpreted --------
    let manifest_offset = manifest_payload_offset(&g.minimal)?;
    cases.push(case(
        Meta {
            name: "manifest-payload-flip",
            file: "hostile/manifest-payload-flip.ctf",
            kind: VectorKind::Hostile,
            hardening: &[8],
            rules: &["§10 step 7", "§5.1"],
            matrix_row: None,
            proves: "the manifest's record root is verified before CBOR decoding: a flipped map header fails as SectionRootMismatch, not as a manifest error. The signature half of the bullet is caller-gated (§10 step 9) and cannot be exercised without a trusted key the bundle deliberately does not carry",
        },
        mutated(&g.minimal, |b| flip(b, manifest_offset)),
        Expectation::Error("SectionRootMismatch"),
    ));

    // ---- 9. Chunk authenticity before chunk bytes -------------------------
    cases.push(case(
        Meta {
            name: "chunk-index-entry-flip",
            file: "hostile/chunk-index-entry-flip.ctf",
            kind: VectorKind::Hostile,
            hardening: &[9],
            rules: &["C4", "C7"],
            matrix_row: None,
            proves: "a tampered index still parses (C rules are on-use) but Bundle::chunk_index reduces it to the root first and refuses it (C4); no entry or chunk is exposed (C7)",
        },
        mutated(&g.demo, |b| flip(b, demo_index)),
        Expectation::ChunkIndexError {
            name_id: 1,
            error: "RootMismatch",
        },
    ));

    // ---- The rest of the named hostile mutations --------------------------
    cases.push(case(
        Meta {
            name: "bad-magic",
            file: "hostile/bad-magic.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["H2"],
            matrix_row: None,
            proves: "the file signature is checked byte-for-byte",
        },
        mutated(&g.minimal, |b| flip(b, 0)),
        Expectation::Error("BadMagic"),
    ));
    cases.push(case(
        Meta {
            name: "bad-footer-magic",
            file: "hostile/bad-footer-magic.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["F6"],
            matrix_row: None,
            proves: "the footer's repeated magic is checked, not used to locate the footer",
        },
        mutated(&g.minimal, |b| {
            let last = b.len().saturating_sub(1);
            flip(b, last);
        }),
        Expectation::Error("BadMagic"),
    ));
    cases.push(case(
        Meta {
            name: "non-zero-padding",
            file: "hostile/non-zero-padding.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["T8"],
            matrix_row: None,
            proves: "bytes belonging to no structure must be zero, so one signature cannot cover two files (T8)",
        },
        mutated(&g.minimal, |b| flip(b, 64)),
        Expectation::Error("PaddingNotZero"),
    ));
    cases.push(case(
        Meta {
            name: "unknown-section-flag-bits",
            file: "hostile/unknown-section-flag-bits.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["R4"],
            matrix_row: None,
            proves: "an unassigned section flag bit is refused rather than ignored",
        },
        committed(&g.minimal, |b| set_u16(b, mrec(0) + REC_FLAGS, 0x0080))?,
        Expectation::Error("UnknownFlagBits"),
    ));
    cases.push(case(
        Meta {
            name: "reserved-non-zero",
            file: "hostile/reserved-non-zero.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["H5"],
            matrix_row: None,
            proves: "header reserved bytes are required to be zero",
        },
        mutated(&g.minimal, |b| set_u8(b, HDR_RESERVED, 1)),
        Expectation::Error("ReservedNotZero"),
    ));
    cases.push(case(
        Meta {
            name: "unknown-section-kind",
            file: "hostile/unknown-section-kind.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["R3"],
            matrix_row: None,
            proves: "kind 0 is never valid, even on an ordinary section: it is a rejection (R3), not an unknown optional kind to skip",
        },
        // The artifact record, not the manifest: zeroing the manifest's kind would
        // also break T1 (no record of kind `manifest` remains), and this vector
        // asserts one rule.
        committed(&g.demo, |b| set_u16(b, drec(1) + REC_KIND, 0))?,
        Expectation::Error("InvalidSectionKind"),
    ));
    cases.push(case(
        Meta {
            name: "unknown-enc-discriminant",
            file: "hostile/unknown-enc-discriminant.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["R10"],
            matrix_row: None,
            proves: "an unassigned enc value is refused on an unknown-kind OPTIONAL section a reader would otherwise skip, so the skip cannot hide R10",
        },
        // The demo's notes.md artifact, not the manifest: mutating the manifest
        // would violate R20 as well. Kind 9 with OPTIONAL makes the record one a
        // reader must skip for serving, so a reader that skipped before checking the
        // codec would accept it; §5.4 still requires R10. R18 is satisfied, and R10
        // is the next rule that can fail.
        committed(&g.demo, |b| {
            set_u16(b, drec(1) + REC_KIND, 9);
            set_u16(
                b,
                drec(1) + REC_FLAGS,
                demo_artifact.flags.0 | SectionFlags::OPTIONAL,
            );
            set_u8(b, drec(1) + REC_ENC, 2);
        })?,
        // R10 is the only rule broken at this step, so the reason is assertable.
        Expectation::Error("UnknownDiscriminant"),
    ));
    cases.push(case(
        Meta {
            name: "unknown-comp-discriminant",
            file: "hostile/unknown-comp-discriminant.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["R10"],
            matrix_row: None,
            proves: "an unassigned comp value is refused on the same unknown-kind OPTIONAL section; §5.4 applies to either field",
        },
        committed(&g.demo, |b| {
            set_u16(b, drec(1) + REC_KIND, 9);
            set_u16(
                b,
                drec(1) + REC_FLAGS,
                demo_artifact.flags.0 | SectionFlags::OPTIONAL,
            );
            set_u8(b, drec(1) + REC_COMP, 2);
        })?,
        Expectation::Error("UnknownDiscriminant"),
    ));
    cases.push(case(
        Meta {
            name: "chunk-index-trailing-bytes",
            file: "hostile/chunk-index-trailing-bytes.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["T8"],
            matrix_row: None,
            proves: "the index length is derived from len_plain/chunk_size, and bytes it no longer claims must be zero",
        },
        committed(&g.demo, |b| set_u32(b, drec(1) + REC_CHUNK_SIZE, 8192))?,
        Expectation::Error("PaddingNotZero"),
    ));
    cases.push(case(
        Meta {
            name: "chunk-index-overlaps-table",
            file: "hostile/chunk-index-overlaps-table.ctf",
            kind: VectorKind::Hostile,
            hardening: &[],
            rules: &["T7"],
            matrix_row: None,
            proves: "a derived chunk-index range is included in overlap detection (T7)",
        },
        committed(&g.demo, |b| {
            // Zero the index the record used to point at; otherwise the orphaned
            // bytes violate T8 and this vector would assert two rules.
            if let Some(old) = b.get_mut(demo_index..demo_index + demo_index_len) {
                old.fill(0);
            }
            let overlap = dh.section_table_off.saturating_sub(32);
            set_u64(b, drec(1) + REC_CHUNK_INDEX_OFF, overlap);
        })?,
        Expectation::Error("OverlapsSectionTable"),
    ));

    // ---- Synthetic future files (spec §16) --------------------------------
    cases.push(case(
        Meta {
            name: "future-incompat-feature",
            file: "future/incompat-feature.ctf",
            kind: VectorKind::Future,
            hardening: &[],
            rules: &["H14"],
            matrix_row: Some(
                "0.4+, `feat_incompat` feature in use → 0.3: Rejected, naming the feature (H14)",
            ),
            proves: "an invented feat_incompat bit is refused by name before any structural rule",
        },
        {
            let mut b = mutated(&g.minimal, |b| {
                set_u32(b, HDR_FEAT_INCOMPAT, INVENTED_FEATURE_BIT);
            });
            // The rest of the file is a valid 0.3 bundle, so H14 is the only rule
            // that fails. H14 itself stops Header::parse, so the commitment is
            // recomputed over the mutated header at the known layout offsets.
            refresh_commitment_at(
                &mut b,
                mh.section_table_off,
                mh.section_table_count,
                mh.footer_off,
            )?;
            b
        },
        Expectation::Error("UnsupportedFeature"),
    ));
    cases.push(case(
        Meta {
            name: "future-ro-compat-bit",
            file: "future/ro-compat-bit.ctf",
            kind: VectorKind::Future,
            hardening: &[],
            rules: &["§4.4"],
            matrix_row: Some(
                "0.3, plus a `ro_compat` bit from a later version → 0.3: Accepted, read-only (§4.4)",
            ),
            proves: "an invented feat_ro_compat bit parses, and Header::may_rewrite() is false",
        },
        committed(&g.minimal, |b| {
            set_u32(
                b,
                HDR_FEAT_RO_COMPAT,
                ctf_format::FEAT_RO_COMPAT_CONTAINER_V1 | INVENTED_FEATURE_BIT,
            );
        })?,
        Expectation::ParsesReadOnly,
    ));
    cases.push(case(
        Meta {
            name: "future-unknown-optional-section",
            file: "future/unknown-optional-section.ctf",
            kind: VectorKind::Future,
            hardening: &[],
            rules: &["§5.2", "C8"],
            matrix_row: Some(
                "0.4+, `OPTIONAL` unknown kind → 0.3: Accepted; the section is carried, never interpreted",
            ),
            proves: "an OPTIONAL section of an undefined kind parses and is carried, Bundle::section_bytes and Bundle::chunk_index refuse it, and verify_inline_sections still verifies and counts it",
        },
        unknown_optional_bundle()?,
        Expectation::ParsesUnknownOptional { name_id: 1 },
    ));

    Ok(cases)
}

fn case(meta: Meta, bytes: Vec<u8>, expect: Expectation) -> Case {
    Case {
        name: meta.name,
        file: meta.file,
        kind: meta.kind,
        hardening: meta.hardening,
        rules: meta.rules,
        matrix_row: meta.matrix_row,
        proves: meta.proves,
        bytes,
        expect,
    }
}

fn read_fixture(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    let path = root.join(rel);
    std::fs::read(&path).map_err(|e| format!("cannot read fixture {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

/// Apply a mutation that does not touch the header or section table.
fn mutated(base: &[u8], mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = base.to_vec();
    mutate(&mut bytes);
    bytes
}

/// Apply a mutation that changes the header or section table, then recompute the
/// commitment root so the fixture differs from the golden only in the rule under
/// test.
fn committed(base: &[u8], mutate: impl FnOnce(&mut Vec<u8>)) -> Result<Vec<u8>, String> {
    let mut bytes = mutated(base, mutate);
    refresh_commitment(&mut bytes)?;
    Ok(bytes)
}

/// Recompute `BLAKE3("ctf/root/v1" ‖ header ‖ table)` and store it in the footer.
fn refresh_commitment(file: &mut [u8]) -> Result<(), String> {
    let header = Header::parse(file).map_err(|e| format!("cannot re-commit: header: {e}"))?;
    refresh_commitment_at(
        file,
        header.section_table_off,
        header.section_table_count,
        header.footer_off,
    )
}

/// Same, at layout offsets known from a header that is no longer parseable (an
/// invented `feat_incompat` bit makes `Header::parse` fail by design).
fn refresh_commitment_at(
    file: &mut [u8],
    table_off: u64,
    count: u32,
    footer_off: u64,
) -> Result<(), String> {
    let start = usize::try_from(table_off).map_err(|_| "table offset does not fit usize")?;
    let len = (count as usize)
        .checked_mul(SECTION_RECORD_LEN)
        .ok_or_else(|| "table length overflow".to_string())?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "table end overflow".to_string())?;
    let header = file
        .get(..HEADER_LEN as usize)
        .ok_or_else(|| "file is shorter than the header".to_string())?;
    let table = file
        .get(start..end)
        .ok_or_else(|| "file is shorter than its section table".to_string())?;
    let root = commitment_root(header, table);
    let foff = usize::try_from(footer_off).map_err(|_| "footer offset does not fit usize")?;
    let fend = foff
        .checked_add(32)
        .ok_or_else(|| "footer root end overflow".to_string())?;
    file.get_mut(foff..fend)
        .ok_or_else(|| "file is shorter than its footer root".to_string())?
        .copy_from_slice(&root);
    Ok(())
}

/// Replace an inline section's plaintext in place, updating the record's `root`
/// and the footer commitment.
///
/// The replacement must be the same length: a fixture is a mutation of a golden,
/// so the layout is fixed. A fixture that needed a different length would be a
/// second writer, which the corpus deliberately is not.
fn replace_plaintext(base: &[u8], name_id: u16, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let bundle = Bundle::parse(base).map_err(|e| format!("base bundle does not parse: {e}"))?;
    let index = bundle
        .sections
        .iter()
        .position(|r| r.name_id == name_id)
        .ok_or_else(|| format!("base bundle has no section {name_id}"))?;
    let record = *bundle
        .sections
        .get(index)
        .ok_or_else(|| format!("base bundle has no section {name_id}"))?;
    if record.enc != ctf_format::Encryption::None || record.comp != ctf_format::Compression::None {
        return Err(format!(
            "section {name_id} is transformed; same-length replacement is not possible"
        ));
    }
    if record.len_stored != plaintext.len() as u64 {
        return Err(format!(
            "replacement for section {name_id} is {} bytes, expected {}",
            plaintext.len(),
            record.len_stored
        ));
    }
    let start = usize::try_from(record.offset)
        .map_err(|_| format!("section {name_id} offset does not fit usize"))?;
    let end = start
        .checked_add(plaintext.len())
        .ok_or_else(|| "replacement range overflow".to_string())?;
    let mut file = base.to_vec();
    file.get_mut(start..end)
        .ok_or_else(|| format!("section {name_id} range is outside the file"))?
        .copy_from_slice(plaintext);

    let suite = ctf_format::suite(bundle.header.suite_id)
        .map_err(|e| format!("suite {}: {e}", bundle.header.suite_id))?;
    let root = suite.hash().hash(plaintext);
    let table_off = usize::try_from(bundle.header.section_table_off)
        .map_err(|_| "table offset does not fit usize".to_string())?;
    let rec_off = table_off
        .checked_add(index * SECTION_RECORD_LEN)
        .ok_or_else(|| "record offset overflow".to_string())?;
    let root_off = rec_off
        .checked_add(REC_ROOT)
        .ok_or_else(|| "record root offset overflow".to_string())?;
    file.get_mut(root_off..root_off + 32)
        .ok_or_else(|| "record root is outside the file".to_string())?
        .copy_from_slice(&root);
    refresh_commitment(&mut file)?;
    Ok(file)
}

fn replace_manifest(base: &[u8], manifest: &[u8]) -> Result<Vec<u8>, String> {
    replace_plaintext(base, 0, manifest)
}

fn manifest_payload_offset(base: &[u8]) -> Result<usize, String> {
    let bundle = Bundle::parse(base).map_err(|e| format!("base bundle does not parse: {e}"))?;
    let record = bundle
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .ok_or_else(|| "base bundle has no manifest".to_string())?;
    usize::try_from(record.offset).map_err(|_| "manifest offset does not fit usize".to_string())
}

/// A 62-byte manifest value nested 17 containers deep: one CborTooDeep violation,
/// with no trailing bytes and no other CBOR rule broken.
fn nested_manifest() -> Vec<u8> {
    let mut v = vec![0x81; 17];
    v.push(0x78);
    v.push(43);
    v.extend_from_slice(&[b'x'; 43]);
    v
}

/// A 62-byte manifest whose `names` value declares an array of `u64::MAX`
/// elements. The last byte is one valid (empty-array) element; decoding then
/// runs out of input. No other required key is disturbed.
fn huge_length_manifest() -> Vec<u8> {
    let mut v = vec![0xa4, 0x62, b'i', b'd', 0x6e];
    v.extend_from_slice(b"whos-that-bird");
    v.extend_from_slice(&[0x64]);
    v.extend_from_slice(b"name");
    v.push(0x6f);
    v.extend_from_slice(b"Who's That Bird");
    v.extend_from_slice(&[0x64]);
    v.extend_from_slice(b"spec");
    v.push(0x01);
    v.push(0x65);
    v.extend_from_slice(b"names");
    v.push(0x9b);
    v.extend_from_slice(&[0xff; 8]);
    v.push(0x80);
    v
}

/// A 62-byte manifest with every required key present and one adjacent duplicate
/// `spec` key. Only M1g can fire.
fn duplicate_key_manifest() -> Vec<u8> {
    let mut v = vec![0xa5, 0x62, b'i', b'd', 0x68];
    v.extend_from_slice(b"dup-id00");
    v.extend_from_slice(&[0x64]);
    v.extend_from_slice(b"name");
    v.push(0x6f);
    v.extend_from_slice(b"Who's That Bird");
    v.extend_from_slice(&[0x64]);
    v.extend_from_slice(b"spec");
    v.push(0x01);
    v.extend_from_slice(&[0x64]);
    v.extend_from_slice(b"spec");
    v.push(0x02);
    v.push(0x65);
    v.extend_from_slice(b"names");
    v.push(0x81);
    v.push(0x68);
    v.extend_from_slice(b"manifest");
    v
}

/// The minimal golden's manifest with the 8-byte `names[0]` entry replaced.
fn manifest_with_name(name: &[u8]) -> Result<Vec<u8>, String> {
    let root = fixtures_root();
    let minimal = read_fixture(&root, "golden/minimal.ctf")?;
    let bundle = Bundle::parse(&minimal).map_err(|e| format!("golden/minimal.ctf: {e}"))?;
    let record = bundle
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .ok_or_else(|| "golden/minimal.ctf has no manifest".to_string())?;
    let start = usize::try_from(record.offset)
        .map_err(|_| "manifest offset does not fit usize".to_string())?;
    let end = start.checked_add(usize::try_from(record.len_stored).map_err(|_| "manifest length")?);
    let mut manifest = minimal
        .get(start..end.ok_or_else(|| "manifest end overflow".to_string())?)
        .ok_or_else(|| "manifest range is outside the golden".to_string())?
        .to_vec();
    if !manifest.ends_with(b"manifest") {
        return Err("the golden manifest does not end with the 8-byte name to replace".into());
    }
    let name_off = manifest
        .len()
        .checked_sub(8)
        .ok_or_else(|| "manifest too short".to_string())?;
    if name.len() != 8 {
        return Err(format!(
            "replacement name must be 8 bytes, got {}",
            name.len()
        ));
    }
    manifest
        .get_mut(name_off..)
        .ok_or_else(|| "name range is outside the manifest".to_string())?
        .copy_from_slice(name);
    Ok(manifest)
}

/// A valid bundle with one compressed artifact section, used as the base for the
/// D1/D2 vectors. The writer builds the compressed frame and its root; the fixtures
/// then mutate only the declared `len_plain`.
fn compressed_section_bundle() -> Result<Vec<u8>, String> {
    let manifest = Manifest::minimal("compressed-cap", "Compressed Cap", &["manifest", "data"])
        .map_err(|e| format!("compressed manifest: {e}"))?
        .encode()
        .map_err(|e| format!("compressed manifest encoding: {e}"))?;
    let payload = vec![b'A'; 8192];
    write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &payload,
            )
            .compressed(),
        ],
    )
    .map_err(|e| format!("compressed base bundle: {e}"))
}

/// A valid bundle with one `OPTIONAL` section of an undefined kind. The writer can
/// emit this because §15 assigns future skippable kinds by number; the reader must
/// carry it and never serve it.
fn unknown_optional_bundle() -> Result<Vec<u8>, String> {
    let manifest = Manifest::minimal(
        "from-the-future",
        "From The Future",
        &["manifest", "mystery"],
    )
    .map_err(|e| format!("future manifest: {e}"))?
    .encode()
    .map_err(|e| format!("future manifest encoding: {e}"))?;
    let payload = vec![0x77; 9000];
    let kind = SectionKind::unknown(9).ok_or_else(|| "kind 9 must be a future kind".to_string())?;
    write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                kind,
                1,
                SectionFlags(SectionFlags::OPTIONAL | SectionFlags::PLAYER_VISIBLE),
                &payload,
            )
            .chunked(4096),
        ],
    )
    .map_err(|e| format!("future optional bundle: {e}"))
}

fn truncate(b: &[u8], n: usize) -> Vec<u8> {
    b.iter().take(n).copied().collect()
}

/// Rebuild an unsigned golden's footer with a forged 1-byte signature pair.
///
/// The result satisfies F1–F9 exactly: the footer is `56 + 1 + 1` bytes, both
/// lengths are non-zero and agree with the file length, the commitment root is
/// untouched, and the trailer is the real one. The only rule left to fire is F10 —
/// suite 1's slots are 64 and 3309 bytes (§20.3), so a footer claiming one byte
/// each is not a suite-1 file.
fn forged_signature_lengths(base: &[u8]) -> Result<Vec<u8>, String> {
    let header = Header::parse(base).map_err(|e| format!("base header: {e}"))?;
    let footer_off = usize::try_from(header.footer_off).map_err(|_| "footer offset".to_string())?;
    let root = base
        .get(footer_off..footer_off + 32)
        .ok_or_else(|| "base footer is shorter than its root".to_string())?;
    let mut out = base
        .get(..footer_off)
        .ok_or_else(|| "base is shorter than its footer".to_string())?
        .to_vec();
    out.extend_from_slice(root);
    out.extend_from_slice(&1u32.to_le_bytes()); // sig_classical_len
    out.extend_from_slice(&1u32.to_le_bytes()); // sig_pq_len
    out.extend_from_slice(&[0, 0]); // the two forged slots
    // `total_len` and the magic are the trailer, so the declared length includes
    // both (F5/F7): it is the file length, not the length written so far.
    let total_len = u64::try_from(out.len() + 16).map_err(|_| "bundle too large".to_string())?;
    out.extend_from_slice(&total_len.to_le_bytes());
    out.extend_from_slice(&MAGIC);
    Ok(out)
}

fn flip(b: &mut [u8], off: usize) {
    if let Some(x) = b.get_mut(off) {
        *x ^= 1;
    }
}

fn set_u8(b: &mut [u8], off: usize, v: u8) {
    if let Some(dst) = b.get_mut(off) {
        *dst = v;
    }
}

fn set_u16(b: &mut [u8], off: usize, v: u16) {
    if let Some(dst) = b.get_mut(off..off + 2) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

fn set_u32(b: &mut [u8], off: usize, v: u32) {
    if let Some(dst) = b.get_mut(off..off + 4) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

fn set_u64(b: &mut [u8], off: usize, v: u64) {
    if let Some(dst) = b.get_mut(off..off + 8) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// The committed index and the maintenance mode
// ---------------------------------------------------------------------------

/// Render `corpus.json` from a catalog.
///
/// The index is generated from the same [`Case`] list that produces the fixtures,
/// so the machine-readable description cannot drift from the bytes.
pub fn corpus_json(cases: &[Case]) -> Result<String, String> {
    let vectors: Vec<serde_json::Value> = cases
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "file": c.file,
                "kind": c.kind.as_str(),
                "hardening": c.hardening,
                "rules": c.rules,
                "matrix_row": c.matrix_row,
                "proves": c.proves,
                "expectation": expectation_json(c.expect),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "format": "ctf-conformance-corpus/1",
        "generated_by": "cargo run -p ctf-conformance -- --emit spec/vectors/conformance",
        "goldens": ["golden/minimal.ctf", "golden/demo.ctf"],
        "not_file_shaped": not_file_shaped_json(),
        "vectors": vectors,
    });
    let mut text = serde_json::to_string_pretty(&doc)
        .map_err(|e| format!("cannot serialize corpus.json: {e}"))?;
    text.push('\n');
    Ok(text)
}

fn expectation_json(expect: Expectation) -> serde_json::Value {
    match expect {
        Expectation::Parses => serde_json::json!({ "kind": "parses" }),
        Expectation::ParsesReadOnly => serde_json::json!({ "kind": "parses_read_only" }),
        Expectation::ParsesUnknownOptional { name_id } => {
            serde_json::json!({ "kind": "parses_unknown_optional", "name_id": name_id })
        }
        Expectation::Rejects => serde_json::json!({ "kind": "rejects" }),
        Expectation::Error(error) => {
            serde_json::json!({ "kind": "error", "error": error })
        }
        Expectation::RejectsOnServe { name_id } => {
            serde_json::json!({ "kind": "rejects_on_serve", "name_id": name_id })
        }
        Expectation::ServeError { name_id, error } => serde_json::json!({
            "kind": "serve_error",
            "name_id": name_id,
            "error": error,
        }),
        Expectation::RejectsChunkIndex { name_id } => {
            serde_json::json!({ "kind": "rejects_chunk_index", "name_id": name_id })
        }
        Expectation::ChunkIndexError { name_id, error } => serde_json::json!({
            "kind": "chunk_index_error",
            "name_id": name_id,
            "error": error,
        }),
    }
}

fn not_file_shaped_json() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "hardening": 10,
            "reason": "Fuzzing is a property of a test run, not of a byte string: the oracle is no panic, no OOM, and round-trip stability over arbitrary input. All six targets and their committed seed corpora are covered by fuzz/fuzz_targets/*, the stable-toolchain mirror in tests/fuzzmirror.rs, and tests/mutation.rs; no single fixture can assert it. The entitlement-chain target landed in 0.13.0 (#107).",
        }),
        serde_json::json!({
            "hardening": 11,
            "reason": "An independent second implementation is source code, not a file: the check is that a reader written from spec/SPEC.md alone round-trips every vector. `go/` is that implementation (0.13.0, #53) and runs this same corpus; the row is kept here because a fixture cannot be the check.",
        }),
    ]
}

/// Regenerate the committed corpus under `dir` from the committed goldens.
///
/// Returns the number of fixture files written. The goldens themselves are inputs
/// and are not rewritten; `corpus.json` is written from the same catalog.
pub fn emit(dir: &Path) -> Result<usize, String> {
    let cases = catalog()?;
    let mut written = 0usize;
    for case in &cases {
        if case.kind == VectorKind::Golden {
            continue;
        }
        let path = dir.join(case.file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &case.bytes)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        written += 1;
    }
    let index = dir.join("corpus.json");
    std::fs::write(&index, corpus_json(&cases)?)
        .map_err(|e| format!("cannot write {}: {e}", index.display()))?;
    Ok(written)
}

/// The hardening bullets named by the committed index, split into those covered by
/// a fixture and those recorded as not file-shaped.
///
/// Exposed for the coverage test, which compares these against the §14 table in
/// `docs/HARDENING-AUDIT.md`.
pub fn hardening_coverage(cases: &[Case]) -> (BTreeSet<u32>, BTreeSet<u32>) {
    let covered: BTreeSet<u32> = cases
        .iter()
        .flat_map(|c| c.hardening.iter().copied())
        .collect();
    let not_file_shaped: BTreeSet<u32> = not_file_shaped_json()
        .iter()
        .filter_map(|v| v.get("hardening").and_then(serde_json::Value::as_u64))
        .filter_map(|n| u32::try_from(n).ok())
        .collect();
    (covered, not_file_shaped)
}
