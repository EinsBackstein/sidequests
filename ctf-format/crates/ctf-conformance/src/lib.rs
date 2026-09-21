//! Conformance vector runner (roadmap phase 8).
//!
//! Two kinds of vector live under `spec/vectors/conformance/golden/`:
//!
//! - **Golden bundles** — committed, known-good `.ctf` files. Each must parse,
//!   the footer commitment must verify, and every inline section must hash to its
//!   record's `root`.
//! - **Hostile inputs** — deterministic, one-field mutations of a golden. Each
//!   must fail with the exact [`ctf_format::Error`] variant the format text
//!   promises, and the runner checks that no earlier rule fired instead.
//!
//! The runner is deliberately thin. It calls [`Bundle::parse`] and
//! [`Bundle::verify_inline_sections`] and compares what comes back against the
//! vector's expectation; it re-implements no container rule, so a vector passing
//! is evidence about the reference implementation rather than about the runner.
//!
//! A failure names the vector and the observed result, which is what makes the
//! output usable in CI: `FAIL non-zero-padding: expected error PaddingNotZero,
//! observed ReservedNotZero { at: "section" }` says both what was wanted and what
//! actually happened.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ctf_format::{
    Bundle, HEADER_LEN, Header, Manifest, SECTION_RECORD_LEN, SectionFlags, SectionKind,
    SectionSpec, footer::commitment_root, write_bundle,
};

/// Fixtures live under the workspace `spec/` tree, relative to this crate's
/// manifest directory (`crates/ctf-conformance`).
const FIXTURE_REL: &str = "../../spec/vectors/conformance";

/// Section-record field offsets, mirrored from `ctf_format::section` so a hostile
/// mutation can name the field it changes rather than a magic number.
const REC_KIND: usize = 0;
const REC_NAME_ID: usize = 2;
const REC_FLAGS: usize = 4;
const REC_ENC: usize = 6;
const REC_OFFSET: usize = 8;
const REC_CHUNK_SIZE: usize = 32;
const REC_CHUNK_INDEX_OFF: usize = 40;

/// Header field offsets.
const HDR_FEAT_INCOMPAT: usize = 40;
const HDR_RESERVED: usize = 48;

/// What a vector asserts about the reference reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// [`Bundle::parse`] must succeed, the footer commitment must re-verify against
    /// the file's own header and table bytes, and [`Bundle::verify_inline_sections`]
    /// must report no mismatches.
    Parses,
    /// [`Bundle::parse`] must fail with an error whose [`std::fmt::Debug`] name
    /// starts with this string — the variant name, e.g. `"PaddingNotZero"`.
    Error(&'static str),
}

/// Whether a vector is a known-good bundle or a deliberately hostile mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorKind {
    /// A committed valid bundle, expected to parse.
    Golden,
    /// A mutation expected to be rejected with a named error.
    Hostile,
}

/// One conformance vector: a name, the bytes, and what parsing them must do.
#[derive(Debug, Clone)]
pub struct Vector {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expectation,
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

/// Run every committed vector.
///
/// A missing fixture is reported as a single failing outcome rather than a panic:
/// a runner that cannot even read its inputs should still say so in the same
/// shape as every other failure.
pub fn run() -> Report {
    match load_vectors() {
        Ok(vectors) => run_vectors(vectors),
        Err(detail) => Report {
            outcomes: vec![Outcome {
                name: "fixtures",
                kind: VectorKind::Golden,
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

fn evaluate(v: Vector) -> Outcome {
    let kind = match v.expect {
        Expectation::Parses => VectorKind::Golden,
        Expectation::Error(_) => VectorKind::Hostile,
    };
    match v.expect {
        Expectation::Parses => evaluate_parses(v.name, kind, &v.bytes),
        Expectation::Error(expected) => evaluate_error(v.name, kind, &v.bytes, expected),
    }
}

fn evaluate_parses(name: &'static str, kind: VectorKind, bytes: &[u8]) -> Outcome {
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
    Outcome {
        name,
        kind,
        passed: true,
        detail,
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
// Fixtures and mutations
// ---------------------------------------------------------------------------

fn read_fixture(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    let path = root.join(rel);
    std::fs::read(&path).map_err(|e| format!("cannot read fixture {}: {e}", path.display()))
}

fn load_vectors() -> Result<Vec<Vector>, String> {
    let root = fixtures_root();
    let minimal = read_fixture(&root, "golden/minimal.ctf")?;
    let demo = read_fixture(&root, "golden/demo.ctf")?;

    let mh =
        Header::parse(&minimal).map_err(|e| format!("golden/minimal.ctf does not parse: {e}"))?;
    let dh = Header::parse(&demo).map_err(|e| format!("golden/demo.ctf does not parse: {e}"))?;
    let mrec = |i: usize| mh.section_table_off as usize + i * SECTION_RECORD_LEN;
    let drec = |i: usize| dh.section_table_off as usize + i * SECTION_RECORD_LEN;

    let mut vectors = Vec::new();

    // Golden bundles.
    vectors.push(Vector {
        name: "golden-minimal",
        bytes: minimal.clone(),
        expect: Expectation::Parses,
    });
    vectors.push(Vector {
        name: "golden-demo",
        bytes: demo.clone(),
        expect: Expectation::Parses,
    });

    // Container rules: magic, footer, truncation, trailing data, padding.
    vectors.push(hostile("bad-magic", &minimal, |b| flip(b, 0), "BadMagic"));
    vectors.push(hostile(
        "bad-footer-magic",
        &minimal,
        |b| {
            let last = b.len().saturating_sub(1);
            flip(b, last);
        },
        "BadMagic",
    ));
    vectors.push(Vector {
        name: "truncated-body",
        bytes: truncate(&minimal, 1000),
        expect: Expectation::Error("ExceedsFile"),
    });
    vectors.push(Vector {
        name: "truncated-footer",
        bytes: truncate(&minimal, minimal.len() - 1),
        expect: Expectation::Error("Truncated"),
    });
    vectors.push(hostile(
        "trailing-bytes-after-footer",
        &minimal,
        |b| b.push(0),
        "BadFooterLen",
    ));
    vectors.push(hostile(
        "wrong-total-len",
        &minimal,
        |b| {
            let n = b.len();
            set_u64(b, n - 16, n as u64 + 1);
        },
        "BadTotalLen",
    ));
    vectors.push(hostile(
        "non-zero-padding",
        &minimal,
        |b| flip(b, 64),
        "PaddingNotZero",
    ));

    // Table and record rules reachable by one field each.
    vectors.push(hostile(
        "duplicate-name-id",
        &demo,
        |b| set_u16(b, drec(1) + REC_NAME_ID, 0),
        "DuplicateSectionName",
    ));
    vectors.push(hostile(
        "misaligned-section-offset",
        &minimal,
        |b| set_u64(b, mrec(0) + REC_OFFSET, 4097),
        "Misaligned",
    ));
    vectors.push(hostile(
        "out-of-range-section-offset",
        &minimal,
        |b| set_u64(b, mrec(0) + REC_OFFSET, 8192),
        "ExceedsFile",
    ));

    // Header and record hardening (H- and R-rules).
    vectors.push(hostile(
        "unsupported-incompat-feature",
        &minimal,
        |b| set_u32(b, HDR_FEAT_INCOMPAT, 0x8000_0000),
        "UnsupportedFeature",
    ));
    vectors.push(hostile(
        "unknown-section-flag-bits",
        &minimal,
        |b| set_u16(b, mrec(0) + REC_FLAGS, 0x0080),
        "UnknownFlagBits",
    ));
    vectors.push(hostile(
        "reserved-non-zero",
        &minimal,
        |b| set_u8(b, HDR_RESERVED, 1),
        "ReservedNotZero",
    ));
    vectors.push(hostile(
        "unknown-section-kind",
        &minimal,
        |b| set_u16(b, mrec(0) + REC_KIND, 0),
        "InvalidSectionKind",
    ));
    vectors.push(hostile(
        "unknown-enc-discriminant",
        &minimal,
        |b| set_u8(b, mrec(0) + REC_ENC, 2),
        "UnknownDiscriminant",
    ));

    // Chunk-index rules. `demo.ctf` is the golden that carries an index (section
    // 1, `len_plain = 9600`, `chunk_size = 4096`, three entries at 17792).
    //
    // C1–C7 are *on-use* rules (§9.3, §10): `Bundle::parse` never reads the index,
    // so the parse-reachable mutations are structural. Raising `chunk_size` shrinks
    // the derived `ceil(len_plain / chunk_size) × 32` index and leaves the old tail
    // unclaimed, which T8 catches as non-zero padding — the trailing bytes of a
    // now-too-short index. Moving `chunk_index_off` so the derived region runs into
    // the table is the overlap rule.
    vectors.push(hostile(
        "chunk-index-trailing-bytes",
        &demo,
        |b| set_u32(b, drec(1) + REC_CHUNK_SIZE, 8192),
        "PaddingNotZero",
    ));
    vectors.push(hostile(
        "chunk-index-overlaps-table",
        &demo,
        |b| {
            let overlap = dh.section_table_off.saturating_sub(32);
            set_u64(b, drec(1) + REC_CHUNK_INDEX_OFF, overlap);
        },
        "OverlapsSectionTable",
    ));

    Ok(vectors)
}

/// Build a hostile vector by copying `base` and applying one mutation.
fn hostile(
    name: &'static str,
    base: &[u8],
    mutate: impl FnOnce(&mut Vec<u8>),
    expected: &'static str,
) -> Vector {
    let mut bytes = base.to_vec();
    mutate(&mut bytes);
    Vector {
        name,
        bytes,
        expect: Expectation::Error(expected),
    }
}

fn truncate(b: &[u8], n: usize) -> Vec<u8> {
    b.iter().take(n).copied().collect()
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
