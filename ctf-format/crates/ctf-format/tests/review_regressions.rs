//! Regression tests for tickets 85 and 81 (GitHub issues #86 and #82).
//!
//! These pin behaviour that the fixes landed but that no test could previously
//! distinguish from the bug, so a future change cannot silently reintroduce it.
//!
//! - **Ticket 85** — `write_bundle` used to hash a chunked inline payload twice
//!   (`blake3::hash(bytes)` for the record root, then a second pass building the
//!   chunk index). It now builds the index first and takes `root` from
//!   `root_from_cvs`, so the two views of the payload are the *same* value. The
//!   tests here assert both views equal `blake3::hash(plaintext)`, which is the
//!   property that diverges if one path is changed while the other is not.
//! - **Ticket 81** — a section-root mismatch now carries the offending
//!   `name_id` (`Error::SectionRootMismatch`) and the verify pass reports *every*
//!   mismatch in `VerifyReport::mismatches` instead of aborting on the first.
//!
//! Fixtures follow the house style: a deterministic filler with no short period,
//! and mutations that touch exactly one thing so a failure names the rule that
//! broke.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Bundle, Error, Manifest, SectionFlags, SectionKind, SectionSpec,
    chunk::{ChunkIndex, chunk_count, root_from_cvs},
    write_bundle,
};

const SUITE: u16 = 1;

/// Deterministic filler with no short period.
///
/// `(i * 31) as u8` repeats every 256 bytes, which is exactly the trap the chunk
/// tests document: every 4096-byte chunk becomes byte-identical and a swapped
/// chunk passes because it genuinely is the same bytes. An XOF stream has no
/// period worth worrying about.
fn plaintext(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    blake3::Hasher::new()
        .update(b"ctf-format review regression filler")
        .finalize_xof()
        .fill(&mut v);
    v
}

/// A bundle with a manifest and one chunked artifact at `name_id` 1 carrying
/// `data`.
fn bundle_with_chunked_artifact(data: &[u8], chunk_size: u32) -> Vec<u8> {
    let manifest = Manifest::minimal("chal", "Chal", &["manifest", "blob"])
        .unwrap()
        .encode()
        .unwrap();
    write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                data,
            )
            .chunked(chunk_size),
        ],
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Ticket 85 — the record root and the chunk index must agree
// ---------------------------------------------------------------------------

/// The record `root` the writer emits for a chunked inline section is
/// `blake3::hash(plaintext)`, and the plaintext read back through the serving
/// path hashes to that same root.
///
/// This is the second bullet of ticket 85. It walks several chunk sizes and
/// payload shapes (exact multiples, and short final chunks) so the check cannot
/// be an accident of one shape.
#[test]
fn chunked_inline_record_root_is_blake3_of_the_plaintext() {
    for cs in [4096u32, 65536] {
        for chunks in [2usize, 3, 5] {
            // A short final chunk: exactly `cs * chunks - 7` bytes.
            let data = plaintext(cs as usize * chunks - 7);
            let file = bundle_with_chunked_artifact(&data, cs);
            let b = Bundle::parse(&file).unwrap();
            let record = *b.section(1).unwrap();

            let expected = *blake3::hash(&data).as_bytes();
            assert_eq!(
                record.root, expected,
                "record root for {chunks} × {cs}-byte chunks must be BLAKE3(plaintext)"
            );
            assert_eq!(record.chunk_size, cs);
            assert_ne!(
                record.chunk_index_off, 0,
                "a multi-chunk section must carry an index"
            );

            // Read the section back through the verified serving path; its root is
            // checked against the record there, and the bytes must be the original.
            let served = b.section_bytes(&record).unwrap();
            assert_eq!(served.as_ref(), data.as_slice());
            assert_eq!(*blake3::hash(&served).as_bytes(), record.root);
        }
    }
}

/// The writer's record `root` and the writer's chunk index describe the same
/// bytes, and both agree with an independently built index.
///
/// This is the first bullet of ticket 85, and the regression detector. The bug
/// was hashing the payload twice — once for `root` and once to build the index.
/// `Bundle::chunk_index` reduces the *stored* index to the record root, so if a
/// future writer hashed twice and the two paths diverged, that call would fail
/// here; the explicit equality checks below name which view drifted.
#[test]
fn chunked_inline_index_reduces_to_the_record_root() {
    for cs in [4096u32, 65536] {
        for chunks in [2usize, 3, 5] {
            let data = plaintext(cs as usize * chunks - 7);
            let file = bundle_with_chunked_artifact(&data, cs);
            let b = Bundle::parse(&file).unwrap();
            let record = *b.section(1).unwrap();

            // Path A: the index the writer actually emitted, verified against the
            // root in the table (which the footer commits to).
            let stored = b.chunk_index(&record).unwrap().unwrap();
            assert_eq!(
                stored.entries().len() as u64,
                chunk_count(record.len_plain, record.chunk_size).unwrap()
            );
            assert_eq!(
                root_from_cvs(stored.entries()),
                Some(record.root),
                "the stored index must reduce to the record root"
            );

            // Path B: an index built independently from the same plaintext. Both
            // must be the same entries, and both must reduce to `blake3::hash`.
            let rebuilt = ChunkIndex::build(&data, cs).unwrap();
            assert_eq!(rebuilt.entries(), stored.entries());
            assert_eq!(root_from_cvs(rebuilt.entries()), Some(record.root));
            assert_eq!(Some(*blake3::hash(&data).as_bytes()), Some(record.root));
        }
    }
}

// ---------------------------------------------------------------------------
// Ticket 81 — the mismatch error names the section, and the pass lists all
// ---------------------------------------------------------------------------

/// A section-root mismatch names the offending section by `name_id`, and never
/// echoes the section's name — a string that came from the (attacker-
/// controllable) manifest.
#[test]
fn section_root_mismatch_error_names_the_section_by_number_only() {
    // The error value itself carries only a number, so the Display cannot leak
    // text. Pin the exact rendering so it cannot grow a text field unnoticed.
    assert_eq!(
        Error::SectionRootMismatch { name_id: 1234 }.to_string(),
        "BLAKE3 root mismatch for section 1234"
    );

    // Drive a real mismatch. The section's name is distinctive so the assertion
    // that it is absent is meaningful.
    let data = plaintext(96);
    let manifest = Manifest::minimal("chal", "Chal", &["manifest", "secret-payload"])
        .unwrap()
        .encode()
        .unwrap();
    let mut file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &data,
            ),
        ],
    )
    .unwrap();

    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    let off = record.offset as usize;
    drop(b);
    // Flip one byte of the payload; the header, table, and commitment are
    // untouched, so the file still opens and only the section root disagrees.
    file[off] ^= 1;

    let b = Bundle::parse(&file).unwrap();
    let err = b.section_bytes(&record).unwrap_err();
    assert_eq!(err, Error::SectionRootMismatch { name_id: 1 });
    let msg = err.to_string();
    assert!(
        msg.contains("section 1"),
        "the diagnostic lost the id: {msg}"
    );
    assert!(
        !msg.contains("secret-payload"),
        "the diagnostic echoed the section name: {msg}"
    );
}

/// Two inline sections whose stored bytes do not match their record roots produce
/// a report listing **both** `name_id`s, in table order — not just the first.
///
/// One section is plain and one is chunked, so the "do not abort" behaviour is
/// exercised for both the direct-hash path and the index-bearing path. The file
/// still `Bundle::parse`s because flipping payload bytes moves neither the header
/// nor the table, and the commitment covers only those; the manifest is left
/// intact because `parse` verifies it eagerly.
#[test]
fn verify_report_lists_every_mismatched_section_not_just_the_first() {
    let manifest = Manifest::minimal("many", "Many", &["manifest", "plain", "chunked"])
        .unwrap()
        .encode()
        .unwrap();
    let plain = plaintext(96);
    let chunked = plaintext(4096 * 2 + 7);
    let mut file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &plain,
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                2,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &chunked,
            )
            .chunked(4096),
        ],
    )
    .unwrap();

    let b = Bundle::parse(&file).unwrap();
    let (plain_off, chunked_off) = (
        b.section(1).unwrap().offset as usize,
        b.section(2).unwrap().offset as usize,
    );
    drop(b);
    file[plain_off] ^= 1;
    file[chunked_off] ^= 1;

    let b = Bundle::parse(&file).unwrap();
    // Individually, each section's error names it.
    let plain_record = *b.section(1).unwrap();
    let chunked_record = *b.section(2).unwrap();
    assert!(matches!(
        b.section_bytes(&plain_record),
        Err(Error::SectionRootMismatch { name_id: 1 })
    ));
    assert!(matches!(
        b.section_bytes(&chunked_record),
        Err(Error::SectionRootMismatch { name_id: 2 })
    ));

    // The pass reports both, in table order. Aborting on the first would leave
    // only `[1]`.
    let report = b.verify_inline_sections().unwrap();
    assert_eq!(report.verified, 1, "only the manifest still matches");
    assert_eq!(
        report.mismatches,
        vec![1, 2],
        "every mismatch must be listed, not just the first"
    );
    assert!(report.mismatches.contains(&1));
    assert!(report.mismatches.contains(&2));
}
