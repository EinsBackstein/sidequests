//! Container tests: round-trips, the golden vector, and one case per hostile-input
//! rule in design §14.
//!
//! Every rejection test mutates a *known-good* structure by exactly one field, so a
//! failure names the rule that broke rather than "something is wrong".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Compression, Encryption, Error, HEADER_LEN, Header, MAGIC, MAX_SECTIONS, SECTION_RECORD_LEN,
    SectionFlags, SectionKind, SectionRecord, section,
};

const PAYLOAD_OFF: u64 = 4096;
const PAYLOAD_LEN: u64 = 100;
const TABLE_OFF: u64 = 8192;
const FOOTER_OFF: u64 = TABLE_OFF + SECTION_RECORD_LEN as u64; // 8320
const FILE_LEN: u64 = 8448;

/// The smallest valid bundle: an OSINT challenge, manifest only.
fn good_header() -> Header {
    Header {
        version_major: 0,
        version_minor: 2,
        suite_id: 1,
        flags: 0,
        section_table_count: 1,
        section_table_off: TABLE_OFF,
        footer_off: FOOTER_OFF,
        feat_incompat: 0,
        feat_ro_compat: 0,
    }
}

fn good_manifest_record() -> SectionRecord {
    SectionRecord {
        kind: SectionKind::Manifest,
        name_id: 0,
        flags: SectionFlags::empty(),
        enc: Encryption::None,
        comp: Compression::None,
        offset: PAYLOAD_OFF,
        len_stored: PAYLOAD_LEN,
        len_plain: PAYLOAD_LEN,
        chunk_size: 0,
        chunk_index_off: 0,
        root: [0xab; 32],
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#[test]
fn header_round_trips() {
    let h = good_header();
    assert_eq!(Header::parse(&h.to_bytes()).unwrap(), h);
}

/// Phase 0's definition of done: a hand-written byte sequence the parser must
/// accept and reproduce exactly. Any change here is a format break, so this test
/// failing is the intended alarm, not an inconvenience.
#[test]
fn header_golden_vector() {
    let expected: [u8; 64] = [
        // magic: PNG construction with CTF as the tag
        0x89, b'C', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a, //
        0x00, 0x00, // version_major = 0
        0x02, 0x00, // version_minor = 2
        0x40, 0x00, 0x00, 0x00, // header_len = 64
        0x01, 0x00, // suite_id = 1
        0x00, 0x00, // flags = 0
        0x01, 0x00, 0x00, 0x00, // section_table_count = 1
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section_table_off = 8192
        0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // footer_off = 8320
        0x00, 0x00, 0x00, 0x00, // feat_incompat = 0
        0x00, 0x00, 0x00, 0x00, // feat_ro_compat = 0
        // 16 reserved bytes, all zero
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(good_header().to_bytes(), expected);
    assert_eq!(Header::parse(&expected).unwrap(), good_header());
}

/// Backward compatibility, proven rather than claimed: the exact bytes of the 0.1
/// golden header must keep parsing forever. 0.1 wrote zeros where 0.2 reads its two
/// feature words, which is why the version could grow without moving a field.
#[test]
fn header_golden_vector_v0_1() {
    let v0_1: [u8; 64] = [
        0x89, b'C', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a, //
        0x00, 0x00, // version_major = 0
        0x01, 0x00, // version_minor = 1
        0x40, 0x00, 0x00, 0x00, // header_len = 64
        0x01, 0x00, // suite_id = 1
        0x00, 0x00, // flags = 0
        0x01, 0x00, 0x00, 0x00, // section_table_count = 1
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section_table_off = 8192
        0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // footer_off = 8320
        // 24 bytes that 0.1 called reserved
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let h = Header::parse(&v0_1).unwrap();
    assert_eq!(h.version_minor, 1);
    assert_eq!((h.feat_incompat, h.feat_ro_compat), (0, 0));
    assert!(h.may_rewrite());
    // Identical to the 0.2 fixture in every field that describes the layout.
    assert_eq!(h.section_table_off, good_header().section_table_off);
    assert_eq!(h.footer_off, good_header().footer_off);
}

#[test]
fn header_rejects_bad_magic() {
    let mut b = good_header().to_bytes();
    b[0] = 0x88;
    assert!(matches!(Header::parse(&b), Err(Error::BadMagic { .. })));
}

/// A text-mode transfer that eats the high bit or rewrites CRLF must be caught by
/// the signature, which is the whole reason for PNG's construction.
#[test]
fn header_magic_catches_transfer_mangling() {
    let mut stripped = good_header().to_bytes();
    stripped[0] = MAGIC[0] & 0x7f;
    assert!(matches!(
        Header::parse(&stripped),
        Err(Error::BadMagic { .. })
    ));

    let mut crlf_eaten = good_header().to_bytes();
    crlf_eaten[4] = 0x0a; // \r\n collapsed to \n
    assert!(matches!(
        Header::parse(&crlf_eaten),
        Err(Error::BadMagic { .. })
    ));
}

#[test]
fn header_rejects_truncated() {
    let b = good_header().to_bytes();
    for n in 0..HEADER_LEN as usize {
        assert!(
            matches!(Header::parse(&b[..n]), Err(Error::Truncated { .. })),
            "length {n} should be truncated"
        );
    }
}

#[test]
fn header_rejects_nonzero_reserved() {
    for off in [48, 63] {
        let mut b = good_header().to_bytes();
        b[off] = 1;
        assert!(
            matches!(Header::parse(&b), Err(Error::ReservedNotZero { .. })),
            "reserved byte {off} should be rejected"
        );
    }
}

/// A file that needs a capability this build lacks must be refused outright: the
/// reader would otherwise be guessing at bytes whose meaning changed.
#[test]
fn header_rejects_unsupported_incompat_feature() {
    let mut h = good_header();
    h.feat_incompat = 1 << 7;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::UnsupportedFeature {
            class: "incompat",
            bits
        }) if bits == 1 << 7
    ));
}

/// The other half of the bargain: an unknown read-only-compatible feature leaves the
/// file readable, because nothing this reader already understands has changed. Only
/// rewriting is unsafe, and that is what `may_rewrite` reports.
#[test]
fn header_accepts_unsupported_ro_compat_feature_as_read_only() {
    let mut h = good_header();
    h.feat_ro_compat = 1 << 3;
    let parsed = Header::parse(&h.to_bytes()).unwrap();
    assert_eq!(parsed.feat_ro_compat, 1 << 3);
    assert!(!parsed.may_rewrite());
    assert!(good_header().may_rewrite());
}

/// Feature negotiation must happen *before* the reserved-zero check, or a future
/// file reports the confusing error instead of the accurate one. This pins that
/// order: bytes 40–47 are features, 48–63 are still reserved.
#[test]
fn header_feature_words_are_checked_before_reserved() {
    // Bit 31 of `feat_incompat`. This version assigns no `incompat` bit at all —
    // `CONTAINER_V1` lives in `feat_ro_compat`, precisely so that a 0.2 reader can
    // still read a 0.3 file — so any bit here is unimplemented.
    let mut b = good_header().to_bytes();
    b[43] = 0x80;
    b[48] = 1;
    assert!(matches!(
        Header::parse(&b),
        Err(Error::UnsupportedFeature { .. })
    ));

    let mut b = good_header().to_bytes();
    b[48] = 1;
    assert!(matches!(
        Header::parse(&b),
        Err(Error::ReservedNotZero { .. })
    ));
}

#[test]
fn header_rejects_unknown_flags() {
    let mut h = good_header();
    h.flags = 0x0001;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::UnknownFlagBits { .. })
    ));
}

#[test]
fn header_rejects_unsupported_major() {
    let mut b = good_header().to_bytes();
    b[8] = 9;
    assert!(matches!(
        Header::parse(&b),
        Err(Error::UnsupportedVersion { major: 9, .. })
    ));
}

#[test]
fn header_rejects_bad_header_len() {
    let mut b = good_header().to_bytes();
    b[12] = 0x80;
    assert!(matches!(Header::parse(&b), Err(Error::BadHeaderLen { .. })));
}

/// The allocation-from-a-length-field rule: the cap is checked at parse time, so a
/// caller never gets a count it could turn into a huge `Vec`.
#[test]
fn header_rejects_section_count_over_cap() {
    let mut h = good_header();
    h.section_table_count = MAX_SECTIONS + 1;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::TooManySections { .. })
    ));
}

#[test]
fn header_rejects_table_inside_header() {
    let mut h = good_header();
    h.section_table_off = 32;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::BadOffset { .. })
    ));
}

#[test]
fn header_rejects_misaligned_table() {
    let mut h = good_header();
    h.section_table_off = TABLE_OFF + 1;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::Misaligned { .. })
    ));
}

#[test]
fn header_rejects_footer_before_table_end() {
    let mut h = good_header();
    h.footer_off = TABLE_OFF + 8;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::BadOffset { .. })
    ));
}

#[test]
fn header_rejects_table_overflowing_u64() {
    let mut h = good_header();
    // Must stay 8-byte aligned, or the alignment check fires before the overflow
    // check and the test proves the wrong thing.
    h.section_table_off = u64::MAX - 7;
    h.section_table_count = 4;
    assert!(matches!(
        Header::parse(&h.to_bytes()),
        Err(Error::LengthOverflow { .. })
    ));
}

#[test]
fn header_check_file_len_rejects_short_file() {
    let h = good_header();
    assert!(h.check_file_len(FILE_LEN).is_ok());
    assert!(matches!(
        h.check_file_len(TABLE_OFF + 4),
        Err(Error::ExceedsFile { .. })
    ));
}

// ---------------------------------------------------------------------------
// Section records
// ---------------------------------------------------------------------------

#[test]
fn record_round_trips() {
    let r = good_manifest_record();
    assert_eq!(SectionRecord::parse(&r.to_bytes()).unwrap(), r);
}

/// The second half of phase 0's definition of done: the record layout pinned to
/// exact bytes, mirrored in `spec/SPEC.md` §5.7. Any change here is a format break.
#[test]
fn record_golden_vector() {
    let expected: [u8; SECTION_RECORD_LEN] = [
        0x01, 0x00, // kind = manifest
        0x00, 0x00, // name_id = 0
        0x00, 0x00, // flags = 0
        0x00, // enc = none
        0x00, // comp = none
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset = 4096
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // len_stored = 100
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // len_plain = 100
        0x00, 0x00, 0x00, 0x00, // chunk_size = 0
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // chunk_index_off = 0
        // root: 32 bytes
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, // 48 reserved bytes, all zero
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(good_manifest_record().to_bytes(), expected);
    assert_eq!(
        SectionRecord::parse(&expected).unwrap(),
        good_manifest_record()
    );
}

#[test]
fn record_round_trips_sealed_chunked_artifact() {
    let r = SectionRecord {
        kind: SectionKind::Writeup,
        name_id: 7,
        flags: SectionFlags(SectionFlags::SEALED),
        enc: Encryption::AeadStream,
        comp: Compression::Zstd,
        offset: PAYLOAD_OFF,
        len_stored: 9000,
        // Spans three chunks. R19 rejects an index of fewer than two entries, so a
        // fixture carrying `chunk_index_off` has to be big enough to need one.
        len_plain: (2 << 20) + 12345,
        chunk_size: 1 << 20,
        chunk_index_off: 8192,
        root: [0x11; 32],
    };
    assert_eq!(SectionRecord::parse(&r.to_bytes()).unwrap(), r);
}

/// A zero-filled record must not read as a plausible manifest section. Kind 0
/// being invalid is what buys that.
#[test]
fn record_rejects_all_zero() {
    let b = [0u8; SECTION_RECORD_LEN];
    assert!(matches!(
        SectionRecord::parse(&b),
        Err(Error::InvalidSectionKind { got: 0 })
    ));
}

#[test]
fn record_rejects_truncated() {
    let b = good_manifest_record().to_bytes();
    assert!(matches!(
        SectionRecord::parse(&b[..SECTION_RECORD_LEN - 1]),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn record_rejects_nonzero_reserved() {
    for off in [36, 127] {
        let mut b = good_manifest_record().to_bytes();
        b[off] = 1;
        assert!(
            matches!(SectionRecord::parse(&b), Err(Error::ReservedNotZero { .. })),
            "reserved byte {off} should be rejected"
        );
    }
}

#[test]
fn record_rejects_unknown_flag_bits() {
    let mut r = good_manifest_record();
    r.flags = SectionFlags(1 << 5);
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::UnknownFlagBits { .. })
    ));
}

/// The invariant that stops the failure mode design §4 calls primary: a sealed
/// section can never be eligible for serving to players.
#[test]
fn record_rejects_sealed_and_player_visible() {
    let mut r = good_manifest_record();
    r.kind = SectionKind::Artifact;
    r.flags = SectionFlags(SectionFlags::SEALED | SectionFlags::PLAYER_VISIBLE);
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Inconsistent { .. })
    ));
}

/// An author who forgets to seal a writeup should be stopped by the format, not by
/// remembering to check.
#[test]
fn record_rejects_unsealed_writeup_and_solver() {
    for kind in [
        SectionKind::Writeup,
        SectionKind::Solver,
        SectionKind::Progress,
    ] {
        let mut r = good_manifest_record();
        r.kind = kind;
        r.flags = SectionFlags::empty();
        assert!(
            matches!(
                SectionRecord::parse(&r.to_bytes()),
                Err(Error::Inconsistent { .. })
            ),
            "{kind:?} must be rejected when not sealed"
        );
    }
}

#[test]
fn record_rejects_player_visible_or_sealed_manifest() {
    for bad in [
        SectionFlags::PLAYER_VISIBLE,
        SectionFlags::SEALED,
        SectionFlags::EXTERNAL,
    ] {
        let mut r = good_manifest_record();
        r.flags = SectionFlags(bad);
        assert!(
            matches!(
                SectionRecord::parse(&r.to_bytes()),
                Err(Error::Inconsistent { .. })
            ),
            "manifest with flag {bad:#x} must be rejected"
        );
    }
}

#[test]
fn record_rejects_external_carrying_inline_bytes() {
    let mut r = good_manifest_record();
    r.kind = SectionKind::Artifact;
    r.flags = SectionFlags(SectionFlags::EXTERNAL);
    // offset and len_stored still set from the inline record
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Inconsistent { .. })
    ));
}

#[test]
fn record_accepts_external_with_zeroed_storage() {
    let r = SectionRecord {
        kind: SectionKind::Artifact,
        name_id: 3,
        flags: SectionFlags(SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE),
        enc: Encryption::None,
        comp: Compression::None,
        offset: 0,
        len_stored: 0,
        len_plain: 41_231_986_688, // the 40 GB forensics image from design §5
        chunk_size: 1 << 20,
        chunk_index_off: 0,
        root: [0x22; 32],
    };
    assert_eq!(SectionRecord::parse(&r.to_bytes()).unwrap(), r);
}

#[test]
fn record_rejects_misaligned_payload_offset() {
    let mut r = good_manifest_record();
    r.offset = PAYLOAD_OFF + 8;
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Misaligned { .. })
    ));
}

#[test]
fn record_rejects_payload_inside_header() {
    let mut r = good_manifest_record();
    r.offset = 0;
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::BadOffset { .. })
    ));
}

#[test]
fn record_rejects_range_overflow() {
    let mut r = good_manifest_record();
    r.offset = PAYLOAD_OFF;
    r.len_stored = u64::MAX;
    r.len_plain = u64::MAX;
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::LengthOverflow { .. })
    ));
}

/// Without compression or encryption there is only one length. Letting the two
/// disagree would let a writer park bytes outside the commitment.
#[test]
fn record_rejects_length_mismatch_when_plain() {
    let mut r = good_manifest_record();
    r.len_plain = PAYLOAD_LEN + 1;
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Inconsistent { .. })
    ));
}

#[test]
fn record_rejects_bad_chunk_size() {
    for bad in [1u32, 3000, (1 << 20) + 1, 128 * 1024 * 1024] {
        let mut r = good_manifest_record();
        r.chunk_size = bad;
        assert!(
            matches!(
                SectionRecord::parse(&r.to_bytes()),
                Err(Error::BadChunkSize { .. })
            ),
            "chunk_size {bad} must be rejected"
        );
    }
}

#[test]
fn record_rejects_stream_without_chunks() {
    let mut r = good_manifest_record();
    r.kind = SectionKind::Artifact;
    r.enc = Encryption::AeadStream;
    r.chunk_size = 0;
    r.len_plain = PAYLOAD_LEN + 16; // plausible AEAD expansion
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Inconsistent { .. })
    ));
}

#[test]
fn record_rejects_chunk_index_without_chunks() {
    let mut r = good_manifest_record();
    r.chunk_index_off = 8192;
    assert!(matches!(
        SectionRecord::parse(&r.to_bytes()),
        Err(Error::Inconsistent { .. })
    ));
}

/// Forward compatibility for section kinds: a writer that marks a future kind
/// OPTIONAL promises that skipping it cannot change the meaning of the rest, so an
/// old reader carries it instead of refusing the file.
#[test]
fn record_accepts_unknown_kind_when_optional() {
    let mut r = good_manifest_record();
    r.kind = SectionKind::unknown(9).unwrap();
    r.name_id = 4;
    r.flags = SectionFlags(SectionFlags::OPTIONAL);
    let parsed = SectionRecord::parse(&r.to_bytes()).unwrap();
    assert_eq!(parsed.kind, SectionKind::unknown(9).unwrap());
    assert!(!parsed.kind.is_known());
    let SectionKind::Unknown(future) = parsed.kind else {
        panic!("expected an unknown kind")
    };
    assert_eq!(future.get(), 9);
    // Round-trips byte-for-byte, which is what lets a tool carry a section it does
    // not understand without corrupting the commitment.
    assert_eq!(parsed.to_bytes(), r.to_bytes());
}

/// Without the promise, an unknown kind is still a hard reject. Silently ignoring
/// it is exactly the parser-differential this format refuses everywhere else.
#[test]
fn record_rejects_unknown_kind_without_optional() {
    let mut b = good_manifest_record().to_bytes();
    b[0] = 9; // kind = 9, flags left at 0
    assert!(matches!(
        SectionRecord::parse(&b),
        Err(Error::InvalidSectionKind { got: 9 })
    ));
}

/// OPTIONAL on a *known* kind must stay legal, or the mechanism breaks the moment a
/// formerly-unknown kind becomes known: files written in between have to remain
/// valid.
#[test]
fn record_accepts_optional_on_known_kind() {
    let mut r = good_manifest_record();
    r.flags = SectionFlags(SectionFlags::OPTIONAL);
    assert_eq!(SectionRecord::parse(&r.to_bytes()).unwrap(), r);
}

/// The `Unknown` invariant from the constructor side: a kind this version defines
/// can never be wrapped as a future one. Without this, `SectionKind::Unknown(1)`
/// would be spellable and would serialize as `kind = 1` — a section silently
/// claiming to be the manifest. `FutureKind`'s private field is what makes the
/// invalid pairing unwritable rather than merely undesirable.
#[test]
fn unknown_kind_constructor_rejects_known_discriminants() {
    for known in 0..=8u16 {
        assert!(
            SectionKind::unknown(known).is_none(),
            "kind {known} is defined by this version and must not wrap as Unknown"
        );
    }
    assert_eq!(SectionKind::unknown(9).unwrap().to_u16(), 9);
    assert_eq!(SectionKind::unknown(u16::MAX).unwrap().to_u16(), u16::MAX);
}

/// The same invariant from the parsing side: a known discriminant always yields its
/// named variant, so `to_u16` can never turn an `Unknown` back into a known kind.
#[test]
fn parse_never_yields_unknown_for_a_known_kind() {
    for k in 1..=8u16 {
        let mut b = good_manifest_record().to_bytes();
        b[0] = k as u8;
        b[4] = SectionFlags::OPTIONAL as u8;
        // Sealed-only kinds reject here; that is a different rule and not this test.
        if let Ok(rec) = SectionRecord::parse(&b) {
            assert!(rec.kind.is_known(), "kind {k} must not parse as Unknown");
            assert_eq!(rec.kind.to_u16(), k);
        }
    }
}

#[test]
fn record_rejects_unknown_enc_and_comp() {
    for off in [6usize, 7] {
        let mut b = good_manifest_record().to_bytes();
        b[off] = 42;
        assert!(
            matches!(
                SectionRecord::parse(&b),
                Err(Error::UnknownDiscriminant { .. })
            ),
            "byte {off} = 42 must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Table and layout
// ---------------------------------------------------------------------------

#[test]
fn table_round_trips() {
    let recs = [good_manifest_record()];
    let mut bytes = Vec::new();
    for r in &recs {
        bytes.extend_from_slice(&r.to_bytes());
    }
    assert_eq!(section::parse_table(&bytes, 1).unwrap(), recs);
}

#[test]
fn table_rejects_truncated() {
    let bytes = good_manifest_record().to_bytes();
    assert!(matches!(
        section::parse_table(&bytes, 2),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn layout_accepts_minimal_bundle() {
    let recs = [good_manifest_record()];
    section::validate_layout(&recs, &good_header(), FILE_LEN).unwrap();
}

#[test]
fn layout_rejects_missing_manifest() {
    let mut r = good_manifest_record();
    r.kind = SectionKind::Artifact;
    assert!(matches!(
        section::validate_layout(&[r], &good_header(), FILE_LEN),
        Err(Error::ManifestCount { got: 0 })
    ));
}

#[test]
fn layout_rejects_two_manifests() {
    let a = good_manifest_record();
    let mut b = good_manifest_record();
    b.name_id = 1;
    b.offset = PAYLOAD_OFF + 4096;
    let mut h = good_header();
    h.section_table_count = 2;
    h.footer_off = TABLE_OFF + 2 * SECTION_RECORD_LEN as u64;
    assert!(matches!(
        section::validate_layout(&[a, b], &h, FILE_LEN),
        Err(Error::ManifestCount { got: 2 })
    ));
}

#[test]
fn layout_rejects_duplicate_name_id() {
    let a = good_manifest_record();
    let mut b = good_manifest_record();
    b.kind = SectionKind::Artifact;
    b.offset = PAYLOAD_OFF + 4096;
    // name_id left at 0, colliding with the manifest
    let mut h = good_header();
    h.section_table_count = 2;
    h.footer_off = TABLE_OFF + 2 * SECTION_RECORD_LEN as u64;
    assert!(matches!(
        section::validate_layout(&[a, b], &h, FILE_LEN),
        Err(Error::DuplicateSectionName { name_id: 0 })
    ));
}

/// Two sections sharing bytes is the ambiguity that becomes a parser-differential
/// exploit, so it is a hard reject rather than a warning.
#[test]
fn layout_rejects_overlapping_payloads() {
    let a = good_manifest_record();
    let mut b = good_manifest_record();
    b.kind = SectionKind::Artifact;
    b.name_id = 1;
    b.offset = PAYLOAD_OFF; // same page as the manifest
    b.len_stored = 4096;
    b.len_plain = 4096;
    let mut h = good_header();
    h.section_table_count = 2;
    h.footer_off = TABLE_OFF + 2 * SECTION_RECORD_LEN as u64;
    assert!(matches!(
        section::validate_layout(&[a, b], &h, FILE_LEN),
        Err(Error::OverlappingSections { .. })
    ));
}

/// A payload may not be laid over the section table either.
#[test]
fn layout_rejects_payload_overlapping_table() {
    let mut r = good_manifest_record();
    // Sits exactly on the table. Kept inside `footer_off` on purpose: a payload
    // past the footer is rejected by the outer bounds check first, which would
    // pass this test without ever exercising overlap detection.
    r.offset = TABLE_OFF;
    r.len_stored = SECTION_RECORD_LEN as u64;
    r.len_plain = SECTION_RECORD_LEN as u64;
    assert!(matches!(
        section::validate_layout(&[r], &good_header(), FILE_LEN),
        Err(Error::OverlapsSectionTable { name_id: 0 })
    ));
}

/// A section this reader cannot interpret is still real, committed bytes: it takes
/// part in bounds and overlap checking like any other, because "skip it" means "do
/// not interpret it", never "pretend it is not there".
#[test]
fn layout_checks_unknown_optional_sections_like_any_other() {
    let manifest = good_manifest_record();
    let mut future = good_manifest_record();
    future.kind = SectionKind::unknown(9).unwrap();
    future.name_id = 1;
    future.flags = SectionFlags(SectionFlags::OPTIONAL);
    future.offset = TABLE_OFF; // laid over the section table
    let mut h = good_header();
    h.section_table_count = 2;
    h.footer_off = TABLE_OFF + 2 * SECTION_RECORD_LEN as u64;
    assert!(matches!(
        section::validate_layout(&[manifest, future], &h, FILE_LEN),
        Err(Error::OverlapsSectionTable { name_id: 1 })
    ));
}

#[test]
fn layout_rejects_payload_past_footer() {
    let mut r = good_manifest_record();
    r.len_stored = 8192;
    r.len_plain = 8192;
    assert!(matches!(
        section::validate_layout(&[r], &good_header(), FILE_LEN),
        Err(Error::ExceedsFile { .. })
    ));
}

#[test]
fn layout_accepts_external_section_regardless_of_size() {
    let manifest = good_manifest_record();
    let huge = SectionRecord {
        kind: SectionKind::Artifact,
        name_id: 1,
        flags: SectionFlags(SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE),
        enc: Encryption::None,
        comp: Compression::None,
        offset: 0,
        len_stored: 0,
        len_plain: 41_231_986_688,
        chunk_size: 1 << 20,
        chunk_index_off: 0,
        root: [0x22; 32],
    };
    let mut h = good_header();
    h.section_table_count = 2;
    h.footer_off = TABLE_OFF + 2 * SECTION_RECORD_LEN as u64;
    section::validate_layout(&[manifest, huge], &h, FILE_LEN).unwrap();
}
