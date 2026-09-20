//! Whole-file tests: the footer, the manifest, and the commitment that ties them
//! to the header and section table.
//!
//! Every rejection test mutates a known-good file by exactly one byte or one field,
//! so a failure names the rule that broke.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Bundle, Error, FEAT_RO_COMPAT_CONTAINER_V1, Footer, HEADER_LEN, Header, MAGIC, Manifest,
    Payload, RuleSet, SECTION_RECORD_LEN, SectionFlags, SectionKind, SectionRecord, SectionSpec,
    Signing,
    cbor::Value,
    chunk::ChunkIndex,
    footer::{MAX_SIG_LEN, MIN_FOOTER_LEN, commitment_root, sig_input},
    section, write_bundle,
};

const SUITE: u16 = 1;

fn minimal_manifest() -> Manifest {
    Manifest::minimal("whos-that-bird", "Who's That Bird", &["manifest"]).unwrap()
}

/// The smallest thing that is a bundle: an OSINT challenge with no artifacts.
/// Design §5 calls this the minimum viable challenge, and R6 is measured on it.
fn minimal_bundle() -> Vec<u8> {
    let m = minimal_manifest().encode().unwrap();
    write_bundle(
        SUITE,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m,
        )],
    )
    .unwrap()
}

fn artifact_bundle() -> Vec<u8> {
    let manifest = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("baby-rop".into())),
            (Value::Text("name".into()), Value::Text("Baby ROP".into())),
            (Value::Text("category".into()), Value::Text("pwn".into())),
            (
                Value::Text("names".into()),
                Value::Array(vec![
                    Value::Text("manifest".into()),
                    Value::Text("chal".into()),
                ]),
            ),
        ])
        .encode()
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let artifact = vec![0x42u8; 5000];
    write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &artifact,
            )
            .chunked(4096),
        ],
    )
    .unwrap()
}

/// Mark the section at table index `i` as AEAD-STREAM encrypted, and repair the
/// commitment root so the file still opens.
///
/// The phase 1 writer cannot emit `enc != 0`, deliberately — it has no crypto — so a
/// bundle carrying an inline payload this build cannot read has to be built by hand.
/// Re-rooting is the whole trick: changing a record changes the table, which changes
/// `BLAKE3("ctf/root/v1" ‖ header ‖ table)`, so without this the file would fail on
/// the commitment and never reach the code under test.
///
/// Only legal on a section with a non-zero `chunk_size` (R-rule: STREAM is defined
/// over a chunk sequence), which is why callers pass an artifact built by
/// `artifact_bundle`.
fn mark_encrypted(file: &mut [u8], i: usize) {
    let header = Header::parse(file).unwrap();
    let table = header.section_table_off as usize;
    file[table + i * SECTION_RECORD_LEN + 6] = 1; // OFF_ENC, Encryption::AeadStream
    let root = commitment_root(
        &file[..HEADER_LEN as usize],
        &file[table..table + header.section_table_count as usize * SECTION_RECORD_LEN],
    );
    let footer = header.footer_off as usize;
    file[footer..footer + 32].copy_from_slice(&root);
}

/// Make the section at table index `i` `SEALED` **and** `AEAD-STREAM`, re-rooting the
/// commitment so the file still opens. R21 requires the pair, so a sealed section
/// the phase-1 writer cannot emit has to be built by hand.
fn mark_sealed_encrypted(file: &mut [u8], i: usize) {
    let header = Header::parse(file).unwrap();
    let table = header.section_table_off as usize;
    let at = table + i * SECTION_RECORD_LEN;
    // Replace the flags outright: R5 forbids SEALED together with PLAYER_VISIBLE.
    file[at + 4..at + 6].copy_from_slice(&SectionFlags::SEALED.to_le_bytes());
    file[at + 6] = 1; // OFF_ENC, Encryption::AeadStream
    let root = commitment_root(
        &file[..HEADER_LEN as usize],
        &file[table..table + header.section_table_count as usize * SECTION_RECORD_LEN],
    );
    let footer = header.footer_off as usize;
    file[footer..footer + 32].copy_from_slice(&root);
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn minimal_bundle_round_trips() {
    let file = minimal_bundle();
    let b = Bundle::parse(&file).unwrap();
    assert_eq!(b.header.version_minor, 3);
    assert_eq!(b.header.suite_id, SUITE);
    assert_eq!(b.sections.len(), 1);
    assert_eq!(b.manifest.id(), "whos-that-bird");
    assert_eq!(b.manifest.name(), "Who's That Bird");
    assert_eq!(b.manifest.name_of(0), Some("manifest"));
    assert_eq!(b.footer.total_len, file.len() as u64);
    assert_eq!(b.verify_inline_sections().unwrap().verified, 1);
}

/// The full-file golden vector, reproduced in spec §11.
///
/// Every byte of the minimal bundle, region by region; the gaps between regions are
/// zero padding. Any change here is a format break — this is the vector the
/// independent Go implementation (design §13) has to reproduce from the spec text
/// alone, so it pins the manifest's canonical key order and the commitment
/// construction as much as it pins the layout.
#[test]
fn minimal_bundle_golden_vector() {
    let file = minimal_bundle();
    assert_eq!(file.len(), 4344);

    #[rustfmt::skip]
    let header: [u8; 64] = [
        0x89, 0x43, 0x54, 0x46, 0x0d, 0x0a, 0x1a, 0x0a,  0x00, 0x00, 0x03, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(&file[..64], &header);

    // Canonical CBOR, keys in encoded-byte order: "id", "name", "spec", "names".
    let manifest: &[u8] = b"\xa4\x62id\x6ewhos-that-bird\x64name\x6fWho's That Bird\x64spec\x01\x65names\x81\x68manifest";
    assert_eq!(manifest.len(), 62);
    assert_eq!(&file[4096..4096 + 62], manifest);
    assert!(
        file[64..4096].iter().all(|&b| b == 0),
        "padding must be zero"
    );
    assert!(file[4158..4160].iter().all(|&b| b == 0));

    #[rustfmt::skip]
    let record: [u8; 128] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xae, 0x64, 0x30, 0xd8, 0x61, 0x29, 0xf6, 0x3b,  0x5a, 0xe6, 0x39, 0x4c, 0x7f, 0xb9, 0x93, 0x17,
        0x1b, 0x54, 0x79, 0xa8, 0x7f, 0xe6, 0x1d, 0x0a,  0xbf, 0x64, 0x3d, 0x55, 0x09, 0x7d, 0x5e, 0x34,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(&file[4160..4288], &record);
    // The record's `root` is BLAKE3 of the manifest plaintext, nothing else.
    assert_eq!(&record[48..80], blake3::hash(manifest).as_bytes());

    #[rustfmt::skip]
    let footer: [u8; 56] = [
        0x20, 0xe7, 0xbc, 0x2b, 0xfd, 0x39, 0x64, 0x51,  0xe6, 0x59, 0x68, 0x16, 0x1d, 0x6a, 0xce, 0xe9,
        0x49, 0x39, 0x44, 0xd8, 0xb8, 0xf1, 0x0c, 0x68,  0x0c, 0x2f, 0x43, 0xd2, 0x07, 0xa0, 0x57, 0xbb,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0xf8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x43, 0x54, 0x46, 0x0d, 0x0a, 0x1a, 0x0a,
    ];
    assert_eq!(&file[4288..], &footer);
    assert_eq!(
        blake3::hash(&file).to_hex().as_str(),
        "e4411ccb6b947f9bc4978299213c795ddf9680e56303f8196e69651365b07fae"
    );
}

/// **Forward compatibility.** A 0.2 reader meeting a 0.3 file reads it and refuses
/// to rewrite it. `CONTAINER_V1` lives in `feat_ro_compat` for exactly this reason,
/// and this test is what stops it drifting back into `feat_incompat`.
///
/// Simulated by masking off the bit this build implements, which is precisely what a
/// 0.2 reader's `SUPPORTED_RO_COMPAT` of zero does. Everything a 0.2 reader checks
/// still holds — R19, R20, T6 and T7 only narrow, so a valid 0.3 file satisfies the
/// looser 0.2 rules too — and the file's own bytes are untouched, so this is the
/// real file, not a mutated one.
#[test]
fn a_0_2_reader_can_read_a_0_3_file_but_not_rewrite_it() {
    let file = minimal_bundle();
    let h = Header::parse(&file).unwrap();

    // This build knows the bit, so it may rewrite.
    assert_eq!(h.feat_ro_compat, FEAT_RO_COMPAT_CONTAINER_V1);
    assert_eq!(h.feat_incompat, 0, "no incompat bit — 0.2 must not reject");
    assert!(h.may_rewrite());

    // A 0.2 reader implements no ro_compat bits. Same predicate, empty mask.
    let supported_by_0_2: u32 = 0;
    assert!(
        h.feat_ro_compat & !supported_by_0_2 != 0,
        "a 0.2 reader must see this file as read-only"
    );
    // And nothing in `feat_incompat` for it to trip over: H14 is what would have
    // made the file unreadable, and it is empty.
    assert_eq!(h.feat_incompat & !supported_by_0_2, 0);

    // The header and section table — everything 0.2 defines — parse in full.
    let (start, end) = h.table_range().unwrap();
    let records =
        section::parse_table(&file[start as usize..end as usize], h.section_table_count).unwrap();
    section::validate_layout(&records, &h, &file).unwrap();
}

/// **Backward compatibility.** A 0.2 file has no footer, no manifest schema, and a
/// chunk index of undefined length, because 0.2 §10.2 forbade inventing any of them.
/// A 0.3 reader reads everything such a file actually defines, and says by name that
/// there is no container to read rather than failing somewhere structural.
#[test]
fn a_0_3_reader_reads_a_0_2_file_and_names_what_is_missing() {
    let mut file = minimal_bundle();
    // Clear the bit, exactly as a 0.2 writer left it.
    file[44..48].copy_from_slice(&0u32.to_le_bytes());

    let h = Header::parse(&file).unwrap();
    assert!(h.may_rewrite(), "no unknown ro_compat bit is set");
    // The rules a file is entitled to be read under come from its own header, never
    // from the reader's preference.
    assert_eq!(RuleSet::of(&h), RuleSet::Legacy);
    let (start, end) = h.table_range().unwrap();
    let records = section::parse_table_with(
        &file[start as usize..end as usize],
        h.section_table_count,
        RuleSet::of(&h),
    )
    .unwrap();
    section::validate_layout(&records, &h, &file).unwrap();

    // Only the whole-container read needs a container. Note the direction: the bit
    // is one this build implements and the *file* lacks it, so this is
    // `FeatureRequired`, not H14's `UnsupportedFeature`.
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::FeatureRequired {
            class: "ro_compat",
            bits: FEAT_RO_COMPAT_CONTAINER_V1
        })
    ));
}

/// A `feat_incompat` bit this build does not implement makes the file unreadable,
/// and the reader says which bit rather than reporting structural nonsense about a
/// layout it was never meant to parse.
#[test]
fn a_file_requiring_an_unknown_feature_is_refused_by_name() {
    let mut file = minimal_bundle();
    file[40..44].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::UnsupportedFeature {
            class: "incompat",
            bits: 0x8000_0000
        })
    ));
    assert!(matches!(
        Header::parse(&file),
        Err(Error::UnsupportedFeature { .. })
    ));
}

/// An unimplemented `ro_compat` bit leaves the file readable and unrewritable. The
/// commitment covers the header, so setting the bit also breaks the root; the point
/// here is which check fires and that `may_rewrite` reports correctly.
#[test]
fn an_unknown_ro_compat_bit_is_readable_but_not_rewritable() {
    let mut file = minimal_bundle();
    file[44..48].copy_from_slice(&(FEAT_RO_COMPAT_CONTAINER_V1 | 0x8000_0000).to_le_bytes());
    let h = Header::parse(&file).unwrap();
    assert!(!h.may_rewrite());
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::RootMismatch {
            at: "commitment root"
        })
    ));
}

/// A parse establishes structure and integrity, never authenticity. There is
/// deliberately no API that says otherwise.
#[test]
fn a_written_bundle_is_unsigned() {
    let file = minimal_bundle();
    let b = Bundle::parse(&file).unwrap();
    assert_eq!(b.signing(), Signing::Unsigned);
    assert!(b.footer.sig_classical.is_empty());
    assert!(b.footer.sig_pq.is_empty());
}

#[test]
fn artifact_bundle_round_trips_with_a_chunk_index() {
    let file = artifact_bundle();
    let b = Bundle::parse(&file).unwrap();
    let artifact = b.section(1).unwrap();
    assert_eq!(artifact.len_plain, 5000);
    assert_eq!(artifact.chunk_size, 4096);
    assert_ne!(artifact.chunk_index_off, 0);

    let index = b.chunk_index(artifact).unwrap().unwrap();
    assert_eq!(index.entries().len(), 2);
    assert_eq!(index.chunk_size(), 4096);
    let bytes = b.section_bytes(artifact).unwrap();
    assert_eq!(bytes.len(), 5000);
    index.verify_chunk(0, &bytes[..4096]).unwrap();
    index.verify_chunk(1, &bytes[4096..]).unwrap();
}

/// The manifest section is the only one whose root is checked during `parse`;
/// everything else is checked on access, so opening a bundle does not hash its
/// payloads.
#[test]
fn section_bytes_are_verified_before_they_are_returned() {
    let mut file = artifact_bundle();
    let b = Bundle::parse(&file).unwrap();
    let off = b.section(1).unwrap().offset as usize;
    drop(b);
    file[off] ^= 1;
    // The bundle still opens: the commitment covers the header and table, not the
    // payload bytes, and the payload's own root is what catches this.
    let b = Bundle::parse(&file).unwrap();
    let artifact = *b.section(1).unwrap();
    assert!(matches!(
        b.section_bytes(&artifact),
        Err(Error::RootMismatch { at: "section" })
    ));
    assert!(b.verify_inline_sections().is_err());
}

// ---------------------------------------------------------------------------
// The commitment
// ---------------------------------------------------------------------------

/// Hashing the header is what makes the feature words unstrippable: an attacker who
/// clears the bit that tells an old reader to refuse a file must also forge the
/// root.
#[test]
fn a_flipped_header_byte_breaks_the_commitment() {
    for off in [16usize, 20, 24, 32, 40, 44] {
        let mut file = minimal_bundle();
        file[off] ^= 1;
        let err = Bundle::parse(&file).unwrap_err();
        assert!(
            !matches!(err, Error::RootMismatch { at: "section" }),
            "header offset {off} produced {err}"
        );
    }
}

#[test]
fn a_flipped_section_table_byte_breaks_the_commitment() {
    let file = minimal_bundle();
    let table_off = Header::parse(&file).unwrap().section_table_off as usize;
    // Offset 48 in the record is `root`: changing it is exactly the substitution
    // the commitment exists to catch.
    let mut tampered = file.clone();
    tampered[table_off + 48] ^= 1;
    assert!(matches!(
        Bundle::parse(&tampered),
        Err(Error::RootMismatch {
            at: "commitment root"
        })
    ));
}

#[test]
fn commitment_root_is_the_documented_construction() {
    let file = minimal_bundle();
    let h = Header::parse(&file).unwrap();
    let (start, end) = h.table_range().unwrap();
    let mut expect = blake3::Hasher::new();
    expect.update(b"ctf/root/v1");
    expect.update(&file[..HEADER_LEN as usize]);
    expect.update(&file[start as usize..end as usize]);
    assert_eq!(
        commitment_root(
            &file[..HEADER_LEN as usize],
            &file[start as usize..end as usize]
        ),
        *expect.finalize().as_bytes()
    );
    assert_eq!(
        Bundle::parse(&file).unwrap().footer.root,
        *expect.finalize().as_bytes()
    );
}

/// The transcript is fixed by design §6 and both signatures cover it identically.
/// Phase 1 cannot sign, but it can pin the bytes phase 2 will sign.
///
/// v2 binds the two signature-slot lengths. F3–F5 leave the split between the two
/// slots free, and §8.1 locates the slots from those fields, so without this the
/// same bytes could be read with two different slot boundaries.
#[test]
fn signature_transcript_is_the_documented_construction() {
    let root = [0xab; 32];
    let t = sig_input(1, 64, 3309, &root, 8448);
    assert_eq!(&t[..17], b"ctf/footer-sig/v2");
    assert_eq!(&t[17..19], &1u16.to_le_bytes());
    assert_eq!(&t[19..23], &64u32.to_le_bytes());
    assert_eq!(&t[23..27], &3309u32.to_le_bytes());
    assert_eq!(&t[27..59], &root);
    assert_eq!(&t[59..67], &8448u64.to_le_bytes());
    assert_eq!(t.len(), 67);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

/// Data appended after a valid container, sitting outside the commitment while
/// leaving the file parseable, is the ambiguity behind a long line of
/// archive-format CVEs. The footer runs to the end of the file, so appending makes
/// it longer than its own contents imply — which is the rule that closes it.
#[test]
fn rejects_trailing_bytes() {
    let mut file = minimal_bundle();
    file.push(0);
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::BadFooterLen {
            got: 57,
            want: MIN_FOOTER_LEN
        })
    ));
}

#[test]
fn rejects_truncation_after_the_footer() {
    let mut file = minimal_bundle();
    file.pop();
    // 55 bytes is below the smallest legal footer, so this stops before the length
    // rule rather than at it.
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::Truncated { need: 56, got: 55 })
    ));
}

/// `total_len` on its own, with the file's real length untouched. The only rule
/// violated, so the diagnostic can be exact (spec §2.1).
#[test]
fn rejects_a_wrong_total_len() {
    let mut file = minimal_bundle();
    let n = file.len();
    file[n - 16..n - 8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
    assert!(matches!(
        Bundle::parse(&file),
        Err(Error::BadTotalLen { .. })
    ));
}

/// Slack inside the footer would be bytes belonging to no structure and covered by
/// no commitment — the trailing-byte problem moved eight bytes to the left.
#[test]
fn rejects_footer_slack() {
    let file = minimal_bundle();
    let h = Header::parse(&file).unwrap();
    let mut padded = file[..h.footer_off as usize].to_vec();
    let footer = Footer::parse(&file, h.footer_off).unwrap();
    padded.extend_from_slice(&footer.root);
    padded.extend_from_slice(&0u32.to_le_bytes());
    padded.extend_from_slice(&0u32.to_le_bytes());
    padded.extend_from_slice(&[0u8; 8]); // slack
    let total = padded.len() as u64 + 16;
    padded.extend_from_slice(&total.to_le_bytes());
    padded.extend_from_slice(&MAGIC);
    assert!(matches!(
        Bundle::parse(&padded),
        Err(Error::BadFooterLen { .. })
    ));
}

/// R1 mandates hybrid: both signatures must verify. A footer carrying one of the
/// pair is a downgrade dressed as a partial file.
#[test]
fn rejects_half_a_hybrid_signature() {
    let f = Footer {
        root: [0; 32],
        sig_classical: vec![0; 64],
        sig_pq: Vec::new(),
        total_len: 0,
    };
    assert!(matches!(f.to_bytes(), Err(Error::Inconsistent { .. })));
}

#[test]
fn rejects_an_oversized_signature() {
    let f = Footer {
        root: [0; 32],
        sig_classical: vec![0; MAX_SIG_LEN as usize + 1],
        sig_pq: vec![0; 1],
        total_len: 0,
    };
    assert!(matches!(f.to_bytes(), Err(Error::SignatureTooLong { .. })));
}

#[test]
fn footer_round_trips_with_signatures() {
    let f = Footer {
        root: [0x5a; 32],
        sig_classical: vec![0x11; 64],
        sig_pq: vec![0x22; 3309],
        total_len: MIN_FOOTER_LEN + 64 + 3309 + 4096,
    };
    let bytes = f.to_bytes().unwrap();
    assert_eq!(bytes.len() as u64, MIN_FOOTER_LEN + 64 + 3309);
    // Place it at the end of a synthetic file so the length rules can apply.
    let mut file = vec![0u8; 4096];
    file.extend_from_slice(&bytes);
    assert_eq!(Footer::parse(&file, 4096).unwrap(), f);
    assert_eq!(
        Footer::parse(&file, 4096).unwrap().signing(),
        Signing::Present
    );
}

/// The repeated magic supports recovery scanning; `footer_off` in the header stays
/// authoritative. A wrong repeat still rejects, because it means the file is not
/// what it claims anywhere.
#[test]
fn rejects_a_bad_footer_magic() {
    let mut file = minimal_bundle();
    let n = file.len();
    file[n - 1] ^= 1;
    assert!(matches!(Bundle::parse(&file), Err(Error::BadMagic { .. })));
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn manifest_round_trips_byte_for_byte() {
    let m = minimal_manifest();
    let bytes = m.encode().unwrap();
    assert_eq!(Manifest::decode(&bytes).unwrap().encode().unwrap(), bytes);
}

/// An unknown key that `crit` does not name is carried, not rejected — otherwise
/// the manifest would be the one unextendable part of an extensible format. Carried
/// means byte-exact, so a rewriter cannot destroy what it does not understand.
#[test]
fn unknown_keys_are_carried_byte_for_byte() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
        (
            // A key from some later schema version.
            Value::Text("zenith".into()),
            Value::Array(vec![Value::Uint(7), Value::Null]),
        ),
    ]);
    let bytes = v.encode().unwrap();
    let m = Manifest::decode(&bytes).unwrap();
    assert_eq!(m.encode().unwrap(), bytes);
    assert!(m.value().get("zenith").is_some());
}

/// The same key becomes a hard reject the moment the writer marks it critical.
#[test]
fn a_critical_unknown_key_is_rejected() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
        (
            Value::Text("crit".into()),
            Value::Array(vec![Value::Text("zenith".into())]),
        ),
        (Value::Text("zenith".into()), Value::Uint(7)),
    ]);
    assert!(matches!(
        Manifest::decode(&v.encode().unwrap()),
        Err(Error::Manifest { .. })
    ));
}

/// A typo appears in neither `crit` nor the known-key list, which is the failure
/// design §10 actually cares about — and it is still caught, because `crit` may only
/// name keys the reader implements.
#[test]
fn a_typo_in_crit_is_rejected() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
        (
            Value::Text("crit".into()),
            Value::Array(vec![Value::Text("nmes".into())]),
        ),
    ]);
    assert!(matches!(
        Manifest::decode(&v.encode().unwrap()),
        Err(Error::Manifest { .. })
    ));
}

/// A newer schema is not by itself a reason to refuse, for the same reason
/// `version_minor` is not validated: what a file needs is stated by `crit`, not by a
/// version number.
#[test]
fn a_higher_spec_number_is_accepted() {
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(99)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
    ]);
    assert_eq!(Manifest::decode(&v.encode().unwrap()).unwrap().spec(), 99);
}

#[test]
fn manifest_rejects_missing_required_keys() {
    for drop_key in ["spec", "id", "name", "names"] {
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("x".into())),
            (Value::Text("name".into()), Value::Text("X".into())),
            (Value::Text("names".into()), Value::Array(vec![])),
        ]
        .into_iter()
        .filter(|(k, _)| k.as_text() != Some(drop_key))
        .collect();
        assert!(
            matches!(
                Manifest::decode(&Value::Map(entries).encode().unwrap()),
                Err(Error::Manifest { .. })
            ),
            "accepted a manifest with no `{drop_key}`"
        );
    }
}

/// A name may become a filename. Every shape that could escape a directory is
/// rejected at the format boundary rather than at whichever extraction path
/// remembers to check.
#[test]
fn manifest_rejects_path_like_names() {
    for bad in [
        "..",
        ".",
        "../etc/passwd",
        "/abs",
        "a/b",
        "a\\b",
        "a\0b",
        "",
    ] {
        let v = Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("x".into())),
            (Value::Text("name".into()), Value::Text("X".into())),
            (
                Value::Text("names".into()),
                Value::Array(vec![Value::Text(bad.into())]),
            ),
        ]);
        assert!(
            matches!(
                Manifest::decode(&v.encode().unwrap()),
                Err(Error::ManifestEntry { .. })
            ),
            "accepted the name {bad:?}"
        );
    }
}

/// The byte tests above cannot see a bidi override: every byte of U+202E's UTF-8 is
/// `≥ 0x80`, so `c < 0x20` and `c == 0x7f` both miss it.
///
/// A name becomes a filename on extraction, and `chal\u{202e}gnp.exe` renders as
/// `chal-exe.png` in a terminal, a file manager, and the phase 5 TUI alike. Escaping
/// at a display site does not help once the name is on disk, so it is rejected here.
#[test]
fn manifest_rejects_bidi_controls_in_names() {
    // U+202A–U+202E embeddings and overrides, U+2066–U+2069 isolates.
    for bad in [
        "chal\u{202e}gnp.exe",
        "\u{202a}lead",
        "\u{202b}x",
        "x\u{202c}",
        "\u{202d}x",
        "\u{2066}x",
        "\u{2067}x",
        "\u{2068}x",
        "x\u{2069}",
    ] {
        let v = Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("x".into())),
            (Value::Text("name".into()), Value::Text("X".into())),
            (
                Value::Text("names".into()),
                Value::Array(vec![Value::Text(bad.into())]),
            ),
        ]);
        assert!(
            matches!(
                Manifest::decode(&v.encode().unwrap()),
                Err(Error::ManifestEntry { .. })
            ),
            "accepted the name {bad:?}"
        );
    }
}

/// The rule targets the nine explicit formatting characters, not right-to-left
/// script. Rejecting Arabic or Hebrew names would be a bug, not extra safety.
#[test]
fn manifest_accepts_right_to_left_script_in_names() {
    for good in ["تحدي", "אתגר", "flag.txt", "日本語", "café"] {
        let v = Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("x".into())),
            (Value::Text("name".into()), Value::Text("X".into())),
            (
                Value::Text("names".into()),
                Value::Array(vec![Value::Text(good.into())]),
            ),
        ]);
        assert!(
            Manifest::decode(&v.encode().unwrap()).is_ok(),
            "rejected the legitimate name {good:?}"
        );
    }
}

#[test]
fn manifest_rejects_a_bad_id() {
    for bad in ["", "-lead", "trail-", "Upper", "sp ace", "under_score"] {
        let v = Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text(bad.into())),
            (Value::Text("name".into()), Value::Text("X".into())),
            (Value::Text("names".into()), Value::Array(vec![])),
        ]);
        assert!(
            matches!(
                Manifest::decode(&v.encode().unwrap()),
                Err(Error::Manifest { .. })
            ),
            "accepted the id {bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Manifest rules with no other dedicated test (M2-M6, M8, M11-M18)
// ---------------------------------------------------------------------------

/// A minimal valid manifest map. Tests mutate this vector rather than appending a
/// duplicate required key, which the canonical encoder rejects before `decode`
/// would ever see it.
fn base_manifest() -> Vec<(Value, Value)> {
    vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (Value::Text("names".into()), Value::Array(vec![])),
    ]
}

fn manifest_error(entries: Vec<(Value, Value)>) -> Error {
    let bytes = Value::Map(entries)
        .encode()
        .expect("test manifest must encode canonically");
    Manifest::decode(&bytes).expect_err("test manifest must be rejected")
}

/// M2: the outermost value must be a map.
#[test]
fn m2_manifest_must_be_a_map() {
    let bytes = Value::Array(vec![]).encode().unwrap();
    assert!(matches!(
        Manifest::decode(&bytes),
        Err(Error::Manifest { .. })
    ));
}

/// M3: every top-level key must be text.
#[test]
fn m3_manifest_keys_must_be_text() {
    let entries = vec![(Value::Uint(1), Value::Uint(2))];
    assert!(matches!(manifest_error(entries), Error::Manifest { .. }));
}

/// M4/M5: `spec` must be present, an unsigned integer, and at least 1.
#[test]
fn m4_m5_spec_must_be_a_positive_uint() {
    let mut not_uint = base_manifest();
    not_uint[0] = (Value::Text("spec".into()), Value::Text("1".into()));
    assert!(matches!(manifest_error(not_uint), Error::Manifest { .. }));

    let mut zero = base_manifest();
    zero[0] = (Value::Text("spec".into()), Value::Uint(0));
    assert!(matches!(manifest_error(zero), Error::Manifest { .. }));
}

/// M6: `crit` must be an array of text strings.
#[test]
fn m6_crit_must_be_an_array_of_text() {
    let mut not_array = base_manifest();
    not_array.push((Value::Text("crit".into()), Value::Uint(1)));
    assert!(matches!(manifest_error(not_array), Error::Manifest { .. }));

    let mut non_text = base_manifest();
    non_text.push((
        Value::Text("crit".into()),
        Value::Array(vec![Value::Uint(1)]),
    ));
    assert!(matches!(manifest_error(non_text), Error::Manifest { .. }));
}

/// M8: a `crit` entry must name a key that is present. (M7 — a key the reader does
/// not implement — has its own test above.)
#[test]
fn m8_crit_must_name_a_present_key() {
    let mut entries = base_manifest();
    // `category` is a known key, but it is absent from this manifest.
    entries.push((
        Value::Text("crit".into()),
        Value::Array(vec![Value::Text("category".into())]),
    ));
    assert!(matches!(manifest_error(entries), Error::Manifest { .. }));
}

/// M11: `category` and `description` are optional, but must be text when present.
#[test]
fn m11_category_and_description_must_be_text() {
    for key in ["category", "description"] {
        let mut entries = base_manifest();
        entries.push((Value::Text(key.into()), Value::Uint(1)));
        assert!(
            matches!(manifest_error(entries), Error::Manifest { .. }),
            "{key} must be rejected when it is not text"
        );
    }
}

/// M12: `version` is optional, but must be an unsigned integer.
#[test]
fn m12_version_must_be_a_uint() {
    let mut entries = base_manifest();
    entries.push((Value::Text("version".into()), Value::Text("1".into())));
    assert!(matches!(manifest_error(entries), Error::Manifest { .. }));
}

/// M14: the name table cannot exceed the `name_id` space.
#[test]
fn m14_name_table_cannot_exceed_the_name_id_space() {
    let mut entries = base_manifest();
    entries[3] = (
        Value::Text("names".into()),
        Value::Array(
            (0..=ctf_format::manifest::MAX_NAMES)
                .map(|i| Value::Text(format!("n{i}")))
                .collect(),
        ),
    );
    assert!(matches!(manifest_error(entries), Error::Manifest { .. }));
}

/// M15: a `names` entry must be text. (Shape violations are covered by
/// `manifest_rejects_path_like_names` and `manifest_rejects_bidi_controls_in_names`.)
#[test]
fn m15_names_entries_must_be_text() {
    let mut entries = base_manifest();
    entries[3] = (
        Value::Text("names".into()),
        Value::Array(vec![Value::Uint(1)]),
    );
    // The diagnostic names the entry by index, never by its non-text content.
    assert!(matches!(
        manifest_error(entries),
        Error::ManifestEntry { index: Some(0), .. }
    ));
}

/// M16: duplicate names are rejected, not resolved.
#[test]
fn m16_duplicate_names_are_rejected() {
    let mut entries = base_manifest();
    entries[3] = (
        Value::Text("names".into()),
        Value::Array(vec![Value::Text("a".into()), Value::Text("a".into())]),
    );
    assert!(matches!(
        manifest_error(entries),
        Error::ManifestEntry { .. }
    ));
}

/// M17: the `external` value must be a map, keyed by unsigned integers within the
/// `name_id` space.
#[test]
fn m17_external_map_shape() {
    // Not a map.
    let mut not_map = base_manifest();
    not_map.push((Value::Text("external".into()), Value::Uint(1)));
    assert!(matches!(manifest_error(not_map), Error::Manifest { .. }));

    // A key that is not an unsigned integer.
    let mut bad_key = base_manifest();
    bad_key.push((
        Value::Text("external".into()),
        Value::Map(vec![(Value::Bool(true), Value::Map(vec![]))]),
    ));
    assert!(matches!(
        manifest_error(bad_key),
        Error::ManifestEntry { .. }
    ));

    // A key outside the `name_id` space.
    let mut out_of_range = base_manifest();
    out_of_range.push((
        Value::Text("external".into()),
        Value::Map(vec![(
            Value::Uint(70_000),
            Value::Map(vec![
                (Value::Text("size".into()), Value::Uint(1)),
                (Value::Text("root".into()), Value::Bytes(vec![0; 32])),
                (
                    Value::Text("mirrors".into()),
                    Value::Array(vec![Value::Text("m".into())]),
                ),
            ]),
        )]),
    ));
    assert!(matches!(
        manifest_error(out_of_range),
        Error::ManifestEntry {
            name_id: Some(70_000),
            ..
        }
    ));
}

/// M18: an `external` entry's required fields, types, and `root` length.
#[test]
fn m18_external_entry_shape() {
    let entry_without = |missing: &str| -> Vec<(Value, Value)> {
        let mut fields = vec![
            (Value::Text("size".into()), Value::Uint(1)),
            (Value::Text("root".into()), Value::Bytes(vec![0; 32])),
            (
                Value::Text("mirrors".into()),
                Value::Array(vec![Value::Text("m".into())]),
            ),
        ];
        fields.retain(|(k, _)| k.as_text() != Some(missing));
        fields
    };

    for missing in ["size", "root", "mirrors"] {
        let mut entries = base_manifest();
        entries.push((
            Value::Text("external".into()),
            Value::Map(vec![(Value::Uint(1), Value::Map(entry_without(missing)))]),
        ));
        assert!(
            matches!(manifest_error(entries), Error::ManifestEntry { .. }),
            "an external entry missing {missing} must be rejected"
        );
    }

    // `root` present but not exactly 32 bytes.
    let mut short_root = base_manifest();
    short_root.push((
        Value::Text("external".into()),
        Value::Map(vec![(
            Value::Uint(1),
            Value::Map(vec![
                (Value::Text("size".into()), Value::Uint(1)),
                (Value::Text("root".into()), Value::Bytes(vec![0; 3])),
                (
                    Value::Text("mirrors".into()),
                    Value::Array(vec![Value::Text("m".into())]),
                ),
            ]),
        )]),
    ));
    assert!(matches!(
        manifest_error(short_root),
        Error::ManifestEntry { .. }
    ));

    // An empty `mirrors` list.
    let mut empty_mirrors = base_manifest();
    empty_mirrors.push((
        Value::Text("external".into()),
        Value::Map(vec![(
            Value::Uint(1),
            Value::Map(vec![
                (Value::Text("size".into()), Value::Uint(1)),
                (Value::Text("root".into()), Value::Bytes(vec![0; 32])),
                (Value::Text("mirrors".into()), Value::Array(vec![])),
            ]),
        )]),
    ));
    assert!(matches!(
        manifest_error(empty_mirrors),
        Error::ManifestEntry { .. }
    ));
}

/// Every section must be nameable, or a section exists that nothing can refer to.
#[test]
fn rejects_a_name_id_past_the_name_table() {
    let m = Manifest::minimal("x", "X", &[]).unwrap().encode().unwrap();
    let err = write_bundle(
        SUITE,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m,
        )],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Error::ManifestEntry {
            name_id: Some(0),
            ..
        }
    ));
}

/// Entry-level diagnostics: a manifest error names the offending entry by *number*,
/// so an operator can find it across a 50-artifact bundle without hand-decoding
/// CBOR. The number is an index or a `name_id`, never the text, so the diagnostic
/// stays an oracle for nothing (spec §13).
#[test]
fn manifest_errors_name_the_offending_entry_by_number() {
    // A bad `names` entry: the second one, at index 1.
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (
            Value::Text("names".into()),
            Value::Array(vec![
                Value::Text("manifest".into()),
                Value::Text("bad/name".into()),
            ]),
        ),
    ]);
    let err = Manifest::decode(&v.encode().unwrap()).unwrap_err();
    assert!(matches!(
        err,
        Error::ManifestEntry {
            index: Some(1),
            name_id: None,
            ..
        }
    ));
    let msg = err.to_string();
    assert!(
        !msg.contains("bad/name"),
        "the diagnostic echoed attacker text: {msg}"
    );
    assert!(
        msg.contains("entry 1"),
        "the diagnostic lost the index: {msg}"
    );

    // A bad mirror inside the `external` entry for `name_id` 1: an over-long URL at
    // position 0. The URL is attacker text and must not reach the diagnostic.
    let long = format!("https://secret.example/{}", "a".repeat(3000));
    let v = Value::Map(vec![
        (Value::Text("spec".into()), Value::Uint(1)),
        (Value::Text("id".into()), Value::Text("x".into())),
        (Value::Text("name".into()), Value::Text("X".into())),
        (
            Value::Text("names".into()),
            Value::Array(vec![
                Value::Text("manifest".into()),
                Value::Text("payload".into()),
            ]),
        ),
        (
            Value::Text("external".into()),
            Value::Map(vec![(
                Value::Uint(1),
                Value::Map(vec![
                    (Value::Text("size".into()), Value::Uint(9)),
                    (Value::Text("root".into()), Value::Bytes(vec![0; 32])),
                    (
                        Value::Text("mirrors".into()),
                        Value::Array(vec![Value::Text(long)]),
                    ),
                ]),
            )]),
        ),
    ]);
    let err = Manifest::decode(&v.encode().unwrap()).unwrap_err();
    assert!(matches!(
        err,
        Error::ManifestEntry {
            index: Some(0),
            name_id: Some(1),
            ..
        }
    ));
    let msg = err.to_string();
    assert!(
        !msg.contains("secret.example"),
        "the diagnostic echoed a mirror URL: {msg}"
    );
    assert!(
        msg.contains("name_id 1") && msg.contains("entry 0"),
        "the diagnostic lost the position: {msg}"
    );
}

fn external_bundle(size: u64, root: [u8; 32]) -> ctf_format::Result<Vec<u8>> {
    let manifest = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("workstation".into())),
            (
                Value::Text("name".into()),
                Value::Text("Workstation".into()),
            ),
            (
                Value::Text("names".into()),
                Value::Array(vec![
                    Value::Text("manifest".into()),
                    Value::Text("workstation.E01".into()),
                ]),
            ),
            (
                Value::Text("external".into()),
                Value::Map(vec![(
                    Value::Uint(1),
                    Value::Map(vec![
                        (Value::Text("size".into()), Value::Uint(size)),
                        (Value::Text("root".into()), Value::Bytes(root.to_vec())),
                        (
                            Value::Text("mirrors".into()),
                            Value::Array(vec![Value::Text(
                                "https://mirror.example/workstation.E01".into(),
                            )]),
                        ),
                    ]),
                )]),
            ),
        ])
        .encode()?,
    )?
    .encode()?;
    write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec {
                kind: SectionKind::Artifact,
                name_id: 1,
                flags: SectionFlags(SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE),
                chunk_size: 0,
                payload: Payload::External {
                    len_plain: 41_231_986_688,
                    root: [0x33; 32],
                },
            },
        ],
    )
}

/// A `.ctf` describing a 40 GB forensics image is a few kilobytes and stays mailable.
#[test]
fn a_40gb_payload_fits_in_a_few_kilobytes() {
    let file = external_bundle(41_231_986_688, [0x33; 32]).unwrap();
    assert!(file.len() < 8192, "bundle grew to {} bytes", file.len());
    let b = Bundle::parse(&file).unwrap();
    let ext = b.manifest.external(1).unwrap();
    assert_eq!(ext.size, 41_231_986_688);
    assert_eq!(ext.mirrors.len(), 1);
    // Its bytes are not here, and asking for them says so rather than returning
    // something plausible.
    let record = *b.section(1).unwrap();
    assert!(b.section_bytes(&record).is_err());
}

/// An absent payload and an unreadable one are different facts, and a verify pass
/// that returned one number could not tell them apart.
///
/// This is the shape that keeps a non-zero exit worth having: a bundle describing a
/// 40 GB external image is *correct*, so its skipped section must not be counted as
/// a failure, or every real bundle fails and the signal is gone.
#[test]
fn a_verify_pass_separates_absent_payloads_from_unreadable_ones() {
    let file = external_bundle(41_231_986_688, [0x33; 32]).unwrap();
    let b = Bundle::parse(&file).unwrap();
    let report = b.verify_inline_sections().unwrap();
    assert_eq!(report.verified, 1, "the manifest is inline and checkable");
    assert_eq!(report.external, 1, "the 40 GB image is absent by design");
    assert_eq!(
        report.unverifiable, 0,
        "nothing here has bytes this build cannot read, so --verify must succeed"
    );
}

/// The other half: an inline payload whose bytes are present and unreadable must be
/// counted, not skipped in silence.
///
/// This is the case the old `-> Result<usize>` signature could not express. It
/// returned the number it *had* checked, so a bundle with an encrypted artifact
/// reported "verified 1 section" and exited 0 — reporting content as verified when
/// it was not.
#[test]
fn an_unreadable_inline_payload_is_counted_not_skipped() {
    let mut file = artifact_bundle();
    mark_encrypted(&mut file, 1);
    let b = Bundle::parse(&file).unwrap();
    let report = b.verify_inline_sections().unwrap();
    assert_eq!(
        report.verified, 1,
        "the manifest is still plain and checked"
    );
    assert_eq!(report.external, 0);
    assert_eq!(
        report.unverifiable, 1,
        "the encrypted artifact's bytes are here and were not checked"
    );

    // And the section itself still refuses to hand anything back, so the count is
    // reporting a real refusal rather than a bookkeeping detail.
    let record = *b.section(1).unwrap();
    assert!(matches!(
        b.section_bytes(&record),
        Err(Error::Inconsistent { .. })
    ));
}

/// Two carriers of one fact with no stated precedence is how one implementation
/// verifies a payload against the record while another verifies it against the
/// manifest. The record wins, and a disagreement rejects rather than resolving.
#[test]
fn external_metadata_must_agree_with_the_record() {
    assert!(matches!(
        external_bundle(41_231_986_687, [0x33; 32]),
        Err(Error::ManifestEntry { .. })
    ));
    assert!(matches!(
        external_bundle(41_231_986_688, [0x34; 32]),
        Err(Error::ManifestEntry { .. })
    ));
}

/// M20: the `external` map's key set is exactly the `name_id`s of `EXTERNAL`
/// sections — no more, no fewer. Checked against the section table, so it is a
/// `validate_against` rule and needs no whole file.
#[test]
fn m20_external_metadata_must_match_the_external_sections() {
    fn external_manifest(ids: &[u64]) -> Manifest {
        let entries: Vec<(Value, Value)> = ids
            .iter()
            .map(|id| {
                (
                    Value::Uint(*id),
                    Value::Map(vec![
                        (Value::Text("size".into()), Value::Uint(10)),
                        (Value::Text("root".into()), Value::Bytes(vec![0x33; 32])),
                        (
                            Value::Text("mirrors".into()),
                            Value::Array(vec![Value::Text("m".into())]),
                        ),
                    ]),
                )
            })
            .collect();
        Manifest::decode(
            &Value::Map(vec![
                (Value::Text("spec".into()), Value::Uint(1)),
                (Value::Text("id".into()), Value::Text("x".into())),
                (Value::Text("name".into()), Value::Text("X".into())),
                (
                    Value::Text("names".into()),
                    Value::Array(vec![
                        Value::Text("manifest".into()),
                        Value::Text("payload".into()),
                    ]),
                ),
                (Value::Text("external".into()), Value::Map(entries)),
            ])
            .encode()
            .unwrap(),
        )
        .unwrap()
    }

    fn record(name_id: u16, external: bool) -> SectionRecord {
        SectionRecord {
            kind: SectionKind::Artifact,
            name_id,
            flags: SectionFlags(if external {
                SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE
            } else {
                SectionFlags::PLAYER_VISIBLE
            }),
            enc: ctf_format::Encryption::None,
            comp: ctf_format::Compression::None,
            offset: if external { 0 } else { 4096 },
            len_stored: if external { 0 } else { 10 },
            len_plain: 10,
            chunk_size: 0,
            chunk_index_off: 0,
            root: [0x33; 32],
        }
    }

    // An EXTERNAL section with no metadata entry.
    let no_metadata = Manifest::minimal("x", "X", &["manifest", "payload"]).unwrap();
    assert!(matches!(
        no_metadata.validate_against(&[record(1, true)]),
        Err(Error::ManifestEntry {
            name_id: Some(1),
            ..
        })
    ));

    // Metadata for a section that is not EXTERNAL.
    assert!(matches!(
        external_manifest(&[1]).validate_against(&[record(1, false)]),
        Err(Error::ManifestEntry {
            name_id: Some(1),
            ..
        })
    ));

    // Metadata naming a `name_id` no EXTERNAL section uses. The entry for 1 is
    // valid, so the extra entry for 2 is what is left over.
    assert!(matches!(
        external_manifest(&[1, 2]).validate_against(&[record(1, true)]),
        Err(Error::ManifestEntry {
            name_id: Some(2),
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Layout, now that the chunk index has a knowable length
// ---------------------------------------------------------------------------

/// 0.2 could not bounds-check a chunk index because its entry size was undefined, so
/// `chunk_index_off` pointed at a region with no length. Deriving the length from
/// `len_plain` and `chunk_size` is what closes that hole.
#[test]
fn a_chunk_index_is_bounds_and_overlap_checked() {
    let file = artifact_bundle();
    let h = Header::parse(&file).unwrap();
    let table_off = h.section_table_off as usize;
    let record_off = table_off + 128; // the artifact is the second record

    // Point the index at the section table.
    let mut tampered = file.clone();
    tampered[record_off + 40..record_off + 48].copy_from_slice(&h.section_table_off.to_le_bytes());
    let err = Bundle::parse(&tampered).unwrap_err();
    assert!(
        matches!(err, Error::OverlapsSectionTable { .. }),
        "expected an overlap error, got {err}"
    );

    // Point it past the footer.
    let mut tampered = file.clone();
    tampered[record_off + 40..record_off + 48].copy_from_slice(&(h.footer_off - 8).to_le_bytes());
    assert!(matches!(
        Bundle::parse(&tampered),
        Err(Error::ExceedsFile {
            at: "chunk index",
            ..
        })
    ));
}

/// The index is committed by construction: it must reduce to the section root,
/// which lives in the table, which the footer commits to. So a forged index needs a
/// forged root, and a forged root needs a forged commitment.
#[test]
fn a_forged_chunk_index_is_caught_by_the_section_root() {
    let mut file = artifact_bundle();
    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    let index_off = record.chunk_index_off as usize;
    drop(b);
    file[index_off] ^= 1;

    let b = Bundle::parse(&file).unwrap();
    assert!(matches!(
        b.chunk_index(&record),
        Err(Error::RootMismatch { at: "chunk index" })
    ));
}

#[test]
fn chunk_index_matches_a_freshly_built_one() {
    let file = artifact_bundle();
    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    let bytes = b.section_bytes(&record).unwrap();
    assert_eq!(
        b.chunk_index(&record).unwrap().unwrap().entries(),
        ChunkIndex::build(bytes, record.chunk_size)
            .unwrap()
            .entries()
    );
}

// ---------------------------------------------------------------------------
// The serving boundary
// ---------------------------------------------------------------------------

/// Spec §10, normative: "A reader MUST NOT serve, execute, decompress, or decrypt a
/// section whose kind it does not implement." §5.2 adds that `PLAYER_VISIBLE` on an
/// unknown kind "confers nothing on a reader that does not understand it".
///
/// `SectionKind::is_known()` existed for exactly this and had no caller outside
/// tests, so an `OPTIONAL` section with a future kind, plain inline bytes and a
/// valid root came straight back out of `section_bytes`.
#[test]
fn an_unknown_kind_is_committed_and_verified_but_never_served() {
    let manifest = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (
                Value::Text("id".into()),
                Value::Text("from-the-future".into()),
            ),
            (
                Value::Text("name".into()),
                Value::Text("From The Future".into()),
            ),
            (
                Value::Text("names".into()),
                Value::Array(vec![
                    Value::Text("manifest".into()),
                    Value::Text("mystery".into()),
                ]),
            ),
        ])
        .encode()
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let payload = vec![0x77u8; 128];
    let file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                // A kind from a later version. OPTIONAL is what makes it skippable
                // rather than a hard reject.
                SectionKind::unknown(9).unwrap(),
                1,
                SectionFlags(SectionFlags::OPTIONAL | SectionFlags::PLAYER_VISIBLE),
                &payload,
            ),
        ],
    )
    .unwrap();

    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    assert!(!record.kind.is_known());

    // Not servable, even though it is PLAYER_VISIBLE, plain, and its root matches.
    assert!(
        matches!(b.section_bytes(&record), Err(Error::Inconsistent { .. })),
        "an unimplemented kind must not come back from the serving API"
    );

    // But still *verified*. Hashing a section against the root the footer already
    // commits to is not serving, executing, decompressing, or decrypting, and
    // refusing to do it would leave the bundle less checked for no gain in safety.
    let report = b.verify_inline_sections().unwrap();
    assert_eq!(
        report.verified, 2,
        "both sections are hashed against a root"
    );
    assert_eq!(report.unverifiable, 0);
}

/// Belt and braces behind R21: even if a sealed section somehow reached the serving
/// boundary, a phase 1 reader has no business returning its plaintext.
///
/// R21 makes the input unreachable through `Bundle::parse` today, so this is built
/// by hand — which is the point. The guard exists so that relaxing R21 later cannot
/// silently turn this into a leak.
#[test]
fn a_sealed_section_is_never_served() {
    let mut file = artifact_bundle();
    let mut record = *Bundle::parse(&file).unwrap().section(1).unwrap();
    mark_encrypted(&mut file, 1);
    let b = Bundle::parse(&file).unwrap();
    record.flags = SectionFlags(SectionFlags::SEALED);
    assert!(matches!(
        b.section_bytes(&record),
        Err(Error::Inconsistent { .. })
    ));
}

/// C8: the chunk index of a section the serving boundary refuses is withheld too.
/// An entry is a chaining value of the section's plaintext (§9.1), so exposing it
/// would hand out a plaintext-derived guess-confirmation oracle for a section whose
/// bytes `section_bytes` refuses.
#[test]
fn a_sealed_sections_chunk_index_is_not_served() {
    let mut file = artifact_bundle();
    mark_sealed_encrypted(&mut file, 1);
    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    assert!(record.flags.sealed());
    assert_ne!(record.chunk_index_off, 0, "the fixture must carry an index");
    assert!(matches!(
        b.chunk_index(&record),
        Err(Error::Inconsistent { .. })
    ));
}

/// The same guard for a kind this build does not implement. The section is still
/// committed to and still verified against its root; only the plaintext-derived
/// index is withheld.
#[test]
fn an_unknown_kinds_chunk_index_is_not_served() {
    let manifest = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (
                Value::Text("id".into()),
                Value::Text("from-the-future".into()),
            ),
            (
                Value::Text("name".into()),
                Value::Text("From The Future".into()),
            ),
            (
                Value::Text("names".into()),
                Value::Array(vec![
                    Value::Text("manifest".into()),
                    Value::Text("mystery".into()),
                ]),
            ),
        ])
        .encode()
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let payload = vec![0x77u8; 5000];
    let file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::unknown(9).unwrap(),
                1,
                SectionFlags(SectionFlags::OPTIONAL | SectionFlags::PLAYER_VISIBLE),
                &payload,
            )
            .chunked(4096),
        ],
    )
    .unwrap();

    let b = Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    assert!(!record.kind.is_known());
    assert_ne!(record.chunk_index_off, 0, "the fixture must carry an index");
    assert!(matches!(
        b.chunk_index(&record),
        Err(Error::Inconsistent { .. })
    ));
    // Still committed and still verified — only the index is withheld.
    assert_eq!(b.verify_inline_sections().unwrap().verified, 2);
}

/// R21's deliberate consequence, asserted rather than left in a comment: R6 forces
/// `writeup` to carry `SEALED`, this version has no encryption, so the writer cannot
/// emit one at all. Today it can emit a *fake*-sealed section, which is worse.
#[test]
fn phase_1_cannot_write_a_kind_that_must_be_sealed() {
    let manifest = Manifest::minimal("baby-rop", "Baby ROP", &["manifest", "writeup"])
        .unwrap()
        .encode()
        .unwrap();
    let result = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Writeup,
                1,
                SectionFlags(SectionFlags::SEALED),
                b"the flag was in the EXIF all along",
            ),
        ],
    );
    assert!(
        result.is_err(),
        "a writer with no encryption must refuse to claim a section is sealed"
    );
}

// ---------------------------------------------------------------------------
// T8: nothing in the file is uncommitted
// ---------------------------------------------------------------------------

/// The bug this closes is signature malleability, so the test states it that way
/// rather than as "a byte was non-zero".
///
/// The commitment root spans the header and section table; each section's `root`
/// spans its own plaintext. Nothing spanned the gaps. A padding byte could therefore
/// be changed in place without moving the root and without moving `total_len` —
/// which are two of the four fields in the §8.4 signature transcript — so one phase 2
/// signature would have verified two different files. Phase 2 cannot fix that: the
/// transcript is already correct, and these bytes were never in scope of anything.
///
/// Note what is asserted: the root is *identical* before and after, and the file is
/// rejected anyway. If this ever fails with `RootMismatch` instead, something else
/// changed and T8 is not the rule doing the work.
#[test]
fn t8_padding_is_committed_by_being_required_to_be_zero() {
    let good = minimal_bundle();
    let root_before = Bundle::parse(&good).unwrap().footer.root;

    // Offset 3000 is inside the gap between the header and the manifest payload —
    // 4032 bytes of alignment padding that R12 forces and nothing claimed.
    let mut tampered = good.clone();
    tampered[3000] = 0x41;

    assert_eq!(tampered.len(), good.len(), "total_len is unchanged");
    assert_eq!(
        &tampered[..64],
        &good[..64],
        "the header is unchanged, so the commitment root cannot move"
    );
    assert_eq!(
        &tampered[4288..],
        &good[4288..],
        "the footer, and therefore the stored root, is byte-identical"
    );

    match Bundle::parse(&tampered) {
        Err(Error::PaddingNotZero { at }) => assert_eq!(at, 3000),
        other => panic!("expected PaddingNotZero at 3000, got {other:?}"),
    }

    // The root really was unchanged: the file the old reader accepted committed to
    // exactly the same 32 bytes as the file it should have accepted.
    let root_after = ctf_format::footer::commitment_root(&tampered[..64], &tampered[4160..4288]);
    assert_eq!(
        root_before, root_after,
        "T8, not the commitment, is what rejects this"
    );
}

/// Every gap, not just the big one. The two-byte gap between the manifest payload and
/// the section table is the one a bounds-only check would miss.
#[test]
fn t8_covers_every_gap_between_structures() {
    let good = minimal_bundle();
    // 64..4096 head padding; 4158..4160 aligning the table; both unclaimed.
    for off in [64usize, 3000, 4095, 4158, 4159] {
        let mut tampered = good.clone();
        tampered[off] = 0xff;
        match Bundle::parse(&tampered) {
            Err(Error::PaddingNotZero { at }) => assert_eq!(at as usize, off),
            other => panic!("offset {off} must be rejected as padding, got {other:?}"),
        }
    }
}

/// T8 must not reject a byte that a structure legitimately owns, or every real
/// bundle would fail. The payload, the table and the footer are all claimed regions.
#[test]
fn t8_does_not_reach_into_claimed_regions() {
    let good = minimal_bundle();
    // A byte inside the manifest payload is caught by that section's root, and a byte
    // inside the table by the commitment — never by T8.
    let mut in_payload = good.clone();
    in_payload[4100] ^= 1;
    assert!(matches!(
        Bundle::parse(&in_payload),
        Err(Error::RootMismatch { .. })
    ));

    let mut in_table = good.clone();
    in_table[4200] ^= 1;
    assert!(!matches!(
        Bundle::parse(&in_table),
        Err(Error::PaddingNotZero { .. })
    ));

    // And the untouched bundle still opens.
    assert!(Bundle::parse(&good).is_ok());
}

/// §16 promises a 0.3 reader accepts a 0.2 file's header and table **in full**.
/// R21 and T8 both narrowed rules a 0.2 file could legally break, so without gating
/// them on `CONTAINER_V1` that promise would have been quietly false.
///
/// This is the test that would have caught it, and it is written from the two
/// concrete shapes rather than from the rule numbers.
#[test]
fn a_0_2_file_keeps_its_own_rules() {
    // Non-zero padding. 0.2 §3 made zeroing a writer's SHOULD with no reader rule,
    // so this file was legal. T8 must not reach it: T8 protects a commitment root
    // and a signature transcript, and a 0.2 file has neither.
    let mut file = minimal_bundle();
    file[44..48].copy_from_slice(&0u32.to_le_bytes()); // clear CONTAINER_V1
    file[3000] = 0x41;

    let h = Header::parse(&file).unwrap();
    assert_eq!(RuleSet::of(&h), RuleSet::Legacy);
    let (start, end) = h.table_range().unwrap();
    let records = section::parse_table_with(
        &file[start as usize..end as usize],
        h.section_table_count,
        RuleSet::of(&h),
    )
    .unwrap();
    section::validate_layout(&records, &h, &file)
        .expect("a 0.2 file's padding was never constrained");

    // The same bytes with the bit set are a 0.3 file, and T8 does apply.
    let mut as_0_3 = file.clone();
    as_0_3[44..48].copy_from_slice(&FEAT_RO_COMPAT_CONTAINER_V1.to_le_bytes());
    let h3 = Header::parse(&as_0_3).unwrap();
    assert_eq!(RuleSet::of(&h3), RuleSet::Container);
    assert!(matches!(
        section::validate_layout(&records, &h3, &as_0_3),
        Err(Error::PaddingNotZero { at: 3000 })
    ));
}

/// The R21 half. 0.2 implemented no encryption at all, so *every* sealed section a
/// 0.2 writer could produce carried `enc = 0` — applying R21 to a legacy file would
/// reject the only form `writeup`, `solver` and `progress` could take, not an abuse
/// of it.
#[test]
fn a_0_2_sealed_section_is_not_judged_by_r21() {
    let mut r = SectionRecord {
        kind: SectionKind::Writeup,
        name_id: 1,
        flags: SectionFlags(SectionFlags::SEALED),
        enc: ctf_format::Encryption::None,
        comp: ctf_format::Compression::None,
        offset: 4096,
        len_stored: 100,
        len_plain: 100,
        chunk_size: 0,
        chunk_index_off: 0,
        root: [0xab; 32],
    };
    let bytes = r.to_bytes();

    assert_eq!(
        SectionRecord::parse_with(&bytes, RuleSet::Legacy).unwrap(),
        r,
        "a 0.2 writeup is exactly what 0.2 could write"
    );
    assert!(
        matches!(
            SectionRecord::parse_with(&bytes, RuleSet::Container),
            Err(Error::Inconsistent { .. })
        ),
        "the same record in a 0.3 file is a claim nothing backs"
    );

    // R6 still applies on both paths: 0.2 had it, and dropping it would let a
    // legacy file carry an unsealed writeup, which was never legal.
    r.flags = SectionFlags::empty();
    assert!(SectionRecord::parse_with(&r.to_bytes(), RuleSet::Legacy).is_err());
}
