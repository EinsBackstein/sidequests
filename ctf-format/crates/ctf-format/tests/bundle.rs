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
    Payload, SECTION_RECORD_LEN, SectionFlags, SectionKind, SectionSpec, Signing,
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
    let (start, end) = h.table_range().unwrap();
    let records =
        section::parse_table(&file[start as usize..end as usize], h.section_table_count).unwrap();
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
    let bytes = b.section_bytes(artifact).unwrap();
    assert_eq!(bytes.len(), 5000);
    index.verify_chunk(0, &bytes[..4096], 4096).unwrap();
    index.verify_chunk(1, &bytes[4096..], 4096).unwrap();
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
#[test]
fn signature_transcript_is_the_documented_construction() {
    let root = [0xab; 32];
    let t = sig_input(1, &root, 8448);
    assert_eq!(&t[..17], b"ctf/footer-sig/v1");
    assert_eq!(&t[17..19], &1u16.to_le_bytes());
    assert_eq!(&t[19..51], &root);
    assert_eq!(&t[51..59], &8448u64.to_le_bytes());
    assert_eq!(t.len(), 59);
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
                Err(Error::Manifest { .. })
            ),
            "accepted the name {bad:?}"
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
    assert!(matches!(err, Error::Manifest { .. }));
}

// ---------------------------------------------------------------------------
// External sections
// ---------------------------------------------------------------------------

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
        Err(Error::Inconsistent { .. })
    ));
    assert!(matches!(
        external_bundle(41_231_986_688, [0x34; 32]),
        Err(Error::Inconsistent { .. })
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
        b.chunk_index(&record).unwrap().unwrap(),
        ChunkIndex::build(bytes, record.chunk_size).unwrap()
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
