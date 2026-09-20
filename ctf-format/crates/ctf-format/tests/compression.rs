//! zstd compression tests (ticket 19).
//!
//! Two halves: the writer's frame alignment and the reader's caps. The caps are
//! checked *before* the decoder runs, which is the property that makes decompressing
//! untrusted input safe at all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{Error, Manifest, SectionFlags, SectionKind, SectionSpec, compress, write_bundle};

fn manifest() -> Vec<u8> {
    Manifest::minimal("chal", "Title", &["manifest", "notes"])
        .unwrap()
        .encode()
        .unwrap()
}

/// A chunked compressed section is several concatenated frames; the reader must
/// decode them all and still return the exact plaintext.
#[test]
fn a_chunked_compressed_section_round_trips() {
    let chunk_size = 4096u32;
    // Three distinct chunks so a frame mix-up cannot pass by coincidence.
    let mut plain = Vec::new();
    for i in 0..3u8 {
        plain.extend(std::iter::repeat_n(i, chunk_size as usize));
    }
    let file = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest()),
            SectionSpec::inline(SectionKind::Artifact, 1, SectionFlags::empty(), &plain)
                .chunked(chunk_size)
                .compressed(),
        ],
    )
    .unwrap();
    let b = ctf_format::Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    assert_eq!(record.chunk_size, chunk_size);
    assert!(record.chunk_index_off != 0, "three chunks need an index");
    assert_eq!(b.section_bytes(&record).unwrap().as_ref(), plain.as_slice());
    assert_eq!(b.verify_inline_sections().unwrap().verified, 2);
}

#[test]
fn a_compressed_section_round_trips() {
    let plain = b"hello hello hello hello hello hello".repeat(100);
    let file = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest()),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &plain,
            )
            .compressed(),
        ],
    )
    .unwrap();
    let b = ctf_format::Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    assert_eq!(record.comp, ctf_format::Compression::Zstd);
    assert_eq!(record.len_plain as usize, plain.len());
    assert!(
        record.len_stored < record.len_plain,
        "repetitive input should compress"
    );
    assert_eq!(b.section_bytes(&record).unwrap().as_ref(), plain.as_slice());
    assert_eq!(b.verify_inline_sections().unwrap().verified, 2);
}

/// Compressing a chunked section must produce one independently decodable frame per
/// chunk, not one frame for the whole payload.
#[test]
fn frames_align_to_chunk_boundaries() {
    let chunk_size = 4096u32;
    let first = vec![b'a'; chunk_size as usize];
    let second = vec![b'b'; chunk_size as usize];
    let plain: Vec<u8> = first.iter().chain(&second).copied().collect();

    let whole = compress::compress(&plain, chunk_size).unwrap();
    let frame_a = compress::compress(&first, 0).unwrap();
    let frame_b = compress::compress(&second, 0).unwrap();
    assert_eq!(whole, [frame_a.clone(), frame_b.clone()].concat());

    // Each frame decodes on its own, without its predecessor's output.
    assert_eq!(
        compress::decompress(&frame_a, chunk_size as u64).unwrap(),
        first
    );
    assert_eq!(
        compress::decompress(&frame_b, chunk_size as u64).unwrap(),
        second
    );
}

/// The two caps are checked before the decoder runs. A bomb is refused, not
/// expanded.
#[test]
fn caps_reject_a_bomb_before_decompression() {
    // Ratio cap: one stored byte claiming 64 MiB of plaintext.
    assert!(matches!(
        compress::check_caps(64 * 1024 * 1024, 1),
        Err(Error::CompressionRatioExceeded { .. })
    ));
    // Absolute cap: a declared output above the constant.
    assert!(matches!(
        compress::check_caps(compress::MAX_DECOMPRESSED_SECTION + 1, u64::MAX),
        Err(Error::CompressionOutputTooLarge { .. })
    ));
    // A legal declaration passes both.
    assert!(compress::check_caps(4096, 4096).is_ok());
    // Decompressing with a hostile declared length is refused before the decoder.
    assert!(compress::decompress(b"\x28\xb5\x2f\xfd", 1 << 40).is_err());
}

/// A stored stream that decodes to a different length than declared is rejected,
/// so compression cannot smuggle bytes past the committed plaintext length.
#[test]
fn a_wrong_declared_length_is_rejected() {
    let frame = compress::compress(b"abcdef", 0).unwrap();
    assert!(matches!(
        compress::decompress(&frame, 5),
        Err(Error::DecompressedLength { .. })
    ));
}

/// R20: the manifest is never compressed.
#[test]
fn the_manifest_is_never_compressed() {
    let err = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest())
                .compressed(),
        ],
    )
    .unwrap_err();
    assert!(matches!(err, Error::Inconsistent { .. }), "{err:?}");
}

/// A compressed section whose bytes are tampered with fails its root check rather
/// than being served.
#[test]
fn a_tampered_compressed_section_fails_verification() {
    let plain = b"the quick brown fox".repeat(50);
    let mut file = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest()),
            SectionSpec::inline(SectionKind::Artifact, 1, SectionFlags::empty(), &plain)
                .compressed(),
        ],
    )
    .unwrap();
    let b = ctf_format::Bundle::parse(&file).unwrap();
    let record = *b.section(1).unwrap();
    // Flip a byte inside the stored frame; the commitment root still covers the
    // record, so a re-parse of the whole file succeeds structurally, but reading
    // the section must fail.
    let at = record.offset as usize + 1;
    file[at] ^= 0xff;
    let b2 = ctf_format::Bundle::parse(&file).unwrap();
    assert!(b2.section_bytes(&b2.sections[1]).is_err());
}
