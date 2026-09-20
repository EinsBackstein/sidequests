//! Encrypted sections, end to end (ticket 16, spec §20.2, §21).
//!
//! A section with `enc = 1` is compressed (when `comp = 1`), sealed with a fresh
//! content key under the AEAD-STREAM construction, and that content key is wrapped
//! to each recipient as a key envelope in the bundle's `keys` section. A holder of
//! the matching secret key recovers the plaintext; a reader without the key gets
//! nothing, because [`ctf_format::Bundle::section_bytes`] refuses an encrypted
//! section outright rather than returning ciphertext.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::cbor::Value;
use ctf_format::envelope::Envelope;
use ctf_format::suite::{KemKeyPair, suite};
use ctf_format::{
    Bundle, Compression, Encryption, Manifest, Recipient, SectionFlags, SectionKind, SectionRecord,
    SectionSpec, write_bundle,
};

const SUITE: u16 = 1;

fn keypair(suite_id: u16) -> KemKeyPair {
    suite(suite_id).unwrap().kem().unwrap().generate().unwrap()
}

/// A bundle with a `manifest`, an encrypted `secret` artifact, and the `keys`
/// section that delivers its content key. Returns the file and the recipient
/// keypair the artifact is sealed to.
fn sealed_bundle(suite_id: u16, plaintext: &[u8], comp: Compression) -> (Vec<u8>, KemKeyPair) {
    let recipient = keypair(suite_id);
    let manifest = Manifest::build(
        "enc-chal",
        "Encrypted Challenge",
        &["manifest", "secret", "keys"],
        Vec::new(),
    )
    .unwrap();
    let manifest_bytes = manifest.encode().unwrap();

    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];

    let mut secret = SectionSpec::inline(
        SectionKind::Artifact,
        1,
        SectionFlags(SectionFlags::SEALED),
        plaintext,
    )
    .chunked(4096)
    .encrypted(&recipients);
    secret.comp = comp;

    let file = write_bundle(
        suite_id,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            secret,
            SectionSpec::envelopes(SectionKind::Keys, 2),
        ],
    )
    .unwrap();
    (file, recipient)
}

fn secret_record<'a>(b: &'a Bundle<'_>) -> &'a SectionRecord {
    b.section(1).unwrap()
}

/// The writer emits the encoding marker and a `keys` section, and the plaintext is
/// recoverable by the holder of the content key through the envelope.
#[test]
fn an_encrypted_section_round_trips_through_its_envelope() {
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let (file, recipient) = sealed_bundle(SUITE, plaintext, Compression::None);
    let b = Bundle::parse(&file).unwrap();

    let record = secret_record(&b);
    assert_eq!(
        record.enc,
        Encryption::AeadStream,
        "writer must set enc = 1"
    );
    assert!(record.flags.sealed());
    assert_ne!(record.root, [0u8; 32]);

    let key = b
        .section_content_key(record, &recipient.secret_key, "seal")
        .unwrap();
    let recovered = b.decrypt_section_bytes(record, &key).unwrap();
    assert_eq!(recovered, plaintext);
}

/// A reader without the key refuses and returns no bytes: the serving boundary
/// never hands out ciphertext, and a wrong key fails the AEAD tag.
#[test]
fn a_reader_without_the_key_gets_nothing() {
    let plaintext = b"secret sauce";
    let (file, recipient) = sealed_bundle(SUITE, plaintext, Compression::None);
    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);

    // No key at all: the serving boundary refuses an encrypted section.
    assert!(b.section_bytes(record).is_err());

    // A wrong secret key cannot recover a content key.
    let other = keypair(SUITE);
    assert!(
        b.section_content_key(record, &other.secret_key, "seal")
            .is_err(),
        "an unrelated recipient must not unwrap the content key"
    );

    // A wrong content key cannot decrypt.
    let wrong = [0x11u8; 32];
    assert!(b.decrypt_section_bytes(record, &wrong).is_err());
    let _ = recipient;
}

/// `comp = 1` composes with `enc = 1`: each zstd frame is one STREAM chunk, and the
/// plaintext root still verifies after decompression.
#[test]
fn compression_composes_with_encryption() {
    let plaintext = vec![0x41u8; 20_000];
    let (file, recipient) = sealed_bundle(SUITE, &plaintext, Compression::Zstd);
    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);

    assert_eq!(record.comp, Compression::Zstd);
    assert_eq!(record.enc, Encryption::AeadStream);
    // Compressed then encrypted, so the stored size is nothing like the plaintext.
    assert!(record.len_stored < record.len_plain);

    let key = b
        .section_content_key(record, &recipient.secret_key, "seal")
        .unwrap();
    assert_eq!(b.decrypt_section_bytes(record, &key).unwrap(), plaintext);
}

/// Suite 2 (XChaCha20-Poly1305) encrypts and reads back identically.
#[test]
fn encryption_round_trips_on_suite_2() {
    let plaintext = b"suite two works too";
    let (file, recipient) = sealed_bundle(2, plaintext, Compression::None);
    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);
    let key = b
        .section_content_key(record, &recipient.secret_key, "seal")
        .unwrap();
    assert_eq!(b.decrypt_section_bytes(record, &key).unwrap(), plaintext);
}

/// The plaintext never appears in the file, and the `keys` section carries only
/// ciphertext: an envelope holds the hybrid KEM ciphertext and the sealed key, not
/// the content key or the plaintext.
#[test]
fn the_file_contains_no_plaintext() {
    let plaintext = b"UNIQUE-PLAINTEXT-MARKER-1234567890";
    let (file, _recipient) = sealed_bundle(SUITE, plaintext, Compression::None);

    assert!(
        !contains(&file, plaintext),
        "the plaintext must not appear anywhere in the file"
    );
}

/// A `keys` section is not sealed, so a recipient can always reach the envelope;
/// its plaintext decodes to an array of envelopes, each naming the section it
/// unlocks and carrying no content key in the clear.
#[test]
fn the_keys_section_is_readable_and_names_its_section() {
    let (file, _recipient) = sealed_bundle(SUITE, b"data", Compression::None);
    let b = Bundle::parse(&file).unwrap();
    let keys = b
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Keys)
        .unwrap();
    assert!(!keys.flags.sealed());

    let bytes = b.section_bytes(keys).unwrap();
    let value = Value::decode(&bytes).unwrap();
    let envelopes: Vec<Envelope> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Envelope::from_cbor(v).unwrap())
        .collect();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].name_id, 1);
    assert_eq!(envelopes[0].context, "seal");
}

/// A stage-gated section is `PLAYER_VISIBLE` and encrypted, never `SEALED` (§5.3),
/// and its content key is delivered to a `stage:N` recipient.
#[test]
fn a_stage_gated_section_is_player_visible_not_sealed() {
    let recipient = keypair(SUITE);
    let manifest = Manifest::build(
        "staged",
        "Staged",
        &["manifest", "stage3", "keys"],
        Vec::new(),
    )
    .unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let plaintext = b"stage three artifact";

    let recipients = [Recipient {
        context: "stage:3",
        public_key: &recipient.public_key,
    }];
    let file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                plaintext,
            )
            .chunked(4096)
            .encrypted(&recipients),
            SectionSpec::envelopes(SectionKind::Keys, 2),
        ],
    )
    .unwrap();

    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);
    assert!(record.flags.player_visible());
    assert!(!record.flags.sealed());
    let key = b
        .section_content_key(record, &recipient.secret_key, "stage:3")
        .unwrap();
    assert_eq!(b.decrypt_section_bytes(record, &key).unwrap(), plaintext);
}

/// A section that spans several chunks round-trips, so the STREAM chunk framing is
/// exercised (not just the single-chunk case).
#[test]
fn a_multi_chunk_encrypted_section_round_trips() {
    let plaintext = vec![0x5au8; 12_345];
    let (file, recipient) = sealed_bundle(SUITE, &plaintext, Compression::None);
    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);
    // 12_345 bytes at 4096 per chunk is four chunks.
    assert_eq!(record.len_stored, record.len_plain + 4 * (16 + 4));
    let key = b
        .section_content_key(record, &recipient.secret_key, "seal")
        .unwrap();
    assert_eq!(b.decrypt_section_bytes(record, &key).unwrap(), plaintext);
}

/// The writer refuses to emit a bundle whose encrypted content key no `keys`
/// section carries: it could never be opened.
#[test]
fn an_encrypted_section_without_a_keys_section_is_refused() {
    let recipient = keypair(SUITE);
    let manifest = Manifest::build("c", "C", &["manifest", "secret"], Vec::new()).unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];
    let result = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(SectionKind::Artifact, 1, SectionFlags::empty(), b"x")
                .chunked(4096)
                .encrypted(&recipients),
        ],
    );
    assert!(result.is_err());
}

/// A zero `chunk_size` with `enc = 1` is refused by the writer (R15).
#[test]
fn an_encrypted_section_must_be_chunked() {
    let recipient = keypair(SUITE);
    let manifest = Manifest::build("c", "C", &["manifest", "secret", "keys"], Vec::new()).unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];
    let result = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(SectionKind::Artifact, 1, SectionFlags::empty(), b"x")
                .encrypted(&recipients),
            SectionSpec::envelopes(SectionKind::Keys, 2),
        ],
    );
    assert!(result.is_err());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Ticket 47: stage 3 stays opaque ciphertext when the whole bundle is handed over,
/// with the platform's gating logic deliberately not in the picture. The gate is
/// cryptographic — stage 3's content key is `stage_key(flag_2, 3)`, and the bundle
/// never carries it.
#[test]
fn stage_three_stays_opaque_without_stage_twos_flag() {
    use ctf_format::derive::{flag, stage_key, subject_seed};

    let event_secret = [0x24u8; 32];
    let seed_alpha = subject_seed(&event_secret, "multi-stage", 1, "team-alpha").unwrap();
    let flag2 = flag(&seed_alpha);
    let stage3_key = stage_key(&flag2, 3).unwrap();

    let manifest = Manifest::build(
        "multi-stage",
        "Multi Stage",
        &["manifest", "stage3"],
        Vec::new(),
    )
    .unwrap();
    let manifest_bytes = manifest.encode().unwrap();
    let plaintext = b"STAGE-3-ONLY-CONTENT";

    let file = write_bundle(
        SUITE,
        &[
            SectionSpec::inline(
                SectionKind::Manifest,
                0,
                SectionFlags::empty(),
                &manifest_bytes,
            ),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                plaintext,
            )
            .chunked(4096)
            .encrypted_with_key(stage3_key, &[]),
        ],
    )
    .unwrap();

    // The whole bundle is in hand. No gating decision is consulted: the bytes are
    // simply sealed under a key the bundle does not contain.
    assert!(
        !contains(&file, plaintext),
        "stage 3 must be opaque ciphertext"
    );
    let b = Bundle::parse(&file).unwrap();
    let record = secret_record(&b);
    assert!(record.flags.player_visible());
    assert!(!record.flags.sealed());

    // With stage 2's flag — and only then — the key is recomputed and it opens.
    let recovered = stage_key(&flag2, 3).unwrap();
    assert_eq!(recovered, stage3_key);
    assert_eq!(
        b.decrypt_section_bytes(record, &recovered).unwrap(),
        plaintext
    );

    // A different subject's stage-2 flag derives a different stage-3 key, and the
    // AEAD tag fails. The key is nowhere in the file to be found.
    let seed_beta = subject_seed(&event_secret, "multi-stage", 1, "team-beta").unwrap();
    let wrong_key = stage_key(&flag(&seed_beta), 3).unwrap();
    assert_ne!(wrong_key, stage3_key);
    assert!(b.decrypt_section_bytes(record, &wrong_key).is_err());

    // Nor is stage 3 reachable from the stage number alone.
    assert!(b.decrypt_section_bytes(record, &[0u8; 32]).is_err());
}
