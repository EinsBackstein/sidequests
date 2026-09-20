//! Derived-flag tests (ticket 15, design §7, spec §20).
//!
//! The construction is pinned by independent known-answer vectors (test 5), and by
//! the leak invariant that a bundle carries the derivation *rule*, never a flag
//! value or the event secret (test 7).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::derive::{base32_lower, flag, stage_key, subject_seed};
use ctf_format::{
    Manifest, Role, SectionFlags, SectionKind, SectionSpec, SuiteError, write_bundle,
};

const SUITE: u16 = 1;

/// The known-answer secret: bytes `00..1f`.
fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

/// The second known-answer secret: 32 bytes of `0xab`.
const SECRET_2: [u8; 32] = [0xab; 32];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Substring search over raw bytes; used by the leak test.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// 1. Determinism
// ---------------------------------------------------------------------------

#[test]
fn same_inputs_derive_the_same_seed_and_flag() {
    let a = subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap();
    let b = subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap();
    assert_eq!(a, b);
    assert_eq!(flag(&a), flag(&b));

    // And the derived flag is a pure function again: re-deriving the seed from the
    // same inputs reproduces it, with no state carried between calls.
    let again = subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap();
    assert_eq!(flag(&again), flag(&a));
}

/// A seed is bound to the challenge identity and version, not just the subject:
/// the same subject on a re-packed challenge is a different flag.
#[test]
fn the_seed_binds_the_challenge_and_version() {
    let base = subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap();
    let other_id = subject_seed(&secret(), "baby-rop", 3, "team-alpha").unwrap();
    let other_version = subject_seed(&secret(), "whos-that-bird", 4, "team-alpha").unwrap();
    let other_secret = subject_seed(&SECRET_2, "whos-that-bird", 3, "team-alpha").unwrap();
    assert_ne!(base, other_id);
    assert_ne!(base, other_version);
    assert_ne!(base, other_secret);
}

// ---------------------------------------------------------------------------
// 2. Per-subject and per-version separation
// ---------------------------------------------------------------------------

#[test]
fn different_subjects_and_versions_derive_different_flags() {
    let alice = flag(&subject_seed(&secret(), "whos-that-bird", 3, "alice").unwrap());
    let bob = flag(&subject_seed(&secret(), "whos-that-bird", 3, "bob").unwrap());
    let v4 = flag(&subject_seed(&secret(), "whos-that-bird", 4, "alice").unwrap());
    assert_ne!(alice, bob, "two subjects must not share a flag");
    assert_ne!(alice, v4, "a version bump must re-key the subject");

    // The LP encoding is what closes the concatenation ambiguity: `("ab","c")` and
    // `("a","bc")` must not collide.
    let ab_c = subject_seed(&secret(), "ab", 1, "c").unwrap();
    let a_bc = subject_seed(&secret(), "a", 1, "bc").unwrap();
    assert_ne!(ab_c, a_bc);
}

// ---------------------------------------------------------------------------
// 3. Flag shape
// ---------------------------------------------------------------------------

#[test]
fn flags_are_16_base32_characters() {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    for (id, version, subject) in [
        ("whos-that-bird", 0, "player"),
        ("baby-rop", 3, "team-alpha"),
        ("x", u64::MAX, ""),
    ] {
        let f = flag(&subject_seed(&secret(), id, version, subject).unwrap());
        assert_eq!(f.len(), 16, "flag {f:?} is not 16 characters");
        assert!(
            f.bytes().all(|b| alphabet.contains(&b)),
            "flag {f:?} left the base32 alphabet"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Stage keys
// ---------------------------------------------------------------------------

#[test]
fn stage_keys_are_deterministic_and_domain_separated() {
    let f0 = flag(&subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap());
    let f1 = flag(&subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap());
    assert_eq!(f0, f1);

    let s1 = stage_key(&f0, 1).unwrap();
    let s1_again = stage_key(&f0, 1).unwrap();
    assert_eq!(s1, s1_again, "stage_key must be deterministic");

    let s2 = stage_key(&f0, 2).unwrap();
    assert_ne!(s1, s2, "different N must derive different keys");

    let other_prev = flag(&subject_seed(&secret(), "whos-that-bird", 3, "bob").unwrap());
    let s1_other = stage_key(&other_prev, 1).unwrap();
    assert_ne!(
        s1, s1_other,
        "different previous flags must derive different keys"
    );
}

// ---------------------------------------------------------------------------
// 5. Independent known-answer vectors
// ---------------------------------------------------------------------------

/// Vectors computed independently with `python3`, using `hmac` and `hashlib` (no
/// part of this crate). The Python, run verbatim:
///
/// ```python
/// import hmac, hashlib
///
/// def hkdf_sha256(ikm, salt, info, length=32):
///     prk = hmac.new(salt, ikm, hashlib.sha256).digest()
///     okm, t, i = b'', b'', 1
///     while len(okm) < length:
///         t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
///         okm += t
///         i += 1
///     return okm[:length]
///
/// def lp(x): return len(x).to_bytes(4, 'little') + x
///
/// def base32_lower(b):
///     alpha = b"abcdefghijklmnopqrstuvwxyz234567"
///     out, buf, bits = "", 0, 0
///     for x in b:
///         buf, bits = (buf << 8) | x, bits + 8
///         while bits >= 5:
///             bits -= 5
///             out += chr(alpha[(buf >> bits) & 31])
///         buf &= (1 << bits) - 1
///     if bits:
///         out += chr(alpha[(buf << (5 - bits)) & 31])
///     return out
///
/// def seed(secret, chal_id, version, subject):
///     info = lp(chal_id.encode()) + version.to_bytes(8, 'little') + lp(subject.encode())
///     return hkdf_sha256(secret, b"ctf/seed/v1", info)
///
/// def flag(s):
///     return base32_lower(hmac.new(s, b"ctf/flag/v1", hashlib.sha256).digest()[:10])
///
/// def stage_key(prev, n):
///     return hkdf_sha256(prev.encode(), b"ctf/stage/v1", n.to_bytes(4, 'little'))
///
/// for secret, cid, ver, subj in [
///     (bytes(range(32)), "whos-that-bird", 3, "team-alpha"),
///     (bytes([0xAB]) * 32, "baby-rop", 1, "player-7"),
/// ]:
///     s = seed(secret, cid, ver, subj); f = flag(s)
///     print(s.hex(), f, stage_key(f, 1).hex(), stage_key(f, 2).hex())
///
/// # seed1 = 20b0f7556a9de4382cda2501eb74791e85474831adfe1ccf84dab59305099f6e
/// # flag1 = oil5phz5xep2ss7j
/// # stage1(1) = 08eeb095eab82304c338dc14155b4975ee71523c41dfbca7f90927f46d281552
/// # stage1(2) = 629c4e12879a15640c3a81b7ef551d08b5b7a0cc979faa6d4b7078e3ecdebf0e
/// # seed2 = cbc510e9f8a31e9efa8d37893f94dd62f479b60c32c01bd59c9350b7728d49cc
/// # flag2 = hsd3aynpnbo6z3d6
/// # stage2(1) = 000850deded12cbcd6f9a3edb3f8bda72955e90a4aa3e0acfc8c346b2c1b0ead
/// # stage2(2) = 295fb759b9073807828da0d25ba7460ffd3515e8b5d24cbc82fb167e7f69377f
/// ```
#[test]
fn known_answer_vectors_from_python() {
    let s1 = subject_seed(&secret(), "whos-that-bird", 3, "team-alpha").unwrap();
    assert_eq!(
        s1.to_vec(),
        hex("20b0f7556a9de4382cda2501eb74791e85474831adfe1ccf84dab59305099f6e")
    );
    let f1 = flag(&s1);
    assert_eq!(f1, "oil5phz5xep2ss7j");
    assert_eq!(
        stage_key(&f1, 1).unwrap().to_vec(),
        hex("08eeb095eab82304c338dc14155b4975ee71523c41dfbca7f90927f46d281552")
    );
    assert_eq!(
        stage_key(&f1, 2).unwrap().to_vec(),
        hex("629c4e12879a15640c3a81b7ef551d08b5b7a0cc979faa6d4b7078e3ecdebf0e")
    );

    let s2 = subject_seed(&SECRET_2, "baby-rop", 1, "player-7").unwrap();
    assert_eq!(
        s2.to_vec(),
        hex("cbc510e9f8a31e9efa8d37893f94dd62f479b60c32c01bd59c9350b7728d49cc")
    );
    let f2 = flag(&s2);
    assert_eq!(f2, "hsd3aynpnbo6z3d6");
    assert_eq!(
        stage_key(&f2, 1).unwrap().to_vec(),
        hex("000850deded12cbcd6f9a3edb3f8bda72955e90a4aa3e0acfc8c346b2c1b0ead")
    );
    assert_eq!(
        stage_key(&f2, 2).unwrap().to_vec(),
        hex("295fb759b9073807828da0d25ba7460ffd3515e8b5d24cbc82fb167e7f69377f")
    );
}

/// A malformed secret is rejected by name, never padded or truncated.
#[test]
fn a_non_32_byte_event_secret_is_rejected() {
    for len in [0usize, 31, 33, 64] {
        let got = subject_seed(&vec![0u8; len], "x", 0, "y").unwrap_err();
        assert_eq!(
            got,
            SuiteError::InvalidLength {
                role: Role::Kdf,
                expected: 32,
                got: len,
            }
        );
    }
}

// ---------------------------------------------------------------------------
// 6. base32 RFC 4648 vectors
// ---------------------------------------------------------------------------

/// RFC 4648 §10 uses the uppercase alphabet; the expected values are lowercased
/// and unpadded here. `fooba` is 5 bytes, so it renders as exactly 8 symbols with
/// no final partial group (`mzxw6ytb`), which is the case the ticket's prose
/// mis-copied from `foobar`.
#[test]
fn base32_matches_rfc_4648() {
    for (input, expected) in [
        (b"".as_slice(), ""),
        (b"f", "my"),
        (b"fo", "mzxq"),
        (b"foo", "mzxw6"),
        (b"foob", "mzxw6yq"),
        (b"fooba", "mzxw6ytb"),
        (b"foobar", "mzxw6ytboi"),
    ] {
        assert_eq!(base32_lower(input), expected, "base32({input:?})");
    }

    // 10 bytes is exactly 16 symbols with no padding — the flag width.
    assert_eq!(base32_lower(&[0xff; 10]).len(), 16);
    assert_eq!(base32_lower(&[0x00; 10]), "aaaaaaaaaaaaaaaa");
    // Non-multiples of 5 round up and zero-fill the final low bits.
    assert_eq!(base32_lower(&[0x00]).len(), 2);
    assert_eq!(base32_lower(&[0x00]), "aa");
    assert_eq!(base32_lower(&[0xff]).len(), 2);
}

// ---------------------------------------------------------------------------
// 7. The bundle carries the rule, never the value
// ---------------------------------------------------------------------------

/// The whole point of derived flags (design §4, Pillar 2): a leaked bundle leaks
/// nothing. The flag's ASCII bytes and the event secret's bytes must not occur
/// anywhere in the file — not in the manifest, not in the footer, not in any
/// padding.
#[test]
fn a_bundle_contains_neither_the_flag_nor_the_secret() {
    let secret = secret();
    let challenge = "whos-that-bird";
    let subject = "team-alpha";
    let version = 3;

    let seed = subject_seed(&secret, challenge, version, subject).unwrap();
    let the_flag = flag(&seed);
    assert_eq!(the_flag, "oil5phz5xep2ss7j");

    let manifest = Manifest::minimal(challenge, "Who's That Bird", &["manifest"])
        .unwrap()
        .encode()
        .unwrap();
    let bundle = write_bundle(
        SUITE,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest,
        )],
    )
    .unwrap();

    assert!(
        !contains(&bundle, the_flag.as_bytes()),
        "the bundle contains the flag value"
    );
    assert!(
        !contains(&bundle, &secret),
        "the bundle contains the event secret"
    );
    // Sanity: the search is real, not trivially false. The challenge id that the
    // bundle legitimately carries is found by the same predicate.
    assert!(contains(&bundle, challenge.as_bytes()));
}
