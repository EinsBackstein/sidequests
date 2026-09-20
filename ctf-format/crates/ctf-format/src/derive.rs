//! Derived flags and stage keys (design §7). Ticket 15.
//!
//! A bundle stores the derivation *rule*, never a flag value: the seed is a
//! function of `event_secret` (a 32-byte KMS/HSM value that never enters a
//! bundle), the challenge identity, and the subject. A leaked bundle therefore
//! leaks nothing — no flag byte and no secret byte occurs anywhere in the file.
//!
//! # The construction
//!
//! ```text
//! LP(x) = u32_le(len(x)) ‖ x
//!
//! seed(challenge, subject) = HKDF-SHA-256(
//!     ikm  = event_secret,
//!     salt = "ctf/seed/v1",
//!     info = LP(chal_id) ‖ u64_le(chal_version) ‖ LP(subject_id) )
//!
//! flag(subject) = base32_lower( HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..10] )
//!
//! stage_key(prev_flag, N) = HKDF-SHA-256(
//!     ikm  = prev_flag.as_bytes(),
//!     salt = "ctf/stage/v1",
//!     info = u32_le(N) )
//! ```
//!
//! # Encoding rule, and the one place it differs from the design sketch
//!
//! Every `‖` above joins **fixed-width fields only**; a variable-length input is
//! length-prefixed first (design §7, spec §20). Without `LP`, `chal_id ‖ subject_id`
//! has the two spellings `("ab","c")` and `("a","bc")` for two different subjects,
//! so per-subject attribution fails open with no error anywhere.
//!
//! `chal_version` enters as a fixed-width `u64_le`, **not** `LP(chal_version)`.
//! The design sketch wrote `LP(chal_version)` for a variable-width reading; this
//! module fixes the encoding to the unambiguous fixed-width one, because the
//! manifest's `version` is a `u64` and a fixed-width field never takes a length
//! prefix (spec §2: "Every `‖` below joins fixed-width fields only, except where
//! `LP` length-prefixes a variable-length input"). The two readings produce
//! different `info` bytes for every version, so this is a pinned choice rather
//! than an undefined one.
//!
//! # Flag size
//!
//! `flag` is exactly 16 characters: 10 bytes is 80 bits, and RFC 4648 base32
//! encodes 10 bytes as exactly 16 symbols with no padding. Design §7 records the
//! 80-bit ceiling inherent to deriving a stage key from what a player types; a
//! challenge that needs a real 128-bit boundary would choose a longer flag, which
//! is a per-challenge decision (`base32_lower` handles any byte length), not a
//! format constant.
//!
//! # The one KDF, reused
//!
//! Both derivations call [`HkdfSha256`], the crate's `kdf` role, rather than a
//! bespoke construction. HMAC-SHA-256 comes from `aws-lc-rs`, already a
//! dependency; no new primitive enters the stack.

use aws_lc_rs::hmac;

use crate::Role;
use crate::crypto::kdf::HkdfSha256;
use crate::crypto::lp;
use crate::suite::{Kdf, SuiteError};

/// Domain label for the per-subject seed derivation. ASCII, no terminator, no
/// length prefix: it is the HKDF salt.
pub const SEED_LABEL: &[u8] = b"ctf/seed/v1";
/// Domain label for the flag derivation. ASCII, no terminator, no length prefix:
/// it is the HMAC message.
pub const FLAG_LABEL: &[u8] = b"ctf/flag/v1";
/// Domain label for a stage key. ASCII, no terminator, no length prefix: it is
/// the HKDF salt.
pub const STAGE_LABEL: &[u8] = b"ctf/stage/v1";

/// `event_secret` is exactly this many bytes; anything else is rejected rather
/// than accepted and padded.
const EVENT_SECRET_LEN: usize = 32;

/// The output length of every derivation here. A seed and a stage key are both
/// content keys, and the frozen content-key size is 32 bytes (spec §12).
const KEY_LEN: usize = 32;

/// The flag is 10 bytes of the HMAC tag, i.e. 80 bits, which base32 renders as
/// exactly 16 symbols.
const FLAG_BYTES: usize = 10;

/// `seed(challenge, subject)` — the per-subject root of the flag derivation.
///
/// `event_secret` MUST be exactly 32 bytes; any other length is a
/// [`SuiteError::InvalidLength`] naming the `kdf` role, never a silently padded
/// value. `chal_id` and `subject_id` are UTF-8 strings and are length-prefixed;
/// `chal_version` is a fixed-width `u64_le` and is not (see the module docs).
pub fn subject_seed(
    event_secret: &[u8],
    chal_id: &str,
    chal_version: u64,
    subject_id: &str,
) -> Result<[u8; 32], SuiteError> {
    if event_secret.len() != EVENT_SECRET_LEN {
        return Err(SuiteError::InvalidLength {
            role: Role::Kdf,
            expected: EVENT_SECRET_LEN,
            got: event_secret.len(),
        });
    }

    // LP(chal_id) ‖ u64_le(chal_version) ‖ LP(subject_id). The version is
    // fixed-width, so it takes no length prefix.
    let mut info = Vec::new();
    lp(&mut info, chal_id.as_bytes());
    info.extend_from_slice(&chal_version.to_le_bytes());
    lp(&mut info, subject_id.as_bytes());

    let mut seed = [0u8; KEY_LEN];
    HkdfSha256::new().derive(event_secret, SEED_LABEL, &info, &mut seed)?;
    Ok(seed)
}

/// The per-subject flag: `base32_lower(HMAC-SHA-256(seed, "ctf/flag/v1")[0..10])`.
///
/// Exactly 16 lowercase base32 characters. Infallible: the HMAC tag is 32 bytes,
/// so truncating to [`FLAG_BYTES`] cannot fail.
pub fn flag(seed: &[u8; 32]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, seed);
    let tag = hmac::sign(&key, FLAG_LABEL);
    // The digest is 32 bytes; the slice is always present. `unwrap_or` keeps the
    // infallible signature without an `unwrap`/`expect` in library code.
    let truncated = tag.as_ref().get(..FLAG_BYTES).unwrap_or(&[]);
    base32_lower(truncated)
}

/// A stage key derived from the previous stage's flag.
///
/// Stage gating is "enforced by math, not by dashboard logic" (design §7): stage
/// *N*'s section key is exactly this HKDF over what a player submitted for stage
/// *N-1*, so opening stage *N* without solving *N-1* costs 2^80 against a held
/// bundle. `N` enters as a fixed-width `u32_le`, so `stage:1` followed by
/// `stage:11` cannot collide with `stage:11` followed by `stage:1`.
pub fn stage_key(previous_flag: &str, stage: u32) -> Result<[u8; 32], SuiteError> {
    let info = stage.to_le_bytes();
    let mut key = [0u8; KEY_LEN];
    HkdfSha256::new().derive(previous_flag.as_bytes(), STAGE_LABEL, &info, &mut key)?;
    Ok(key)
}

/// RFC 4648 §6 base32, lowercase, unpadded.
///
/// Alphabet `abcdefghijklmnopqrstuvwxyz234567`. Emits `ceil(8n/5)` symbols and
/// zero-fills the final partial group's low bits, so it is correct for any byte
/// length, not only multiples of 5.
pub fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    // ceil(8n / 5) output symbols. Fixed arithmetic on a usize length cannot
    // overflow before the bytes themselves are allocated.
    let out_len = bytes.len().saturating_mul(8).div_ceil(5);
    let mut out = String::with_capacity(out_len);

    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            // Masked to five bits, so `index` is always in `0..32`.
            let symbol = ALPHABET.get(index).copied().unwrap_or(b'a');
            out.push(symbol as char);
        }
        // Keep only the unconsumed low bits; without this the accumulator grows
        // without bound across a long input.
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        let symbol = ALPHABET.get(index).copied().unwrap_or(b'a');
        out.push(symbol as char);
    }

    out
}
