//! Derived flags and stage keys (design §7, spec §22). Ticket 15.
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
//! flag_with_bytes(seed, n) = base32_lower(
//!     HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..clamp(n, 1, 32)] )
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
//! The flag length is a **per-challenge choice, not a format constant** (spec
//! §22.3): a challenge that needs a real 128-bit boundary uses a longer derived
//! flag, while the default stays short enough to read aloud and type. [`flag`] is
//! exactly 16 characters, the 10-byte / 80-bit default (spec §22.3 rule DF3);
//! [`flag_with_bytes`] exposes the choice and renders `ceil(8n/5)` symbols for `n`
//! tag bytes — 16 bytes is exactly the 26 base32 characters of that 128-bit
//! boundary (spec §22.3, §22.5).
//!
//! The ceiling is the HMAC-SHA-256 tag itself: 32 bytes / 256 bits, rendered as 52
//! symbols. Design §7 records the 80-bit ceiling inherent to deriving a stage key
//! from what a player types; a longer flag raises that ceiling because the stage
//! key inherits the flag's entropy, and [`base32_lower`] handles any byte length.
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

/// The full HMAC-SHA-256 tag length in bytes. A derived flag can never carry more
/// than the tag's own 256 bits, so [`flag_with_bytes`] clamps its request to this.
const TAG_LEN: usize = 32;

/// The default flag is 10 bytes of the HMAC tag, i.e. 80 bits, which base32
/// renders as exactly 16 symbols (spec §22.3 rule DF3).
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
/// Exactly 16 lowercase base32 characters, the [`FLAG_BYTES`]-byte / 80-bit
/// default of spec §22.3. This is [`flag_with_bytes`] at that length; it stays the
/// stable entry point a caller reaches for when the challenge does not opt into a
/// longer boundary.
pub fn flag(seed: &[u8; 32]) -> String {
    flag_with_bytes(seed, FLAG_BYTES)
}

/// A derived flag of a caller-chosen byte length, for a challenge that needs more
/// than the 80-bit default.
///
/// Spec §22.3 makes the flag length a per-challenge choice: the default 10 bytes
/// is 80 bits / 16 symbols, below the 128-bit floor the rest of the stack targets,
/// and a challenge that needs that boundary asks for 16 bytes, which base32 renders
/// as 26 symbols. `bytes` is the number of HMAC tag bytes to keep and the tag is
/// [`TAG_LEN`] = 32 bytes, so the result is `ceil(8*bytes/5)` lowercase base32
/// characters of the same `HMAC-SHA-256(seed, "ctf/flag/v1")` tag [`flag`] uses.
///
/// Infallible, like [`flag`]: `bytes` is **clamped** into `1..=TAG_LEN`. `0` reads
/// as one byte (never an empty flag) and anything above [`TAG_LEN`] reads as the
/// full tag, because asking for more bits than the tag carries is a length mistake
/// the function cannot satisfy, not a security condition it can act on. The clamp is
/// the documented behavior; a caller that wants an out-of-range length rejected
/// checks it before calling. `flag_with_bytes(seed, FLAG_BYTES) == flag(seed)`.
pub fn flag_with_bytes(seed: &[u8; 32], bytes: usize) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, seed);
    let tag = hmac::sign(&key, FLAG_LABEL);
    // The digest is 32 bytes and `bytes` is clamped to 1..=32, so the slice is
    // always present. `unwrap_or` keeps the infallible signature without an
    // `unwrap`/`expect` in library code.
    let truncated = tag.as_ref().get(..bytes.clamp(1, TAG_LEN)).unwrap_or(&[]);
    base32_lower(truncated)
}

/// A stage key derived from the previous stage's flag.
///
/// Stage gating is "enforced by math, not by dashboard logic" (design §7, spec
/// §22.4 rule DF4): stage *N*'s section key is exactly this HKDF over what a player
/// submitted for stage *N-1*, so opening stage *N* without solving *N-1* costs 2^80
/// against a held bundle (more if the challenge chose a longer flag, §22.3). There
/// is no input here that is a function of `stage` alone — remove the previous flag
/// and the key does not exist — so stage *N* is not derivable from its number. `N`
/// enters as a fixed-width `u32_le`, so `stage:1` followed by `stage:11` cannot
/// collide with `stage:11` followed by `stage:1`.
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
