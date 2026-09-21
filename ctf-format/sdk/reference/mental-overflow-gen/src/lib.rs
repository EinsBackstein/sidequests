//! Deterministic generator for the reference `Mental Overflow` challenge.
//!
//! This is the Rust port of the reference Python generator (`src/script.py` in
//! `CTF-FlagFrenzy/challenges`), rewritten so the artifact is a pure function of
//! the seed and the host's determinism gate (rules G9/G10, spec §23) accepts it.
//!
//! # What was removed, and why
//!
//! The reference picks the two characters that stand in for the flag's braces
//! with `random.sample(...)`, which is exactly the nondeterminism the gate exists
//! to reject. The port derives those two characters from the seed instead
//! (`seed[0] % charset.len()` and `seed[1] % charset.len()`), so two runs on the
//! same seed choose the same braces. Everything else is a faithful port:
//!
//! 1. the flag is derived from the seed (spec §22.3) and rendered as `FF{…}`;
//! 2. each character becomes `"+" * ord(c) + ".>"`, wrapped at 80 columns, with a
//!    final `<` repeated once per character to reset the data pointer;
//! 3. the Brainfuck program is Base64-encoded and emitted as `challenge.bin`.
//!
//! The flag itself is the spec derivation,
//! `base32_lower(HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..10])`. It is
//! validated against an independent Python known-answer vector in the unit tests
//! below.
//!
//! # No imports
//!
//! SHA-256, HMAC, Base64, and the Brainfuck encoder are implemented here so the
//! module links nothing. The host rejects a module with any import (rule G2).

use ctf_generator_sdk::{export_generator, Generator, Outputs};

/// The generator the host instantiates. `Default` is all the SDK needs.
#[derive(Default)]
struct MentalOverflow;

impl Generator for MentalOverflow {
    fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str> {
        let flag = derive_flag(seed);
        let hashed_flag = format!("FF{{{flag}}}");

        // `string.ascii_letters + string.digits + "!@#$%^&*()"` from the reference.
        const CHARSET: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        let first = usize::from(seed.first().copied().unwrap_or(0)) % CHARSET.len();
        let second = usize::from(seed.get(1).copied().unwrap_or(0)) % CHARSET.len();
        let open = CHARSET[first] as char;
        let close = CHARSET[second] as char;

        // The reference replaces the braces with `"c"` (quote, char, quote).
        let brainfuck_flag = hashed_flag
            .replacen('{', &format!("\"{open}\""), 1)
            .replacen('}', &format!("\"{close}\""), 1);

        let script = brainfuck(&brainfuck_flag);
        out.add(
            "challenge.bin",
            base64_encode(script.as_bytes()).into_bytes(),
        );
        out.set_flag(flag);
        Ok(())
    }
}

export_generator!(MentalOverflow);

/// `base32_lower(HMAC-SHA-256(seed, "ctf/flag/v1")[0..10])` (spec §22.3).
fn derive_flag(seed: &[u8]) -> String {
    let tag = hmac_sha256(seed, b"ctf/flag/v1");
    base32_lower(&tag[..10])
}

/// The Brainfuck program the reference builds (spec of the challenge, not the
/// format): `"+" * ord(c) + ".>"` per character, wrapped at 80 columns, then a
/// `<` per character to reset the pointer.
fn brainfuck(text: &str) -> String {
    const LINE_LENGTH: usize = 80;

    let mut script = String::new();
    let mut current = 0usize;
    for ch in text.chars() {
        let mut code = String::with_capacity(ch as usize + 2);
        for _ in 0..(ch as u32) {
            code.push('+');
        }
        code.push('.');
        code.push('>');
        if current + code.len() > LINE_LENGTH {
            script.push('\n');
            current = 0;
        }
        script.push_str(&code);
        current += code.len();
    }

    let mut reset = String::new();
    for _ in 0..text.chars().count() {
        reset.push('<');
    }
    if current + reset.len() > LINE_LENGTH {
        script.push('\n');
    }
    script.push_str(&reset);
    script
}

/// Lowercase, unpadded Base32 (RFC 4648 alphabet) as the flag derivation uses it.
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Standard Base64 with `=` padding, the encoding the reference writes.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// HMAC-SHA-256 (RFC 2104).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;

    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&sha256(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= padded[i];
        outer_pad[i] ^= padded[i];
    }

    let mut inner = inner_pad.to_vec();
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = outer_pad.to_vec();
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// SHA-256 (FIPS 180-4).
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// The independent vector from `crates/ctf-format/tests/derive.rs`
    /// (`known_answer_vectors_from_python`), computed with Python's `hmac` and
    /// `hashlib`. This is the pair the CLI regression test also pins.
    #[test]
    fn flag_matches_the_independent_known_answer() {
        let seed = hex("20b0f7556a9de4382cda2501eb74791e85474831adfe1ccf84dab59305099f6e");
        assert_eq!(derive_flag(&seed), "oil5phz5xep2ss7j");
    }
}
