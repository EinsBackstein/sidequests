//! Zipception: a ZIP archive nested 150 times, ported to the `.ctf` format.
//!
//! The upstream challenge ([`EinsBackstein/Challenges`](https://github.com/EinsBackstein/Challenges))
//! is a Go service that builds a nested archive once per deployment and serves it
//! over HTTP. In this format the same archive is a **deterministic function of the
//! per-subject seed** (spec §22.2, §23): the generator rebuilds it for every team,
//! and the flag inside it is the flag that team was derived.
//!
//! What is preserved from upstream:
//!
//! - 150 layers, each wrapped in a 120-character directory component whose name
//!   starts with `layer_NNNN_of_0150_`.
//! - The innermost layer holds `flag.txt`; every other layer holds `next.zip`.
//! - Streaming the layers through memory is the intended solve; extracting in place
//!   still hits `PATH_MAX` / `MAX_PATH` around layer 9 / 2.
//!
//! What changed:
//!
//! - The layer names derive from the seed instead of a fixed `SEED` environment
//!   variable, so every subject gets a different archive.
//! - Entries are stored, not deflated. A pure-Rust deflate encoder would be another
//!   dependency in the guest, and the format cares about determinism, not size; the
//!   outer archive stays well under 100 KB.
//! - The flag is §22.3's derived value: 16 lowercase base32 characters. The
//!   upstream `FLAG_PREFIX`/`FLAG_SUFFIX` wrapper is a presentation choice the
//!   format does not carry, and the gate compares the bare derivation.
//!
//! The module is pure by construction: the host supplies no clock, network,
//! filesystem, or randomness (spec §23.1), so two runs on the same seed agree.

use ctf_generator_sdk::{export_generator, Generator, Outputs};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Nested archives, and the directory components they add. Upstream's defaults.
const LAYERS: usize = 150;
/// Characters per directory component (upstream `NAME_LEN`).
const NAME_LEN: usize = 120;
/// File inside every wrapping layer.
const ENTRY: &str = "next.zip";
/// File inside the innermost layer.
const CORE: &str = "flag.txt";
/// Output name declared by `generate.outputs` in `challenge.yaml`.
const OUTPUT: &str = "inception.zip";

/// Base62, the alphabet upstream uses for the random part of a layer name.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A fixed DOS timestamp (2023-11-14 22:13:20 UTC, upstream's default `Modified`).
/// Stored entries would otherwise pick up the build time and break determinism.
const DOS_TIME: u16 = 0xB1AA;
const DOS_DATE: u16 = 0x576E;

#[derive(Default)]
struct Zipception;

impl Generator for Zipception {
    fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str> {
        let (flag, archive) = build(seed)?;
        out.add(OUTPUT, archive);
        out.set_flag(flag);
        Ok(())
    }
}

export_generator!(Zipception);

/// Build the archive and the flag it contains from one seed.
///
/// Public so the `preview` binary can render what a player receives without going
/// through WebAssembly.
pub fn build(seed: &[u8]) -> Result<(String, Vec<u8>), &'static str> {
    let flag = derived_flag(seed)?;
    let names = layer_names(seed);

    // Build from the inside out: the innermost archive holds the payload, and each
    // wrapping archive embeds the previous bytes under its own long component.
    let mut bytes = archive(&entry_name(&names[LAYERS - 1], CORE), flag.as_bytes());
    for name in names.iter().take(LAYERS - 1).rev() {
        bytes = archive(&entry_name(name, ENTRY), &bytes);
    }
    Ok((flag, bytes))
}

/// `flag(seed)` exactly as spec §22.3 defines it: the first 10 bytes of
/// `HMAC-SHA-256(key = seed, message = "ctf/flag/v1")`, base32 with the lowercase
/// RFC 4648 alphabet and no padding. 80 bits encode to exactly 16 symbols.
fn derived_flag(seed: &[u8]) -> Result<String, &'static str> {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).map_err(|_| "bad HMAC key")?;
    mac.update(b"ctf/flag/v1");
    let tag = mac.finalize().into_bytes();
    let truncated = tag.get(..10).ok_or("short HMAC tag")?;
    Ok(base32_lower(truncated))
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            if let Some(symbol) = ALPHABET.get(index) {
                out.push(char::from(*symbol));
            }
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        if let Some(symbol) = ALPHABET.get(index) {
            out.push(char::from(*symbol));
        }
    }
    out
}

/// One 120-character component per layer: `layer_NNNN_of_0150_` plus base62
/// characters drawn from a SHA-256 counter stream keyed by the seed.
fn layer_names(seed: &[u8]) -> Vec<String> {
    (0..LAYERS)
        .map(|layer| {
            let mut name = format!("layer_{:04}_of_{:04}_", layer + 1, LAYERS);
            let mut counter = 0u32;
            while name.len() < NAME_LEN {
                let block = name_block(seed, layer as u32, counter);
                for byte in block {
                    if name.len() == NAME_LEN {
                        break;
                    }
                    // The modulo is over 62 and a byte is 0..=255, so the bias is
                    // one extra draw in 256 for four symbols; names carry no
                    // security property, only uniqueness.
                    if let Some(symbol) = BASE62.get(usize::from(byte) % BASE62.len()) {
                        name.push(char::from(*symbol));
                    }
                }
                counter = counter.wrapping_add(1);
            }
            name
        })
        .collect()
}

fn name_block(seed: &[u8], layer: u32, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ctf/zipception/names/v1");
    hasher.update((seed.len() as u32).to_le_bytes());
    hasher.update(seed);
    hasher.update(layer.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

fn entry_name(component: &str, file: &str) -> String {
    let mut name = String::with_capacity(component.len() + file.len() + 1);
    name.push_str(component);
    name.push('/');
    name.push_str(file);
    name
}

/// A one-entry ZIP archive with the entry stored uncompressed.
///
/// Hand-rolled so the bytes are exactly the same on both engines and in a native
/// build: a ZIP writer that picks up a clock or an OS-specific attribute would
/// fail the determinism gate on the machine that happens to differ.
fn archive(name: &str, data: &[u8]) -> Vec<u8> {
    let name = name.as_bytes();
    let crc = crc32(data);
    let size = data.len() as u32;
    let mut out = Vec::with_capacity(name.len() * 2 + data.len() + 128);

    // Local file header, spec 4.3.7 of APPNOTE.TXT.
    push_u32(&mut out, 0x0403_4b50);
    push_u16(&mut out, 20); // version needed to extract
    push_u16(&mut out, 0); // general purpose flags
    push_u16(&mut out, 0); // method 0 = store
    push_u16(&mut out, DOS_TIME);
    push_u16(&mut out, DOS_DATE);
    push_u32(&mut out, crc);
    push_u32(&mut out, size); // compressed size
    push_u32(&mut out, size); // uncompressed size
    push_u16(&mut out, name.len() as u16);
    push_u16(&mut out, 0); // extra field length
    out.extend_from_slice(name);
    out.extend_from_slice(data);

    let central_offset = out.len() as u32;

    // Central directory header.
    push_u32(&mut out, 0x0201_4b50);
    push_u16(&mut out, 20); // version made by
    push_u16(&mut out, 20); // version needed
    push_u16(&mut out, 0); // flags
    push_u16(&mut out, 0); // method
    push_u16(&mut out, DOS_TIME);
    push_u16(&mut out, DOS_DATE);
    push_u32(&mut out, crc);
    push_u32(&mut out, size);
    push_u32(&mut out, size);
    push_u16(&mut out, name.len() as u16);
    push_u16(&mut out, 0); // extra
    push_u16(&mut out, 0); // comment
    push_u16(&mut out, 0); // disk number start
    push_u16(&mut out, 0); // internal attributes
    push_u32(&mut out, 0); // external attributes
    push_u32(&mut out, 0); // local header offset
    out.extend_from_slice(name);

    let central_size = out.len() as u32 - central_offset;

    // End of central directory.
    push_u32(&mut out, 0x0605_4b50);
    push_u16(&mut out, 0); // this disk
    push_u16(&mut out, 0); // disk with the central directory
    push_u16(&mut out, 1); // entries on this disk
    push_u16(&mut out, 1); // entries total
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0); // comment length
    out
}

/// CRC-32/ISO-HDLC (the ZIP polynomial), bitwise so it needs no table.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
