//! Hostile-input sweep: the oracle from design §14, run on the pinned stable
//! toolchain.
//!
//! This is **not** a replacement for coverage-guided fuzzing — `fuzz/` holds the
//! `cargo-fuzz` targets and finds what a blind sweep cannot. It is the part of that
//! oracle which runs on every `cargo test`, on the toolchain this project pins, with
//! no nightly and no external tool. Both exist because the fuzzer is the one that
//! finds things and this is the one that keeps finding them once fixed.
//!
//! The oracle, on every input:
//!
//! - **No panic.** A panic on a hostile byte stream is the bug class this crate's
//!   `Option`-returning readers exist to make unrepresentable, so any panic here
//!   fails the test by definition.
//! - **Determinism.** Parsing the same bytes twice gives the same answer. A parser
//!   that depends on uninitialized or ambient state is one that two implementations
//!   cannot agree with.
//! - **Round-trip stability**, when the parse succeeds: the manifest re-encodes to
//!   exactly the bytes it was decoded from, and the footer likewise. If a mutated
//!   file is accepted, the structures it yields must still be canonical — otherwise
//!   a rewriter would change a bundle's commitment root without changing its meaning.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Bundle, Footer, Manifest, SectionFlags, SectionKind, SectionSpec, cbor::Value,
    chunk::ChunkIndex, header::Header, section, write_bundle,
};

/// xorshift64*. Deterministic, so a failure is reproducible from the seed alone,
/// and dependency-free, which matters more here than statistical quality.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let m = Manifest::minimal("whos-that-bird", "Who's That Bird", &["manifest"])
        .unwrap()
        .encode()
        .unwrap();
    let minimal = write_bundle(
        1,
        &[SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &m,
        )],
    )
    .unwrap();

    let m2 = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (Value::Text("id".into()), Value::Text("baby-rop".into())),
            (Value::Text("name".into()), Value::Text("Baby ROP".into())),
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
    let artifact = vec![0x42u8; 9000];
    let chunked = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &m2),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &artifact,
            )
            .chunked(4096),
        ],
    )
    .unwrap();

    vec![minimal, chunked]
}

/// Check the invariants that must hold for any input, mutated or not.
fn oracle(file: &[u8]) {
    let first = Bundle::parse(file);
    let second = Bundle::parse(file);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "parse is not deterministic for this input"
    );
    let Ok(b) = first else { return };

    // Round-trip stability. An accepted file's structures must be canonical.
    let record = b
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .unwrap();
    let bytes = b.section_bytes(record).unwrap();
    assert_eq!(
        b.manifest.encode().unwrap(),
        bytes.as_ref(),
        "manifest did not re-encode to its own bytes"
    );
    assert_eq!(
        b.footer.to_bytes().unwrap(),
        &file[b.header.footer_off as usize..],
        "footer did not re-encode to its own bytes"
    );
    assert_eq!(Footer::parse(file, b.header.footer_off).unwrap(), b.footer);

    // Every record re-serializes to the bytes it came from, which is what makes the
    // commitment over the table bytes a commitment over the parsed records too.
    let (start, _) = b.header.table_range().unwrap();
    for (i, r) in b.sections.iter().enumerate() {
        let at = start as usize + i * 128;
        assert_eq!(r.to_bytes(), file[at..at + 128], "record {i} is not stable");
    }
    assert_eq!(b.header.to_bytes(), file[..64]);
}

/// Single-byte flips across the whole file. This is where a parser that trusts one
/// field to bound another gives way.
#[test]
fn survives_single_byte_flips() {
    for base in corpus() {
        // Every byte of the structures, and a sample of the payload interior, which
        // is uniform filler where an exhaustive sweep would prove nothing new.
        let h = Header::parse(&base).unwrap();
        let interesting: Vec<usize> = (0..64)
            .chain(h.section_table_off as usize..base.len())
            .chain((4096..4200).filter(|i| *i < base.len()))
            .collect();
        for i in interesting {
            for bit in [0u8, 7] {
                let mut f = base.clone();
                f[i] ^= 1 << bit;
                oracle(&f);
            }
        }
    }
}

/// Truncation at every length. A reader that reads a length before checking it has
/// bytes to back it fails here first.
#[test]
fn survives_truncation_at_every_length() {
    for base in corpus() {
        for len in 0..base.len().min(300) {
            oracle(&base[..len]);
        }
        for len in (300..base.len()).step_by(7) {
            oracle(&base[..len]);
        }
    }
}

/// Multi-byte corruption, which reaches states a single flip cannot: an offset
/// pointing at a plausible structure, a count that is large but under the cap.
#[test]
fn survives_random_multi_byte_corruption() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    for base in corpus() {
        for _ in 0..20_000 {
            let mut f = base.clone();
            for _ in 0..1 + rng.below(6) {
                let i = rng.below(f.len());
                f[i] = rng.next() as u8;
            }
            oracle(&f);
        }
    }
}

/// Bytes that were never a bundle. Most stop at the magic; the ones that do not are
/// the interesting cases.
#[test]
fn survives_arbitrary_bytes() {
    let mut rng = Rng(0xdead_beef_0000_0001);
    for _ in 0..20_000 {
        let len = rng.below(600);
        let mut f: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Half the inputs get a valid magic, so they reach past the first check.
        if rng.next() & 1 == 0 && f.len() >= 8 {
            f[..8].copy_from_slice(&[0x89, b'C', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a]);
        }
        oracle(&f);
    }
}

/// The sub-parsers, reached directly rather than through a whole file, so an input
/// that a header check would have rejected still gets to them.
#[test]
fn sub_parsers_survive_arbitrary_bytes() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..50_000 {
        let len = rng.below(400);
        let f: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();

        let _ = Header::parse(&f);
        let _ = section::parse_table(&f, rng.below(8) as u32);
        let _ = Footer::parse(&f, rng.below(f.len().max(1)) as u64);
        let _ = ChunkIndex::parse(&f, rng.below(20) as u64);
        let _ = Manifest::decode(&f);

        // CBOR gets the canonicality oracle as well: whatever decodes must
        // re-encode to exactly the bytes it came from.
        if let Ok(v) = Value::decode(&f) {
            assert_eq!(v.encode().unwrap(), f, "cbor round trip is not stable");
        }
    }
}
