//! Canonical CBOR tests.
//!
//! Most of these are rejections, and each rejects an encoding that a permissive
//! CBOR library would happily accept. That is the point: the manifest's commitment
//! is over bytes, so an encoding a decoder tolerates but an encoder would never
//! produce is a second spelling of the same manifest — and two spellings mean two
//! commitment roots for one challenge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ctf_format::{
    Error,
    cbor::{MAX_DEPTH, Value},
};

fn round_trip(v: &Value) -> Vec<u8> {
    let b = v.encode().unwrap();
    assert_eq!(&Value::decode(&b).unwrap(), v, "decode(encode(v)) != v");
    assert_eq!(
        Value::decode(&b).unwrap().encode().unwrap(),
        b,
        "encode(decode(b)) != b"
    );
    b
}

#[test]
fn encodes_the_rfc_8949_examples() {
    // RFC 8949 Appendix A, the cases inside this subset.
    assert_eq!(Value::Uint(0).encode().unwrap(), [0x00]);
    assert_eq!(Value::Uint(23).encode().unwrap(), [0x17]);
    assert_eq!(Value::Uint(24).encode().unwrap(), [0x18, 0x18]);
    assert_eq!(Value::Uint(1000).encode().unwrap(), [0x19, 0x03, 0xe8]);
    assert_eq!(
        Value::Uint(1_000_000).encode().unwrap(),
        [0x1a, 0x00, 0x0f, 0x42, 0x40]
    );
    assert_eq!(Value::Nint(0).encode().unwrap(), [0x20]); // -1
    assert_eq!(Value::Nint(99).encode().unwrap(), [0x38, 0x63]); // -100
    assert_eq!(Value::Text("a".into()).encode().unwrap(), [0x61, 0x61]);
    assert_eq!(
        Value::Bytes(vec![1, 2, 3, 4]).encode().unwrap(),
        [0x44, 1, 2, 3, 4]
    );
    assert_eq!(Value::Bool(false).encode().unwrap(), [0xf4]);
    assert_eq!(Value::Bool(true).encode().unwrap(), [0xf5]);
    assert_eq!(Value::Null.encode().unwrap(), [0xf6]);
}

#[test]
fn round_trips_every_kind_in_the_subset() {
    round_trip(&Value::Uint(u64::MAX));
    round_trip(&Value::Nint(u64::MAX));
    round_trip(&Value::Bytes(vec![0xff; 300]));
    round_trip(&Value::Text("naïve ✓".into()));
    round_trip(&Value::Array(vec![Value::Uint(1), Value::Null]));
    round_trip(&Value::Map(vec![
        (Value::Uint(1), Value::Text("a".into())),
        (Value::Text("b".into()), Value::Bool(true)),
    ]));
}

/// The encoder sorts, so a caller may build a map in whatever order reads naturally
/// and still get canonical bytes.
#[test]
fn encoder_sorts_map_keys() {
    let unsorted = Value::Map(vec![
        (Value::Text("zz".into()), Value::Uint(1)),
        (Value::Text("a".into()), Value::Uint(2)),
        (Value::Uint(7), Value::Uint(3)),
    ]);
    let b = unsorted.encode().unwrap();
    // Canonical order is over the *encoded key*, so shorter encodings sort first:
    // 0x07 (uint 7), then 0x61 'a', then 0x62 'zz'.
    assert_eq!(
        b,
        [0xa3, 0x07, 0x03, 0x61, b'a', 0x02, 0x62, b'z', b'z', 0x01]
    );
    // And the decoded value is in that order, so a round trip is stable.
    let Value::Map(entries) = Value::decode(&b).unwrap() else {
        panic!("not a map")
    };
    assert_eq!(entries[0].0, Value::Uint(7));
}

#[test]
fn encoder_rejects_duplicate_keys() {
    let v = Value::Map(vec![
        (Value::Text("a".into()), Value::Uint(1)),
        (Value::Text("a".into()), Value::Uint(2)),
    ]);
    assert!(matches!(v.encode(), Err(Error::CborDuplicateKey)));
}

/// `1` has five spellings in CBOR. Four of them are rejected, which is what makes
/// the encoding injective and the commitment root a function of the manifest rather
/// than of whoever wrote it.
#[test]
fn rejects_non_shortest_integers() {
    for b in [
        vec![0x18, 0x01],                               // uint 1 in 1 byte
        vec![0x19, 0x00, 0x01],                         // in 2
        vec![0x1a, 0x00, 0x00, 0x00, 0x01],             // in 4
        vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0x01],          // in 8
        vec![0x19, 0x00, 0xff],                         // 255 in 2 bytes
        vec![0x1a, 0x00, 0x00, 0xff, 0xff],             // 65535 in 4
        vec![0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], // 2^32-1 in 8
    ] {
        assert!(
            matches!(Value::decode(&b), Err(Error::CborNotShortest)),
            "accepted non-shortest {b:02x?}"
        );
    }
}

#[test]
fn rejects_indefinite_lengths() {
    // Indefinite-length text string: 0x7f 0x61 'a' 0xff
    assert!(matches!(
        Value::decode(&[0x7f, 0x61, b'a', 0xff]),
        Err(Error::CborUnsupported { .. })
    ));
    // Indefinite-length array.
    assert!(matches!(
        Value::decode(&[0x9f, 0x01, 0xff]),
        Err(Error::CborUnsupported { .. })
    ));
}

#[test]
fn rejects_tags_and_floats_and_undefined() {
    assert!(matches!(
        // Tag 0 over a text string.
        Value::decode(&[0xc0, 0x61, b'a']),
        Err(Error::CborUnsupported { .. })
    ));
    assert!(matches!(
        // Half-precision float 1.0.
        Value::decode(&[0xf9, 0x3c, 0x00]),
        Err(Error::CborUnsupported { .. })
    ));
    assert!(matches!(
        // Double 1.0.
        Value::decode(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]),
        Err(Error::CborUnsupported { .. })
    ));
    assert!(matches!(
        Value::decode(&[0xf7]), // undefined
        Err(Error::CborUnsupported { .. })
    ));
    assert!(matches!(
        Value::decode(&[0xf8, 0xff]), // simple value 255
        Err(Error::CborUnsupported { .. })
    ));
}

/// Reserved additional-information values 28-30 have no meaning at all, so there is
/// nothing to skip past.
#[test]
fn rejects_reserved_additional_information() {
    for ai in 28..=30u8 {
        assert!(matches!(
            Value::decode(&[ai]),
            Err(Error::CborUnsupported { .. })
        ));
    }
}

#[test]
fn rejects_unsorted_and_duplicate_map_keys() {
    // {"b": 1, "a": 2} — keys out of canonical order.
    assert!(matches!(
        Value::decode(&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02]),
        Err(Error::CborUnsortedKeys)
    ));
    // {"a": 1, "a": 2} — the parser differential this closes by construction.
    assert!(matches!(
        Value::decode(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]),
        Err(Error::CborDuplicateKey)
    ));
}

#[test]
fn rejects_trailing_bytes() {
    assert!(matches!(
        Value::decode(&[0x01, 0x02]),
        Err(Error::CborTrailing { at: 1, len: 2 })
    ));
}

#[test]
fn rejects_truncation() {
    assert!(matches!(Value::decode(&[]), Err(Error::CborTruncated)));
    assert!(matches!(
        Value::decode(&[0x62, b'a']), // 2-byte text, 1 byte present
        Err(Error::CborTruncated)
    ));
    assert!(matches!(
        Value::decode(&[0x82, 0x01]), // 2-element array, 1 element present
        Err(Error::CborTruncated)
    ));
}

#[test]
fn rejects_bad_utf8() {
    assert!(matches!(
        Value::decode(&[0x62, 0xff, 0xfe]),
        Err(Error::CborBadUtf8)
    ));
}

/// Unbounded recursion over attacker-supplied nesting is a stack-overflow DoS
/// (design §14). The cap is what stops it, and it is checked on both sides.
#[test]
fn rejects_nesting_past_the_depth_cap() {
    let mut deep = Value::Uint(0);
    for _ in 0..=MAX_DEPTH {
        deep = Value::Array(vec![deep]);
    }
    assert!(matches!(deep.encode(), Err(Error::CborTooDeep { .. })));

    // The same shape as bytes, so the decoder is checked independently of whether
    // the encoder would have produced it.
    let mut b = vec![0x81u8; (MAX_DEPTH + 2) as usize];
    b.push(0x00);
    assert!(matches!(Value::decode(&b), Err(Error::CborTooDeep { .. })));
}

/// A huge declared array length must not size an allocation. Every element costs at
/// least one input byte, so growing the `Vec` bounds it by the input instead.
#[test]
fn a_huge_length_field_does_not_allocate() {
    // Array claiming 2^64-1 elements, with none present.
    let b = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(Value::decode(&b), Err(Error::CborTruncated)));
    // Byte string claiming 2^64-1 bytes.
    let b = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(Value::decode(&b), Err(Error::CborTruncated)));
}
