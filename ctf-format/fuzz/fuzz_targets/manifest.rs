//! Canonical CBOR and the manifest schema.
//!
//! Oracle: anything that decodes must re-encode to exactly the input. That is the
//! canonicality property stated as an executable claim — if the fuzzer finds an
//! input that decodes to a value whose encoding differs, it has found a second
//! spelling of one manifest, and therefore two commitment roots for one challenge.
#![no_main]

use ctf_format::{Manifest, cbor::Value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = Value::decode(data) {
        assert_eq!(v.encode().expect("a decoded value must re-encode"), data);
    }
    if let Ok(m) = Manifest::decode(data) {
        assert_eq!(m.encode().expect("re-encode"), data);
        // Accessors must not panic on any accepted manifest.
        let _ = m.names();
        let _ = m.name_of(u16::MAX);
        let _ = m.external(0);
    }
});
