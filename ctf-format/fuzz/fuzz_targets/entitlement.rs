//! Entitlement chain parsing (spec §18).
//!
//! Oracle: no panic, deterministic parse, and an accepted chain's canonical encoding
//! must reproduce the input byte-for-byte. A record id is a hash of the record's
//! canonical bytes, so a second spelling of one record would give two ids — and `prev`
//! links, and therefore the whole chain, would mean two different things.
//!
//! E9 is deliberately not reached: signature verification needs trusted keys the
//! bundle does not carry (§14, §18.4), so it is the caller's separate step.
#![no_main]

use ctf_format::{EntitlementChain, RecordType};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(chain) = EntitlementChain::from_bytes(data) else {
        return;
    };
    // Canonicality: `from_bytes` accepted one spelling, so re-encoding must produce
    // exactly the bytes it came from. `encode` and its `to_bytes` alias are both
    // checked because callers use both names.
    assert_eq!(
        chain.to_bytes().expect("an accepted chain must re-encode"),
        data
    );
    assert_eq!(chain.encode().expect("encode is to_bytes"), data);
    // Parsing is a pure function of the input.
    assert_eq!(
        EntitlementChain::from_bytes(data).expect("an accepted chain must re-parse"),
        chain
    );

    // Accessors must not panic on any accepted chain, including out-of-range indexes.
    let _ = chain.validate();
    let _ = chain.len();
    let _ = chain.is_empty();
    let records = chain.records();
    let _ = EntitlementChain::new().records();
    for n in [
        0,
        records.len().saturating_sub(1),
        records.len(),
        records.len().saturating_add(1),
        usize::MAX,
    ] {
        let _ = chain.get(n);
        let _ = chain.record_id(n);
    }

    // `validate_against_root` is a second validation entry point; it must not panic
    // for a root that does or does not match the genesis binding.
    let _ = chain.validate_against_root(&[0u8; 32]);
    if let Some(genesis) = records.first() {
        let _ = chain.validate_against_root(&genesis.root.unwrap_or([0u8; 32]));
    }

    for record in records {
        let _ = record.check();
        let _ = record.record_id();
        let _ = record.record_type.name();
        let _ = RecordType::from_name(record.record_type.name());
        if let Some(timestamp) = record.timestamp {
            let _ = timestamp.to_value();
        }
    }
});
