//! The WTFlag adapter (ticket 58): team maps to subject, and the adapter is exactly
//! spec §22 with that mapping, so a platform implementing the spec matches it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ctf_format::derive;
use ctf_format::wtflag;

const SECRET: [u8; 32] = [0x42; 32];

#[test]
fn team_maps_to_subject_verbatim() {
    assert_eq!(wtflag::subject_id("team-rocket"), "team-rocket");
}

#[test]
fn the_adapter_is_the_spec_derivation() {
    let seed = wtflag::seed(&SECRET, "baby-rop", 3, "team-rocket").unwrap();
    assert_eq!(
        seed,
        derive::subject_seed(&SECRET, "baby-rop", 3, "team-rocket").unwrap()
    );
    assert_eq!(
        wtflag::flag(&SECRET, "baby-rop", 3, "team-rocket").unwrap(),
        derive::flag(&seed)
    );
}

#[test]
fn two_teams_get_different_flags() {
    let a = wtflag::flag(&SECRET, "baby-rop", 3, "team-a").unwrap();
    let b = wtflag::flag(&SECRET, "baby-rop", 3, "team-b").unwrap();
    assert_ne!(a, b);
}

#[test]
fn one_team_gets_one_flag() {
    let a = wtflag::flag(&SECRET, "baby-rop", 3, "team-a").unwrap();
    let b = wtflag::flag(&SECRET, "baby-rop", 3, "team-a").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 16);
}

#[test]
fn a_secret_that_is_not_32_bytes_is_refused() {
    assert!(wtflag::seed(&[0u8; 31], "baby-rop", 0, "team").is_err());
}
