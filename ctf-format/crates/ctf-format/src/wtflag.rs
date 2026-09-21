//! The WTFlag adapter (ticket 58).
//!
//! The platform already mints flags from a per-challenge key and a team. The format
//! mints them from a challenge `id`/`version` and a **subject** (spec §22). This
//! module is the documented adapter between the two, so the platform does not have
//! to invent a second derivation or protect a second secret.
//!
//! # The mapping, explicitly
//!
//! | Platform concept | Format concept |
//! |---|---|
//! | challenge key | manifest `id` (`chal_id`) |
//! | challenge revision | manifest `version` (`chal_version`) |
//! | **team** | **`subject_id`** |
//! | signing pod's secret | `event_secret` |
//!
//! Team maps to subject one-to-one: with `subject_scope: team` (the default,
//! spec §7.6) every member of a team derives the same flag, which is what a team
//! challenge wants, and a handoff between teammates is free because it is not a
//! subject change (design §9).
//!
//! # One oracle
//!
//! `event_secret` lives in exactly one place — the platform's signing pod — and
//! every flag is minted by that one holder (design §4, §7). The format never carries
//! the secret or a flag (rule DF1), so the bundle a player downloads leaks nothing
//! and the platform does not gain a second secret to protect.
//!
//! # Testability
//!
//! [`seed`] and [`flag`] are exactly [`crate::derive::subject_seed`] and
//! [`crate::derive::flag`] with the mapping above, and the tests assert that
//! equality. A platform that adopts spec §22 therefore matches this adapter by
//! construction rather than by a second implementation being written twice.

use crate::derive;
use crate::suite::SuiteError;

/// The subject a team maps to: the team identifier, verbatim.
///
/// The mapping is the identity function, stated as a function so it has one name and
/// one place to change if a platform's team identifiers ever need a prefix.
pub fn subject_id(team: &str) -> &str {
    team
}

/// The per-subject seed for a WTFlag challenge: `seed(challenge_key, version, team)`.
pub fn seed(
    event_secret: &[u8],
    challenge_key: &str,
    version: u64,
    team: &str,
) -> Result<[u8; 32], SuiteError> {
    derive::subject_seed(event_secret, challenge_key, version, subject_id(team))
}

/// The flag a team receives for a WTFlag challenge (spec §22.3).
///
/// The default 16-character / 80-bit flag. A challenge that needs a 128-bit boundary
/// calls [`flag_with_bytes`](crate::derive::flag_with_bytes) on [`seed`].
pub fn flag(
    event_secret: &[u8],
    challenge_key: &str,
    version: u64,
    team: &str,
) -> Result<String, SuiteError> {
    seed(event_secret, challenge_key, version, team).map(|s| derive::flag(&s))
}
