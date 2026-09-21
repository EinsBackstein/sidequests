# The WTFlag adapter

Normative: [`spec/SPEC.md`](../spec/SPEC.md) §33, §22. This document is the
migration note for the platform's existing flag oracle.

## The mapping

The platform already mints flags from a per-challenge key and a team. The format
mints them from a challenge `id`/`version` and a **subject** (spec §22). The adapter
is the identity map on the team identifier:

| Platform concept | Format concept |
|---|---|
| challenge key | manifest `id` (`chal_id`) |
| challenge revision | manifest `version` (`chal_version`) |
| **team** | **`subject_id`** |
| the signing pod's secret | `event_secret` |

Concretely, for challenge key `K`, revision `V`, team `T`, and the platform's
secret `S`:

```text
seed = HKDF-SHA-256(
    ikm  = S,
    salt = "ctf/seed/v1",
    info = LP(K) ‖ u64_le(V) ‖ LP(T) )

flag = base32_lower( HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..10] )
```

This is exactly `spec/SPEC.md` §22.2 and §22.3, and the reference implementation is
`ctf_format::wtflag::{seed, flag}` (or `derive::subject_seed` with `subject_id = T`).

## One oracle

`event_secret` lives in exactly one place — the platform's signing pod — and every
flag is minted by that one holder. The format never carries the secret or a flag
(spec §22.5 rule DF1), so:

- the bundle a player downloads leaks nothing, and
- the platform does not gain a second secret to protect.

There is no per-challenge secret. A challenge's identity is its `id` and `version`,
both of which are manifest fields inside the commitment root.

## Team maps to subject

With `subject_scope: team` (the default, spec §7.6) every member of a team derives
the same flag. A handoff between teammates is then free: it is a holder change, not
a subject change (design §9), so no flag is regenerated and no artifact is revoked.

A `subject_scope: player` challenge binds the seed to the player instead; that is
the expensive path (regeneration on handoff) and should be opted into deliberately.

## Migration

1. **New challenges** use the format derivation directly. No change to the platform
   is needed beyond mapping `team -> subject_id`.
2. **Existing stored flags** were minted by the old oracle. They cannot be
   recomputed from `event_secret` unless the old oracle's inputs were exactly the
   mapping above. For an event already in progress, keep the stored flags as they
   are and treat the bundle's derivation as authoritative only for subjects that
   have not yet received a flag; a challenge re-packed under the format gets a new
   `version`, which changes its seed, so the two derivations never collide on one
   `(id, version, subject)`.
3. **The per-challenge key** maps to `(id, version)`. A re-pack increments
   `version`; that is the migration boundary.

## Testability

`crates/ctf-format/tests/wtflag.rs` asserts that the adapter equals the spec
derivation, that two teams differ, and that one team is stable. A platform that
implements spec §22 matches this adapter by construction.
