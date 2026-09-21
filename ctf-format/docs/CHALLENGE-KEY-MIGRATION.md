# The challenge key mapping and migration

Normative: [`spec/SPEC.md`](../spec/SPEC.md) §7.2, §7.6, §22, §29.1, §33. That
document is normative and wins over this one; where they disagree, the spec is
correct. This is the operator-facing migration runbook for a platform whose flag
oracle predates the format. It references [`docs/WTFLAG-ADAPTER.md`](WTFLAG-ADAPTER.md),
which states the adapter itself; it does not repeat its rationale.

## The mapping

The platform already mints flags from a per-challenge key, a revision, and a team.
The format mints them from a challenge `id`/`version` and a **subject** (§22, §33).
The adapter is the identity map on the team identifier (rule W1):

| Platform concept | Format concept | Source |
|---|---|---|
| challenge key | manifest `id` (`chal_id`) | §7.2, §33 |
| challenge revision | manifest `version` (`chal_version`) | §7.2, §33 |
| team | `subject_id` | §33 rule W1 |
| platform signing secret | `event_secret` | §33 rule W3 |
| platform `slug` | manifest `id` | §29.1 |
| platform challenge `version` | manifest `version` | §29.1 |

The ingest descriptor projects these two fields directly: `slug` = manifest `id`,
`version` = manifest `version` (§29.1, `crates/ctf-format/src/descriptor.rs`).

## The derivation

`LP(x)` is `u32_le(len(x)) ‖ x` (§22.1). Every variable-length input is
length-prefixed; `chal_version` is a fixed-width `u64_le` and is **not**
length-prefixed (rule DF2, §22.2). For challenge key `K`, revision `V`, subject
`T`, and the platform's 32-byte secret `S`:

```text
seed = HKDF-SHA-256(
    ikm  = S,
    salt = "ctf/seed/v1",
    info = LP(K) ‖ u64_le(V) ‖ LP(T) )

flag = base32_lower( HMAC-SHA-256(key = seed, message = "ctf/flag/v1")[0..10] )
```

`"ctf/seed/v1"` is 11 ASCII bytes and `"ctf/flag/v1"` is 11 ASCII bytes. The first
10 bytes of the tag are 80 bits and render as exactly 16 lowercase base32 symbols
(alphabet `abcdefghijklmnopqrstuvwxyz234567`, no `=`) — rule DF3. This is §22.2 and
§22.3, implemented by `derive::subject_seed` and `derive::flag` in
`crates/ctf-format/src/derive.rs`; `wtflag::seed`/`wtflag::flag`
(`crates/ctf-format/src/wtflag.rs`) are exactly those functions with
`subject_id = T`.

## Effect on existing stored flags

- A flag already stored by the legacy oracle is **not recomputable** from
  `event_secret` unless that oracle's inputs were exactly `(K, V, T)` under the
  construction above. If its construction or its inputs differ, the old flag is an
  opaque string and no derivation reproduces it.
- A bundle never carries a flag or the secret (rule DF1, §22.5): it carries the
  derivation *rule* only. A leaked bundle therefore leaks nothing, and the platform
  keeps one oracle rather than gaining a second secret to protect (rule W3).
- A re-pack increments `version`, which changes the seed. A legacy flag is bound to
  the old revision and a format-derived flag to the new one, so there is no single
  `(id, version, subject)` at which both exist and they never collide.
- Where the legacy flag is stored and how it is checked is the platform's database,
  which is downstream of this repository (design §2 scope boundary). This document
  fixes the derivation and the mapping; it cannot promise what an external oracle
  did.

## Migration for an event already in progress

Concrete, ordered. Steps that touch the platform database are operational guidance;
the format owns the derivation and the manifest fields, not the DB (design §2).

1. **Snapshot the flags.** Export every stored flag for the challenge as
   `(challenge_key, revision, subject, flag, minted_at, consumed?)`. Keep the export
   read-only for the rest of the event.
2. **Keep serving issued flags.** Already-minted flags stay valid and are served
   unchanged. Do not recompute, re-key, or invalidate them; a player holding a
   legacy flag must keep passing.
3. **Freeze the current revision.** Do not re-pack the challenge mid-event unless
   you must. The migration boundary is the `version` increment (step 4), so an
   un-migrated challenge simply keeps its legacy flags.
4. **Pack or re-pack under the format.** Set manifest `id` to the platform
   challenge key, and bump `version` to the next value. `ctf pack` emits the ingest
   descriptor with `slug` = `id` and `version` = `version` (§29.1). The new
   `version` is what makes the migrated challenge a new seed.
5. **Mint only for subjects with no flag yet.** A subject that already holds a
   legacy flag keeps it. A subject that has not yet received one gets the
   format-derived flag for `(id, new_version, subject)`. Record the `version`
   alongside every newly minted flag.
6. **Verify a derived flag locally.** Run
   `ctf run challenge.yaml --secret <64-hex-digits> --subject <subject>`
   (`crates/ctf-cli/src/main.rs`, ticket 28): it derives the reference subject's
   flag, runs the generator and solver gates, and exits non-zero if the solver does
   not recover it. The library equivalent is `derive::subject_seed` followed by
   `derive::flag`, or `wtflag::seed`/`wtflag::flag`.
7. **Tell which oracle produced a stored flag.** The format carries no flag and no
   marker for one, so there is no in-band way to label a stored flag as legacy or
   derived. The durable discriminator is the revision stored beside it: a flag
   minted for revision `V` belongs to `V`, and a format-derived flag for
   `(id, V+1)` is a different string by construction. If you do not already store
   the revision with the flag, start doing so before the re-pack.
8. **Roll back if needed.** Because issued flags are untouched and the bundle
   carries no flag, rollback is dropping the new bundle and descriptor and
   continuing to serve the old stored flags. No stored flag becomes invalid and
   there is nothing to re-key. The one caught case: a subject who received a
   format-derived flag after the re-pack cannot be re-minted by the old oracle, so
   keep both oracles serving until the event ends.
9. **If a re-pack ships mid-event.** Subjects with legacy flags keep passing
   unchanged. Subjects with no flag yet get the format-derived flag at the new
   `version`. The two sets are distinct because the version differs; never serve a
   format-derived flag at the old revision, and never expect a legacy flag to be
   recomputable at the new one.

## Worked example

`event_secret` = 32 bytes `00 01 02 … 1f`, challenge key `whos-that-bird`, subject
`team-alpha`. Same key and subject, two format-derived versions, two distinct
seeds and flags:

```text
id = "whos-that-bird"   subject_id = "team-alpha"
event_secret = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

version = 3
  seed = 20b0f7556a9de4382cda2501eb74791e85474831adfe1ccf84dab59305099f6e
  flag = oil5phz5xep2ss7j

version = 4   (the re-pack; the migration boundary)
  seed = 0ffb1a15e6c82833586810a98047448ed028036bf1e48118bf6a791b3e61219f
  flag = w3cbfgrck6j4t3mt
```

The version-3 values match the known-answer vector in
`crates/ctf-format/tests/derive.rs`. Any legacy flag stored at revision 3 is a
third, unknown string: it is not recomputable here, and it cannot equal the
version-4 value because the seed differs. A legacy flag minted at revision 3 and a
format-derived flag at revision 4 never occupy the same `(id, version, subject)`.

## Terminology reconciliation

Design and WTFLAG prose say `subject_scope: team`. The manifest key the spec
actually defines is **`flag.scope`**, with values `player`, `team`, or `event`
(§7.6). They name the same idea; `subject_scope` is the design synonym. This
runbook uses `flag.scope`. The default is `team`: every member of a team derives
the same flag, so a handoff between teammates is not a subject change (§7.6, §33).
A `flag.scope` of `player` binds the seed to the player and is the expensive path.

## Scope boundary

`event_secret` custody, flag storage, and flag checking are the platform's, not
this repository's (design §2). The format fixes the derivation (§22), the manifest
fields `id`, `version`, and `flag.scope` (§7.2, §7.6), and the adapter mapping
(§33); the runbook above applies those to an operator's database without claiming
what that database does.
