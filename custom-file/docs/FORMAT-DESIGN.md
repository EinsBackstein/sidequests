# `.ctf` — Challenge Transport Format

**Status:** design draft. Not a spec yet. Nothing here is implemented.

## 1. What this is

A single-file, verifiable, encrypted container that carries **one CTF challenge**
from an author's machine to the platform's admin TUI, and onward
into a long-term archive.

The design premise that separates it from CTFd's `challenge.yml`, kCTF, or a
zip-plus-YAML wrapper:

> A challenge is not static content. It is a **pure deterministic function**
> `challenge(seed) -> (artifacts, flag, oracle)`, plus a **verifiable
> commitment** to that function.

Every feature below is a consequence of that premise.

## 2. Requirements (fixed)

| # | Requirement | Source |
|---|---|---|
| R1 | Encryption at rest, hybrid classical + post-quantum | mandated |
| R2 | Covers every archetype: OSINT text-only → multi-GB forensics image | mandated |
| R3 | Subject may be a single player, a team, or transferred between players | mandated |
| R4 | Extension `.ctf` | mandated |
| R5 | Low-level performance without weakening security | mandated |
| R6 | Trivial for challenge developers, however hard that makes the standard | mandated |
| R7 | Runtime is a digest-pinned image ref (no in-bundle build context) | decided |
| R8 | Shared *and* per-team on-demand instancing | decided |
| R9 | Static and per-subject derived flags | decided |
| R10 | Bundles authored in-house (single trusted author org) | decided |

### Scope boundary — instance orchestration is a separate project

This repository defines and implements **the format and its tooling**. Actually
scheduling containers, allocating ports, enforcing TTLs, and reaping per-team
instances is a downstream project, started only once this standard is stable.

That does not remove `runtime` from the manifest. The format still *declares* the
runtime contract — digest-pinned image, ports, resource limits, instancing mode,
TTL, readiness probe — because that declaration is exactly the interface the future
orchestrator consumes. R7 and R8 remain in force as **schema** requirements.

One real consequence, addressed in Pillar 5 below: a solver cannot be run against a
live instance without an orchestrator, so the solvability gate splits into an
offline half (implemented here) and a live half (specified here, implemented there).

## 3. The five pillars

1. **Deterministic generator** — `gen.wasm`, a pure function of a seed. Determinism
   is enforced by the sandbox, not by author discipline.
2. **Derived flags** — the bundle stores a derivation rule, never a flag value. A
   leaked bundle leaks nothing.
3. **Publish-before / prove-after** — commitment published pre-event; solver and
   writeup sealed until the seal key is released.
4. **Cryptographic stage gating** — stage *N*'s key derives from stage *N-1*'s flag.
   Ordering enforced by math, not by dashboard logic.
5. **Solvability publish gate** — a bundle that cannot be solved cannot be published.
   Two halves:
   - **Offline gate (this repo).** Run the generator at the reference seed, then run
     `solver.wasm` against the generated artifacts in the same sandbox, with no
     network. Assert its output equals the derived flag. Covers every archetype whose
     solution is artifact-only: OSINT, crypto, RE, forensics.
   - **Live gate (orchestrator project).** For challenges declaring `runtime`, the
     same solver runs against a booted instance over a socket the orchestrator hands
     back. Specified here as an interface; not implemented here. Until it exists,
     `runtime`-bearing bundles pass ingest with the live gate recorded as `unverified`
     rather than silently as `passed` — an honest `unverified` is a usable state, a
     false `passed` is worse than no gate at all.

## 4. Threat model — read before trusting any claim below

**Protected against:**

- Storage/backup/laptop theft of `.ctf` files (R1, per-section AEAD).
- Pre-release leak of a bundle: no flag is recoverable without `event_secret`.
- Mid-event artifact substitution: pre-published commitment root is checkable.
- Post-event dispute over the intended solution: sealed sections were committed
  to in advance.
- Flag sharing: derived per-subject flags attribute a leaked flag to its holder.
- Buggy dashboard serving too much: stage-gated sections stay opaque ciphertext.
- Untrusted parser input: a `.ctf` is a hostile byte stream until verified.

**Explicitly NOT protected against:**

- **A compromised platform during the event.** The platform holds the storage
  decryption key and `event_secret` by necessity — it must serve artifacts and
  derive flags. At-rest encryption defends stolen media, not a live attacker with
  the running platform's keys.
- **Sealing when the platform holds the seal key.** If the seal key is available to
  the running platform, Pillar 3 is policy, not cryptography. *Normative
  requirement:* the seal key MUST NOT be resident on the platform during the
  event — offline, HSM, or split-key held by organizers. Sealed sections are
  encrypted to the seal recipient **only**, never additionally wrapped to the
  platform's storage key. If you cannot hold that key offline, do not claim the
  guarantee.
- Malicious challenge authors (R10 puts them out of scope). Ingest still sandboxes.
- Players attacking each other's instances (platform network policy, not format).

## 5. Archetype coverage (R2)

The dynamic range is roughly 2 KB → 40 GB. Three mechanisms cover it:

| Archetype | Sections used | Bundle size |
|---|---|---|
| OSINT, a few strings of context | manifest only | ~6 KB (PQ material dominates) |
| Reverse-engineering binary | manifest + artifact + optional `gen.wasm` + sealed solver | ~100 KB – few MB |
| Forensics workstation image (E01/VMDK) | manifest + **external** section (hash + size + mirrors) | ~8 KB; payload fetched out-of-band |
| Networked pwn/web | manifest + digest-pinned image ref + sealed solver | ~50 KB |

- **External sections** keep a 40 GB image out of the file while keeping it inside
  the commitment: the manifest carries its BLAKE3 root, length, and mirror list.
  A `.ctf` stays mailable regardless of payload size.
- **Chunked verified streaming** lets a 40 GB payload be verified incrementally,
  resumed after a broken transfer, and streamed to a player while still unverified
  bytes are in flight.
- Minimum viable challenge is manifest-only. No generator, no crypto choices, no
  sections. That is what makes R6 achievable.

## 6. File layout

```
┌──────────────────────────────────────────────────────────────┐
│ Header — 64 B, fixed, plaintext, 64-byte aligned             │
│   magic[8]  = \x89 'C' 'T' 'F' \x0d \x0a \x1a \x0a           │
│   version_major u16 | version_minor u16                      │
│   header_len u32                                             │
│   suite_id u16          crypto suite (§7)                    │
│   flags u16                                                  │
│   section_table_off u64 | section_table_count u32            │
│   footer_off u64                                             │
│   reserved[…]           MUST be zero, validated              │
├──────────────────────────────────────────────────────────────┤
│ Section payloads — each 4096-byte aligned (mmap/page)        │
├──────────────────────────────────────────────────────────────┤
│ Section table — fixed-width 128 B records, castable, aligned │
│ Chunk indices — fixed-width, one per chunked section         │
│ Manifest — canonical CBOR (RFC 8949 §4.2)                    │
│ Key envelopes — hybrid KEM, one per recipient                │
│ Entitlement chain — append-only signed records (§9)          │
├──────────────────────────────────────────────────────────────┤
│ Footer                                                       │
│   root[32]              BLAKE3 over table + all section roots │
│   sig_classical[64]     Ed25519                              │
│   sig_pq[3309]          ML-DSA-65                            │
│   total_len u64 | magic[8] repeated                          │
└──────────────────────────────────────────────────────────────┘
```

### Header (64 B, normative offsets)

Little-endian throughout, every field naturally aligned so the header stays
castable:

```
off  size  field
  0     8  magic                = 89 43 54 46 0d 0a 1a 0a
  8     2  version_major        reader MUST reject an unimplemented major
 10     2  version_minor
 12     4  header_len           = 64 for this major
 16     2  suite_id             crypto suite (§7)
 18     2  flags                no bits assigned yet — MUST be 0
 20     4  section_table_count  capped before it can size an allocation
 24     8  section_table_off    ≥ 64, 8-byte aligned
 32     8  footer_off           ≥ section table end
 40    24  reserved             MUST be zero
```

The signature is exactly PNG's construction with `CTF` as the three-character tag,
which is why it is 8 bytes and why every byte is load-bearing:

| Byte | Value | Job |
|---|---|---|
| 0 | `\x89` | Non-ASCII. Detects 7-bit stripping and flags the file as binary |
| 1–3 | `C` `T` `F` | Human-readable in a hexdump and in `strings` |
| 4–5 | `\x0d\x0a` | CRLF. Detects CRLF→LF mangling by a text-mode transfer |
| 6 | `\x1a` | DOS EOF. Stops `type file.ctf` dumping binary to a terminal |
| 7 | `\x0a` | LF. Detects the reverse LF→CRLF mangling |

Keeping it at 8 bytes also leaves the following `u16`/`u32` fields naturally aligned,
so the header is castable without shifting. Footer magic repeat enables reverse scan
and truncation recovery.

### Section record (128 B, fixed-width, every field naturally aligned)

```
off  size  field
  0     2  kind             1=manifest 2=artifact 3=generator 4=solver
                            5=writeup 6=entitlement 7=keys 8=progress
                            0 is never valid — a zero-filled record must reject
  2     2  name_id          index into the manifest name table
  4     2  flags            bit0 SEALED, bit1 PLAYER_VISIBLE, bit2 EXTERNAL
  6     1  enc              0=none 1=AEAD-STREAM
  7     1  comp             0=none 1=zstd (frame-aligned to chunks)
  8     8  offset           0 when EXTERNAL; else 4096-aligned
 16     8  len_stored       after compression and encryption; 0 when EXTERNAL
 24     8  len_plain        before compression and encryption
 32     4  chunk_size       0 = single chunk; else a power of two in 4 KiB..64 MiB
 36     4  reserved         MUST be zero
 40     8  chunk_index_off  0 when single chunk
 48    32  root             BLAKE3 root of the *plaintext*
 80    48  reserved         MUST be zero
```

`external` is a **flag, not a kind**. A section's kind says what it semantically
is; whether its bytes live inline or elsewhere is orthogonal, and an external
artifact and an external writeup are both sensible. Folding `external` into the
kind enum would make those unrepresentable.

`public` is likewise not a flag — it is the absence of `SEALED`. Encoding both
would create a fourth state that means nothing.

### Layout freedom

Sections may live anywhere in `[HEADER_LEN, footer_off)`. The diagram above is
illustrative, not normative: a writer streaming a multi-GB payload does not learn
final sizes until it finishes, so mandating a region order would force it to
buffer. The normative rules are only these, and all are enforced at parse time:

- No section overlaps another, and none overlaps the section table.
- Every inline range lies within `[HEADER_LEN, footer_off)`.
- Exactly one manifest section exists, and it is neither sealed, player-visible,
  nor external — the manifest is needed to do anything at all, so it cannot wait
  on a seal key that is offline during the event, and it carries the flag
  template, so it is never player-facing.
- `solver`, `writeup`, and `progress` sections **must** carry `SEALED`. An author
  who forgets to seal a writeup is stopped by the container, not by remembering.
- `SEALED` and `PLAYER_VISIBLE` are mutually exclusive. This is the first of §10's
  two independent checks, placed where a caller cannot skip it.
- `name_id` is unique across sections.

**Why not just zip** (the question from the first design pass): Pillar 3 needs a
byte-exact commitment, and zip metadata is not canonical — timestamps, entry
order, extra fields, per-writer quirks. Merkle-rooting a zip means fighting the
container. Canonical CBOR for semantics plus fixed-width aligned tables for
machine indices gives a deterministic commitment *and* a zero-parse hot path.

### Performance notes (R5)

- Semantic manifest is CBOR; **hot structures are not**. Section table and chunk
  indices are fixed-width and aligned so they are read by cast, not by parse.
- Hash is **BLAKE3**, which is already a Merkle tree — verified streaming and
  incremental verification come free. Do not hand-roll a Merkle tree.
  Verification is SIMD- and thread-parallel.
- Chunk size 1 MiB default. Nonce and chunk index derive from position, so
  verification and decryption parallelize across chunks.
- AES-256-GCM where AES-NI / ARMv8 crypto extensions exist (≈GB/s), ChaCha20 suite
  otherwise.
- **Zero-copy and verify-first conflict.** Resolution, normative: plaintext public
  sections may be mmap'd and verified lazily *per chunk* before that chunk's bytes
  are exposed to a caller. Encrypted sections are decrypted chunk-wise into owned
  buffers — never handed out as mapped ciphertext. No API returns unverified bytes.

## 7. Cryptography (R1)

Hybrid throughout: an attacker must break **both** the classical and the
post-quantum component.

### Suite 1 — default

| Role | Primitive |
|---|---|
| KEM | X25519 **+** ML-KEM-768 (FIPS 203), hybrid |
| AEAD | AES-256-GCM, STREAM-chunked |
| Hash / commitment | BLAKE3 (verified streaming) |
| KDF | HKDF-SHA-256 |
| Signature | Ed25519 **+** ML-DSA-65 (FIPS 204) — both MUST verify |

### Suite 2 — no AES acceleration

Identical, with XChaCha20-Poly1305 as AEAD.

### Suite 3 — long-term archive signature (optional)

Adds SLH-DSA (FIPS 205) alongside. Hash-based, conservative, large signatures.
Worth it for the permanent archive copy where ML-DSA's relative youth is a real
consideration; not worth it for in-event bundles.

### Hybrid KEM combiner

The combiner MUST be a KDF over both shared secrets **and the full transcript** —
never XOR, never plain concatenation of secrets alone:

```
ss = HKDF-SHA-256(
       ikm  = ss_x25519 ‖ ss_mlkem,
       salt = suite_id ‖ format_version,
       info = ct_x25519 ‖ ct_mlkem ‖ pk_x25519 ‖ pk_mlkem ‖ context_label )
```

Transcript binding prevents an attacker who controls one component's ciphertext
from steering the derived key. This mirrors TLS `X25519MLKEM768` and the hybrid
HPKE drafts. Follow them; do not improvise.

### Chunked AEAD — STREAM, not naive per-chunk

Naive per-chunk AEAD is reorderable and truncatable. Use the STREAM construction
(Hoang–Reyhanitabar–Rogaway–Vizár):

```
nonce = nonce_prefix(section_id, key_epoch) ‖ u32_be(chunk_index) ‖ final_flag
aad   = section_id ‖ chunk_index ‖ len_plain ‖ suite_id
```

`final_flag` on the last chunk only — this is what makes truncation detectable.
`aad` binds position and total length, which is what makes reordering and
splicing detectable. For a 40 GB forensics image this is the difference between
integrity and the appearance of integrity.

### Key hierarchy

```
event_secret (32 B — KMS/HSM, never in a bundle, never in git)
└── seed(challenge, subject) = HKDF(event_secret, chal_id ‖ version ‖ subject_id)
    ├── flag(subject)     = base32(HMAC(seed,"flag")[:10])   # 80 bits
    └── artifact_key      # per-subject generated artifacts

content_key (random, per section)
└── wrapped per recipient via hybrid KEM envelope:
    ├── storage   — platform KMS key. Gives R1 at rest.
    ├── seal      — offline/HSM, released at event end. NOT on the platform (§4).
    └── stage:N   — HKDF(flag(N-1), "stage" ‖ N)

holder_key(player) — X25519 + ML-KEM keypair, for entitlement and progress (§9)
```

Stage gating requires **derived** flags. The validator MUST reject `stage_gate` on
a static flag: an 80-bit derived flag is an acceptable key, a guessable static
string is not.

**Write zero crypto primitives.** Providers, with maturity noted honestly:

| Role | Crate | Status |
|---|---|---|
| BLAKE3 | `blake3` | Reference implementation, SIMD + rayon |
| Verified streaming | `bao` | Bao encoding lives here, not in `blake3` — audit its maturity before depending on it |
| AES-256-GCM, Ed25519 | `aws-lc-rs` | Audited, FIPS track, AES-NI |
| STREAM chunking | `aead::stream` (RustCrypto) | Implements Hoang et al. directly |
| ML-KEM-768 | `aws-lc-rs::kem` (stable), cross-checked against `libcrux-ml-kem` | libcrux is formally verified |
| ML-DSA-65 | dedicated crate, exact version pinned | **Weakest link.** `aws-lc-rs` exposes ML-DSA only under its `unstable` feature, which is mutually exclusive with `fips` and carries no semver guarantee |
| SLH-DSA | `slh-dsa` | For the archive suite only |

ML-DSA is the least settled primitive in the whole design. Isolate it behind a single
trait so `suite_id` can retire a suite without touching the container format. That
field exists precisely for this.

## 8. Generator execution model

`gen.wasm` — WebAssembly, minimal host ABI, **no WASI**. No clock, no network, no
filesystem, no `getrandom`. Input: seed bytes. Output: named artifact byte
streams plus the flag.

Determinism is a property of the sandbox, not of author discipline. Reproducible
native builds fail constantly on timestamps, build paths, and toolchain drift; a
capability-free WASM module cannot observe any of them.

Determinism traps that the host MUST close:

- Pin the enabled WASM feature set in the format version. Determinism is only
  guaranteed relative to a pinned feature set.
- `relaxed-simd` is nondeterministic by specification, but it does not have to be
  banned: Wasmtime's `Config::relaxed_simd_deterministic(true)` forces one defined
  behaviour on every architecture, trading some performance for determinism. Set it
  rather than rejecting the feature.
- Canonicalize float NaN bits via `Config::cranelift_nan_canonicalization(true)`.
  Banning floats in generators outright is also acceptable and simpler; no real
  generator needs them.
- Forbid threads.
- **CPU limits must use fuel, not epochs.** `Config::consume_fuel` instruments
  generated code and traps at a fixed fuel count, so the limit is part of the
  deterministic result. `Config::epoch_interruption` is cheaper but wall-clock
  driven, which makes the interruption point nondeterministic — a generator near
  the limit would pass ingest and fail in production, or vice versa.
- Wasmtime's `rr` (record/replay) config *validates* that the determinism-relevant
  settings above are set, and fails otherwise. Use it in the conformance suite as a
  cross-check that the host was configured correctly.

Ingest runs the generator twice with the reference seed and rejects the bundle if
output roots differ. A challenge that would rot cannot be uploaded. Two runs in one
process catch nondeterminism from host state; the conformance suite must also run
the same bundle on a second architecture (x86-64 and aarch64) to catch the
codegen-level traps above.

`determinism: flag_only` requires **no generator at all** — static artifacts,
per-subject flag only. This is the default and it covers most challenges. Strict
per-subject artifact generation is opt-in for crypto and RE, where flag sharing
actually costs you something. Without this knob, R6 is unreachable.

## 9. Subjects, teams, and handoff (R3)

Two separate concepts, deliberately:

- **Subject** — what a seed binds to. `subject_scope: player | team | event`.
  Determines flags and per-subject artifacts. Default `team`.
- **Holder** — which player currently holds the challenge instance. A capability,
  not an identity.

Handoff (player A → player B, same team) is a holder change, not a subject change.
With `subject_scope: team`, B's artifacts and flag are identical to A's, so the
transfer is free. With `subject_scope: player`, transfer forces regeneration and
revocation of A's artifacts — support it, but it is the expensive path.

### Entitlement chain

An append-only, hash-chained, signed log carried in the bundle instance:

```
record {
  seq          u32           primary ordering — authoritative
  type         u8            grant | transfer | revoke | progress
  challenge_id, subject_id
  holder_pk_hash  [32]
  prev_hash       [32]
  timestamp       i64        platform-issued, ADVISORY ONLY
  payload         …          e.g. sealed progress blob
  sig_holder      hybrid     required for `transfer`
  sig_platform    hybrid     always
}
```

- `transfer` requires a signature from the **current** holder, making handoff
  non-repudiable — A cannot later claim B took it.
- `progress` carries stage flags already earned, sealed to B's holder key, so a
  handoff mid-multi-stage challenge does not reset progress.
- Ordering is by `seq`, never by `timestamp`. Clocks drift and clients lie; the
  timestamp is for humans and audit display only.

Why this belongs in the format rather than a database table: on-site CTFs run
air-gapped forensics workstations off USB media. The chain has to validate with no
platform reachable, and it has to stay auditable even if the platform's DB is
later found to be wrong.

## 10. Authoring surface (R6)

Authors never see CBOR, Merkle roots, KEMs, or suite IDs. They write YAML;
`ctf pack` compiles it to `.ctf`.

Minimum viable OSINT challenge:

```yaml
spec: 1
id: whos-that-bird
name: "Who's That Bird"
category: osint
description: "Where was this photo taken?"
flag: derived            # entire crypto stack configured by this one word
```

Full pwn challenge:

```yaml
spec: 1
id: baby-rop
version: 3
name: "Baby ROP"
category: pwn
description: |
  markdown; may reference attachments by label

flag:
  derive: hkdf-sha256
  template: "ctf{rop_%s}"
  scope: team              # player | team | event

generate:
  wasm: gen.wasm
  determinism: strict      # strict | flag_only | none
  outputs:
    - { name: chal,    player_visible: true }
    - { name: key.pem, player_visible: false }

runtime:
  image: "ghcr.io/ctf/baby-rop@sha256:…"   # digest-pinned, never a tag
  ports:     [{ container: 1337, protocol: tcp }]
  resources: { cpu: "0.5", memory: "256Mi", pids: 64 }
  instancing: per_team     # shared | per_team
  ttl: 30m
  readiness: { tcp: 1337, timeout: 30s }

sealed:
  release: event_end       # event_end | manual | stage:<id>
  members: [solver.wasm, writeup.md]

verify:
  solver: solver.wasm
  expect: flag
  offline: true            # gate implemented here (§3 pillar 5)
  live:                    # consumed by the orchestrator project
    interval: 5m           # re-solve cadence during the event

external:                  # forensics-scale payloads
  - name: workstation.E01
    size: 41231986688
    root: "blake3:…"
    mirrors: ["https://…"]
```

### Serving rule — default-deny, two independent checks

Only sections flagged `player_visible` are ever served, **and** a section flagged
`sealed` can never be `player_visible`. Enforce both; a leak here loses the event.
Never implement this as "serve everything except…".

### Validator strictness

Reject unknown keys rather than ignoring them. A typo'd `visibility` silently
publishing a hidden challenge mid-event is a real incident, not a hypothetical.

### CLI

| Command | Purpose |
|---|---|
| `ctf init <archetype>` | scaffold: osint / rev / pwn / web / forensics |
| `ctf validate` | schema + policy check, prose errors with fixes |
| `ctf pack` | YAML → `.ctf` |
| `ctf run` | **run the platform's full ingest gate locally**, same sandbox |
| `ctf inspect` | annotated hexdump, section table, commitment root |
| `ctf keys` / `ctf seal` / `ctf unseal` | key and seal-release management |
| `ctf transfer` | issue a handoff record |

`ctf run` is the single highest-leverage item for R6: if it passes locally, ingest
cannot surprise you.

### Admin TUI

The admin surface is a terminal UI, not a web dashboard. Consequences worth stating
because they are load-bearing, not cosmetic:

- No HTTP API, no auth layer, no session handling, no frontend build. The TUI links
  the core library directly and talks to Postgres over a connection string. The
  entire ingest path is one process.
- Ingest is a foreground operation with a real progress bar over chunk verification —
  which is the correct shape for a job that may be verifying 40 GB.
- `ctf inspect`'s annotated hexdump is the same widget in CLI and TUI.
- Operator access is SSH, so remote administration is free and needs no exposed
  service. For a 48-hour event this removes the largest attack surface a web
  dashboard would have added.

Screens: challenge list, ingest/validate, bundle inspector (section table + hexdump),
seal-release, entitlement/handoff audit log, verification status per challenge
(`passed` / `unverified` / `failed`, per §3 pillar 5).

## 11. Implementation stack (decided)

| Layer | Choice | Note |
|---|---|---|
| Core library | **Rust** | Zero-copy fixed tables via `zerocopy`, `memmap2`, `cargo-fuzz`, and the best crypto ecosystem for §7 |
| WASM host | **Wasmtime** | Only engine exposing all of §8's determinism knobs; pooling allocator for sub-ms instantiation |
| Determinism cross-check | `wasmi` | Second engine in the conformance suite. Two engines agreeing is a far stronger signal than one engine run twice |
| Generator interface | WIT + `wit-bindgen` | One interface definition, guest bindings for Rust/Go/C/Python free. Buys R6 with standard-side complexity, which R6 explicitly authorizes |
| CLI | Rust, `clap` | §10 |
| Admin TUI | `ratatui` + `crossterm` | §10 |
| Database | **Postgres**, deployed via **CloudNativePG** | Advisory locks for allocation, `LISTEN/NOTIFY` for status, JSONB for cached manifests |
| DB access | `sqlx` | Compile-time-checked SQL and built-in migrations; no ORM |
| Compression | `zstd` | Frame-aligned to chunk boundaries so sections stay seekable |
| Second implementation | Go | §14 — deliberately a different language with different crypto libraries |

Two notes on that table:

- **CloudNativePG is a Kubernetes operator, so it implies a cluster.** That is a
  deployment choice, not a code dependency: pin the Postgres major version, target
  plain SQL through `sqlx`, and develop against a local `postgres` container. Nothing
  in the codebase should know CNPG exists.
- The Go second implementation is not redundancy for its own sake. §14 wants a spec
  unambiguous enough that a different language with a different crypto stack produces
  byte-identical output. Go's stdlib `crypto/mlkem` makes it a genuinely independent
  path rather than a rewrite against the same libraries.

Deliberately **not** in this repo: container orchestration, scheduling, port
allocation, TTL reaping, object storage for external payloads. See §2's scope
boundary. External payload mirrors are URLs in the manifest; who hosts them is the
downstream project's problem.

## 12. Known costs

- **A minimal `.ctf` is ~6 KB, mostly PQ material.** ML-DSA-65 signatures are
  ~3.3 KB and public keys ~1.95 KB. Irrelevant next to a 40 GB image, dominant for
  a text-only OSINT challenge. Accepted consequence of R1, not a bug.
- **This is a large standard.** Hybrid KEM + STREAM + verified streaming +
  entitlement chain + WASM host is weeks of spec-and-implementation work for one
  person, not a weekend. R6 explicitly accepts that trade.
- Per-subject artifact generation costs CPU and storage. Cache by seed, generate
  lazily on first fetch. WASM makes this cheap; a Docker build per team would not.
- `.ctf` collides with Compact C Type Format (`libctf`, `ctfdump`, magic `0xcff1`).
  Different magic bytes, so `file`/libmagic can disambiguate cleanly, but the
  extension is shared. Noted, not blocking.

## 13. Build order

Each phase ships something usable on its own.

| Phase | Contents | Why here |
|---|---|---|
| 0 | Spec skeleton, hand-crafted hexdump example, test vectors | Byte layout is cheapest to change before code exists |
| 1 | Header, section table, canonical CBOR manifest, BLAKE3 verified streaming, external sections, `ctf inspect` | Already covers OSINT + RE + forensics with hashing only |
| 2 | Hybrid KEM envelopes, AEAD-STREAM, derived flags | R1 is mandated, so it lands before generators |
| 3 | Wasmtime host, determinism gate, WIT interface + guest SDKs | Pillar 1 |
| 4 | **Offline** solver gate | Pillar 5's implementable half. Live gate is specified only |
| 5 | Postgres schema, ingest pipeline, admin TUI | First point at which the thing is operable end to end |
| 6 | Entitlement chain, handoff, `ctf transfer` | Pillar 3's subject/holder split |
| 7 | Stage gating | Depends on derived flags from phase 2 |
| 8 | Fuzzing, conformance suite, Go second implementation | See §14 |

The TUI lands at phase 5 rather than phase 1 on purpose: until the offline gate
exists there is nothing for an operator to decide, and a TUI over an unverified
ingest path would only make a missing check look complete.

## 14. Parser hardening — non-negotiable

The reader is the attack surface, not the writer. Every item below has shipped as
a CVE in some real format:

- **Never allocate from a length field before validating it against remaining
  bytes.** This is the single most common format-parser bug.
- Bounds-check every offset before dereference. Reject offsets that point
  backwards, into the header, or that overlap another section.
- Depth cap on nested CBOR. Unbounded recursion is a stack-overflow DoS.
- Absolute output cap and ratio cap on zstd decompression.
- Reject duplicate section IDs and duplicate manifest keys. Ambiguity becomes a
  parser-differential exploit.
- Normalize and reject path-like names (`../`, absolute, symlink-shaped) in
  artifact names.
- Verify signatures and the commitment root **before** interpreting the manifest
  semantically. Nothing acts on unauthenticated content.
- Verify chunk authenticity before exposing chunk bytes (§6).
- Fuzz from day one: `cargo-fuzz` targets over header, section table, manifest,
  chunk index, and entitlement chain. Oracle: no panic, no OOM, and round-trip
  stability.
- **Write an independent second implementation from the spec text alone.** It is
  the only real test of whether the spec is unambiguous.
