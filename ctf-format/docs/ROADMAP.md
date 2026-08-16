# Roadmap

Companion to [FORMAT-DESIGN.md](FORMAT-DESIGN.md). Phases follow design §13. Each
phase must end with something runnable — no phase exists purely to enable the next.

## Repository layout (target)

```
Cargo.toml                workspace root
rust-toolchain.toml       pinned toolchain — determinism starts here
crates/
  ctf-format/             core library: container, crypto, wasm host
  ctf-cli/                `ctf` binary (clap)
  ctf-tui/                admin TUI (ratatui) — phase 5
  ctf-conformance/        vector runner + cross-engine checks — phase 8
spec/
  SPEC.md                 normative byte-level spec, extracted from the design doc
  vectors/                golden `.ctf` fixtures + hostile-input corpus
go/                       independent second implementation — phase 8
docs/
```

`ctf-format`, `ctf-cli`, and `fuzz/` exist today. Remaining crates get created
when their phase starts, not before.

---

## Phase 0 — Byte layout frozen ▸ *done*

Byte layout is cheapest to change before any code depends on it.

- [x] Header layout: 64 B, field offsets fixed, all fields naturally aligned
- [x] Section record layout: 128 B, field offsets fixed, naturally aligned
- [x] 8-byte signature, PNG construction, per-byte rationale
- [x] `rust-toolchain.toml` pinning 1.97.1
- [x] Endianness stated normatively: **little-endian throughout**
- [x] Golden vector for the header: exact 64 bytes asserted in
      `tests/container.rs::header_golden_vector`
- [x] Golden vector for a section record: exact 128 bytes asserted in
      `tests/container.rs::record_golden_vector`
- [x] `spec/SPEC.md` — normative, RFC-style: numbered rules H1–H14, R1–R18,
      T1–T5, golden vectors, reader conformance procedure, security
      considerations, and an explicit list of what is *not* yet specified
- [x] **Compatibility model frozen at 0.2** — `feat_incompat` / `feat_ro_compat`
      words in the header, `OPTIONAL` section flag, extension policy binding
      future editors, and a compatibility matrix. No field moved, so the 0.1
      header stays valid and is kept as a regression test

---

## Phase 1 — Container: read, write, verify ▸ *done*

Covers OSINT + RE + forensics archetypes with hashing only. No crypto beyond
BLAKE3. Shipped as format version **0.3**, announced by `feat_ro_compat` bit 0
(`CONTAINER_V1`) — the narrowings below constrain structures 0.2 declared
unspecified, so the extension policy requires a bit rather than a silent bump.
`ro_compat` rather than `incompat`: a 0.2 reader answers correctly about
everything it checks, while a 0.2 *rewriter* would drop the footer. So 0.3 files
stay readable by 0.2 readers and unrewritable by them.

- [x] `Header` parse/write, hardened: magic, version, `header_len`, reserved-zero,
      unknown-flag reject, count cap before allocation, offset bounds, alignment,
      checked overflow, footer ordering
- [x] `SectionRecord` parse/write; fixed width, so record *N* is seekable without
      parsing `0..N`
- [x] Record invariants: kind 0 invalid, unknown enc/comp/flags rejected,
      `SEALED` excludes `PLAYER_VISIBLE`, solver/writeup/progress forced sealed,
      manifest never sealed or player-visible, EXTERNAL carries no inline bytes,
      chunk size a power of two in range, AEAD requires chunking,
      `len_stored == len_plain` when neither compressed nor encrypted
- [x] Layout validator: exactly one manifest, unique `name_id`, no section overlaps
      another or the section table, everything inside `[HEADER_LEN, footer_off)`
- [x] Tests one per rule, each mutating a known-good fixture by one field
- [x] Footer + commitment root as fixed in design §6: `BLAKE3("ctf/root/v1" ‖
      header ‖ section table)`, the signed transcript, and the no-trailing-bytes
      rule. Footer is variable-width — a signature's size is a suite property —
      and carries no padding at all, so slack cannot hide bytes outside the
      commitment
- [x] Golden vector for a whole minimal `.ctf`: 4344 bytes, every region pinned,
      spec §11
- [x] Canonical CBOR manifest encode/decode (RFC 8949 §4.2.1), **enforced on
      decode as well as encode**, with duplicate keys unrepresentable, a depth
      cap, and floats and tags excluded
- [x] BLAKE3 section roots + footer commitment root
- [x] Chunked verified streaming — **`bao` audited and rejected**, see below
- [x] `external` sections: hash + size + mirror list, no bytes inline; record
      outranks the manifest and a mismatch rejects
- [x] `ctf inspect` — annotated hexdump, section table, commitment root
- [x] `cargo-fuzz` targets: whole bundle, header, section table, manifest, chunk
      index, with a seed corpus committed
- [x] `tests/mutation.rs` — the same oracle on the pinned stable toolchain, so a
      fixed finding stays fixed without needing nightly

**Done:** a 40 GB external payload verifies incrementally, in bounded memory or
per chunk, and a truncated or byte-flipped file is rejected with a precise error.

### The `bao` audit, and what replaced it

`bao` 0.13.1 is BLAKE3 verified streaming by BLAKE3's own author, with a written
spec and test vectors. It was still the wrong dependency here, for a reason that
has nothing to do with code quality: adopting it means adopting **its encoding**
as a normative part of `.ctf`, which phase 8's independent Go implementation would
then have to reproduce from a second document, with no Go `bao` to lean on. Being
pre-1.0 with a single maintainer was the secondary concern.

The replacement is better than the roadmap's stated fallback. Rather than an index
of independent per-chunk hashes — which would not reduce to the section's `root`,
and so would need a commitment of its own in a frozen record field — the index
stores each chunk's BLAKE3 **chaining value**, via `blake3::hazmat`. Because
`chunk_size` is a power of two of at least 4 KiB, every chunk boundary is a BLAKE3
subtree boundary, so merging the entries reproduces `BLAKE3(plaintext)` exactly.

Three consequences:

- **The index is committed by construction.** A forged index cannot reduce to the
  section root, which lives in the table, which the footer commits to. No new
  field, no addition to the root definition.
- **Its length is derived** — `ceil(len_plain / chunk_size) × 32` — so
  `chunk_index_off` is finally bounds- and overlap-checked like every other
  region. That closes the `ponytail:` comment 0.2 left in `section.rs`.
- **The cost is stated**: no interior tree nodes, so verifying one chunk means
  reading the whole index. Kilobytes against gigabytes, and not something ingest
  or serving needs.

The claim that the merge equals `blake3::hash` is checked against `blake3::hash`
across 48 input shapes, not argued from the tree structure.

---

## Phase 2 — Cryptography (design §7)

R1 is mandated, so this lands before generators.

- [ ] Suite registry + `suite_id` dispatch behind one trait per primitive role
- [ ] Hybrid KEM: X25519 + ML-KEM-768, transcript-binding HKDF combiner
- [ ] Hybrid signature: Ed25519 + ML-DSA-65, **both** must verify
- [ ] AEAD-STREAM chunked encryption (`aead::stream`), `final_flag` on last chunk
- [ ] Key envelopes: `storage`, `seal`, `stage:N` recipients
- [ ] Flag derivation from `event_secret`; `event_secret` never touches a bundle
- [ ] `ctf keys` / `ctf seal` / `ctf unseal`
- [ ] Test vectors for every primitive, checked against a second library

**Done when** a sealed bundle cannot be opened without the seal key, and the
offline test suite proves it rather than asserting it.

**Known risk:** ML-DSA is the least mature primitive in the stack. Keep it behind
its trait; `suite_id` exists so a suite can be retired without a format change.

---

## Phase 3 — Generator (design §8)

- [ ] Wasmtime host, no WASI, custom capability-free ABI
- [ ] Determinism config: `relaxed_simd_deterministic`, `cranelift_nan_canonicalization`,
      threads off, **fuel not epochs** for CPU limits
- [ ] WIT interface + `wit-bindgen` guest SDKs (Rust first, then C)
- [ ] Determinism gate: two runs in-process, plus x86-64 and aarch64 in CI
- [ ] `determinism: flag_only` path requiring no generator at all — this is the
      default and it carries most challenges
- [ ] `ctf init <archetype>` scaffolds a working generator per archetype

**Done when** the same bundle produces byte-identical artifacts on x86-64 and
aarch64, and a deliberately nondeterministic generator is rejected at ingest.

---

## Phase 4 — Offline solvability gate

Pillar 5's implementable half.

- [ ] Run `solver.wasm` against generated artifacts, no network, same sandbox
- [ ] Assert solver output equals the derived flag
- [ ] Live-gate interface specified in `spec/SPEC.md` — the socket contract the
      orchestrator project must satisfy
- [ ] Verification status is tri-state: `passed` / `unverified` / `failed`.
      `runtime`-bearing bundles land on `unverified`, never `passed`
- [ ] `ctf run` — the full local ingest gate, identical to the platform's

**Done when** `ctf run` passing locally guarantees ingest cannot surprise the
author. This is the highest-leverage item in the roadmap for R6.

---

## Phase 5 — Platform: Postgres + admin TUI

First point at which the system is operable end to end.

- [ ] Postgres schema: challenges, bundles, sections, verification status,
      entitlement records
- [ ] `sqlx` migrations; plain SQL only, no CloudNativePG awareness in code
- [ ] Ingest pipeline: validate → verify → offline gate → store
- [ ] `ratatui` screens: challenge list, ingest, bundle inspector, seal release,
      verification status, entitlement audit log
- [ ] Chunk-verification progress bar (a 40 GB ingest needs one)
- [ ] Serving rule enforced with two independent checks: `player_visible` allowlist
      **and** `sealed` never visible. Never "everything except"

**Done when** an operator can ingest, inspect, and release a bundle without
touching the CLI.

---

## Phase 6 — Subjects, holders, handoff (design §9)

- [ ] Entitlement chain: append-only, hash-chained, hybrid-signed
- [ ] `grant` / `transfer` / `revoke` / `progress` records
- [ ] `transfer` requires the current holder's signature — non-repudiable handoff
- [ ] `progress` carries earned stage flags sealed to the new holder's key
- [ ] Ordering by `seq`; `timestamp` is advisory display only
- [ ] Offline validation: chain verifies with no platform reachable (air-gapped
      forensics workstation on USB media)
- [ ] `ctf transfer`

**Done when** a handoff mid-multi-stage challenge preserves progress and the chain
validates offline.

---

## Phase 7 — Stage gating

Depends on phase 2's derived flags.

- [ ] `stage:N` section key = `HKDF(flag(N-1), "stage" ‖ N)`
- [ ] Validator **rejects** `stage_gate` on static flags — a guessable string is
      not a key
- [ ] Test: stage 3 stays opaque ciphertext even when the whole bundle is handed
      over

**Done when** the crypto enforces unlock order with the platform's gating logic
deliberately disabled in the test.

---

## Phase 8 — Hardening and the second implementation

- [ ] Full §14 hardening checklist audited line by line against the code
- [ ] Fuzzing in CI, corpus committed
- [ ] Hostile-input vector corpus: one fixture per §14 bullet, each with its
      expected error
- [ ] **Synthetic "future file" vectors** — files that set an invented
      `feat_incompat` bit, an invented `feat_ro_compat` bit, and an `OPTIONAL`
      section of an undefined kind. The only way to test forward compatibility
      before a real extension exists, and the check that spec §12's compatibility
      matrix is true rather than aspirational
- [ ] `wasmi` as a second engine in the determinism cross-check
- [ ] **Go second implementation written from `spec/SPEC.md` alone**, no peeking at
      the Rust source
- [ ] Both implementations produce byte-identical output on every vector

**Done when** the Go implementation round-trips every vector without a single spec
clarification needed. Any clarification required is a spec bug, and the spec gets
fixed rather than the Go code.

---

## Deliberate simplifications

Tracked here so they do not rot into permanent accidents. Each is also marked with
a `ponytail:` comment at its site in the code.

- **Section records parsed with `from_le_bytes`, not a zero-copy cast.** The design
  doc's "castable" requirement is really about fixed width — seeking to record *N*
  without parsing records 0..*N* — and `from_le_bytes` preserves that. A challenge
  has tens of sections, not millions; the hot path is BLAKE3 over gigabytes.
  Upgrade to `zerocopy` typed LE fields only if profiling shows table parsing on a
  flame graph.
- **Canonical CBOR is hand-written, not a dependency.** The subset is small — six
  major types and three simple values — and the requirement that makes it worth
  writing is one no mainstream CBOR crate offers: *rejecting* non-canonical input
  on decode. A library that encodes canonically but decodes permissively would
  leave the commitment's injectivity unenforced, which is the property the whole
  of pillar 3 rests on. Revisit if a strict-decoding crate appears.
- **No compression or encryption in the writer.** `write_bundle` emits `enc = 0`,
  `comp = 0` only. zstd needs the output and ratio caps that are still unspecified,
  and AEAD is phase 2. The reader parses both fields and refuses to act on them,
  which is the honest state rather than a silent gap.
- **`ctf` has no argument-parsing dependency.** `clap` is right at the roadmap's
  eight subcommands with flags and completions; it is not right at one subcommand
  and two flags. Add it when the second subcommand lands.
- **The chunk index has no interior tree nodes**, so single-chunk random access
  costs a full index read. See the `bao` note above.
- **External dependencies: `blake3` only.** Header, section table, CBOR, manifest,
  footer, and chunk index are otherwise pure `std`.

## Out of scope (see design §2)

Container orchestration, scheduling, port allocation, TTL reaping, and hosting of
external payloads. All belong to the downstream orchestrator project, which starts
once this standard is stable. External payload mirrors are URLs in the manifest;
who serves them is not this repository's concern.
