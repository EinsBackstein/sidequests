# Reference challenge fixtures

Two real challenges from
[`CTF-FlagFrenzy/challenges`](https://github.com/CTF-FlagFrenzy/challenges),
vendored as authoring documents so `ctf pack` and the determinism gate are
regression-tested against something that is not a synthetic minimal example.

| Fixture | Reference | `id` | `name` | `category` | Port |
| --- | --- | --- | --- | --- | --- |
| `file_and_seek/challenge.yaml` | `File_And_Seek` | `file-and-seek` | `File And Seek` | `Web-challenge` | 80 |
| `mental_overflow/challenge.yaml` | `Mental_Overflow` | `mental-overflow` | `Mental Overflow` | `Reverse Engineering` | 80 |

Both upstream challenges are Flask apps exposing port 80 under docker-compose,
so both fixtures declare `runtime` with `ports: [{ container: 80, protocol: tcp }]`
and `readiness: { tcp: 80, ... }`.

## Why the account is a *declaration*, not a bundle

`ctf pack` compiles the authoring YAML into an unsigned `.ctf` bundle whose
manifest carries the declaration keys (spec §7.6); it does not run a generator,
fetch an image, or boot a container. The fixtures therefore test the authoring
surface and the platform descriptor against realistic declarations — not the
upstream Python.

## The image digest is a placeholder

`runtime.image` must be digest-pinned (`name@sha256:<64 lowercase hex>`, ticket
61). The fixtures use the reserved `.invalid` TLD (RFC 2606) and all-`1` /
all-`2` digests to signal that these are shape-valid **placeholders**, not real
image digests. No container is pulled or booted anywhere in these tests.

## Mental Overflow's generator

`mental_overflow/gen.wasm` is built from the detached guest crate at
`sdk/reference/mental-overflow-gen/`:

```text
cargo build --release --target wasm32-unknown-unknown \
  --manifest-path sdk/reference/mental-overflow-gen/Cargo.toml
```

It is the deterministic port of the upstream `src/script.py`. The only change
that matters for the format is that the two characters standing in for the
flag's braces are derived from the seed instead of `random.sample`, so the
artifact is a pure function of the seed and the determinism gate passes. The
output flag is the spec §22.3 derivation; the regression test pins it against
the independent Python known-answer vector from
`crates/ctf-format/tests/derive.rs`.

The reference challenge carries no `verify` block: it is a runtime challenge,
so it is `unverified`, never `passed` (spec §25.6).
