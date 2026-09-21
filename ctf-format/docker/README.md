# The challenge base image contract

Normative: [`spec/SPEC.md`](../spec/SPEC.md) §31, §26. This image runs a
generator-based `.ctf` challenge on the platform. It is the contract between the
format's tooling and the orchestrator project (design §2): the format declares it,
the orchestrator boots it.

## What is in the image

- The `ctf-generator` host, built from this repository at the pinned toolchain.
  It runs `gen.wasm` under the determinism gate (spec §23) — no WASI, no clock, no
  network, no filesystem, fuel-limited — and writes the generated artifacts.
- Nothing else. No shell, no package manager, no challenge code beyond what the
  bundle's runtime image adds.

Build it from `ctf-format/`:

```bash
docker build -f docker/Dockerfile -t ctf-challenge-base .
```

## Mounts

| Path | Contents | Direction |
|---|---|---|
| `/ctf/data` | generated artifacts | written by the generator |
| `/ctf/seed` | the 32-byte per-subject seed (raw, or 64 hex digits) | read-only |
| `/ctf/flag` | the derived flag text | read-only (optional) |

The seed may instead be injected as the `CTF_SEED` environment variable (64
lowercase hex digits); the environment wins over the mount (spec §26). The derived
flag may be injected as `CTF_FLAG`; when it is present, the generator's computed
flag must match it or the container fails at start.

## Security defaults

- **Non-root.** The image's `USER` is `nonroot` (distroless UID 65532).
- **Read-only root filesystem.** The orchestrator MUST run the container with
  `--read-only` (or the equivalent), so only `/ctf/data` is writable.
- **No network.** The generator needs none; the runtime instance's network is the
  orchestrator's policy, not the format's.

```bash
docker run --rm \
  --read-only \
  --tmpfs /ctf/data \
  --mount type=bind,src="$SEED",dst=/ctf/seed,readonly \
  --mount type=bind,src="$GEN",dst=/ctf/gen.wasm,readonly \
  ctf-challenge-base --module /ctf/gen.wasm --out /ctf/data
```

## End to end

A container with no injected seed fails rather than guessing (spec §26). With a
seed, the generator runs and the artifacts appear under `/ctf/data`. The reference
test `crates/ctf-generator/tests/container.rs` runs the binary end to end against
the sample generator and asserts the outputs; the Docker layer only adds the image
around that same binary.
