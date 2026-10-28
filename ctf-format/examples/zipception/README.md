# Zipception, ported to `.ctf`

This is the [`zipception`](https://github.com/EinsBackstein/Challenges/tree/t3/nested-zip-ctf-challenge/zipception)
challenge from `EinsBackstein/Challenges`, packaged as a self-contained
`zipception.ctf` bundle. Nothing about the puzzle changed: the player still gets a
ZIP nested 150 times, every layer adds a 120-character directory component, and
extracting in place still hits `PATH_MAX` (macOS/Linux) or `MAX_PATH` (Windows)
long before the flag.

What changed is where the bytes come from and how the flag is chosen. The bundle
carries the generator module, so deploying it needs no authoring directory: a
platform derives the subject's seed, runs the module from the bundle, and serves
the archive it produces.

## Quick start

From this directory:

```sh
./build.sh
```

That builds `gen.wasm` and `solver.wasm`, validates and packs `challenge.yaml`
into a 60 KB bundle that carries the generator, runs the offline gate, then copies
the bundle into a scratch directory with nothing else, generates the reference
subject's archive from it, and solves that archive with `solve.py`. Expected tail:

```text
gate          passed
  determinism passed  (2 runs; second engine agreed)
  ...
  compare     solver flag == derived flag
bundle: zipception.ctf
subject: reference
output: played.zip (53416 bytes)
flag: ox4vm4izat66vmt5
[*] unwrapped 150 layers in 0.003s; ...
player solver recovered: ox4vm4izat66vmt5
```

`build.sh` uses a development secret. Set `CTF_EVENT_SECRET` to 64 hex digits for
a different subject seed, and therefore a different flag, layer names and archive.

## The files

| File | What it is |
|---|---|
| `challenge.yaml` | The authoring document: identity, derived flag, strict generator, sealed solver, offline verification. |
| `generator/src/lib.rs` | The generator guest. Builds the 150 nested archives and derives the flag, both from the seed alone. |
| `generator/src/bin/preview.rs` | Development tool: renders the archive for a hex seed so you can look at what a player receives. |
| `solver/src/lib.rs` | The gate solver guest. Unwraps the archive in memory and returns the flag. |
| `play/src/main.rs` | Deployment-side tool: reads the bundle, derives a subject's seed, runs the bundle's generator section, writes the player artifact. |
| `solve.py` | The player-facing solver, adapted from the upstream Python reference. |
| `build.sh` | End-to-end: build, pack, gate, then deploy the bundle into a scratch directory and play it. |

`gen.wasm`, `solver.wasm`, `zipception.ctf`, `inception.zip`, the status records
and the `play` output are build output and are git-ignored.

## How the port maps

| Upstream | Here |
|---|---|
| Go generator in `src/internal/nestzip` | `generator/src/lib.rs`, built to `gen.wasm` and carried in the bundle's `generator` section (spec §5.2 kind 3, §23) |
| HTTP service serving `challenge.zip` | No service. The platform derives the subject seed, runs the bundle's generator, and serves the `generate.outputs` artifact it produces. |
| `.env` `CHALLENGE_KEY` + `FLAG_PREFIX`/`FLAG_SUFFIX` | The §22.3 derived flag: `HKDF-SHA-256` for the subject seed, then `HMAC-SHA-256(seed, "ctf/flag/v1")[0..10]` as 16 lowercase base32 characters. |
| `SEED` environment variable | The subject seed itself; every team gets different layer names and a different flag. |
| `docs/parameters.yaml` | The manifest declarations (`generate`, `verify`, `sealed`, `flag`). |
| `docker-compose.yaml`, `Dockerfile` | Not needed: there is no service to boot. |
| `solvers/solve.py` | `solve.py` for players; `solver/src/lib.rs` is the same idea as a gate solver. |

The event secret never enters the bundle (rule DF1). The bundle carries only the
derivation rule and the declarations; `crates/ctf-tui`'s ingest pipeline is what
would record a gate result for it.

### Why the flag has no braces

The upstream flag is `FLAG_PREFIX + CHALLENGE_KEY + FLAG_SUFFIX`, normally
`flag{...}`. The format fixes the flag as a value derived from the seed, so it
cannot also be an author-chosen wrapper: §22.3's value is what the gate compares a
solver's output to. This port therefore uses the 16-character derived value
(`ox4vm4izat66vmt5` above, for the `reference` subject with the development
secret) as the flag, and `flag.txt` at the bottom of the chain holds exactly those
bytes.

`challenge.yaml` does not declare `flag.template`: a template is carried for the
platform, but the reference gate compares the bare derivation, and a wrapper that
the solver had to strip would only add a place to disagree.

### Why entries are stored, not deflated

The upstream generator defaults to DEFLATE. This one stores entries (ZIP method 0)
for two reasons:

- A guest module cannot import a deflate implementation from the host (spec
  §23.1 provides no I/O at all), so it would have to carry one. That is a
  dependency with no effect on the puzzle.
- A hand-written ZIP writer with a fixed DOS timestamp is byte-identical on both
  engines and in a native build, which is what the determinism gate checks.

The outer archive is about 53 KB with 150 layers; enabling deflate would save a
few kilobytes and change nothing a player sees.

### Layer names

Upstream draws 100 base62 characters per layer from Go's PCG, seeded by a single
`SEED`. Here each layer's 100 characters come from a SHA-256 counter stream keyed
by the per-subject seed and the layer index, so the archive is stable for a
subject and different between subjects. The recognisable
`layer_0150_of_0150_...` prefix is unchanged.

## Deploying it

`ctf pack` writes a 60,568-byte bundle with two sections:

| `name_id` | Kind | Name | Notes |
|---:|---|---|---|
| 0 | `manifest` | `manifest` | identity, `generate`, `sealed`, `verify`, `flag` |
| 1 | `generator` | `gen.wasm` | 52,060 bytes of WebAssembly, not player-visible |

The module is embedded because it sits beside `challenge.yaml` when `ctf pack`
runs; the bundle declares `generate.wasm: gen.wasm`, and §7.6 makes the section's
`name_id` that same name-table entry. Without the file the bundle still packs and
the module has to travel with the challenge image instead (spec §31 B1) — that is
why `ctf pack` prints a note rather than failing.

The solver is **not** in the bundle. `sealed: { release: event_end, members:
[solver.wasm] }` and rule R6 require a solver section to be `SEALED`, which R21
requires to be encrypted; the reference tooling holds no key for it. Withholding
it until event end is the point, and the authoring-side gate reads the author's
file.

`play/` is the deployment path in miniature and the proof that the file is
self-contained:

```sh
# from a directory containing only zipception.ctf
cargo run --manifest-path …/play/Cargo.toml -- \
  zipception.ctf --secret "$CTF_EVENT_SECRET" --subject alice --out alice.zip
```

It reads the manifest, derives `seed(zipception, alice)` (§22.2), runs the
`generator` section under the §23 sandbox, checks that the flag the module returns
is the one §22.3 derives, and writes the one player-visible output. That is
exactly what a platform does per subject; `play` is the reference implementation
because the runtime generator host (§26) lives in the orchestrator, outside this
repository.

One consequence worth knowing: `ctf serving-manifest zipception.ctf` reports
`0 servable artifact(s)`. That is correct — `inception.zip` is generated per
subject, not a static artifact in the file, so it is the generator host, not the
static serving manifest, that produces it.

The gate can also be run against the bundle's own module, with the authoring
document supplying only the solver:

```sh
ctf verify zipception.ctf --challenge challenge.yaml --secret "$CTF_EVENT_SECRET"
```

`build.sh` does this from the scratch directory, where `gen.wasm` is absent:
`status: passed` there is the proof that the generator came out of the bundle.

## Solving it by hand

Everything from the upstream writeup still applies, with the file renamed:

```sh
python3 solve.py inception.zip      # any platform, stdlib only
unzip -p inception.zip ...          # loop, Linux/macOS
7z e -so inception.zip > next.zip   # Windows
```

The trap is the same: extracting to disk creates a path of
`150 × (120 + 1) + 8 = 18,158` characters, so the OS refuses around layer 9 on
macOS, 2 on Windows, and 34 on Linux. Streaming never creates the path.

## Rebuilding only the archive

```sh
cargo run --manifest-path generator/Cargo.toml --bin preview -- <64 hex digits> inception.zip
```

The seed is not the event secret; it is the 32-byte per-subject seed of §22.2.
Passing the raw event secret produces a different (still valid) archive, which is
why the gate, not the preview, is what decides whether a deployment is correct.
