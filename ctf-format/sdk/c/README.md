# C guest SDK for `.ctf` generators

This directory is the C half of the generator interface (design §8). A `.ctf`
bundle commits to a generator, and the generator is a pure function of a seed:
the host runs it, hashes the outputs, and accepts the challenge only when a
second run produces the same bytes. This SDK lets a C author write such a
generator without guessing at the host's calling convention or re-deriving the
output encoding by hand.

The interface is small on purpose. The module imports nothing — no WASI, no
clock, no filesystem, no `getrandom`. It cannot observe a timestamp, a path, or
a locale, so there is nothing for it to vary on. Determinism is a property of
the sandbox rather than of the author's discipline, and a C module with no
imports inherits that property for free.

## Files

| File | Purpose |
|---|---|
| `ctf_generator.h` | The ABI, the output-block wire format, and buffer-building helpers. Only `<stdint.h>` and `<stddef.h>` are included. |
| `example.c` | A complete generator: the three ABI exports, a bump allocator, and one output named `chal` carrying the seed plus a fixed flag. |

## Interface version

`ctf_generator.h` defines `CTF_GENERATOR_INTERFACE_VERSION` as `1`. It is the
version of the host-to-guest calling convention, pinned in the header rather
than negotiated at runtime.

It is deliberately not the container format version, and not the manifest's
`generate.profile` (spec §23.5). The `.ctf` byte layout, the WASM feature set a
generator may use, and the ABI are three independent contracts that retire on
their own schedules. Tying them to one number means a change that touches nothing about
generators silently changes what a generator must do. A host that reads a module
built against a different interface version must refuse it.

## ABI

The module exports `memory` and exactly three functions:

```c
uint32_t ctf_alloc(uint32_t len);
uint32_t ctf_generate(uint32_t seed_ptr, uint32_t seed_len);
uint32_t ctf_output_len(void);
```

- `ctf_alloc` allocates `len` zeroed bytes and returns their offset into linear
  memory, or 0 on failure. The host uses it to place the seed before calling the
  generator. Offset 0 is the failure sentinel.
- `ctf_generate` reads `seed_len` bytes at `seed_ptr` and returns the offset of
  an output block in linear memory. The block must stay valid until the next
  `ctf_generate` call. It returns 0 on failure.
- `ctf_output_len` reports the byte length of the block the last
  `ctf_generate` produced, and 0 before the first call.

All three have C linkage and exactly these names.

## Output-block wire format

The host reads `ctf_output_len()` bytes starting at the pointer `ctf_generate`
returned. That block is, little-endian throughout:

```
u32 count
count × { u32 name_len; name bytes (UTF-8); u32 data_len; data bytes }
u32 flag_len; flag bytes (UTF-8)
```

`count` is the number of named outputs. Each name is a UTF-8 byte string that
the host resolves through the manifest's name table. The flag follows the last
output. Integers are written explicitly little-endian so a generator built by
any toolchain produces the same bytes.

`ctf_generator.h` provides `ctf_output_begin`, `ctf_output_add`,
`ctf_output_set_flag`, and `ctf_output_finish` to build this block in a buffer
the caller owns. They never allocate: a freestanding module with no allocator,
or with a fixed arena it cannot grow, can still use them. `finish` patches
`count`, writes the flag, and returns the block pointer; afterwards
`writer.used` is the length to report from `ctf_output_len`. See `example.c`.

## Build

Apple clang and upstream clang both ship a wasm32 target. The link step needs
`wasm-ld` (LLVM's `lld`) on `PATH`. It ships with LLVM distributions and with
many package managers' LLVM packages, but it is not present in every Xcode
command-line-tools install; if the command below fails with `posix_spawn
failed`, that is a missing linker rather than a bad module.

```sh
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-memory \
  -Wl,--export=ctf_alloc -Wl,--export=ctf_generate -Wl,--export=ctf_output_len \
  -o gen.wasm example.c
```

What each flag is for:

- `--target=wasm32` selects the guest architecture and its 32-bit pointers. The
  ABI passes offsets as `uint32_t`, so a 64-bit target would not match.
- `-nostdlib` keeps libc and crt out of the module. The header and the helpers
  are self-contained, so nothing in libc is needed, and a module that reached
  for one would pull in an import.
- `-Wl,--no-entry` says there is no `_start`. A generator is entered through
  `ctf_generate`, not by the runtime.
- `-Wl,--export-memory` is required because the host reads the output block out
  of the module's linear memory by offset. Without it wasm-ld does not export
  `memory` and the host has nowhere to read.
- `-Wl,--export=ctf_alloc`, `--export=ctf_generate`, and
  `--export=ctf_output_len` are how the three ABI functions become visible. They
  are otherwise dead code to the linker and would be dropped.

`-Wl,--allow-undefined` is deliberately **not** passed. It would let the link
succeed with an unresolved symbol turned into an import, and the module must
have no imports. A generator that fails to link is telling you it depends on
something the sandbox does not provide; silence that error and the challenge
stops being deterministic.

## Verification without a link

To syntax-check the header and example without a wasm linker:

```sh
clang --target=wasm32 -fsyntax-only -I. example.c
```

A failing link for lack of `wasm-ld` is expected in environments that do not
have LLVM's `lld`; the syntax check above still catches header and type errors.
