# Rust guest SDK

`ctf-generator-sdk` is the Rust front end to the `.ctf` generator interface
(spec §23). An author writes one `generate` function, calls `export_generator!`,
and builds to `wasm32-unknown-unknown`; the macro emits the three ABI exports the
host calls.

```rust
use ctf_generator_sdk::{Generator, Outputs, export_generator};

#[derive(Default)]
struct Chal;

impl Generator for Chal {
    fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str> {
        let mut bytes = b"artifact:".to_vec();
        bytes.extend_from_slice(seed);
        out.add("chal", bytes);
        out.set_flag("ctf{example}");
        Ok(())
    }
}

export_generator!(Chal);
```

## Build

```
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The resulting `.wasm` has no imports: the host provides no WASI, clock, network,
filesystem, or randomness, so a module built from this SDK cannot observe one. That
is what makes determinism a property of the sandbox rather than of author
discipline.

## What the host calls

| Export | Signature | Meaning |
|---|---|---|
| `memory` | linear memory | Where the seed is written and the output block read |
| `ctf_alloc` | `(len: u32) -> u32` | Allocate `len` zeroed bytes; `0` on failure |
| `ctf_generate` | `(seed_ptr: u32, seed_len: u32) -> u32` | Run the generator; pointer to the output block, `0` on failure |
| `ctf_output_len` | `() -> u32` | Byte length of the block `ctf_generate` produced |

The output block is `u32 count`, then `count × { u32 name_len, name, u32 data_len,
data }`, then `u32 flag_len, flag`, all little-endian (spec §23.3).

## The sample

`sdk/sample-generator` is a complete module built with this SDK. It is compiled to
`crates/ctf-generator/tests/fixtures/generator.wasm`, which the host's tests run,
so the guest path is exercised end to end rather than mocked.
