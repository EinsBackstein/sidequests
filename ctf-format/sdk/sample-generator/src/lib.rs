//! A sample generator built with the Rust guest SDK.
//!
//! It emits one player-visible artifact, `chal`, whose bytes are a deterministic
//! function of the seed, and a fixed flag. It is the fixture the host's tests run
//! and the module `ctf init rev` names, so it doubles as the worked example of the
//! interface (spec §23).
//!
//! Build:
//!
//! ```text
//! cargo build --release --target wasm32-unknown-unknown
//! ```

use ctf_generator_sdk::{export_generator, Generator, Outputs};

/// The sample's generator type. `Default` is all the SDK needs to instantiate it.
#[derive(Default)]
struct Sample;

impl Generator for Sample {
    fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str> {
        // A deterministic transform of the seed: the host proves the same seed
        // yields the same bytes on two engines and two architectures.
        let mut artifact = Vec::with_capacity(seed.len() + 16);
        artifact.extend_from_slice(b"artifact-v1:");
        for (i, byte) in seed.iter().enumerate() {
            artifact.push(byte.wrapping_add((i as u8).wrapping_mul(31)));
        }
        // A second output, never served to a player, exercises the
        // `player_visible` mapping (spec §7.6).
        let mut key = Vec::with_capacity(seed.len());
        key.extend_from_slice(seed);
        key.reverse();

        out.add("chal", artifact);
        out.add("key.bin", key);
        out.set_flag("ctf{example}");
        Ok(())
    }
}

export_generator!(Sample);
