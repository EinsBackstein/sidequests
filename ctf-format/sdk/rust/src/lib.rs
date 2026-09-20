//! Rust guest SDK for the `.ctf` deterministic generator interface (spec §23).
//!
//! An author writes one function against [`Generator`], calls
//! [`export_generator!`], and builds to `wasm32-unknown-unknown`. The macro emits
//! the three exports the host calls — `ctf_alloc`, `ctf_generate`, and
//! `ctf_output_len` — plus the `memory` the target exports by default, so the
//! author writes no host glue.
//!
//! ```ignore
//! use ctf_generator_sdk::{export_generator, Generator, Outputs};
//!
//! #[derive(Default)]
//! struct Chal;
//!
//! impl Generator for Chal {
//!     fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str> {
//!         let mut bytes = b"artifact:".to_vec();
//!         bytes.extend_from_slice(seed);
//!         out.add("chal", bytes);
//!         out.set_flag("ctf{example}");
//!         Ok(())
//!     }
//! }
//!
//! export_generator!(Chal);
//! ```
//!
//! # Purity
//!
//! The SDK uses only `std` allocation. It never reads a clock, the network, the
//! filesystem, or randomness, and the host provides no import for any of them, so
//! a module built from this SDK is pure by construction. Two `ctf_generate` calls
//! with the same seed always produce the same block.
//!
//! # The ABI, in one line
//!
//! `ctf_generate` writes a canonical little-endian block into a static buffer and
//! returns its pointer; the host reads `ctf_output_len()` bytes there. The block is
//! `u32 count`, then `count × { u32 name_len, name, u32 data_len, data }`, then
//! `u32 flag_len, flag`.

use std::sync::Mutex;

/// The generator interface version this SDK targets (spec §23.5).
pub const INTERFACE_VERSION: u32 = 1;

/// The output block produced by the last `ctf_generate`, held for the host to read.
///
/// A `Mutex` rather than a thread-local or `static mut`: the module has no threads,
/// so the lock is uncontended, and it keeps the SDK free of `unsafe` state.
static BLOCK: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// What an author's [`Generator`] writes into.
#[derive(Default)]
pub struct Outputs {
    outputs: Vec<(String, Vec<u8>)>,
    flag: Option<String>,
}

impl Outputs {
    /// Add a named byte stream. Names are checked by the host against the
    /// manifest's declared `generate.outputs`, so the SDK does not duplicate that
    /// rule — but an empty name is a programming error the host will reject.
    pub fn add(&mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.outputs.push((name.into(), bytes.into()));
    }

    /// Set the flag the generator computed for this seed.
    pub fn set_flag(&mut self, flag: impl Into<String>) {
        self.flag = Some(flag.into());
    }

    /// The canonical block of spec §23.3.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for (name, bytes) in &self.outputs {
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let flag = self.flag.clone().unwrap_or_default();
        out.extend_from_slice(&(flag.len() as u32).to_le_bytes());
        out.extend_from_slice(flag.as_bytes());
        out
    }
}

/// An author's pure function `seed -> (artifacts, flag)`.
pub trait Generator: Default {
    /// Derive the outputs and the flag. Returning `Err` makes `ctf_generate` fail
    /// with a `0` pointer, which the host reports as a guest failure.
    fn generate(&self, seed: &[u8], out: &mut Outputs) -> Result<(), &'static str>;
}

/// The `ctf_alloc` implementation: `len` zeroed bytes the host can write a seed
/// into. The allocation is leaked on purpose — it must outlive the call.
pub fn host_alloc(len: u32) -> u32 {
    let mut bytes = vec![0u8; len as usize];
    let ptr = bytes.as_mut_ptr() as u32;
    core::mem::forget(bytes);
    ptr
}

/// The `ctf_generate` implementation. Reads the seed, runs `G`, publishes the
/// block, and returns its pointer (`0` on failure or a poisoned lock).
pub fn host_generate<G: Generator>(seed_ptr: u32, seed_len: u32) -> u32 {
    // The host wrote `seed_len` bytes at `seed_ptr` after a successful `ctf_alloc`;
    // the pointer is valid for that region of the module's own linear memory.
    let seed = unsafe { core::slice::from_raw_parts(seed_ptr as *const u8, seed_len as usize) };
    let mut outputs = Outputs::default();
    if G::default().generate(seed, &mut outputs).is_err() {
        return 0;
    }
    publish(outputs.encode())
}

/// The `ctf_output_len` implementation.
pub fn host_output_len() -> u32 {
    match BLOCK.lock() {
        Ok(g) => g.len() as u32,
        Err(_) => 0,
    }
}

/// Store `block` and return its pointer, keeping it alive for the host's read.
fn publish(block: Vec<u8>) -> u32 {
    match BLOCK.lock() {
        Ok(mut g) => {
            *g = block;
            g.as_ptr() as u32
        }
        Err(_) => 0,
    }
}

/// Emit the three ABI exports for a [`Generator`] type. See the crate docs.
#[macro_export]
macro_rules! export_generator {
    ($ty:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn ctf_alloc(len: u32) -> u32 {
            $crate::host_alloc(len)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn ctf_generate(seed_ptr: u32, seed_len: u32) -> u32 {
            $crate::host_generate::<$ty>(seed_ptr, seed_len)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn ctf_output_len() -> u32 {
            $crate::host_output_len()
        }
    };
}
