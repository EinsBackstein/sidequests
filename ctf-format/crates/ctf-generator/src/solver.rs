//! The offline solver host (spec §25, design §3 pillar 5).
//!
//! A `solver` section (kind 4) carries `solver.wasm`: the challenge author's proof
//! that the challenge is solvable from the generated artifacts alone. Ingest runs
//! the generator at the reference seed, feeds the resulting **artifact block**
//! (§25.3 — the output block without the flag, so the solver cannot echo it), runs
//! the solver in the same capability-free sandbox as the generator, and asserts the
//! flag it produces equals the derived flag. A bundle that cannot be solved cannot
//! be published.
//!
//! # Same sandbox
//!
//! The module has **no imports** (§25.1): no WASI, clock, network, filesystem, or
//! randomness. Its only inputs are the artifact block and its own bytes, exactly as
//! the generator's only input is the seed. Determinism and no-network are properties
//! of the sandbox, not of author discipline.
//!
//! # Live challenges
//!
//! A challenge that declares `runtime` needs a booted instance to be solved, which
//! is the orchestrator project's job (design §2). [`crate::gate::offline_gate`]
//! records such a bundle as **unverified**, never `passed` — an honest `unverified`
//! is usable, a false `passed` is worse than no gate at all.

use wasmtime::{Engine, Linker, Module, Store, StoreLimitsBuilder};

use crate::abi::decode_solver_flag;
use crate::host::{
    GeneratorError, HostState, Limits, classify, pinned_config, read_guest, write_guest,
};

/// A solver module, compiled once and run.
pub struct Solver {
    engine: Engine,
    module: Module,
}

impl Solver {
    /// Compile `wasm` under profile 1 and reject a module with imports (§25.1, G2).
    pub fn new(wasm: &[u8]) -> Result<Self, GeneratorError> {
        let engine =
            Engine::new(&pinned_config()).map_err(|e| GeneratorError::Module(e.to_string()))?;
        let module =
            Module::new(&engine, wasm).map_err(|e| GeneratorError::Module(e.to_string()))?;
        if module.imports().next().is_some() {
            return Err(GeneratorError::ImportsNotAllowed);
        }
        Ok(Self { engine, module })
    }

    /// Run the solver on an artifact block and return the flag it produces.
    ///
    /// The block is written into guest memory through `ctf_alloc`, `ctf_solve` is
    /// called, and its output is decoded as the §25.4 flag block. Every pointer and
    /// length is bounds-checked against the module's current memory.
    pub fn run(&self, input: &[u8], limits: &Limits) -> Result<String, GeneratorError> {
        if input.len() > limits.max_input_bytes {
            return Err(GeneratorError::SeedTooLarge);
        }
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(limits.max_memory_bytes)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|_| GeneratorError::OutOfFuel)?;
        let linker = Linker::<HostState>::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(classify)?;

        let input_len = u32::try_from(input.len()).map_err(|_| GeneratorError::SeedTooLarge)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(GeneratorError::MissingExport("memory"))?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "ctf_alloc")
            .map_err(|_| GeneratorError::MissingExport("ctf_alloc"))?;
        let solve = instance
            .get_typed_func::<(u32, u32), u32>(&mut store, "ctf_solve")
            .map_err(|_| GeneratorError::MissingExport("ctf_solve"))?;
        let output_len = instance
            .get_typed_func::<(), u32>(&mut store, "ctf_output_len")
            .map_err(|_| GeneratorError::MissingExport("ctf_output_len"))?;

        let input_ptr = alloc.call(&mut store, input_len).map_err(classify)?;
        if input_len != 0 {
            if input_ptr == 0 {
                return Err(GeneratorError::GuestReturnedFailure);
            }
            write_guest(&memory, &mut store, input_ptr, input)?;
        }
        let block_ptr = solve
            .call(&mut store, (input_ptr, input_len))
            .map_err(classify)?;
        if block_ptr == 0 {
            return Err(GeneratorError::GuestReturnedFailure);
        }
        let block_len = output_len.call(&mut store, ()).map_err(classify)?;
        let block = read_guest(
            &memory,
            &mut store,
            block_ptr,
            block_len,
            limits.max_output_bytes,
        )?;
        decode_solver_flag(&block, crate::abi::MAX_FLAG_LEN).map_err(GeneratorError::Abi)
    }
}

/// The artifact block a solver receives (spec §25.3), re-exported for callers that
/// build one without running a generator.
pub use crate::abi::ArtifactBlock;
