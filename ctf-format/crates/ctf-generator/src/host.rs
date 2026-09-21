//! The Wasmtime-side generator host: sandbox configuration, execution, and the
//! resource limits (spec §23.1, §23.6).
//!
//! The engine is built from a fixed configuration rather than a caller-supplied
//! one, so the determinism settings cannot be forgotten: there is no public
//! constructor for a host that runs a generator under a different feature set. A
//! profile this build does not implement is rejected before a module loads
//! (rules G6, G7).

use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::abi::{AbiError, GeneratorOutput};

/// The interface and profile this host runs (spec §23.5).
pub use crate::abi::{INTERFACE_VERSION, WASM_PROFILE};

/// Resource limits for one generator run (rule G5).
///
/// Fuel, not wall-clock interruption: the limit is a fixed count, so it is part of
/// the deterministic result rather than a race with the host clock.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Fuel units the whole run may consume. Traps at a fixed count.
    pub fuel: u64,
    /// Ceiling on the module's linear memory, in bytes, enforced by the store.
    pub max_memory_bytes: usize,
    /// Ceiling on the total artifact bytes decoded from the output block.
    pub max_output_bytes: usize,
    /// Ceiling on the seed the host will write into guest memory.
    pub max_seed_bytes: usize,
    /// Ceiling on the input block the host writes for a solver (spec §25.3).
    ///
    /// Larger than [`Limits::max_seed_bytes`] because a solver receives the
    /// generated artifacts, not a 32-byte seed.
    pub max_input_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // A generator is a pure function, not a solver: a billion fuel units is
            // far beyond any artifact derivation and still terminates quickly.
            fuel: 1_000_000_000,
            max_memory_bytes: 256 * 1024 * 1024,
            max_output_bytes: 256 * 1024 * 1024,
            max_seed_bytes: 1024 * 1024,
            max_input_bytes: 256 * 1024 * 1024,
        }
    }
}

/// The engine a module is run on (rule G10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    /// The primary host.
    Wasmtime,
    /// The second engine, used only by the cross-check.
    Wasmi,
}

/// A generator failure. All variants are static.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorError {
    /// The module could not be loaded or compiled. The text is the engine's, which
    /// names a byte offset in the module, not a bundle offset.
    Module(String),
    /// The module imports something; the sandbox provides nothing (rule G2).
    ImportsNotAllowed,
    /// A required export is absent (rule G3).
    MissingExport(&'static str),
    /// An export exists with the wrong signature (rule G3).
    BadExport(&'static str),
    /// A pointer or length did not fit the module's current memory (rule G4).
    OutOfBounds,
    /// The module exhausted its fuel (rule G5).
    OutOfFuel,
    /// The module's memory reached the store's cap (rule G5).
    MemoryLimit,
    /// `ctf_generate` or `ctf_alloc` returned `0`.
    GuestReturnedFailure,
    /// The seed was larger than [`Limits::max_seed_bytes`].
    SeedTooLarge,
    /// The output block was malformed (rule G8).
    Abi(AbiError),
    /// A trap other than fuel exhaustion.
    Trap,
    /// The interface version is not [`INTERFACE_VERSION`] (rule G6).
    InterfaceUnsupported(u32),
    /// The profile is not [`WASM_PROFILE`] (rule G7).
    ProfileUnsupported(u32),
    /// Two runs of the same module disagreed (rule G9). Carries the run index whose
    /// root differed from the first.
    Nondeterministic { run: usize },
    /// The two engines disagreed (rule G10).
    EngineDisagreement,
}

impl core::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Module(e) => write!(f, "generator module could not be loaded: {e}"),
            Self::ImportsNotAllowed => {
                f.write_str("generator module imports something; the sandbox provides nothing")
            }
            Self::MissingExport(name) => write!(f, "generator module does not export `{name}`"),
            Self::BadExport(name) => {
                write!(
                    f,
                    "generator export `{name}` does not have the required signature"
                )
            }
            Self::OutOfBounds => f.write_str("generator read or wrote outside its memory"),
            Self::OutOfFuel => f.write_str("generator exhausted its fuel"),
            Self::MemoryLimit => f.write_str("generator reached its memory limit"),
            Self::GuestReturnedFailure => f.write_str("generator reported failure"),
            Self::SeedTooLarge => f.write_str("seed is larger than the configured cap"),
            Self::Abi(e) => write!(f, "{e}"),
            Self::Trap => f.write_str("generator trapped"),
            Self::InterfaceUnsupported(v) => {
                write!(f, "generator interface version {v} is not implemented")
            }
            Self::ProfileUnsupported(v) => write!(f, "WASM profile {v} is not implemented"),
            Self::Nondeterministic { run } => {
                write!(
                    f,
                    "generator run {run} differed from the first; it is not deterministic"
                )
            }
            Self::EngineDisagreement => f.write_str(
                "the two engines produced different output for the same module and seed",
            ),
        }
    }
}

impl core::error::Error for GeneratorError {}

impl From<AbiError> for GeneratorError {
    fn from(e: AbiError) -> Self {
        Self::Abi(e)
    }
}

/// Store state: only the resource limiter, so the guest can reach nothing else.
pub(crate) struct HostState {
    pub(crate) limits: StoreLimits,
}

/// The profile-1 Wasmtime configuration (spec §23.6).
///
/// This is the only configuration a generator runs under. It is deliberately not
/// parameterised: profile 1 *is* the setting, and a caller that wants a different
/// feature set needs a new profile number, not a looser host.
pub(crate) fn pinned_config() -> Config {
    let mut config = Config::new();
    // Threads off: no shared state, no scheduling.
    config.wasm_threads(false);
    config.wasm_shared_everything_threads(false);
    // Relaxed SIMD is not banned; it is lowered to one defined behaviour on every
    // architecture, which is the determinism property that matters.
    config.wasm_simd(true);
    config.wasm_relaxed_simd(true);
    config.relaxed_simd_deterministic(true);
    // Canonicalize NaN bits so float codegen cannot vary the result.
    config.cranelift_nan_canonicalization(true);
    // Fuel, not epochs.
    config.consume_fuel(true);
    // Features outside profile 1, off explicitly.
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_tail_call(false);
    config.wasm_gc(false);
    config.wasm_function_references(false);
    config.wasm_exceptions(false);
    config.wasm_wide_arithmetic(false);
    config.wasm_custom_page_sizes(false);
    config.wasm_stack_switching(false);
    // The bulk operations a normal allocator emits, and multi-value, stay on.
    config.wasm_bulk_memory(true);
    config.wasm_multi_value(true);
    config.wasm_reference_types(true);
    config
}

/// A generator module, compiled once and run many times.
pub struct Generator {
    engine: Engine,
    module: Module,
}

impl Generator {
    /// Compile `wasm` under profile 1 and reject a module with imports (rule G2).
    pub fn new(wasm: &[u8]) -> Result<Self, GeneratorError> {
        let engine =
            Engine::new(&pinned_config()).map_err(|e| GeneratorError::Module(e.to_string()))?;
        let module =
            Module::new(&engine, wasm).map_err(|e| GeneratorError::Module(e.to_string()))?;
        // Instantiation would also refuse an import, but checking here gives the
        // accurate diagnostic (rule G2) before any guest code can run.
        if module.imports().next().is_some() {
            return Err(GeneratorError::ImportsNotAllowed);
        }
        Ok(Self { engine, module })
    }

    /// Run the generator once on the Wasmtime engine.
    pub fn run(&self, seed: &[u8], limits: &Limits) -> Result<GeneratorOutput, GeneratorError> {
        let (mut store, instance) = self.instantiate(limits)?;
        call_generate(&mut store, &instance, seed, limits)
    }

    /// Run the generator `runs` times **in one instance**, returning each result.
    ///
    /// Calling twice in one instance is what catches a generator whose output
    /// depends on its own call count or on a global that changes between calls
    /// (rule G9). A fresh instance would hide exactly that class of state.
    pub fn run_repeated(
        &self,
        seed: &[u8],
        limits: &Limits,
        runs: usize,
    ) -> Result<Vec<GeneratorOutput>, GeneratorError> {
        let (mut store, instance) = self.instantiate(limits)?;
        let mut out = Vec::with_capacity(runs);
        for _ in 0..runs {
            out.push(call_generate(&mut store, &instance, seed, limits)?);
        }
        Ok(out)
    }

    fn instantiate(&self, limits: &Limits) -> Result<(Store<HostState>, Instance), GeneratorError> {
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
        Ok((store, instance))
    }
}

/// Map a Wasmtime trap to a static generator error.
pub(crate) fn classify(e: wasmtime::Error) -> GeneratorError {
    if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => GeneratorError::OutOfFuel,
            wasmtime::Trap::UnreachableCodeReached => GeneratorError::GuestReturnedFailure,
            _ => GeneratorError::Trap,
        };
    }
    GeneratorError::Module(e.to_string())
}

/// The ABI call sequence of spec §23.2, against an instantiated guest.
fn call_generate(
    store: &mut Store<HostState>,
    instance: &Instance,
    seed: &[u8],
    limits: &Limits,
) -> Result<GeneratorOutput, GeneratorError> {
    if seed.len() > limits.max_seed_bytes {
        return Err(GeneratorError::SeedTooLarge);
    }
    let seed_len = u32::try_from(seed.len()).map_err(|_| GeneratorError::SeedTooLarge)?;

    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or(GeneratorError::MissingExport("memory"))?;
    let alloc = instance
        .get_typed_func::<u32, u32>(&mut *store, "ctf_alloc")
        .map_err(|_| GeneratorError::MissingExport("ctf_alloc"))?;
    let generate = instance
        .get_typed_func::<(u32, u32), u32>(&mut *store, "ctf_generate")
        .map_err(|_| GeneratorError::MissingExport("ctf_generate"))?;
    let output_len = instance
        .get_typed_func::<(), u32>(&mut *store, "ctf_output_len")
        .map_err(|_| GeneratorError::MissingExport("ctf_output_len"))?;

    let seed_ptr = alloc.call(&mut *store, seed_len).map_err(classify)?;
    if seed_len != 0 {
        if seed_ptr == 0 {
            return Err(GeneratorError::GuestReturnedFailure);
        }
        write_guest(&memory, &mut *store, seed_ptr, seed)?;
    }

    let block_ptr = generate
        .call(&mut *store, (seed_ptr, seed_len))
        .map_err(classify)?;
    if block_ptr == 0 {
        return Err(GeneratorError::GuestReturnedFailure);
    }
    let block_len = output_len.call(&mut *store, ()).map_err(classify)?;
    let block = read_guest(
        &memory,
        &mut *store,
        block_ptr,
        block_len,
        limits.max_output_bytes,
    )?;
    GeneratorOutput::decode(&block, limits.max_output_bytes).map_err(GeneratorError::Abi)
}

pub(crate) fn write_guest(
    memory: &Memory,
    store: &mut Store<HostState>,
    at: u32,
    bytes: &[u8],
) -> Result<(), GeneratorError> {
    let start = at as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or(GeneratorError::OutOfBounds)?;
    let data = memory.data_mut(store);
    if end > data.len() {
        return Err(GeneratorError::OutOfBounds);
    }
    let dst = data
        .get_mut(start..end)
        .ok_or(GeneratorError::OutOfBounds)?;
    dst.copy_from_slice(bytes);
    Ok(())
}

pub(crate) fn read_guest(
    memory: &Memory,
    store: &mut Store<HostState>,
    at: u32,
    len: u32,
    cap: usize,
) -> Result<Vec<u8>, GeneratorError> {
    if (len as usize) > cap {
        return Err(GeneratorError::Abi(AbiError::OutputTooLarge));
    }
    let start = at as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or(GeneratorError::OutOfBounds)?;
    let data = memory.data(&*store);
    data.get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or(GeneratorError::OutOfBounds)
}
