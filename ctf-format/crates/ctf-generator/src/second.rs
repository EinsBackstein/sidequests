//! The second engine (rule G10, spec §23.6).
//!
//! Wasmtime is the primary host; `wasmi` is a completely separate interpreter used
//! by the cross-check. Two engines agreeing is a far stronger signal than one
//! engine run twice: it catches a host that was configured wrongly rather than a
//! generator that varies. The settings of §23.6 are therefore *validated* by
//! agreement, not trusted.
//!
//! `wasmi` implements neither SIMD nor relaxed-SIMD, so a profile-1 module that
//! uses them cannot be cross-checked and is reported as unsupported by this
//! engine rather than silently skipped. The determinism guarantee still holds for
//! such a module on the primary engine; the cross-check simply is not available.

use wasmi::core::TrapCode;
use wasmi::{Config, Engine, Instance, Linker, Module, Store};

use crate::abi::GeneratorOutput;
use crate::host::{GeneratorError, Limits};

/// Whether the second engine can run a given module's feature set.
///
/// Wasmi is a scalar interpreter: SIMD and relaxed-SIMD are outside its feature
/// set, so a module using them is not cross-checkable. This is a capability query,
/// not a failure — the primary engine still runs the module.
pub fn second_engine_supported(wasm: &[u8]) -> bool {
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    Module::new(&engine, wasm).is_ok()
}

/// Run `wasm` once on the `wasmi` engine, with fuel for CPU limits.
pub fn run_second_engine(
    wasm: &[u8],
    seed: &[u8],
    limits: &Limits,
) -> Result<GeneratorOutput, GeneratorError> {
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, wasm).map_err(|e| GeneratorError::Module(e.to_string()))?;
    if module.imports().next().is_some() {
        return Err(GeneratorError::ImportsNotAllowed);
    }

    let mut store = Store::new(&engine, ());
    store
        .set_fuel(limits.fuel)
        .map_err(|_| GeneratorError::OutOfFuel)?;
    let linker = Linker::<()>::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(map_error)?
        .start(&mut store)
        .map_err(map_error)?;

    call(&mut store, &instance, seed, limits)
}

fn map_error(e: wasmi::Error) -> GeneratorError {
    if e.as_trap_code() == Some(TrapCode::OutOfFuel) {
        return GeneratorError::OutOfFuel;
    }
    if e.as_trap_code() == Some(TrapCode::UnreachableCodeReached) {
        return GeneratorError::GuestReturnedFailure;
    }
    GeneratorError::Trap
}

fn call(
    store: &mut Store<()>,
    instance: &Instance,
    seed: &[u8],
    limits: &Limits,
) -> Result<GeneratorOutput, GeneratorError> {
    if seed.len() > limits.max_seed_bytes {
        return Err(GeneratorError::SeedTooLarge);
    }
    let seed_len = u32::try_from(seed.len()).map_err(|_| GeneratorError::SeedTooLarge)?;

    let memory = instance
        .get_memory(&*store, "memory")
        .ok_or(GeneratorError::MissingExport("memory"))?;
    let alloc = instance
        .get_typed_func::<u32, u32>(&*store, "ctf_alloc")
        .map_err(|_| GeneratorError::MissingExport("ctf_alloc"))?;
    let generate = instance
        .get_typed_func::<(u32, u32), u32>(&*store, "ctf_generate")
        .map_err(|_| GeneratorError::MissingExport("ctf_generate"))?;
    let output_len = instance
        .get_typed_func::<(), u32>(&*store, "ctf_output_len")
        .map_err(|_| GeneratorError::MissingExport("ctf_output_len"))?;

    let seed_ptr = alloc.call(&mut *store, seed_len).map_err(map_error)?;
    if seed_len != 0 {
        if seed_ptr == 0 {
            return Err(GeneratorError::GuestReturnedFailure);
        }
        memory
            .write(&mut *store, seed_ptr as usize, seed)
            .map_err(|_| GeneratorError::OutOfBounds)?;
    }

    let block_ptr = generate
        .call(&mut *store, (seed_ptr, seed_len))
        .map_err(map_error)?;
    if block_ptr == 0 {
        return Err(GeneratorError::GuestReturnedFailure);
    }
    let block_len = output_len.call(&mut *store, ()).map_err(map_error)?;
    if block_len as usize > limits.max_output_bytes {
        return Err(GeneratorError::Abi(crate::abi::AbiError::OutputTooLarge));
    }
    let mut block = vec![0u8; block_len as usize];
    memory
        .read(&*store, block_ptr as usize, &mut block)
        .map_err(|_| GeneratorError::OutOfBounds)?;
    GeneratorOutput::decode(&block, limits.max_output_bytes).map_err(GeneratorError::Abi)
}
