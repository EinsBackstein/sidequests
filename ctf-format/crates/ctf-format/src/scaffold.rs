//! Archetype scaffolds for `ctf init` (design §10, roadmap phase 3).
//!
//! `ctf init <archetype>` exists to make the first five minutes of authoring
//! productive: an author should land on a directory that already parses and
//! validates, then edit it into their challenge, rather than reconstruct the
//! declaration keys of spec §7.6 by hand and discover a typo at pack time.
//!
//! # Why these five archetypes
//!
//! The set is design §10's CLI table, and it is exactly the set of challenge
//! shapes that differ in *which declaration keys they carry*, not merely in
//! prose:
//!
//! - `osint` is the generator-free path: `flag: derived`, no `generate`, no
//!   `runtime`, no `verify`. Design §8 and the roadmap call this out as the
//!   default that carries most challenges.
//! - `rev` is the strict-generator path: a `generate` block with
//!   `determinism: strict`, a player-visible artifact plus a withheld one, a
//!   sealed solver, and an offline verification gate.
//! - `pwn` and `web` add a `runtime` block; they differ in that `web` declares a
//!   live gate (`verify.offline: false` with a re-solve interval) while `pwn`
//!   verifies offline.
//! - `forensics` is included because it is in the design's table and because its
//!   payload scale is the case that motivates the `external` mechanism.
//!
//! Five archetypes are the minimal spanning set of the declaration-key
//! combinations an author actually starts from; a sixth would differ only in
//! prose, and prose is what the scaffold's `README.md` is for.
//!
//! # Why the file shape is what it is
//!
//! Every archetype emits `challenge.yaml`, because that is the only file
//! `ctf pack` requires. Everything else is present only where it has something
//! to say: `rev` emits a `generator/` crate because `generate.wasm: gen.wasm` is
//! useless without a module to build, `forensics` emits `notes.md` for the
//! inventory that has no other home, and every archetype emits a `README.md`
//! with next-step guidance. Nothing else is emitted, so a scaffold is a starting
//! point rather than a tree to delete.
//!
//! # The `external` gap
//!
//! Design §10's full pwn example ends with an `external:` list for
//! forensics-scale payloads (design §10, spec §5.7). The authoring schema in
//! [`crate::authoring`] has **no `external` field** on
//! [`crate::authoring::ChallengeDoc`], and
//! [`crate::authoring::ChallengeDoc::from_yaml`] rejects unknown keys (spec
//! §7.8), so a scaffold that emitted `external:` would not parse. The
//! `forensics` scaffold therefore carries that guidance in its `README.md`
//! instead of inventing a key, and the manifest-level `external` mechanism
//! (spec §5.7) remains reachable only through the bundle layer until the
//! authoring surface grows the key.
//!
//! # Determinism
//!
//! The output is a pure function of `(archetype, id)`: files are returned in a
//! fixed order, paths always use `/`, and no content carries a timestamp, hash,
//! or random value. Two `ctf init` runs on the same input produce byte-identical
//! trees, which is what lets the scaffold be diffed and tested.
//!
//! # Validation is a test, not a promise
//!
//! [`scaffold`] validates the archetype and the `id`, but it does not re-parse
//! the YAML it emits on every call. The integration tests do that for all five
//! archetypes, so a scaffold that stopped validating fails CI rather than a
//! `ctf init` in front of an author.

use core::fmt;

use crate::manifest::check_id;

/// The archetypes `ctf init` can scaffold (design §10).
pub const ARCHETYPES: &[&str] = &["osint", "rev", "pwn", "web", "forensics"];

/// One file in a scaffold, addressed relative to the scaffold root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldFile {
    /// Path relative to the scaffold root, POSIX separators, e.g. `challenge.yaml`.
    pub path: String,
    pub contents: String,
}

/// Why a scaffold could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaffoldError {
    /// The archetype is not one of [`ARCHETYPES`]. Carries the requested value.
    UnknownArchetype(String),
    /// The supplied challenge id is not a valid manifest id.
    InvalidId,
}

impl fmt::Display for ScaffoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArchetype(requested) => write!(
                f,
                "unknown archetype `{requested}`; expected one of {}",
                ARCHETYPES.join(", ")
            ),
            Self::InvalidId => f.write_str(
                "the challenge id must be 1-64 bytes of lowercase ASCII letters, digits, \
                 and interior hyphens",
            ),
        }
    }
}

impl core::error::Error for ScaffoldError {}

/// The files for one archetype scaffold, given a challenge id.
///
/// The returned files are in a fixed order and the contents are a pure function
/// of `(archetype, id)`; see the module docs. The `id` is checked against the
/// same shape the manifest enforces, so a scaffold can always be packed.
pub fn scaffold(archetype: &str, id: &str) -> Result<Vec<ScaffoldFile>, ScaffoldError> {
    if !ARCHETYPES.contains(&archetype) {
        return Err(ScaffoldError::UnknownArchetype(archetype.to_owned()));
    }
    if check_id(id).is_err() {
        return Err(ScaffoldError::InvalidId);
    }
    let files = match archetype {
        "osint" => osint(id),
        "rev" => rev(id),
        "pwn" => pwn(id),
        "web" => web(id),
        "forensics" => forensics(id),
        // The guard above makes this unreachable, but a `match` over `&str`
        // needs an arm for every other value; returning the error keeps the
        // function total without a panic.
        other => return Err(ScaffoldError::UnknownArchetype(other.to_owned())),
    };
    Ok(files)
}

/// A 64-hex-digit placeholder digest. The image reference must be digest-pinned
/// (design §10), so the scaffold uses a well-formed placeholder rather than a
/// tag; the author replaces it with the real digest before packing.
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn file(path: &str, contents: String) -> ScaffoldFile {
    ScaffoldFile {
        path: path.to_owned(),
        contents,
    }
}

/// The keys every archetype shares: identity, category, a prose placeholder, and
/// the one-word derived flag. Each archetype appends the declaration blocks that
/// distinguish it.
fn header(id: &str, category: &str, title: &str, description: &str) -> String {
    format!(
        "spec: 1\nid: {id}\nname: \"{title}\"\ncategory: {category}\ndescription: \"{description}\"\nflag: derived\n"
    )
}

fn readme(id: &str, archetype: &str, body: &str) -> String {
    format!("# {id} ({archetype} scaffold)\n\n{body}")
}

fn runtime_block(id: &str, port: u16) -> String {
    format!(
        "runtime:\n  image: \"ghcr.io/example/{id}@sha256:{ZERO_DIGEST}\"\n  ports:\n    - {{ container: {port}, protocol: tcp }}\n  resources: {{ cpu: \"0.5\", memory: \"256Mi\", pids: 64 }}\n  instancing: per_team\n  ttl: 30m\n  readiness: {{ tcp: {port}, timeout: 30s }}\n"
    )
}

/// `flag: derived` with no generator at all — ticket 24's `flag_only` path.
fn osint(id: &str) -> Vec<ScaffoldFile> {
    vec![
        file(
            "challenge.yaml",
            header(
                id,
                "osint",
                "OSINT challenge",
                "Replace this with the puzzle prompt; the material the solver works from travels in the bundle.",
            ),
        ),
        file("README.md", readme(id, "osint", OSINT_BODY)),
    ]
}

/// Strict generation plus a sealed solver: the `generate` block is what an
/// offline gate and a per-subject artifact derivation both need.
fn rev(id: &str) -> Vec<ScaffoldFile> {
    let mut yaml = header(
        id,
        "rev",
        "Reverse engineering challenge",
        "Recover the flag from the artifacts the generator derives for each subject.",
    );
    yaml.push_str(SEALED_SOLVER);
    yaml.push_str(VERIFY_OFFLINE);
    yaml.push_str(GENERATE_STRICT);
    vec![
        file("challenge.yaml", yaml),
        file("README.md", readme(id, "rev", REV_BODY)),
        file("generator/Cargo.toml", GENERATOR_CARGO.to_owned()),
        file("generator/src/lib.rs", GENERATOR_LIB.to_owned()),
        file("generator/README.md", GENERATOR_README.to_owned()),
    ]
}

/// A runtime-bearing challenge, verified offline.
fn pwn(id: &str) -> Vec<ScaffoldFile> {
    let mut yaml = header(
        id,
        "pwn",
        "Pwn challenge",
        "Exploit the per-team service; the flag is derived per subject.",
    );
    yaml.push_str(&runtime_block(id, 1337));
    yaml.push_str(SEALED_SOLVER);
    yaml.push_str(VERIFY_OFFLINE);
    vec![
        file("challenge.yaml", yaml),
        file("README.md", readme(id, "pwn", PWN_BODY)),
    ]
}

/// A runtime-bearing challenge whose solvability is re-checked live.
fn web(id: &str) -> Vec<ScaffoldFile> {
    let mut yaml = header(
        id,
        "web",
        "Web challenge",
        "Exploit the per-team service; the flag is derived and the live gate re-solves it.",
    );
    yaml.push_str(&runtime_block(id, 8080));
    yaml.push_str(SEALED_WRITEUP);
    yaml.push_str(VERIFY_LIVE);
    vec![
        file("challenge.yaml", yaml),
        file("README.md", readme(id, "web", WEB_BODY)),
    ]
}

/// The generator-free forensic path. `external:` is not yet an authoring key, so
/// the payload inventory lives in `notes.md` (see the module docs).
fn forensics(id: &str) -> Vec<ScaffoldFile> {
    vec![
        file(
            "challenge.yaml",
            header(
                id,
                "forensics",
                "Forensics challenge",
                "Analyze the provided material; see notes.md for the payload inventory.",
            ),
        ),
        file("README.md", readme(id, "forensics", FORENSICS_BODY)),
        file("notes.md", notes(id)),
    ]
}

fn notes(id: &str) -> String {
    format!(
        "# {id} analysis notes\n\n\
         Design 10 expresses forensics-scale payloads with an `external:` list, but the\n\
         authoring schema has no such key yet and rejects unknown keys (spec 7.8). Record\n\
         the payload inventory here until it does.\n\n\
         - name:\n\
         - size:\n\
         - root (blake3):\n\
         - mirrors:\n"
    )
}

const GENERATE_STRICT: &str = "generate:\n  wasm: gen.wasm\n  determinism: strict\n  outputs:\n    - { name: chal, player_visible: true }\n    - { name: key.pem, player_visible: false }\n";

const SEALED_SOLVER: &str = "sealed:\n  release: event_end\n  members: [solver.wasm]\n";

const SEALED_WRITEUP: &str = "sealed:\n  release: event_end\n  members: [writeup.md]\n";

const VERIFY_OFFLINE: &str = "verify:\n  solver: solver.wasm\n  expect: flag\n  offline: true\n";

const VERIFY_LIVE: &str =
    "verify:\n  solver: solver.wasm\n  expect: flag\n  offline: false\n  live:\n    interval: 5m\n";

const OSINT_BODY: &str = "\
This is the generator-free path: `flag: derived` with no `generate`, no
`runtime`, and no `verify`. Design 8 calls this the default, and it carries most
challenges.

Next steps:

1. Add the puzzle material (photo, document, capture) to this directory.
2. Replace `name` and `description` in `challenge.yaml`.
3. Run `ctf validate`, then `ctf pack`.
";

const REV_BODY: &str = "\
`generate.determinism: strict` means the host runs `gen.wasm` twice with the
reference seed and rejects the bundle if the two outputs differ. Build the crate
in `generator/`, then pack.

The solver is sealed until `event_end` and is not player-visible, which is the
serving rule spec 5.3 enforces.

Next steps:

1. Implement the derivation in `generator/src/lib.rs`.
2. Build it with the command in `generator/README.md`.
3. Replace `name` and `description` in `challenge.yaml`.
4. Run `ctf validate`, then `ctf pack`.
";

const PWN_BODY: &str = "\
The `runtime.image` is a placeholder digest; replace it with the real
digest-pinned image before packing. `instancing: per_team` gives each team its
own instance and its own derived flag.

Next steps:

1. Replace the placeholder `runtime.image` digest.
2. Replace `name` and `description` in `challenge.yaml`.
3. Run `ctf validate`, then `ctf pack`.
";

const WEB_BODY: &str = "\
`verify.offline: false` with a `live:` interval declares that the challenge is
re-solved against a running instance during the event, so the platform re-checks
solvability on a cadence rather than once at ingest.

Next steps:

1. Replace the placeholder `runtime.image` digest and port.
2. Replace `name` and `description` in `challenge.yaml`.
3. Run `ctf validate`, then `ctf pack`.
";

const FORENSICS_BODY: &str = "\
Design 10's forensics-scale payloads are declared with an `external:` list, but
the authoring schema has no `external` key yet and rejects unknown keys (spec
7.8). The scaffold therefore carries only `flag: derived`; keep the payload paths
and hashes in `notes.md` for now. The manifest's `external` mechanism (spec 5.7)
is reachable through the bundle layer until the authoring surface grows the key.

Next steps:

1. Put the analysis and payload inventory in `notes.md`.
2. Replace `name` and `description` in `challenge.yaml`.
3. Run `ctf validate`, then `ctf pack`.
";

const GENERATOR_CARGO: &str = "\
[package]
name = \"generator\"
version = \"0.1.0\"
edition = \"2024\"

[lib]
crate-type = [\"cdylib\"]

[profile.release]
opt-level = \"s\"
lto = true
panic = \"abort\"
";

const GENERATOR_README: &str = "\
# Generator

Build the generator for the fixed target design 8 requires:

    cargo build --target wasm32-unknown-unknown --release

The artifact is `target/wasm32-unknown-unknown/release/generator.wasm`; copy it
to `gen.wasm` beside `challenge.yaml`, which is the name the manifest declares.

The module is `no_std` and links no WASI, so it cannot observe a clock, the
network, or the filesystem. The host drives it through the three exports the
source declares: `ctf_alloc`, `ctf_generate`, and `ctf_output_len`.
";

const GENERATOR_LIB: &str = r#"//! Deterministic generator for this challenge.
//!
//! Built for `wasm32-unknown-unknown` with no WASI, as design 8 requires: the
//! host passes a per-subject seed in and receives artifact bytes out, and the
//! module can observe nothing else. A pure function of the seed is the whole
//! contract; the host runs it twice and rejects the bundle if the two runs
//! differ.
//!
//! The ABI is the three `extern "C"` exports at the bottom of this file.

#![no_std]

use core::panic::PanicInfo;

/// Upper bound on a seed and on any artifact this generator produces. The host
/// enforces its own cap, so this is a convenience, not the security boundary.
const BUF_LEN: usize = 64 * 1024;

static mut SEED: [u8; BUF_LEN] = [0; BUF_LEN];
static mut OUTPUT: [u8; BUF_LEN] = [0; BUF_LEN];
static mut OUTPUT_LEN: usize = 0;

/// Hand the host a buffer to write the seed into. Returns null if `len` is over
/// the cap.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_alloc(len: usize) -> *mut u8 {
    if len > BUF_LEN {
        return core::ptr::null_mut();
    }
    core::ptr::addr_of_mut!(SEED).cast::<u8>()
}

/// Derive the artifacts and the flag from the seed at `seed_ptr`. Returns 0 on
/// success and a negative value on a malformed request.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_generate(seed_ptr: *const u8, seed_len: usize) -> i32 {
    if seed_ptr.is_null() || seed_len > BUF_LEN {
        return -1;
    }
    // SAFETY: the host wrote `seed_len` bytes into the buffer `ctf_alloc`
    // returned, which is `SEED`, and never wrote more than the cap checked
    // above. This entry point is called only by the single-threaded host.
    let seed = unsafe { core::slice::from_raw_parts(seed_ptr, seed_len) };
    let len = derive(seed);
    // SAFETY: written only here, before any `ctf_output_len` call, on the same
    // single-threaded host.
    unsafe {
        OUTPUT_LEN = len;
    }
    0
}

/// The length of the artifact produced by the last `ctf_generate`.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_output_len() -> usize {
    // SAFETY: `ctf_generate` runs first and writes this once.
    unsafe { OUTPUT_LEN }
}

/// A placeholder derivation. Replace the body with the real artifact and flag
/// derivation, but keep it a pure function of `seed`: any read of a clock, the
/// network, or uninitialized memory breaks the determinism gate.
fn derive(seed: &[u8]) -> usize {
    let out = core::ptr::addr_of_mut!(OUTPUT).cast::<u8>();
    let mut len = 0;
    for (i, byte) in seed.iter().take(BUF_LEN).enumerate() {
        // SAFETY: `i < BUF_LEN` because of `take`, so the offset is in bounds.
        unsafe { out.add(i).write(*byte) };
        len = i + 1;
    }
    len
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
"#;
