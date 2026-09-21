//! `ctf` — the command-line tool for `.ctf` bundles.
//!
//! Subcommands: `inspect`, `validate`, `pack`, `keygen`, `keys`, `sign`, `seal`,
//! `unseal`, and `completions`. The rest of design §10's table arrives with the
//! phases that give it something to do — `run` needs phase 4's gate, and
//! `init`/`transfer` need the authoring archetypes and the entitlement and
//! seal-release management. `completions` is the one §10 CLI item that needs no
//! runtime behind it, so it lands with the parser.
//!
//! The `keys`/`seal`/`unseal` trio is the key-envelope workflow of spec §21: a
//! recipient's hybrid KEM keypair is generated once, a section's fresh content key
//! is wrapped to that recipient's public key on `seal`, and recovered with the
//! matching secret key on `unseal`. The secret key is never written into a bundle;
//! only the envelope is.
//!
//! # What `inspect` will not print
//!
//! Bytes from a sealed section, in any mode. `--hex` dumps the fixed structures —
//! header, section table, footer — and the manifest, which R7 already requires to be
//! neither sealed nor player-visible. A hexdump tool that would happily dump a
//! sealed writeup on request is a decryption oracle with a friendly interface.

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use memmap2::Mmap;

use ctf_format::authoring::ChallengeDoc;
use ctf_format::cbor::Value;
use ctf_format::derive;
use ctf_format::oci;
use ctf_format::pack::{self, PackError};
use ctf_format::{
    Bundle, Compression, Encryption, EntitlementChain, HEADER_LEN, HolderKeys, HybridPublicKey,
    HybridSigningKey, KemKeyPair, MAGIC, Payload, Recipient, SECTION_RECORD_LEN, SectionFlags,
    SectionKind, SectionSpec, ServingManifest, Signing, Timestamp, VERSION_MAJOR, holder_hash,
    release_at_event_end, seal_progress,
};

/// `ctf` — the command-line tool for `.ctf` challenge bundles.
#[derive(Parser)]
#[command(
    name = "ctf",
    version,
    about = "The `ctf` command-line tool for `.ctf` challenge bundles.",
    after_help = "\
Key files are a local convenience, not a container format:
  signing keys  two lines of lowercase hex, the classical component first and
                the post-quantum component second
  KEM keys      one line of lowercase hex
Whitespace and blank lines are ignored.

exit codes:
  0  success
  1  usage, parse, or validation failure
  2  inspect --verify found an intact but unauthentic (unsigned) bundle"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a bundle and print its structures.
    Inspect(InspectArgs),
    /// Schema- and policy-check an authoring file, naming every offending key.
    Validate(ValidateArgs),
    /// Compile a validated authoring file into an unsigned `.ctf` bundle.
    Pack(PackArgs),
    /// Generate a hybrid signing keypair.
    Keygen(KeygenArgs),
    /// Generate a hybrid KEM keypair for a recipient context.
    Keys(KeysArgs),
    /// Sign an unsigned `.ctf` bundle.
    Sign(SignArgs),
    /// Encrypt a section to a recipient and emit its key envelope.
    Seal(SealArgs),
    /// Decrypt a sealed section with a recipient's secret key.
    Unseal(UnsealArgs),
    /// Scaffold a working authoring project for an archetype.
    Init(InitArgs),
    /// Append a signed handoff to an entitlement chain.
    Transfer(TransferArgs),
    /// Emit the static artifact serving manifest for a bundle (ticket 65).
    ServingManifest(ServingManifestArgs),
    /// Export a bundle as an OCI image layout (ticket 63).
    OciExport(OciExportArgs),
    /// Import a bundle from an OCI image layout (ticket 63).
    OciImport(OciImportArgs),
    /// Release a bundle's sealed sections with the offline seal key (ticket 66).
    Release(ReleaseArgs),
    /// Run the local ingest gate: determinism and offline solvability (ticket 28).
    Run(RunArgs),
    /// Generate a shell completion script to stdout.
    Completions(CompletionsArgs),
}

#[derive(Args)]
struct InspectArgs {
    /// Annotated hexdump of the header, section table, and footer.
    #[arg(long)]
    hex: bool,

    /// Re-hash every inline section against its root.
    ///
    /// Exits non-zero if any section's bytes are present but unreadable by this
    /// build. External payloads are reported, not counted as failures: their
    /// bytes are elsewhere by design.
    #[arg(long)]
    verify: bool,

    /// Accept a bundle that carries no signatures.
    ///
    /// Without it, a `--verify` run on an unsigned bundle reports it intact but
    /// not authentic and exits 2.
    #[arg(long)]
    allow_unsigned: bool,

    /// The `.ctf` bundle to inspect.
    file: String,
}

#[derive(Args)]
struct ValidateArgs {
    /// The authoring YAML file to check.
    challenge: String,
}

#[derive(Args)]
struct PackArgs {
    /// The validated authoring YAML file to compile.
    challenge: String,

    /// Where to write the unsigned `.ctf` bundle.
    #[arg(long)]
    out: String,

    /// Crypto suite id.
    #[arg(long, default_value_t = pack::DEFAULT_SUITE_ID)]
    suite: u16,

    /// Where to write the platform ingest descriptor JSON.
    ///
    /// Defaults to `<out>.descriptor.json`. The descriptor is projected from the
    /// bundle's committed manifest, so it can never disagree with it.
    #[arg(long)]
    descriptor: Option<String>,
}

#[derive(Args)]
struct KeygenArgs {
    /// Where to write the signing key.
    #[arg(long)]
    out_key: String,

    /// Where to write the public key.
    #[arg(long)]
    out_pub: String,

    /// Crypto suite id.
    #[arg(long, default_value_t = pack::DEFAULT_SUITE_ID)]
    suite: u16,
}

#[derive(Args)]
struct SignArgs {
    /// The unsigned `.ctf` bundle to sign.
    bundle: String,

    /// The signing key file.
    #[arg(long)]
    key: String,

    /// The public key file.
    #[arg(long = "pub")]
    public: String,

    /// Where to write the signed bundle.
    #[arg(long)]
    out: String,
}

/// `ctf keys`: a KEM keypair for one recipient context.
///
/// The context is metadata for the operator, not part of the key material: a key is
/// bound to its context later, at envelope-seal time (spec §21).
#[derive(Args)]
struct KeysArgs {
    /// Recipient context: `storage`, `seal`, `holder`, or `stage:<decimal>`.
    #[arg(long)]
    context: String,

    /// Where to write the KEM secret key (one line of lowercase hex).
    #[arg(long)]
    out_key: String,

    /// Where to write the KEM public key (one line of lowercase hex).
    #[arg(long)]
    out_pub: String,

    /// Crypto suite id.
    #[arg(long, default_value_t = pack::DEFAULT_SUITE_ID)]
    suite: u16,
}

/// `ctf seal`: re-emit a bundle with one section encrypted to a recipient.
#[derive(Args)]
struct SealArgs {
    /// The unsigned `.ctf` bundle to seal.
    bundle: String,

    /// The recipient's hybrid KEM public key file.
    #[arg(long = "pub")]
    public: String,

    /// Recipient context: `storage`, `seal`, `holder`, or `stage:<decimal>`.
    #[arg(long)]
    context: String,

    /// The name of the section to encrypt.
    #[arg(long)]
    section: String,

    /// Where to write the sealed bundle.
    #[arg(long)]
    out: String,
}

/// `ctf unseal`: recover one section's plaintext with a recipient secret key.
#[derive(Args)]
struct UnsealArgs {
    /// The sealed `.ctf` bundle.
    bundle: String,

    /// The recipient's hybrid KEM secret key file.
    #[arg(long)]
    key: String,

    /// Recipient context: `storage`, `seal`, `holder`, or `stage:<decimal>`.
    #[arg(long)]
    context: String,

    /// The name of the section to decrypt.
    #[arg(long)]
    section: String,

    /// Where to write the recovered plaintext.
    #[arg(long)]
    out: String,
}

#[derive(Args)]
struct CompletionsArgs {
    /// The shell to generate a completion script for.
    #[arg(value_enum)]
    shell: Shell,
}

/// `ctf init`: write an archetype scaffold, ready to `ctf validate` and `ctf pack`.
#[derive(Args)]
struct InitArgs {
    /// osint, rev, pwn, web, or forensics.
    archetype: String,

    /// Directory to scaffold into. Must not already contain a `challenge.yaml`.
    #[arg(long)]
    out: String,

    /// Challenge id for the generated `challenge.yaml`.
    #[arg(long, default_value = "my-challenge")]
    id: String,
}

/// `ctf transfer`: append a holder-signed `transfer` to an entitlement chain.
///
/// The chain is read from a `.ctf` bundle's `entitlement` section, or from a file
/// holding the chain plaintext. The updated chain is written to `--out`; with
/// `--bundle` it is embedded back into the input bundle instead.
#[derive(Args)]
struct TransferArgs {
    /// A `.ctf` bundle with an `entitlement` section, or a chain-plaintext file.
    input: String,

    /// Where to write the updated chain, or the rewritten bundle with `--bundle`.
    #[arg(long)]
    out: String,

    /// Challenge `id` the record is about.
    #[arg(long)]
    challenge: String,

    /// Subject the record binds.
    #[arg(long)]
    subject: String,

    /// The new holder's 32-byte public-key hash, lowercase hex.
    #[arg(long, conflicts_with = "new_holder_pub")]
    new_holder: Option<String>,

    /// The new holder's hybrid signing public-key file; its hash is the new holder.
    #[arg(long = "new-holder-pub", conflicts_with = "new_holder")]
    new_holder_pub: Option<String>,

    /// The current holder's hybrid signing key file (signs the handoff).
    #[arg(long)]
    holder_key: String,

    /// The current holder's hybrid signing public-key file (checked against).
    #[arg(long = "holder-pub")]
    holder_pub: String,

    /// The platform's hybrid signing key file.
    #[arg(long)]
    platform_key: String,

    /// The platform's hybrid signing public-key file.
    #[arg(long = "platform-pub")]
    platform_pub: String,

    /// Plaintext progress to seal to the new holder.
    #[arg(long)]
    progress: Option<String>,

    /// The new holder's hybrid KEM public-key file (required with `--progress`).
    #[arg(long = "holder-kem", requires = "progress")]
    holder_kem: Option<String>,

    /// Advisory timestamp stored on the record.
    #[arg(long)]
    timestamp: Option<i64>,

    /// Embed the updated chain back into `input` and write a bundle.
    #[arg(long)]
    bundle: bool,

    /// Crypto suite id.
    #[arg(long, default_value_t = pack::DEFAULT_SUITE_ID)]
    suite: u16,
}

/// `ctf serving-manifest`: write the canonical-CBOR serving manifest for a bundle.
#[derive(Args)]
struct ServingManifestArgs {
    /// The `.ctf` bundle to project.
    bundle: String,

    /// Where to write the canonical-CBOR serving manifest. Prints a summary if omitted.
    #[arg(long)]
    out: Option<String>,
}

/// `ctf oci-export`: write an OCI image layout containing the bundle.
#[derive(Args)]
struct OciExportArgs {
    /// The `.ctf` bundle to export.
    bundle: String,

    /// The layout directory to create.
    #[arg(long)]
    out: String,
}

/// `ctf oci-import`: read the bundle back out of an OCI image layout.
#[derive(Args)]
struct OciImportArgs {
    /// The OCI image layout directory.
    layout: String,

    /// Where to write the recovered `.ctf` bundle.
    #[arg(long)]
    out: String,
}

/// `ctf release`: decrypt a bundle's sealed sections with the offline seal key.
#[derive(Args)]
struct ReleaseArgs {
    /// The `.ctf` bundle whose sealed sections are released.
    bundle: String,

    /// The `seal` recipient's hybrid KEM secret key file.
    #[arg(long)]
    key: String,

    /// Directory to write the released members into.
    #[arg(long)]
    out: String,

    /// Where to write the JSON audit report.
    #[arg(long)]
    report: Option<String>,
}

/// `ctf run`: run the platform's full offline ingest gate locally (ticket 28).
///
/// Reads the authoring document, resolves the generator and solver modules
/// relative to it, derives the reference subject's flag from `--secret`, and runs
/// the generator determinism gate followed by the solver gate. Each stage of spec
/// §25.5 is named, and a failure names the stage and reason (ticket 29). A solver
/// that does not recover the derived flag exits non-zero, so a bundle that cannot
/// be solved cannot be published.
///
/// The tri-state outcome can be persisted as a `ctf/verification/v1` record
/// (ticket 30): `--status` names the path, or `--bundle` writes
/// `<bundle>.status.json` alongside the bundle it describes.
#[derive(Args)]
struct RunArgs {
    /// The authoring YAML file.
    challenge: String,

    /// The event secret, 64 lowercase hex digits (spec §22.2). Never written anywhere.
    #[arg(long)]
    secret: String,

    /// The reference subject id. Defaults to `reference`.
    #[arg(long, default_value = "reference")]
    subject: String,

    /// Where to write the tri-state verification record (JSON, spec §25.6).
    #[arg(long)]
    status: Option<String>,

    /// The bundle this gate result describes.
    ///
    /// When given without `--status`, the record is written to
    /// `<bundle>.status.json`, alongside the bundle.
    #[arg(long)]
    bundle: Option<String>,
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => run(cli),
        Err(e) => {
            // clap exits 2 on a usage error by default, but 2 is reserved here for
            // `inspect --verify` finding an intact-but-unauthentic bundle. Route
            // every parse/usage failure to 1 instead. `--help` and `--version` are
            // not errors (`use_stderr` is false) and still exit 0.
            let code = if e.use_stderr() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
            let _ = e.print();
            code
        }
    }
}

fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Commands::Inspect(args) => run_inspect(&args),
        Commands::Validate(args) => run_validate(&args),
        Commands::Pack(args) => run_pack(&args),
        Commands::Keygen(args) => run_keygen(&args),
        Commands::Keys(args) => run_keys(&args),
        Commands::Sign(args) => run_sign(&args),
        Commands::Seal(args) => run_seal(&args),
        Commands::Unseal(args) => run_unseal(&args),
        Commands::Init(args) => run_init(&args),
        Commands::Transfer(args) => run_transfer(&args),
        Commands::ServingManifest(args) => run_serving_manifest(&args),
        Commands::OciExport(args) => run_oci_export(&args),
        Commands::OciImport(args) => run_oci_import(&args),
        Commands::Release(args) => run_release(&args),
        Commands::Run(args) => run_gate(&args),
        Commands::Completions(args) => run_completions(&args),
    }
}

fn run_inspect(args: &InspectArgs) -> ExitCode {
    let path = &args.file;
    match inspect(path, args.hex, args.verify, args.allow_unsigned) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ctf validate`: schema and policy check, prose errors that name the key, and an
/// exit status that reflects validity. The point is that an author learns what is
/// wrong *before* packing (design §10), which is why the same check is not deferred
/// to `ctf pack`.
fn run_validate(args: &ValidateArgs) -> ExitCode {
    let path = &args.challenge;

    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A schema error already names the offending key (spec §7.8); a semantic or
    // policy error is produced by `validate` below.
    let doc = match ChallengeDoc::from_yaml(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let issues = doc.validate();
    let errors = issues.iter().filter(|i| i.is_error()).count();
    for issue in issues.iter().filter(|i| !i.is_error()) {
        eprintln!("ctf: {path}: warning: {issue}");
    }
    if errors == 0 {
        println!("{path}: ok");
        return ExitCode::SUCCESS;
    }
    for issue in issues.iter().filter(|i| i.is_error()) {
        eprintln!("ctf: {path}: {issue}");
    }
    eprintln!("ctf: {path}: {errors} problem(s) found");
    ExitCode::FAILURE
}

/// `ctf pack`: compile an authoring file into an unsigned bundle.
///
/// Validation happens inside [`pack_with_suite`] — the same schema and policy
/// checks `ctf validate` runs — so an invalid document is refused here with the key
/// named, before a byte is written.
fn run_pack(args: &PackArgs) -> ExitCode {
    let path = &args.challenge;
    let out = &args.out;
    let suite = args.suite;

    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let doc = match ChallengeDoc::from_yaml(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Warnings do not block packing (spec §7.8); report them before the bundle so
    // an author sees them even on success.
    for issue in doc.warnings() {
        eprintln!("ctf: {path}: warning: {issue}");
    }
    let (file, descriptor) = match pack::pack_with_descriptor(&doc, suite) {
        Ok(f) => f,
        Err(PackError::Invalid(issues)) => {
            for issue in &issues {
                eprintln!("ctf: {path}: {issue}");
            }
            return ExitCode::FAILURE;
        }
        Err(PackError::Policy(issues)) => {
            for issue in &issues {
                eprintln!("ctf: {path}: {issue}");
            }
            return ExitCode::FAILURE;
        }
        Err(PackError::Format(e)) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(out, &file) {
        eprintln!("ctf: {out}: {e}");
        return ExitCode::FAILURE;
    }
    let descriptor_path = args
        .descriptor
        .clone()
        .unwrap_or_else(|| format!("{out}.descriptor.json"));
    let descriptor_json = match descriptor.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("ctf: {descriptor_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(&descriptor_path, descriptor_json) {
        eprintln!("ctf: {descriptor_path}: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "{out}: {} bytes, manifest {}, suite {suite} (unsigned)",
        file.len(),
        doc.id
    );
    println!("{descriptor_path}: platform ingest descriptor");
    ExitCode::SUCCESS
}

/// `ctf keygen`: write a fresh hybrid keypair as two hex key files.
/// `ctf serving-manifest`: write the canonical-CBOR serving manifest.
fn run_serving_manifest(args: &ServingManifestArgs) -> ExitCode {
    let path = &args.bundle;
    let file = match open_mapped(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bundle = match Bundle::parse(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let manifest = ServingManifest::from_bundle(&bundle);
    let bytes = match manifest.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match &args.out {
        Some(out) => {
            if let Err(e) = std::fs::write(out, &bytes) {
                eprintln!("ctf: {out}: {e}");
                return ExitCode::FAILURE;
            }
            println!(
                "{out}: {} servable artifact(s), {} bytes of canonical CBOR",
                manifest.artifacts.len(),
                bytes.len()
            );
        }
        None => {
            println!(
                "{}: {} servable artifact(s)",
                manifest.challenge_id,
                manifest.artifacts.len()
            );
            for a in &manifest.artifacts {
                println!(
                    "  {:<5} {:<24} {:>12}  {}{}",
                    a.name_id,
                    truncate(&a.name, 24),
                    a.size,
                    hexstr(&a.root),
                    if a.external { "  (external)" } else { "" }
                );
                for m in &a.mirrors {
                    println!("        mirror  {m:?}");
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// `ctf oci-export`: write an OCI image layout containing the bundle.
fn run_oci_export(args: &OciExportArgs) -> ExitCode {
    let path = &args.bundle;
    let file = match open_mapped(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match oci::export(&file, Path::new(&args.out)) {
        Ok(layout) => {
            println!(
                "{}: OCI image layout, bundle digest {}",
                layout.root.display(),
                layout.bundle_digest
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ctf oci-import`: read the bundle back out of an OCI image layout.
fn run_oci_import(args: &OciImportArgs) -> ExitCode {
    let layout = &args.layout;
    match oci::import(Path::new(layout)) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&args.out, &bytes) {
                eprintln!("ctf: {}: {e}", args.out);
                return ExitCode::FAILURE;
            }
            println!(
                "{}: {} bytes recovered from {layout}",
                args.out,
                bytes.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctf: {layout}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ctf release`: decrypt a bundle's sealed sections with the offline seal key.
fn run_release(args: &ReleaseArgs) -> ExitCode {
    let path = &args.bundle;
    let file = match open_mapped(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bundle = match Bundle::parse(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match read_hex_key_file(&args.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ctf: {}: {e}", args.key);
            return ExitCode::FAILURE;
        }
    };
    let release = match release_at_event_end(&bundle, &key) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&args.out) {
        eprintln!("ctf: {}: {e}", args.out);
        return ExitCode::FAILURE;
    }
    for asset in &release.assets {
        let dest = Path::new(&args.out).join(&asset.member.name);
        if let Err(e) = std::fs::write(&dest, &asset.bytes) {
            eprintln!("ctf: {}: {e}", dest.display());
            return ExitCode::FAILURE;
        }
    }
    let report_path = args
        .report
        .clone()
        .unwrap_or_else(|| format!("{}/release.json", args.out));
    let report = match release.report.to_json() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ctf: {report_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(&report_path, report) {
        eprintln!("ctf: {report_path}: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "{}: released {} member(s), report {report_path}",
        args.out,
        release.assets.len()
    );
    ExitCode::SUCCESS
}

/// `ctf run`: the platform's full offline ingest gate, run locally.
fn run_gate(args: &RunArgs) -> ExitCode {
    let path = &args.challenge;
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let doc = match ChallengeDoc::from_yaml(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let errors = doc.errors();
    if !errors.is_empty() {
        for issue in &errors {
            eprintln!("ctf: {path}: {issue}");
        }
        return ExitCode::FAILURE;
    }
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new("."));

    // Resolve the modules the document names, relative to the document.
    let read_module = |key: &str, name: &str| -> Result<Vec<u8>, String> {
        std::fs::read(dir.join(name)).map_err(|e| format!("`{key}`: {name}: {e}"))
    };
    let generator = match doc.generate.as_ref().and_then(|g| g.wasm.as_deref()) {
        Some(name) => match read_module("generate.wasm", name) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("ctf: {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let solver = match doc.verify.as_ref().map(|v| v.solver.as_str()) {
        Some(name) => match read_module("verify.solver", name) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("ctf: {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let secret = match hex_decode(&args.secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ctf: --secret: {e}");
            return ExitCode::FAILURE;
        }
    };
    let seed = match derive::subject_seed(&secret, &doc.id, doc.version, &args.subject) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ctf: --secret: {e}");
            return ExitCode::FAILURE;
        }
    };
    let expected = derive::flag(&seed);

    let report = match ctf_generator::offline_gate(
        ctf_generator::OfflineGate {
            generator: generator.as_deref(),
            solver: solver.as_deref(),
            seed: &seed,
            expected_flag: &expected,
            runtime_declared: doc.runtime.is_some(),
            offline_declared: doc.verify.as_ref().is_some_and(|v| v.offline),
        },
        &ctf_generator::Limits::default(),
    ) {
        Ok(r) => r,
        Err(e) => {
            // A hard stage failure (`GateError`) names the stage and the reason.
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Name each stage of spec §25.5 that ran, and the reason for a non-passed
    // outcome (ticket 29, rule S9).
    println!("gate          {}", report.status);
    if let (Some(runs), Some(cross), Some(count)) = (
        report.generator_runs,
        report.cross_engine,
        report.artifact_count,
    ) {
        println!(
            "  determinism passed  ({runs} runs; second engine {})",
            if cross {
                "agreed"
            } else {
                "unavailable for this module"
            }
        );
        println!(
            "  generator   {}  ({count} output{})",
            report
                .generator_root
                .map_or_else(|| "-".to_owned(), |r| hex_encode(&r)),
            if count == 1 { "" } else { "s" }
        );
        println!("  artifact    {count} output(s) handed to the solver, flag omitted");
        println!("  solver      ran in the same capability-free sandbox");
    }
    let code = match report.status {
        ctf_generator::GateStatus::Passed => {
            println!("  compare     solver flag == derived flag");
            ExitCode::SUCCESS
        }
        ctf_generator::GateStatus::Failed => {
            println!("  compare     solver flag != derived flag");
            eprintln!(
                "ctf: {path}: compare: the solver produced {:?}, not the derived flag — refusing to publish",
                report.solver_flag.as_deref().unwrap_or("")
            );
            ExitCode::FAILURE
        }
        ctf_generator::GateStatus::Unverified => {
            let reason = report
                .unverified_reason
                .map_or_else(|| "the gate did not run".to_owned(), |r| r.to_string());
            println!("  determinism not run ({reason})");
            println!("              this bundle is unverified, never passed");
            ExitCode::SUCCESS
        }
    };

    // Persist the tri-state alongside the bundle (ticket 30). The record is derived
    // data about this run, not a container structure.
    let status_path = args
        .status
        .clone()
        .or_else(|| args.bundle.as_ref().map(|b| format!("{b}.status.json")));
    if let Some(status_path) = status_path {
        let record = ctf_generator::VerificationRecord::from_report(
            &doc.id,
            doc.version,
            &args.subject,
            &report,
        );
        if let Err(e) = std::fs::write(&status_path, record.to_json()) {
            eprintln!("ctf: {status_path}: {e}");
            return ExitCode::FAILURE;
        }
        println!("{status_path}: verification status ({})", report.status);
    }
    code
}

fn run_keygen(args: &KeygenArgs) -> ExitCode {
    let key_path = &args.out_key;
    let pub_path = &args.out_pub;
    let suite = args.suite;

    let (signing_key, public_key) = match keypair(suite) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ctf: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_key_file(
        key_path,
        &hex_encode(&signing_key.classical),
        &hex_encode(&signing_key.pq),
    ) {
        eprintln!("ctf: {key_path}: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_key_file(
        pub_path,
        &hex_encode(&public_key.classical),
        &hex_encode(&public_key.pq),
    ) {
        eprintln!("ctf: {pub_path}: {e}");
        return ExitCode::FAILURE;
    }
    println!("signing key   {key_path}");
    println!("public key    {pub_path}");
    ExitCode::SUCCESS
}

/// `ctf keys`: generate a fresh hybrid KEM keypair and write it as two single-line
/// hex files.
///
/// The context is validated and printed but is deliberately *not* part of the key
/// material: a KEM public key is context-independent, and the context is bound into
/// the KEM combiner only when an envelope is sealed to it (spec §21.1). Generating
/// one pair and using it for two contexts would therefore work cryptographically but
/// is not what the command means, so the operator is told which context the pair is
/// intended for.
fn run_keys(args: &KeysArgs) -> ExitCode {
    let key_path = &args.out_key;
    let pub_path = &args.out_pub;
    let context = &args.context;

    if let Err(e) = check_context(context) {
        eprintln!("ctf: --context {context}: {e}");
        return ExitCode::FAILURE;
    }
    let pair = match kem_keypair(args.suite) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ctf: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_hex_key_file(key_path, &hex_encode(&pair.secret_key)) {
        eprintln!("ctf: {key_path}: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_hex_key_file(pub_path, &hex_encode(&pair.public_key)) {
        eprintln!("ctf: {pub_path}: {e}");
        return ExitCode::FAILURE;
    }
    println!("secret key    {key_path}  ({context})");
    println!("public key    {pub_path}  ({context})");
    ExitCode::SUCCESS
}

/// `ctf sign`: append both hybrid signatures to an unsigned bundle.
fn run_sign(args: &SignArgs) -> ExitCode {
    let bundle = &args.bundle;
    let key_path = &args.key;
    let pub_path = &args.public;
    let out = &args.out;

    let file = match std::fs::read(bundle) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {bundle}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signing_key = match read_key_file(key_path) {
        Ok((classical, pq)) => HybridSigningKey { classical, pq },
        Err(e) => {
            eprintln!("ctf: {key_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let public_key = match read_key_file(pub_path) {
        Ok((classical, pq)) => HybridPublicKey { classical, pq },
        Err(e) => {
            eprintln!("ctf: {pub_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signed = match ctf_format::sign_bundle(&file, &signing_key, &public_key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ctf: {bundle}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(out, &signed) {
        eprintln!("ctf: {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!("{out}: {} bytes, signed", signed.len());
    ExitCode::SUCCESS
}

/// `ctf seal`: rewrite an unsigned, unencrypted bundle with one more section
/// encrypted to a recipient, plus the `keys` section carrying its envelope.
///
/// A rewrite rather than an in-place patch, because encryption changes a section's
/// stored bytes, its lengths, its `enc` flag, and the layout around them, and the
/// writer's parse-back is what enforces every format rule (spec §20.2, §21). The
/// refusal of an already-signed or already-encrypted input is deliberate: a rewrite
/// of either would silently invalidate an existing signature or discard an existing
/// envelope's content key.
fn run_seal(args: &SealArgs) -> ExitCode {
    let bundle = &args.bundle;
    let out = &args.out;
    match seal_section(bundle, &args.public, &args.context, &args.section, out) {
        Ok(len) => {
            println!(
                "{out}: {len} bytes, `{}` encrypted to {}",
                args.section, args.context
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctf: {bundle}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ctf unseal`: recover one section's plaintext with the matching recipient key.
///
/// Writes nothing unless the envelope opens and every chunk authenticates, so a
/// wrong or missing key fails at exit 1 and leaves no output file (spec §21.2).
fn run_unseal(args: &UnsealArgs) -> ExitCode {
    let bundle = &args.bundle;
    let out = &args.out;
    match unseal_section(bundle, &args.key, &args.context, &args.section, out) {
        Ok(len) => {
            println!("{out}: {len} bytes, `{}` unsealed", args.section);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctf: {bundle}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `ctf init`: write an archetype scaffold to disk.
///
/// The scaffold is a pure function in the library (`ctf_format::scaffold`), so
/// this only creates directories and files. It refuses to overwrite an existing
/// `challenge.yaml`: a scaffold is a starting point, and clobbering an author's
/// work is worse than a second command.
fn run_init(args: &InitArgs) -> ExitCode {
    let files = match ctf_format::scaffold::scaffold(&args.archetype, &args.id) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("ctf: init {}: {e}", args.archetype);
            return ExitCode::FAILURE;
        }
    };
    let root = std::path::Path::new(&args.out);
    if root.join("challenge.yaml").exists() {
        eprintln!(
            "ctf: {}: already contains a challenge.yaml; refusing to overwrite",
            args.out
        );
        return ExitCode::FAILURE;
    }
    for file in &files {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("ctf: {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
        if let Err(e) = std::fs::write(&path, &file.contents) {
            eprintln!("ctf: {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("{}", path.display());
    }
    ExitCode::SUCCESS
}

/// `ctf transfer`: append a holder-signed handoff.
fn run_transfer(args: &TransferArgs) -> ExitCode {
    match transfer(args) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctf: {}: {e}", args.input);
            ExitCode::FAILURE
        }
    }
}

fn transfer(args: &TransferArgs) -> Result<String, Box<dyn std::error::Error>> {
    let suite = args.suite;
    let mut chain = read_chain(&args.input)?;

    let platform_key = read_signing_key(&args.platform_key)?;
    let platform_pub = read_public_key(&args.platform_pub)?;
    let holder_key = read_signing_key(&args.holder_key)?;
    let holder_pub = read_public_key(&args.holder_pub)?;

    let new_holder = match (&args.new_holder, &args.new_holder_pub) {
        (Some(hex), _) => <[u8; 32]>::try_from(hex_decode(hex)?.as_slice())
            .map_err(|_| "--new-holder must be exactly 32 bytes of hex")?,
        (None, Some(path)) => holder_hash(&read_public_key(path)?),
        (None, None) => {
            return Err("one of --new-holder or --new-holder-pub is required".into());
        }
    };

    let payload = match (&args.progress, &args.holder_kem) {
        (Some(progress_path), Some(kem_path)) => {
            let plaintext = std::fs::read(progress_path)?;
            let kem_public = read_hex_key_file(kem_path).map_err(|e| format!("{kem_path}: {e}"))?;
            Some(seal_progress(
                suite,
                VERSION_MAJOR,
                &kem_public,
                &args.challenge,
                &args.subject,
                &plaintext,
            )?)
        }
        (None, None) => None,
        _ => return Err("--progress requires --holder-kem, and vice versa".into()),
    };

    let timestamp = args.timestamp.map(|v| {
        if v < 0 {
            Timestamp::Nint((-(v + 1)) as u64)
        } else {
            Timestamp::Uint(v as u64)
        }
    });

    chain.append_transfer(
        &args.challenge,
        &args.subject,
        new_holder,
        suite,
        &platform_key,
        &holder_key,
        timestamp,
        payload,
    )?;
    chain.validate()?;

    // Fail before writing if the keys do not actually vouch for the chain: a
    // transfer that does not verify is not a handoff. The current holder's key is
    // the one the predecessor record names.
    let mut holders = HolderKeys::new();
    holders.insert(holder_hash(&holder_pub), holder_pub);
    chain.verify_signatures(suite, &platform_pub, &holders)?;

    let encoded = chain.encode()?;
    let written = if args.bundle {
        let bytes = embed_entitlement(&args.input, &encoded)?;
        std::fs::write(&args.out, &bytes)?;
        bytes.len()
    } else {
        std::fs::write(&args.out, &encoded)?;
        encoded.len()
    };
    Ok(format!(
        "{}: {written} bytes, entitlement chain of {} record(s)",
        args.out,
        chain.len()
    ))
}

/// Read a chain from a `.ctf` bundle's `entitlement` section, or from a file of
/// chain plaintext. The magic check is what lets one argument accept both.
fn read_chain(path: &str) -> Result<EntitlementChain, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(&MAGIC) {
        let bundle = Bundle::parse(&bytes)?;
        let record = bundle
            .sections
            .iter()
            .find(|r| r.kind == SectionKind::Entitlement)
            .ok_or("bundle has no entitlement section")?;
        Ok(EntitlementChain::from_bytes(
            &bundle.section_bytes(record)?,
        )?)
    } else {
        Ok(EntitlementChain::from_bytes(&bytes)?)
    }
}

/// Re-emit `path` with its `entitlement` section replaced by `chain`, appending a
/// section and a name-table entry when the bundle has none.
///
/// This is the authoring surface of ticket 44: a chain is a section of the bundle,
/// so updating it is a rewrite, not a side file. A signed bundle is refused — a
/// rewrite would invalidate its signature — and the writer's parse-back enforces
/// every format rule.
fn embed_entitlement(path: &str, chain: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = std::fs::read(path)?;
    let bundle = Bundle::parse(&file)?;
    if bundle.signing() != Signing::Unsigned {
        return Err(
            "refusing to rewrite a bundle that already carries signatures; a rewrite \
             would invalidate them"
                .into(),
        );
    }
    let manifest_record = bundle
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .ok_or("bundle has no manifest section")?;

    let existing = bundle
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Entitlement);
    let (name_id, appended_name) = match existing {
        Some(r) => (r.name_id, None),
        None => {
            let names = bundle.manifest.names();
            let next = u16::try_from(names.len()).map_err(
                |_| "the manifest name table is full; no room for an entitlement section",
            )?;
            (next, Some(unique_name(&names, "entitlement")))
        }
    };

    let manifest_plain = bundle.section_bytes(manifest_record)?;
    let mut manifest_value = Value::decode(&manifest_plain)?;
    if let Some(name) = &appended_name {
        append_manifest_name(&mut manifest_value, name)?;
    }
    let manifest_bytes = manifest_value.encode()?;

    let mut payloads: Vec<std::borrow::Cow<'_, [u8]>> = Vec::with_capacity(bundle.sections.len());
    let mut kept: Vec<usize> = Vec::with_capacity(bundle.sections.len());
    for (i, r) in bundle.sections.iter().enumerate() {
        if r.kind == SectionKind::Entitlement {
            continue;
        }
        kept.push(i);
        if r.kind == SectionKind::Manifest {
            payloads.push(std::borrow::Cow::Owned(manifest_bytes.clone()));
        } else if r.flags.contains(SectionFlags::EXTERNAL) {
            payloads.push(std::borrow::Cow::Owned(Vec::new()));
        } else {
            payloads.push(bundle.section_bytes(r)?);
        }
    }

    let mut specs: Vec<SectionSpec<'_>> = Vec::with_capacity(kept.len() + 1);
    for (slot, &i) in kept.iter().enumerate() {
        let Some(r) = bundle.sections.get(i) else {
            continue;
        };
        let plain = payloads.get(slot).map_or(&[][..], |c| c.as_ref());
        if r.flags.contains(SectionFlags::EXTERNAL) {
            specs.push(SectionSpec {
                kind: r.kind,
                name_id: r.name_id,
                flags: r.flags,
                chunk_size: r.chunk_size,
                comp: r.comp,
                payload: Payload::External {
                    len_plain: r.len_plain,
                    root: r.root,
                },
                chunk_index: None,
                encryption: None,
            });
            continue;
        }
        let mut spec = SectionSpec::inline(r.kind, r.name_id, r.flags, plain).chunked(r.chunk_size);
        if r.comp == Compression::Zstd {
            spec = spec.compressed();
        }
        specs.push(spec);
    }
    specs.push(SectionSpec::inline(
        SectionKind::Entitlement,
        name_id,
        SectionFlags::empty(),
        chain,
    ));

    let bytes = ctf_format::write_bundle(bundle.header.suite_id, &specs)?;
    Ok(bytes)
}

/// A name not already in the table, preferring `preferred`, then
/// `<preferred>.1`, `.2`, …; all pass the manifest's name-shape rules.
fn unique_name(existing: &[&str], preferred: &str) -> String {
    if !existing.contains(&preferred) {
        return preferred.to_owned();
    }
    let mut n = 1u32;
    loop {
        let candidate = format!("{preferred}.{n}");
        if candidate.len() <= ctf_format::manifest::MAX_NAME_LEN
            && !existing.contains(&candidate.as_str())
        {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

/// Read a hybrid signing key from a two-line hex key file.
fn read_signing_key(path: &str) -> Result<HybridSigningKey, Box<dyn std::error::Error>> {
    let (classical, pq) = read_key_file(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(HybridSigningKey { classical, pq })
}

/// Read a hybrid public key from a two-line hex key file.
fn read_public_key(path: &str) -> Result<HybridPublicKey, Box<dyn std::error::Error>> {
    let (classical, pq) = read_key_file(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(HybridPublicKey { classical, pq })
}

/// `ctf completions`: emit a completion script for `shell` to stdout. Built from
/// the same [`Cli`] the parser uses, so the script can never drift from the flags
/// this build actually accepts.
fn run_completions(args: &CompletionsArgs) -> ExitCode {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "ctf", &mut std::io::stdout());
    ExitCode::SUCCESS
}

/// Generate a keypair for `suite_id`, resolving the signature role where the
/// diagnostic names the missing role if this build cannot provide one.
fn keypair(
    suite_id: u16,
) -> Result<(HybridSigningKey, HybridPublicKey), Box<dyn std::error::Error>> {
    let suite = ctf_format::suite(suite_id)?;
    let role = suite.signature()?;
    Ok(role.keypair()?)
}

/// Generate a hybrid KEM keypair for `suite_id`, resolving the `kem` role so an
/// unimplemented role is reported by name rather than as a missing capability.
fn kem_keypair(suite_id: u16) -> Result<KemKeyPair, Box<dyn std::error::Error>> {
    let suite = ctf_format::suite(suite_id)?;
    let role = suite.kem()?;
    Ok(role.generate()?)
}

/// Validate a recipient context: `storage`, `seal`, `holder`, or `stage:<decimal>`
/// (spec §21.1). The value is carried verbatim into the envelope, so any other shape
/// is a usage error the operator should see before a bundle is written.
fn check_context(context: &str) -> Result<(), String> {
    if matches!(context, "storage" | "seal" | "holder") {
        return Ok(());
    }
    if let Some(n) = context.strip_prefix("stage:")
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && n.parse::<u32>().is_ok()
    {
        return Ok(());
    }
    Err("must be `storage`, `seal`, `holder`, or `stage:<decimal>`".to_owned())
}

/// Rewrite `path` with `section` encrypted to the recipient in `pub_path`.
///
/// Returns the sealed file's length. See [`run_seal`] for the shape of the rewrite;
/// the work is here so the command wrapper stays a thin error reporter.
fn seal_section(
    path: &str,
    pub_path: &str,
    context: &str,
    section: &str,
    out: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    check_context(context).map_err(|e| format!("--context: {e}"))?;
    let public_key = read_hex_key_file(pub_path).map_err(|e| format!("{pub_path}: {e}"))?;

    let file = std::fs::read(path)?;
    let b = Bundle::parse(&file)?;

    // A rewrite reproduces the header's suite and every other section byte-for-byte,
    // so it must not touch a file whose integrity depends on an existing signature,
    // and it cannot re-encrypt a section whose content key it does not hold.
    if b.signing() != Signing::Unsigned {
        return Err(
            "refusing to rewrite a bundle that already carries signatures; a rewrite \
             would invalidate them"
                .into(),
        );
    }
    if let Some(r) = b.sections.iter().find(|r| r.enc != Encryption::None) {
        return Err(format!(
            "refusing to rewrite a bundle that already has an encrypted section \
             (name_id {})",
            r.name_id
        )
        .into());
    }

    let target_index = b
        .sections
        .iter()
        .position(|r| b.manifest.name_of(r.name_id) == Some(section))
        .ok_or_else(|| format!("no section named `{section}`"))?;
    let target = b
        .sections
        .get(target_index)
        .ok_or("the resolved section vanished from the table")?;
    if target.kind == SectionKind::Manifest {
        return Err(format!("`{section}` is the manifest and cannot be encrypted").into());
    }
    if target.flags.contains(SectionFlags::EXTERNAL) {
        return Err(format!(
            "`{section}` is EXTERNAL; its bytes are not in the file and cannot be encrypted"
        )
        .into());
    }
    let target_name_id = target.name_id;

    let manifest_record = b
        .sections
        .iter()
        .find(|r| r.kind == SectionKind::Manifest)
        .ok_or("bundle has no manifest section")?;

    // The `keys` section's `name_id` must index the manifest's `names`. An input
    // that already has one reuses it; otherwise a fresh name is appended to the
    // table, which spec §7.2 permits to be longer than the section count.
    let (keys_name_id, appended_name) =
        match b.sections.iter().find(|r| r.kind == SectionKind::Keys) {
            Some(keys) => (keys.name_id, None),
            None => {
                let names = b.manifest.names();
                let next = u16::try_from(names.len())
                    .map_err(|_| "the manifest name table is full; no room for a keys section")?;
                (next, Some(unique_keys_name(&names, section)))
            }
        };

    // Re-emit the manifest. The decode/encode round trip is byte-identical for an
    // unchanged manifest, and the append is the only mutation.
    let manifest_plain = b.section_bytes(manifest_record)?;
    let mut manifest_value = Value::decode(&manifest_plain)?;
    if let Some(name) = &appended_name {
        append_manifest_name(&mut manifest_value, name)?;
    }
    let manifest_bytes = manifest_value.encode()?;

    // Every section's plaintext, in table order. The `keys` section is skipped: the
    // writer regenerates it from the envelopes.
    let mut payloads: Vec<std::borrow::Cow<'_, [u8]>> = Vec::with_capacity(b.sections.len());
    let mut kept: Vec<usize> = Vec::with_capacity(b.sections.len());
    for (i, r) in b.sections.iter().enumerate() {
        if r.kind == SectionKind::Keys {
            continue;
        }
        kept.push(i);
        if r.kind == SectionKind::Manifest {
            payloads.push(std::borrow::Cow::Owned(manifest_bytes.clone()));
        } else if r.flags.contains(SectionFlags::EXTERNAL) {
            // Never read; the external branch below uses only the record's metadata.
            payloads.push(std::borrow::Cow::Owned(Vec::new()));
        } else {
            payloads.push(b.section_bytes(r)?);
        }
    }

    let recipients = [Recipient {
        context,
        public_key: &public_key,
    }];
    let mut specs: Vec<SectionSpec<'_>> = Vec::with_capacity(kept.len() + 1);
    for (slot, &i) in kept.iter().enumerate() {
        let Some(r) = b.sections.get(i) else {
            continue;
        };
        let plain = payloads.get(slot).map_or(&[][..], |c| c.as_ref());
        if r.flags.contains(SectionFlags::EXTERNAL) {
            specs.push(SectionSpec {
                kind: r.kind,
                name_id: r.name_id,
                flags: r.flags,
                chunk_size: r.chunk_size,
                comp: r.comp,
                payload: Payload::External {
                    len_plain: r.len_plain,
                    root: r.root,
                },
                chunk_index: None,
                encryption: None,
            });
        } else {
            // R15: encryption needs a non-zero chunk_size, so a target that was a
            // single chunk is chunked at the minimum. Every other inline section
            // keeps the chunking it had.
            let chunk_size = if r.name_id == target_name_id {
                r.chunk_size.max(ctf_format::MIN_CHUNK_SIZE)
            } else {
                r.chunk_size
            };
            let mut spec =
                SectionSpec::inline(r.kind, r.name_id, r.flags, plain).chunked(chunk_size);
            if r.comp == Compression::Zstd {
                spec = spec.compressed();
            }
            if r.name_id == target_name_id {
                spec = spec.encrypted(&recipients);
            }
            specs.push(spec);
        }
    }
    specs.push(SectionSpec::envelopes(SectionKind::Keys, keys_name_id));

    let sealed = ctf_format::write_bundle(b.header.suite_id, &specs)?;
    std::fs::write(out, &sealed)?;
    Ok(sealed.len())
}

/// Recover `section`'s plaintext from a sealed bundle with the recipient's secret
/// key, writing it to `out`. Returns the plaintext length.
fn unseal_section(
    path: &str,
    key_path: &str,
    context: &str,
    section: &str,
    out: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    check_context(context).map_err(|e| format!("--context: {e}"))?;
    let secret_key = read_hex_key_file(key_path).map_err(|e| format!("{key_path}: {e}"))?;

    let file = std::fs::read(path)?;
    let b = Bundle::parse(&file)?;
    let record = b
        .sections
        .iter()
        .find(|r| b.manifest.name_of(r.name_id) == Some(section))
        .ok_or_else(|| format!("no section named `{section}`"))?;

    let content_key = b.section_content_key(record, &secret_key, context)?;
    let plain = b.decrypt_section_bytes(record, &content_key)?;
    std::fs::write(out, &plain)?;
    Ok(plain.len())
}

/// A `keys` name that is not already in the manifest's table and that passes the
/// manifest's name-shape rules. `keys` is the preferred name; a collision falls back
/// to `<section>.keys`, then to a numbered `keys.N`.
fn unique_keys_name(existing: &[&str], section: &str) -> String {
    if !existing.contains(&"keys") {
        return "keys".to_owned();
    }
    let dotted = format!("{section}.keys");
    if dotted.len() <= ctf_format::manifest::MAX_NAME_LEN && !existing.contains(&dotted.as_str()) {
        return dotted;
    }
    let mut n = 1u32;
    loop {
        let candidate = format!("keys.{n}");
        if !existing.contains(&candidate.as_str()) {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

/// Append `name` to the manifest value's `names` array, in place.
fn append_manifest_name(value: &mut Value, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Value::Map(entries) = value else {
        return Err("manifest is not a CBOR map".into());
    };
    for (key, val) in entries.iter_mut() {
        if key.as_text() == Some("names") {
            let Value::Array(items) = val else {
                return Err("manifest `names` is not an array".into());
            };
            items.push(Value::Text(name.to_owned()));
            return Ok(());
        }
    }
    Err("manifest has no `names` array".into())
}

/// Write one key file: classical component, then post-quantum, each on its own line.
fn write_key_file(path: &str, classical: &str, pq: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{classical}\n{pq}\n"))
}

/// Read a key file into its two hex components: classical first, post-quantum
/// second. Blank lines and surrounding whitespace are ignored.
fn read_key_file(path: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let [classical, pq] = lines.as_slice() else {
        return Err(format!(
            "a key file has exactly two non-empty lines (classical then post-quantum); \
             found {}",
            lines.len()
        ));
    };
    let classical = hex_decode(classical)?;
    let pq = hex_decode(pq)?;
    Ok((classical, pq))
}

/// Write a KEM key file: a single line of lowercase hex. Unlike a signing key file
/// there is no classical/post-quantum split to preserve — the hybrid key is one
/// concatenated blob (spec §20.1).
fn write_hex_key_file(path: &str, hex: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{hex}\n"))
}

/// Read a KEM key file: exactly one non-empty line of hex. Blank lines and
/// surrounding whitespace are ignored, matching [`read_key_file`].
fn read_hex_key_file(path: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "a KEM key file has exactly one non-empty line of hex; found {}",
            lines.len()
        ));
    };
    hex_decode(line)
}

/// Lowercase hex. The encoding side of [`hex_decode`].
fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a `String` cannot fail; the `Result` is discarded deliberately.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decode lowercase or uppercase hex, rejecting an odd length or a non-hex byte
/// with a message that names the offending character.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!(
            "hex string has an odd number of digits ({})",
            s.len()
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes.get(i).copied().unwrap_or_default())?;
        let lo = hex_nibble(bytes.get(i + 1).copied().unwrap_or_default())?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit `{}`", char::from(c))),
    }
}

/// Map `path` read-only, so `ctf inspect` never allocates the whole file.
///
/// `mmap` cannot map zero bytes, and a `.ctf` is never empty, so an empty file is
/// reported as a clean error rather than as an OS `EINVAL`. The 4096-byte payload
/// alignment the format already requires (spec §12, `PAYLOAD_ALIGN`) is what makes
/// the mapped region usable directly, with no copy to align it.
#[allow(unsafe_code)]
fn open_mapped(path: &str) -> Result<Mmap, Box<dyn std::error::Error>> {
    let f = std::fs::File::open(path)?;
    if f.metadata()?.len() == 0 {
        return Err(format!("{path}: file is empty").into());
    }
    // SAFETY: the mapping is read-only and shared. `Bundle` treats the bytes as a
    // hostile input stream and never writes through them, and the returned `Mmap`
    // outlives every borrow `inspect` takes from it.
    let map = unsafe { Mmap::map(&f)? };
    Ok(map)
}

fn inspect(
    path: &str,
    hex: bool,
    verify: bool,
    allow_unsigned: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let file = open_mapped(path)?;
    let b = Bundle::parse(&file)?;

    println!("file          {path}");
    println!("size          {} bytes", file.len());
    println!(
        "version       {}.{}",
        b.header.version_major, b.header.version_minor
    );
    println!("suite_id      {}", b.header.suite_id);
    println!(
        "features      incompat {:#010x}  ro_compat {:#010x}{}",
        b.header.feat_incompat,
        b.header.feat_ro_compat,
        if b.header.may_rewrite() {
            ""
        } else {
            "  (read-only: unimplemented ro_compat feature)"
        }
    );
    println!("root          {}", hexstr(&b.footer.root));
    // Present is not verified. Saying so on every run is cheaper than one operator
    // reading "signatures: 2" as "signed and checked".
    println!(
        "signatures    {}",
        match b.signing() {
            Signing::Unsigned => "none — this bundle authenticates nothing".to_owned(),
            Signing::Present => format!(
                "{} + {} bytes, NOT VERIFIED (no trusted key supplied)",
                b.footer.sig_classical.len(),
                b.footer.sig_pq.len()
            ),
        }
    );

    println!();
    println!(
        "manifest      spec {} — {}",
        b.manifest.spec(),
        b.manifest.id()
    );
    println!("              {:?}", b.manifest.name());
    // `{:?}` rather than `{}`, matching the title line above. `category`,
    // `description` and the mirror URLs are free-form text straight out of an
    // attacker-controllable manifest, and unlike `names` they can never take a
    // `check_name`-style rule — a description may legitimately contain anything.
    // Debug formatting escapes control characters, which is what stops a crafted
    // bundle from injecting terminal escape sequences and spoofing this output.
    if let Some(c) = b.manifest.category() {
        println!("              category {c:?}");
    }
    if b.manifest.version() != 0 {
        println!("              version {}", b.manifest.version());
    }

    println!();
    println!(
        "{:<5} {:<11} {:<20} {:>14} {:>14}  flags",
        "id", "kind", "name", "offset", "len_plain"
    );
    for r in &b.sections {
        let name = b.manifest.name_of(r.name_id).unwrap_or("?");
        let offset = if r.flags.contains(SectionFlags::EXTERNAL) {
            "external".to_owned()
        } else {
            r.offset.to_string()
        };
        println!(
            "{:<5} {:<11} {:<20} {:>14} {:>14}  {}",
            r.name_id,
            kind_name(r.kind),
            truncate(name, 20),
            offset,
            r.len_plain,
            flag_names(r.flags)
        );
        // The table's `name` column is truncated for alignment, so two long names
        // that share a prefix render to the same label and the operator cannot tell
        // the sections apart. Print the full name on its own line, `{:?}`-escaped,
        // matching the manifest's `name` and the `mirror` lines: the name comes from
        // the manifest and Debug formatting keeps any control character as visible
        // text rather than letting it reach the terminal.
        println!("      name    {name:?}");
        // The expected digest for this section's payload, inline or fetched
        // out-of-band. An operator fetching a 40 GB external image needs it from the
        // tool: without it, the only copy is inside the very file being checked. It
        // is a digest and a number, so printing it cannot leak payload or echo
        // attacker text. For an external section it is the record's `root`, which
        // spec §5.7 makes authoritative over the manifest's copy.
        println!(
            "      root    {}{}",
            hexstr(&r.root),
            if r.flags.contains(SectionFlags::EXTERNAL) {
                "  (external)"
            } else {
                ""
            }
        );
        if let Some(ext) = b.manifest.external(r.name_id) {
            for m in &ext.mirrors {
                println!("      mirror  {m:?}");
            }
        }
        if r.chunk_size != 0 {
            // A sealed or unknown-kind section's index is deliberately not read
            // (C8). Report where it is, not what is in it, rather than failing the
            // whole inspection over one unreadable section.
            match b.chunk_index(r) {
                Ok(Some(i)) => println!(
                    "      chunks  {} × {} bytes, index at {}",
                    i.entries().len(),
                    r.chunk_size,
                    r.chunk_index_off
                ),
                Ok(None) => println!("      chunks  none × {} bytes", r.chunk_size),
                Err(_) => println!("      chunks  index at {} (not read)", r.chunk_index_off),
            }
        }
    }

    if verify {
        println!();
        let r = b.verify_inline_sections()?;
        println!(
            "verified      {} inline section(s) against their roots",
            r.verified
        );
        // Every mismatch, not just the first: an operator fixing a bundle should not
        // have to bisect. `name_id` is a number and the name is validated, so this
        // cannot leak or spoof (the name is Debug-escaped).
        for name_id in &r.mismatches {
            let name = b.manifest.name_of(*name_id).unwrap_or("?");
            println!("              section {name_id} ({name:?}) does NOT match its root");
        }
        if r.external != 0 {
            println!(
                "              {} external — bytes are not here; stream them separately",
                r.external
            );
        }
        // Printed before the error is returned, so an operator sees the count even
        // though the command is about to fail.
        if r.unverifiable != 0 {
            println!(
                "              {} inline section(s) NOT VERIFIED — encrypted or \
                 compressed, which this build cannot read",
                r.unverifiable
            );
            return Err(format!(
                "--verify could not check {} inline section(s); this file is not fully verified",
                r.unverifiable
            )
            .into());
        }
        if !r.mismatches.is_empty() {
            return Err(format!(
                "--verify found {} section(s) whose bytes do not match their roots",
                r.mismatches.len()
            )
            .into());
        }

        // Integrity is not authenticity. `Bundle::parse` and the pass above proved
        // the file is internally consistent; they said nothing about *who* made it.
        // A bundle with no signatures has no author to vouch for, so `--verify`
        // alone must not read as "safe" — hence a distinct exit code the caller can
        // branch on, and an explicit opt-in to accept it anyway.
        match b.signing() {
            Signing::Unsigned if allow_unsigned => {
                println!();
                println!(
                    "authenticity  accepted (--allow-unsigned): this bundle is intact but carries \
                     no signatures; the caller vouches for its provenance"
                );
            }
            Signing::Unsigned => {
                println!();
                println!(
                    "authenticity  INTACT BUT NOT AUTHENTIC — this bundle carries no signatures, \
                     so nothing vouches for its author"
                );
                println!(
                    "              pass --allow-unsigned to accept an unsigned bundle, or verify \
                     it against a signature you already trust"
                );
                return Ok(ExitCode::from(2));
            }
            Signing::Present => {
                println!();
                println!(
                    "authenticity  signatures present but NOT verified — no trusted key was \
                     supplied, so this run established integrity only"
                );
            }
        }
    }

    if hex {
        dump("header", 0, file.get(..HEADER_LEN as usize).unwrap_or(&[]));
        let (start, _) = b.header.table_range()?;
        for (i, r) in b.sections.iter().enumerate() {
            let at = start as usize + i * SECTION_RECORD_LEN;
            dump(
                &format!("section record {} (name_id {})", i, r.name_id),
                at,
                file.get(at..at + SECTION_RECORD_LEN).unwrap_or(&[]),
            );
        }
        let f = b.header.footer_off as usize;
        dump("footer", f, file.get(f..).unwrap_or(&[]));
        if let Some(r) = b.sections.iter().find(|r| r.kind == SectionKind::Manifest) {
            dump(
                "manifest (canonical CBOR)",
                r.offset as usize,
                &b.section_bytes(r)?,
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn kind_name(k: SectionKind) -> String {
    match k {
        SectionKind::Manifest => "manifest".to_owned(),
        SectionKind::Artifact => "artifact".to_owned(),
        SectionKind::Generator => "generator".to_owned(),
        SectionKind::Solver => "solver".to_owned(),
        SectionKind::Writeup => "writeup".to_owned(),
        SectionKind::Entitlement => "entitlement".to_owned(),
        SectionKind::Keys => "keys".to_owned(),
        SectionKind::Progress => "progress".to_owned(),
        SectionKind::Unknown(v) => format!("?{}", v.get()),
    }
}

fn flag_names(f: SectionFlags) -> String {
    let mut v = Vec::new();
    if f.sealed() {
        v.push("SEALED");
    }
    if f.player_visible() {
        v.push("PLAYER_VISIBLE");
    }
    if f.external() {
        v.push("EXTERNAL");
    }
    if f.optional() {
        v.push("OPTIONAL");
    }
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.join("|")
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_owned();
    }
    s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
}

fn hexstr(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn dump(label: &str, at: usize, b: &[u8]) {
    println!("\n{label}  @ {at}, {} bytes", b.len());
    for (i, row) in b.chunks(16).enumerate() {
        let hex: Vec<String> = row.iter().map(|x| format!("{x:02x}")).collect();
        let (a, c) = hex.split_at(hex.len().min(8));
        let ascii: String = row
            .iter()
            .map(|&x| {
                if (0x20..0x7f).contains(&x) {
                    x as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "  {:08x}  {:<23}  {:<23}  |{ascii}|",
            at + i * 16,
            a.join(" "),
            c.join(" ")
        );
    }
}
