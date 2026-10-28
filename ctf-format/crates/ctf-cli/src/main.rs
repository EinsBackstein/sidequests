//! `ctf` — the command-line tool for `.ctf` bundles.
//!
//! Subcommands: `inspect`, `validate`, `pack`, `keygen`, `keys`, `sign`, `seal`,
//! `unseal`, `run`, `verify`, and `completions`. The rest of design §10's table
//! arrives with the phases that give it something to do — `init`/`transfer` need
//! the authoring archetypes and the entitlement and seal-release management.
//! `completions` is the one §10 CLI item that needs no runtime behind it, so it
//! lands with the parser.
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

mod verify;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use memmap2::Mmap;

use ctf_format::authoring::ChallengeDoc;
use ctf_format::cbor::Value;
use ctf_format::derive;
use ctf_format::oci;
use ctf_format::pack::{self, PackError};
use ctf_format::policy;
use ctf_format::{
    Bundle, Compression, Encryption, EntitlementChain, HEADER_LEN, HolderKeys, HybridPublicKey,
    HybridSigningKey, KemKeyPair, MAGIC, Manifest, Payload, Recipient, SECTION_RECORD_LEN,
    SectionFlags, SectionKind, SectionRecord, SectionSpec, ServingManifest, Signing, Timestamp,
    VERSION_MAJOR, holder_hash, release_at_event_end, seal_progress,
};

use verify::{Artifact, SectionCounts, Status};

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
  2  inspect --verify found an intact but unauthentic (unsigned) bundle, or
     verify found an intact bundle that is unverified rather than passed"
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
    /// Run the ingest checks and emit one stable `ctf/ingest-verification/v1` artifact (ticket 64).
    Verify(VerifyArgs),
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

    /// The event secret, 64 hex digits (32 bytes) by this CLI's contract.
    /// §22.2 leaves the library's secret length unconstrained. Never written anywhere.
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

/// `ctf verify`: run the ingest checks and emit one machine-readable artifact
/// (ticket 64, spec §25.6.1).
///
/// The commitment checks always run: the bundle must parse and every inline
/// section must hash to its root. `--challenge` with `--secret` additionally runs
/// the same §25 offline gate as `ctf run`, so the verdict can be `passed` instead
/// of merely `unverified`. A rejected or failed bundle exits 1; an intact but
/// unverified one exits 2, never 0.
///
/// The artifact is derived data about this run. It is not a container structure,
/// it is not covered by the commitment root, and it never includes the event
/// secret or the flag.
#[derive(Args)]
struct VerifyArgs {
    /// The `.ctf` bundle to verify.
    bundle: String,

    /// The authoring YAML file. Runs the §25 offline gate together with `--secret`.
    #[arg(long, requires = "secret")]
    challenge: Option<String>,

    /// The event secret, 64 hex digits (32 bytes) by this CLI's contract.
    /// §22.2 leaves the library's secret length unconstrained. Never written to the artifact.
    #[arg(long, requires = "challenge")]
    secret: Option<String>,

    /// The reference subject id for the gate. Defaults to `reference`.
    #[arg(long, default_value = "reference")]
    subject: String,

    /// Where to write the JSON artifact. Prints it to stdout when omitted.
    #[arg(long)]
    out: Option<String>,
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
        Commands::Verify(args) => run_verify(&args),
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
            // A schema error echoes the offending key, which is free-form text in
            // the file; escape it before it reaches the terminal (§13).
            eprintln!("ctf: {path}: {}", escape_terminal(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };
    let issues = doc.validate();
    let mut errors: Vec<String> = issues
        .iter()
        .filter(|i| i.is_error())
        .map(|i| escape_terminal(&i.to_string()))
        .collect();
    for issue in issues.iter().filter(|i| !i.is_error()) {
        eprintln!(
            "ctf: {path}: warning: {}",
            escape_terminal(&issue.to_string())
        );
    }
    // `ctf validate` is the author's pre-flight, so it runs the descriptor's
    // policy checks too (§29.1): `ctf pack` refuses an out-of-range port or a
    // zero PID limit, and `validate` must not report `ok` for a document pack
    // would reject. Only project when the document is otherwise valid, so a
    // schema error is not reported twice.
    if errors.is_empty() {
        match pack::descriptor_for(&doc) {
            Ok(_) => {}
            Err(PackError::Policy(policy_issues)) => {
                errors.extend(
                    policy_issues
                        .iter()
                        .map(|i| escape_terminal(&i.to_string())),
                );
            }
            Err(PackError::Invalid(validation_issues)) => {
                errors.extend(
                    validation_issues
                        .iter()
                        .map(|i| escape_terminal(&i.to_string())),
                );
            }
            Err(PackError::Format(e)) => errors.push(escape_terminal(&e.to_string())),
        }
    }
    if errors.is_empty() {
        println!("{path}: ok");
        return ExitCode::SUCCESS;
    }
    for error in &errors {
        eprintln!("ctf: {path}: {error}");
    }
    eprintln!("ctf: {path}: {} problem(s) found", errors.len());
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
            // A schema error echoes the offending key, which is free-form text in
            // the file; escape it before it reaches the terminal (§13).
            eprintln!("ctf: {path}: {}", escape_terminal(&e.to_string()));
            return ExitCode::FAILURE;
        }
    };
    // Warnings do not block packing (spec §7.8); report them before the bundle so
    // an author sees them even on success.
    for issue in doc.warnings() {
        eprintln!(
            "ctf: {path}: warning: {}",
            escape_terminal(&issue.to_string())
        );
    }
    // Artifact `source` paths are relative to the authoring document, not to the
    // operator's shell (spec §7.8). A bare filename has no parent, so `.` is the
    // root the author meant.
    let root = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let (file, descriptor) = match pack::pack_with_descriptor_root(&doc, suite, root) {
        Ok(f) => f,
        Err(PackError::Invalid(issues)) => {
            for issue in &issues {
                eprintln!("ctf: {path}: {}", escape_terminal(&issue.to_string()));
            }
            return ExitCode::FAILURE;
        }
        Err(PackError::Policy(issues)) => {
            for issue in &issues {
                eprintln!("ctf: {path}: {}", escape_terminal(&issue.to_string()));
            }
            return ExitCode::FAILURE;
        }
        Err(PackError::Format(e)) => {
            eprintln!("ctf: {path}: {}", escape_terminal(&e.to_string()));
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
    report_policy(&bundle.manifest);
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
    // Read-time policy pass (spec §29.2). Diagnostics only: no exit code, stdout
    // line, or released artifact changes.
    report_policy(&bundle.manifest);
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
    // Without `--bundle` every declaration is the document's, so an unsupported
    // interface or profile is refused here as before. With `--bundle`, §25.6 makes
    // the bundle authoritative and its values are applied below; the document's
    // versions must not veto a run the bundle permits.
    let loaded = match args.bundle {
        Some(_) => {
            load_gate_setup_inner(path, &args.subject, &args.secret, DeclarationSource::Bundle)
        }
        None => load_gate_setup(path, &args.subject, &args.secret),
    };
    let mut setup = match loaded {
        Ok(s) => s,
        Err(GateSetupError::Issues(issues)) => {
            for issue in &issues {
                eprintln!("ctf: {path}: {}", escape_terminal(&issue.to_string()));
            }
            return ExitCode::FAILURE;
        }
        Err(GateSetupError::Message(message)) => {
            eprintln!("ctf: {path}: {}", escape_terminal(&message));
            return ExitCode::FAILURE;
        }
    };

    // Spec §25.6/S10: the record is written next to a bundle, so it must describe
    // that bundle. Without this check `ctf run --bundle` could persist a verdict
    // about this document beside an unrelated file.
    if let Some(path) = &args.bundle {
        let bundle_file = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("ctf: {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bundle = match Bundle::parse(&bundle_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ctf: {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        // Read-time policy pass (spec §29.2), the same diagnostic `ctf verify`
        // prints. The gate's verdict and exit code are unchanged.
        report_policy(&bundle.manifest);
        let (id, version) = (bundle.manifest.id(), bundle.manifest.version());
        if id != setup.doc_id || version != setup.doc_version {
            eprintln!(
                "ctf: {path}: the authoring document describes `{}` version {}, not this \
                 bundle's `{id}` version {version}",
                setup.doc_id, setup.doc_version
            );
            return ExitCode::FAILURE;
        }

        // Spec §25.6: the declarations that decide whether the gate may run are the
        // bundle's, not the document's. Apply them before anything executes, so a
        // bundle declaring `runtime`, no offline gate, or an interface/profile this
        // build does not implement is persisted as `unverified`, never `passed`.
        if let Err(reason) = apply_bundle_declarations(&bundle, &mut setup) {
            println!("gate          unverified");
            println!("  determinism not run ({reason})");
            let status_path = run_status_path(args);
            if let Some(status_path) = status_path {
                let record = ctf_generator::VerificationRecord {
                    challenge: bundle.manifest.id().to_owned(),
                    version: bundle.manifest.version(),
                    subject: args.subject.clone(),
                    status: ctf_generator::GateStatus::Unverified,
                    reason,
                    generator_root: None,
                    cross_engine: None,
                    runs: None,
                };
                if let Err(e) = std::fs::write(&status_path, record.to_json()) {
                    eprintln!("ctf: {status_path}: {e}");
                    return ExitCode::FAILURE;
                }
                println!("{status_path}: verification status (unverified)");
            }
            // `ctf run`'s accepted exit for `unverified`; rule S11's non-zero
            // contract governs `ctf verify`, which has its own exit code.
            return ExitCode::SUCCESS;
        }
    }

    let report = match run_setup_gate(&setup) {
        Ok(r) => r,
        Err(e) => {
            // A hard stage failure (`GateError`) names the stage and the reason.
            eprintln!("ctf: {path}: {e}");
            // It is still a gate outcome, so persist it where a record is expected
            // (§25.6). Whatever the determinism stage produced stays in the record;
            // only a determinism-stage failure leaves those fields null.
            if let Some(status_path) = run_status_path(args) {
                let determinism = e.determinism;
                let record = ctf_generator::VerificationRecord {
                    challenge: setup.doc_id.clone(),
                    version: setup.doc_version,
                    subject: args.subject.clone(),
                    status: ctf_generator::GateStatus::Failed,
                    reason: format!(
                        "the offline gate could not complete a §25.5 stage ({})",
                        e.stage
                    ),
                    generator_root: determinism.map(|d| d.output_root),
                    cross_engine: determinism.map(|d| d.cross_engine),
                    runs: determinism.map(|d| d.runs),
                };
                if let Err(write) = std::fs::write(&status_path, record.to_json()) {
                    eprintln!("ctf: {status_path}: {write}");
                } else {
                    println!("{status_path}: verification status (failed)");
                }
            }
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
    let status_path = run_status_path(args);
    if let Some(status_path) = status_path {
        let record = ctf_generator::VerificationRecord::from_report(
            &setup.doc_id,
            setup.doc_version,
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

/// Where `ctf run` persists its record: `--status` when given, else beside the
/// bundle it describes (spec §25.6/S10).
fn run_status_path(args: &RunArgs) -> Option<String> {
    args.status
        .clone()
        .or_else(|| args.bundle.as_ref().map(|b| format!("{b}.status.json")))
}

/// Everything the §25 gate needs, resolved from an authoring document.
///
/// For `ctf run` without `--bundle` every field comes from the document. `ctf run
/// --bundle` and `ctf verify` replace the declarations with the bundle's, prefer
/// the bundle's module sections, and keep a document module only when the bundle
/// declares it (see [`apply_bundle_declarations`]). Resolving is separated from
/// running so the commands cannot disagree about the seed, the derived flag, or
/// which stages a gate names. They differ only in what they do with a non-`passed`
/// outcome.
struct GateSetup {
    /// The document's `id`, as authored. A gate record describes the bundle whose
    /// manifest must agree with this.
    doc_id: String,
    /// The document's `version`, likewise.
    doc_version: u64,
    /// The `generate.interface` the gate will use: the document's, or the bundle's
    /// when one is supplied; 1 when absent (§7.6).
    interface: u32,
    /// The `generate.profile` the gate will use, likewise; 1 when absent (§7.6).
    profile: u32,
    /// The generator module's bytes, when the gate has one.
    generator: Option<Vec<u8>>,
    /// The solver module's bytes, when the gate has one.
    solver: Option<Vec<u8>>,
    /// The reference subject's seed (§22.2).
    seed: [u8; 32],
    /// The derived flag the solver must recover (§22.3).
    expected: String,
    /// Whether the gate's manifest declares `runtime`, which needs a live instance.
    runtime_declared: bool,
    /// Whether the gate's manifest declares `verify.offline`.
    offline_declared: bool,
    /// The `generate.determinism` declaration the gate will use (§23.7): the
    /// document's, or the bundle's when one is supplied. `Absent` does not suppress
    /// the gate; a present but unrecognised value is `unverified`.
    determinism: ctf_generator::DeterminismDeclaration,
    /// The output names `generate.outputs` declares (§7.6, G8), likewise. Every name
    /// the generator emits must be a member.
    declared_outputs: Vec<String>,
    /// The authoring document's modules, deferred. Set only when a bundle supplies
    /// the declarations: resolving them eagerly would let the document's filesystem
    /// state fail a bundle that carries its own module sections (§25.6).
    document_modules: Option<DocumentModules>,
}

/// Where a gate's module bytes may come from when they were not read up front.
///
/// Holds the document's directory and the file names it declares, never the bytes:
/// a bundle that carries a module section must not touch these paths at all.
struct DocumentModules {
    /// The directory the authoring document lives in; its module names are relative
    /// to it.
    dir: PathBuf,
    /// The document's `generate.wasm`, when it names one.
    generator: Option<String>,
    /// The document's `verify.solver`, when it names one.
    solver: Option<String>,
}

impl DocumentModules {
    /// Read one deferred module, or `None` when the document named none.
    ///
    /// A read failure is a fixed, path-free sentence (rule S12): the artifact names
    /// the condition, and the detail stays out of it.
    fn read(&self, name: Option<&str>, what: &str) -> Result<Option<Vec<u8>>, String> {
        let Some(name) = name else {
            return Ok(None);
        };
        let path = self.dir.join(name);
        std::fs::read(&path).map(Some).map_err(|e| {
            eprintln!(
                "ctf: the offline gate could not run: `{}`: {e}",
                path.display()
            );
            format!(
                "the offline gate could not run: the authoring document's {what} module could not \
                 be read"
            )
        })
    }
}

/// Why a gate could not even be constructed: it did not run.
enum GateSetupError {
    /// The authoring document has schema or policy errors.
    Issues(Vec<ctf_format::authoring::ValidationIssue>),
    /// A file, a secret, or a derivation failed. The message names which.
    Message(String),
}

impl core::fmt::Display for GateSetupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Issues(issues) => {
                let mut first = true;
                for issue in issues {
                    if !first {
                        f.write_str("; ")?;
                    }
                    first = false;
                    write!(f, "{issue}")?;
                }
                Ok(())
            }
            Self::Message(message) => f.write_str(message),
        }
    }
}

/// A `generate.interface`/`generate.profile` from a document, or 1 when absent
/// (§7.6).
///
/// `Err(v)` is a version the build cannot implement: either `implemented` rejects
/// it, or it does not fit `u32` at all. Both are unsupported rather than malformed,
/// so the caller reports one diagnostic and the value that caused it.
fn declared_version(
    value: Option<u64>,
    implemented: fn(u32) -> Result<(), u32>,
) -> Result<u32, u64> {
    let Some(value) = value else {
        return Ok(1);
    };
    u32::try_from(value)
        .ok()
        .filter(|small| implemented(*small).is_ok())
        .ok_or(value)
}

/// The diagnostic for a version this build does not implement, naming the value so
/// an author knows what to change.
fn unsupported_version(key: &str, value: u64) -> String {
    format!("`{key}`: {value} is not a version this build implements")
}

/// Read and resolve the authoring document, the modules it names, the event secret,
/// and the reference subject's seed. This is every input a gate needs and nothing
/// more: it does not run the gate.
fn load_gate_setup(
    path: &str,
    subject: &str,
    secret_hex: &str,
) -> Result<GateSetup, GateSetupError> {
    load_gate_setup_inner(path, subject, secret_hex, DeclarationSource::Document)
}

/// Where the declarations a gate runs come from: the authoring document, or a
/// bundle whose manifest is authoritative (§25.6).
#[derive(Clone, Copy)]
enum DeclarationSource {
    /// Bare `ctf run`: the document is the only input, so its versions are enforced
    /// and its modules are read eagerly.
    Document,
    /// `ctf run --bundle` and `ctf verify`: the bundle supplies the declarations, so
    /// the document's versions are not the ones that run and its modules are only
    /// read if the bundle declares a module without carrying it.
    Bundle,
}

/// [`load_gate_setup`] with control over which declarations a gate will run.
///
/// With [`DeclarationSource::Bundle`] the document's `generate.interface`/`profile`
/// are not the versions that run — [`apply_bundle_declarations`] overwrites both from
/// the bundle, absent meaning 1 (§7.6) — so refusing the document's value would let
/// it veto a run the bundle permits. The placeholders set in that mode are never
/// executed. Its modules are deferred rather than read, for the same reason: a
/// bundle that carries a module section must not fail on a missing document file
/// (§25.6).
fn load_gate_setup_inner(
    path: &str,
    subject: &str,
    secret_hex: &str,
    source: DeclarationSource,
) -> Result<GateSetup, GateSetupError> {
    let text = std::fs::read_to_string(path).map_err(|e| GateSetupError::Message(e.to_string()))?;
    let doc = ChallengeDoc::from_yaml(&text).map_err(|e| GateSetupError::Message(e.to_string()))?;
    let issues = doc.errors();
    if !issues.is_empty() {
        return Err(GateSetupError::Issues(issues));
    }
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new("."));

    // Rules G6/G7: an interface or profile this build does not implement means the
    // gate cannot run at all, so it is refused before a module is read — let alone
    // executed. An integer wider than `u32` is one such version: no build can
    // implement it, and truncating it would name the wrong one in the diagnostic.
    //
    // When a bundle supplies the declarations, the check applies to its values
    // instead (§25.6); leaving the document's unsupported number in the setup would
    // be wrong even though it is overwritten, so the documented absent value 1
    // stands in for both.
    let (interface, profile) = match source {
        DeclarationSource::Document => {
            let interface = declared_version(
                doc.generate.as_ref().and_then(|g| g.interface),
                ctf_generator::abi::ensure_interface,
            )
            .map_err(|v| GateSetupError::Message(unsupported_version("generate.interface", v)))?;
            let profile = declared_version(
                doc.generate.as_ref().and_then(|g| g.profile),
                ctf_generator::abi::ensure_profile,
            )
            .map_err(|v| GateSetupError::Message(unsupported_version("generate.profile", v)))?;
            (interface, profile)
        }
        DeclarationSource::Bundle => (1, 1),
    };

    // Resolve the modules the document names, relative to the document. When a
    // bundle supplies the declarations, this is deferred: the document's filesystem
    // state must not decide whether a bundle that carries its own module can be
    // gated (§25.6).
    let generator_name = doc.generate.as_ref().and_then(|g| g.wasm.clone());
    let solver_name = doc.verify.as_ref().map(|v| v.solver.clone());
    let read_module = |key: &str, name: &str| -> Result<Vec<u8>, String> {
        std::fs::read(dir.join(name)).map_err(|e| format!("`{key}`: {name}: {e}"))
    };
    let (generator, solver, document_modules) = match source {
        DeclarationSource::Document => {
            let generator = match generator_name.as_deref() {
                Some(name) => {
                    Some(read_module("generate.wasm", name).map_err(GateSetupError::Message)?)
                }
                None => None,
            };
            let solver = match solver_name.as_deref() {
                Some(name) => {
                    Some(read_module("verify.solver", name).map_err(GateSetupError::Message)?)
                }
                None => None,
            };
            (generator, solver, None)
        }
        DeclarationSource::Bundle => (
            None,
            None,
            Some(DocumentModules {
                dir: dir.to_path_buf(),
                generator: generator_name,
                solver: solver_name,
            }),
        ),
    };

    let secret =
        hex_decode(secret_hex).map_err(|e| GateSetupError::Message(format!("--secret: {e}")))?;
    // §22.2's derivation is length-agnostic so library callers can use any IKM, but
    // the CLI's contract is exactly the 64 hex digits both help strings name. Without
    // this, `--secret ""` derives a flag from an empty, publicly computable secret.
    if secret.len() != 32 {
        return Err(GateSetupError::Message(format!(
            "--secret: expected 64 hex digits (32 bytes), got {} bytes",
            secret.len()
        )));
    }
    let seed = derive::subject_seed(&secret, &doc.id, doc.version, subject)
        .map_err(|e| GateSetupError::Message(format!("--secret: {e}")))?;
    let expected = derive::flag(&seed);

    // §23.7/G8: the document's declarations, unless a bundle supplies them (then
    // [`apply_bundle_declarations`] overwrites both before a gate runs). The
    // document's `determinism` is a required string, so only the mode name can be
    // missing; `parse` failing is still a present-but-unrecognised declaration. The
    // authoring validator restricts it, but the gate must not assume it did.
    let (determinism, declared_outputs) = match source {
        DeclarationSource::Document => {
            let generate = doc.generate.as_ref();
            let determinism = match generate {
                None => ctf_generator::DeterminismDeclaration::Absent,
                Some(generate) => {
                    match ctf_generator::DeterminismMode::parse(&generate.determinism) {
                        Some(mode) => ctf_generator::DeterminismDeclaration::Mode(mode),
                        None => ctf_generator::DeterminismDeclaration::Unrecognized,
                    }
                }
            };
            let declared_outputs = generate
                .map(|g| g.outputs.iter().map(|o| o.name.clone()).collect())
                .unwrap_or_default();
            (determinism, declared_outputs)
        }
        // The bundle's declarations decide (§25.6). These placeholders are never
        // used: every bundle path applies the bundle's values first.
        DeclarationSource::Bundle => (ctf_generator::DeterminismDeclaration::Absent, Vec::new()),
    };

    Ok(GateSetup {
        doc_id: doc.id.clone(),
        doc_version: doc.version,
        interface,
        profile,
        generator,
        solver,
        seed,
        expected,
        runtime_declared: doc.runtime.is_some(),
        offline_declared: doc.verify.as_ref().is_some_and(|v| v.offline),
        determinism,
        declared_outputs,
        document_modules,
    })
}

/// Run the §25 gate for a resolved document. Pure with respect to the filesystem:
/// every input was read by [`load_gate_setup`].
fn run_setup_gate(
    setup: &GateSetup,
) -> Result<ctf_generator::OfflineGateReport, ctf_generator::GateError> {
    // G6/G7 again at the point of use: `ctf verify` replaces these from the bundle
    // manifest, and an unimplemented version means no stage can start.
    if let Err(interface) = ctf_generator::abi::ensure_interface(setup.interface) {
        return Err(ctf_generator::GateError {
            stage: ctf_generator::GateStage::Determinism,
            source: ctf_generator::GeneratorError::InterfaceUnsupported(interface),
            determinism: None,
        });
    }
    if let Err(profile) = ctf_generator::abi::ensure_profile(setup.profile) {
        return Err(ctf_generator::GateError {
            stage: ctf_generator::GateStage::Determinism,
            source: ctf_generator::GeneratorError::ProfileUnsupported(profile),
            determinism: None,
        });
    }
    ctf_generator::offline_gate(
        ctf_generator::OfflineGate {
            generator: setup.generator.as_deref(),
            solver: setup.solver.as_deref(),
            seed: &setup.seed,
            expected_flag: &setup.expected,
            runtime_declared: setup.runtime_declared,
            offline_declared: setup.offline_declared,
            determinism: setup.determinism,
            declared_outputs: &setup.declared_outputs,
        },
        &ctf_generator::Limits::default(),
    )
}

/// The §25.6 verification record for `bundle`, running the gate if the inputs allow.
///
/// The gate describes **the bundle**. Its `runtime` and `verify.offline`
/// declarations, and whether it declares a generator and a solver, are read from
/// `bundle` itself (§25.6). The module bytes are the bundle's own sections when it
/// carries them; otherwise they come from the authoring document, and only for a
/// module the bundle actually declares. The document supplies the reference seed,
/// the derived flag, and the id/version cross-check, and never the declarations
/// that decide whether the gate may run.
///
/// A gate that cannot be constructed is `unverified` — the gate did not run, and
/// rule S8 forbids reporting that as `passed`. A gate that runs but fails a stage
/// outright is `failed`: the bundle is intact, but it is not publishable.
fn gate_record_for_bundle(
    challenge: &str,
    secret_hex: &str,
    subject: &str,
    bundle: &Bundle<'_>,
) -> ctf_generator::VerificationRecord {
    let id = bundle.manifest.id();
    let version = bundle.manifest.version();
    let unverified = |reason: String| ctf_generator::VerificationRecord {
        challenge: id.to_owned(),
        version,
        subject: subject.to_owned(),
        status: ctf_generator::GateStatus::Unverified,
        reason,
        generator_root: None,
        cross_engine: None,
        runs: None,
    };

    let loaded = load_gate_setup_inner(challenge, subject, secret_hex, DeclarationSource::Bundle);
    let mut setup = match loaded {
        Ok(s) => s,
        Err(e) => {
            // The artifact is stable and path-free (spec §25.6.1, S12): the detail
            // names the authoring file, so it goes to stderr and never into the
            // record.
            eprintln!("ctf: the offline gate could not run: {e}");
            return unverified(
                "the offline gate could not run: the authoring inputs were rejected".to_owned(),
            );
        }
    };
    // The gate derives its expected flag from the document's id and version, so a
    // document for another challenge would produce a verdict about that challenge
    // while being attached to this bundle. Refuse rather than mislabel the record.
    if setup.doc_id != id || setup.doc_version != version {
        return unverified(format!(
            "the authoring document describes `{}` version {}, not this bundle's `{id}` \
             version {version}",
            setup.doc_id, setup.doc_version
        ));
    }

    if let Err(reason) = apply_bundle_declarations(bundle, &mut setup) {
        return unverified(reason);
    }

    match run_setup_gate(&setup) {
        Ok(report) => ctf_generator::VerificationRecord::from_report(id, version, subject, &report),
        Err(e) => {
            // Same rule as above: a stage error can name a module path, so the
            // record carries the fact and the stage only, and the detail is on
            // stderr. S9 is satisfied by naming the stage, not by leaking a path.
            eprintln!("ctf: the offline gate could not complete: {e}");
            // §25.6: these are `null` only when the determinism stage did not
            // produce them. A solver-stage failure after a successful determinism
            // run keeps the root, run count, and cross-engine result.
            let determinism = e.determinism;
            ctf_generator::VerificationRecord {
                challenge: id.to_owned(),
                version,
                subject: subject.to_owned(),
                status: ctf_generator::GateStatus::Failed,
                reason: format!(
                    "the offline gate could not complete a §25.5 stage ({})",
                    e.stage
                ),
                generator_root: determinism.map(|d| d.output_root),
                cross_engine: determinism.map(|d| d.cross_engine),
                runs: determinism.map(|d| d.runs),
            }
        }
    }
}

/// Replace `setup`'s gate declarations with `bundle`'s (spec §25.6).
///
/// `Ok(())` means the bundle's declarations and sections leave the gate runnable;
/// what the run then reports — including `unverified` for `runtime` or a missing
/// `verify.offline` — is [`run_setup_gate`]'s. `Err(reason)` means the gate may not
/// even be constructed, and the sentence is fixed and path-free for the persisted
/// record (S12).
fn apply_bundle_declarations(bundle: &Bundle<'_>, setup: &mut GateSetup) -> Result<(), String> {
    // Spec §25.6 decides `unverified` from what the **bundle** declares. Reading
    // these from the verification document would let a bundle that declares
    // `runtime`, or one that never asked for the offline gate, be reported as
    // `passed` because the document the operator supplied happened to say
    // otherwise.
    setup.runtime_declared = bundle.manifest.declaration("runtime").is_some();
    setup.offline_declared = bundle
        .manifest
        .declaration("verify")
        .and_then(|verify| verify.get("offline"))
        .is_some_and(|offline| matches!(offline, Value::Bool(true)));

    // G6/G7 are about the **bundle** too, for the same reason: a version this build
    // does not implement means no stage can start, so the outcome is `unverified`
    // (S8), not `failed`. Absent means 1 (§7.6), but a present value that is not a
    // non-negative integer is not a version at all: reading it as absent would run
    // the module at 1 and could report `passed` for a version the bundle never
    // declared. The reason is fixed and path-free (S12).
    let generate = bundle.manifest.declaration("generate");
    // §23.7: the bundle's determinism declaration decides whether a gate exists.
    // Absent is not a suppression: the gate runs. A present value that is not text,
    // or text this build does not define, is likewise not absent — it is
    // unrecognised, and the gate reports `unverified` rather than running a stage it
    // cannot know is permitted (§25.6). This overrides the document's value
    // unconditionally (§25.6).
    setup.determinism = match generate.and_then(|generate| generate.get("determinism")) {
        None => ctf_generator::DeterminismDeclaration::Absent,
        Some(value) => match value
            .as_text()
            .and_then(ctf_generator::DeterminismMode::parse)
        {
            Some(mode) => ctf_generator::DeterminismDeclaration::Mode(mode),
            None => ctf_generator::DeterminismDeclaration::Unrecognized,
        },
    };
    // G8/§23.3: the declared output names are the bundle's too. An absent list
    // declares no output, so a module that names one is rejected rather than passed
    // on the document's say-so.
    setup.declared_outputs = generate
        .and_then(|generate| generate.get("outputs"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|output| output.get("name").and_then(Value::as_text))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let bundle_version = |key: &str| bundle_declared_version(generate, key);
    setup.interface = match bundle_version("interface") {
        Ok(version) => match declared_version(version, ctf_generator::abi::ensure_interface) {
            Ok(interface) => interface,
            Err(interface) => {
                return Err(format!(
                    "the bundle declares generator interface {interface}, which this build does not implement"
                ));
            }
        },
        Err(()) => {
            return Err(
                "the bundle's `generate.interface` is not an integer version, so this build \
                 cannot run its module"
                    .to_owned(),
            );
        }
    };
    setup.profile = match bundle_version("profile") {
        Ok(version) => match declared_version(version, ctf_generator::abi::ensure_profile) {
            Ok(profile) => profile,
            Err(profile) => {
                return Err(format!(
                    "the bundle declares WASM profile {profile}, which this build does not implement"
                ));
            }
        },
        Err(()) => {
            return Err(
                "the bundle's `generate.profile` is not an integer version, so this build \
                 cannot run its module"
                    .to_owned(),
            );
        }
    };

    // §25.6's "declares no generator or no solver" is a statement about the
    // manifest's `generate.wasm` and `verify.solver` declarations (§7.6), not
    // about whether `pack` emitted module sections — it never does. The document's
    // module may fill in for a declaration the bundle makes; it must not resurrect
    // one the bundle does not.
    let declared_generator = bundle
        .manifest
        .declaration("generate")
        .and_then(|generate| generate.get("wasm"))
        .and_then(Value::as_text);
    let declared_solver = bundle
        .manifest
        .declaration("verify")
        .and_then(|verify| verify.get("solver"))
        .and_then(Value::as_text);
    let declares_generator = declared_generator.is_some();
    let declares_solver = declared_solver.is_some();

    // A bundle that carries the module is stricter than one that merely declares
    // it: its own bytes are the ones §25.5 says to run, and they win over the
    // document's path — which is never even read in that case (§25.6). Only a
    // bundle that declares the module without carrying it falls back to the
    // authoring document, whose name was deferred until now. A read error is
    // `unverified` with a path-free reason (S12).
    let modules = setup.document_modules.take();
    let eager_generator = setup.generator.take();
    let eager_solver = setup.solver.take();

    setup.generator = match bundle_module(bundle, SectionKind::Generator, declared_generator) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) if declares_generator => match &modules {
            Some(modules) => modules.read(modules.generator.as_deref(), "generator")?,
            None => eager_generator,
        },
        Ok(None) => None,
        Err(e) => {
            eprintln!("ctf: the offline gate could not run: {e}");
            return Err(
                "the offline gate could not run: the bundle's generator section is unreadable"
                    .to_owned(),
            );
        }
    };
    setup.solver = match bundle_module(bundle, SectionKind::Solver, declared_solver) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) if declares_solver => match &modules {
            Some(modules) => modules.read(modules.solver.as_deref(), "solver")?,
            None => eager_solver,
        },
        Ok(None) => None,
        Err(e) => {
            eprintln!("ctf: the offline gate could not run: {e}");
            return Err(
                "the offline gate could not run: the bundle's solver section is unreadable"
                    .to_owned(),
            );
        }
    };

    Ok(())
}

/// A bundle's `generate.interface`/`generate.profile` (§7.6).
///
/// `Ok(None)` is absent, which means version 1. `Err(())` is present but not a
/// non-negative integer: no host can implement it, and treating it as absent would
/// silently run the module at a version the bundle never declared (G6/G7).
fn bundle_declared_version(generate: Option<&Value>, key: &str) -> Result<Option<u64>, ()> {
    match generate.and_then(|g| g.get(key)) {
        None => Ok(None),
        Some(value) => value.as_uint().map(Some).ok_or(()),
    }
}

/// The bytes of the module `declared` names, verified against its root.
///
/// §7.6 makes `generate.wasm`/`verify.solver` name entries of `names`, and the
/// entry's `name_id` is the section that carries the module. A section of the same
/// kind under another name is not that module, and §25.6 says a module the bundle
/// does not declare cannot be gated at all — so no declaration, or a declaration
/// with no `names` entry, yields `Ok(None)` rather than the first section of the
/// kind.
///
/// `Ok(None)` means the bundle carries no such section, which is a §25.6 condition
/// for `unverified`, not an error. `Err` means the section is present but this
/// reading cannot hand out its plaintext — sealed, external, encrypted, or of a
/// kind this build does not implement. The caller turns that into `unverified` and
/// keeps the detail on stderr (rule S12).
fn bundle_module(
    bundle: &Bundle<'_>,
    kind: SectionKind,
    declared: Option<&str>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(name) = declared else {
        return Ok(None);
    };
    let Some(name_id) = bundle
        .manifest
        .names()
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| u16::try_from(index).ok())
    else {
        return Ok(None);
    };
    let Some(record) = bundle
        .sections
        .iter()
        .find(|record| record.kind == kind && record.name_id == name_id)
    else {
        return Ok(None);
    };
    bundle
        .section_bytes(record)
        .map(|bytes| Some(bytes.into_owned()))
        .map_err(|e| format!("the bundle's {} section: {e}", kind_name(kind)))
}

/// Report the spec §29.2 read-time policy issues for `manifest` on stderr.
///
/// Diagnostic only: it changes no exit code, stdout line, or artifact. The message
/// can carry author-supplied text (an origin extracted from `description`, a flagged
/// image reference), so it is Debug-escaped and a crafted manifest cannot inject a
/// newline or a terminal escape. The key is this crate's static constant.
fn report_policy(manifest: &Manifest) {
    for issue in policy::check_manifest(manifest) {
        eprintln!("policy: {}: {:?}", issue.key(), issue.message());
    }
}

/// `ctf verify`: the ingest checks plus, when asked, the offline gate, as one
/// stable machine-readable artifact. See [`verify`] for the shape and the rules.
fn run_verify(args: &VerifyArgs) -> ExitCode {
    let path = &args.bundle;
    // Read the whole file rather than mapping it: the artifact names the bundle by a
    // digest of these exact bytes, so there must be one unambiguous buffer behind
    // both the digest and the parse.
    let file = match std::fs::read(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut artifact = Artifact::new(
        blake3::hash(&file).to_hex().to_string(),
        u64::try_from(file.len()).unwrap_or(u64::MAX),
    );

    match Bundle::parse(&file) {
        Err(e) => artifact.reject(format!("the bundle did not parse: {e}")),
        Ok(bundle) => {
            // Read-time policy pass (spec §29.2). Diagnostics only: the stable
            // artifact on stdout and the status-derived exit code are unchanged.
            report_policy(&bundle.manifest);
            artifact.commitment_root = Some(bundle.footer.root);
            artifact.signing = Some(bundle.signing());
            match bundle.verify_inline_sections() {
                Err(e) => {
                    artifact.reject(format!("the section pass could not complete: {e}"));
                }
                Ok(report) => {
                    artifact.sections = SectionCounts {
                        verified: report.verified,
                        external: report.external,
                        unverifiable: report.unverifiable,
                        chunk_indices: report.chunk_indices,
                        mismatches: report.mismatches,
                    };
                    if !artifact.sections.mismatches.is_empty() {
                        // A mismatch means the bytes are not the bytes the footer
                        // commits to. `intact` stays false and the file is rejected.
                        let count = artifact.sections.mismatches.len();
                        let in_table = artifact.sections.verified + count;
                        artifact.reject(format!(
                            "{count} of {in_table} inline section(s) do not hash to their roots"
                        ));
                    } else {
                        // Present-but-unreadable sections are disclosed in
                        // `sections.unverifiable`, not rejected: their plaintext
                        // cannot be hashed without a key, and the spec puts that in
                        // the record rather than treating it as corruption.
                        artifact.intact = true;
                        match (&args.challenge, &args.secret) {
                            (Some(challenge), Some(secret)) => {
                                let record = gate_record_for_bundle(
                                    challenge,
                                    secret,
                                    &args.subject,
                                    &bundle,
                                );
                                artifact.status = Status::from(record.status);
                                artifact.reason = match record.status {
                                    ctf_generator::GateStatus::Passed => {
                                        "the bundle is intact and the offline gate passed"
                                            .to_owned()
                                    }
                                    ctf_generator::GateStatus::Failed => format!(
                                        "the bundle is intact but the offline gate failed: {}",
                                        record.reason
                                    ),
                                    ctf_generator::GateStatus::Unverified => format!(
                                        "the bundle is intact but unverified: {}",
                                        record.reason
                                    ),
                                };
                                artifact.gate = Some(record);
                            }
                            _ => {
                                artifact.status = Status::Unverified;
                                artifact.reason = if artifact.sections.unverifiable == 0 {
                                    "the bundle is intact but no offline gate was requested; \
                                     this run established integrity only"
                                        .to_owned()
                                } else {
                                    format!(
                                        "the bundle is intact but no offline gate was requested, \
                                         and {} inline section(s) could not be read by this build",
                                        artifact.sections.unverifiable
                                    )
                                };
                            }
                        }
                    }
                }
            }
        }
    }

    let json = artifact.to_json();
    match &args.out {
        Some(out) => {
            if let Err(e) = std::fs::write(out, &json) {
                eprintln!("ctf: {out}: {e}");
                return ExitCode::FAILURE;
            }
            println!("{out}: ingest verification ({})", artifact.status.as_str());
        }
        None => print!("{json}"),
    }
    ExitCode::from(artifact.status.exit_code())
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
    // Spec §4.4: a file with an ro_compat bit this build does not implement MUST NOT
    // be rewritten. Checked before anything else because every branch below rewrites.
    if !bundle.header.may_rewrite() {
        return Err(
            "refusing to rewrite a read-only bundle: its header sets an unimplemented \
             `feat_ro_compat` bit, and an automatic rewrite of such a file is forbidden \
             by spec §4.4"
                .into(),
        );
    }
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
                chunk_index: external_chunk_index(&file, r)?,
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

/// An EXTERNAL section's chunk index exactly as the file stores it, for a rewrite to
/// copy.
///
/// Spec §5.2 requires a rewrite to preserve an unknown-kind section byte-for-byte,
/// and the index is part of what the author wrote. This deliberately does not use
/// [`Bundle::chunk_index`]: that refuses an unknown kind or a sealed section (C8),
/// which governs handing an index to a caller, not copying the record's bytes. The
/// writer validates whatever is copied against the section root, so a bad index
/// still fails rather than being emitted.
fn external_chunk_index<'a>(
    file: &'a [u8],
    record: &SectionRecord,
) -> ctf_format::Result<Option<&'a [u8]>> {
    let Some((start, end)) = record.index_range()? else {
        return Ok(None);
    };
    let (Ok(from), Ok(to)) = (usize::try_from(start), usize::try_from(end)) else {
        return Err(ctf_format::Error::LengthOverflow { at: "chunk index" });
    };
    file.get(from..to)
        .map(Some)
        .ok_or(ctf_format::Error::ExceedsFile {
            at: "chunk index",
            end,
            file_len: u64::try_from(file.len()).unwrap_or(u64::MAX),
        })
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

    // Spec §4.4: rewriting a file whose header carries an ro_compat bit this build
    // does not implement is forbidden, automatically. This comes before the
    // already-signed check because it applies to unsigned files too.
    if !b.header.may_rewrite() {
        return Err(
            "refusing to rewrite a read-only bundle: its header sets an unimplemented \
             `feat_ro_compat` bit, and an automatic rewrite of such a file is forbidden \
             by spec §4.4"
                .into(),
        );
    }

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
                chunk_index: external_chunk_index(&file, r)?,
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

    // Read-time policy pass (spec §29.2). It is not a parse failure: a tagged
    // `runtime.image` is a readable bundle that the platform will refuse to boot,
    // so the exit code stays 0 and no line above changes. The key and message can
    // carry author-supplied text (an origin extracted from `description`), so both
    // are Debug-escaped like the manifest and mirror lines above.
    let issues = policy::check_manifest(&b.manifest);
    if !issues.is_empty() {
        println!();
        println!("policy        {} issue(s)", issues.len());
        for issue in &issues {
            println!("              {:?}: {:?}", issue.key(), issue.message());
        }
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

/// Escape the characters that can act on the operator's terminal (spec §13).
///
/// `name`, `category`, `description`, and mirror URLs are free-form text, and a
/// diagnostic that echoes one is still a terminal write. C0/C1 controls, DEL,
/// and the bidi-format marks `check_name` does not reject (LRM, RLM, ALM) can
/// move, hide, or execute text around the output, so each becomes its visible
/// `escape_default` form. Everything else is copied unchanged.
fn escape_terminal(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(
                c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
        {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

/// Truncate to `n` characters for a fixed-width column, escaping control
/// characters first (spec §13).
///
/// A manifest `name` may contain C1 controls such as U+0085 — `check_name` rejects
/// C0 and DEL, but not every Unicode control — and a table cell is still a terminal
/// write. Escaping before truncating makes the injected text visible instead of
/// letting it act on the operator's terminal; escaping after would count the escape
/// sequence against the column budget.
fn truncate(s: &str, n: usize) -> String {
    let escaped = escape_terminal(s);
    if escaped.chars().count() <= n {
        return escaped;
    }
    escaped
        .chars()
        .take(n.saturating_sub(1))
        .collect::<String>()
        + "…"
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
