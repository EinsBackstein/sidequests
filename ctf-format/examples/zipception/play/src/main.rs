//! Render the player artifact for one subject straight out of the `.ctf` bundle.
//!
//! This is the deployment path in miniature. The platform derives the subject's
//! seed (spec §22.2), runs the bundle's own `generator` section (spec §23), and
//! serves the outputs the manifest marks `player_visible` (§7.6). Nothing is read
//! from the authoring directory: the module is the section's plaintext, which is
//! what makes `zipception.ctf` deployable on its own.
//!
//! ```text
//! play zipception.ctf --secret <64 hex> --subject alice --out alice.zip
//! ```
//!
//! The flag is printed for the operator (it is the answer the gate compares);
//! a real deployment keeps it in the database and never writes it to a log.

use std::process::ExitCode;

use ctf_format::cbor::Value;
use ctf_format::{derive, Bundle, SectionKind};
use ctf_generator::{Generator, Limits};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("play: {message}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    bundle: String,
    secret: String,
    subject: String,
    out: Option<String>,
}

fn usage() -> &'static str {
    "usage: play <bundle.ctf> --secret <64 hex> [--subject <id>] [--out <file>]"
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let secret = hex_decode(&args.secret)?;

    let file = std::fs::read(&args.bundle).map_err(|e| format!("{}: {e}", args.bundle))?;
    let bundle = Bundle::parse(&file).map_err(|e| format!("{}: {e}", args.bundle))?;

    let generate = bundle
        .manifest
        .declaration("generate")
        .ok_or("the bundle declares no `generate`, so there is nothing to run")?;
    let wasm = generate
        .get("wasm")
        .and_then(Value::as_text)
        .ok_or("the bundle's `generate` declaration has no `wasm`")?;
    let name_id = bundle
        .manifest
        .names()
        .iter()
        .position(|name| *name == wasm)
        .ok_or_else(|| format!("`{wasm}` is not an entry of the manifest name table"))?;
    let name_id = u16::try_from(name_id).map_err(|_| "the name table is too large".to_owned())?;
    let record = bundle.section(name_id).ok_or_else(|| {
        format!(
            "the bundle declares `{wasm}` but does not carry it; deploy it with the challenge \
             image instead (spec §31 B1)"
        )
    })?;
    if record.kind != SectionKind::Generator {
        return Err(format!(
            "the section named `{wasm}` is {:?}, not a generator",
            record.kind
        ));
    }
    let module = bundle
        .section_bytes(record)
        .map_err(|e| format!("`{wasm}`: {e}"))?;

    // The per-subject seed and the flag it implies (spec §22.2, §22.3). The
    // generator is expected to return the same flag; a disagreement means the
    // module is not the one this bundle was validated with.
    let seed = derive::subject_seed(
        &secret,
        bundle.manifest.id(),
        bundle.manifest.version(),
        &args.subject,
    )
    .map_err(|e| format!("the subject seed could not be derived: {e}"))?;
    let flag = derive::flag(&seed);

    let generator =
        Generator::new(&module).map_err(|e| format!("the bundle's generator was rejected: {e}"))?;
    let produced = generator
        .run(&seed, &Limits::default())
        .map_err(|e| format!("the generator failed: {e}"))?;
    if produced.flag != flag {
        return Err(format!(
            "the generator returned `{}` but the derived flag is `{flag}`",
            produced.flag
        ));
    }

    let visible = player_visible(generate)?;
    if visible.len() != 1 {
        return Err(format!(
            "expected one player-visible output, the manifest declares {}",
            visible.len()
        ));
    }
    let name = visible[0];
    let artifact = produced
        .outputs
        .iter()
        .find(|output| output.name == name)
        .ok_or_else(|| format!("the generator did not emit the declared output `{name}`"))?;
    let out = args.out.unwrap_or_else(|| name.to_owned());
    std::fs::write(&out, &artifact.bytes).map_err(|e| format!("{out}: {e}"))?;

    println!("bundle: {}", args.bundle);
    println!("subject: {}", args.subject);
    println!("output: {out} ({} bytes)", artifact.bytes.len());
    println!("flag: {flag}");
    Ok(())
}

fn player_visible(generate: &Value) -> Result<Vec<&str>, String> {
    let outputs = generate
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or("the bundle's `generate` declaration has no `outputs`")?;
    Ok(outputs
        .iter()
        .filter(|output| matches!(output.get("player_visible"), Some(Value::Bool(true))))
        .filter_map(|output| output.get("name").and_then(Value::as_text))
        .collect())
}

fn parse_args() -> Result<Args, String> {
    let mut positional = Vec::new();
    let mut secret = None;
    let mut subject = None;
    let mut out = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--secret" => {
                secret = Some(
                    arguments
                        .next()
                        .ok_or_else(|| format!("--secret needs a value\n{}", usage()))?,
                );
            }
            "--subject" => {
                subject = Some(
                    arguments
                        .next()
                        .ok_or_else(|| format!("--subject needs a value\n{}", usage()))?,
                );
            }
            "--out" => {
                out = Some(
                    arguments
                        .next()
                        .ok_or_else(|| format!("--out needs a value\n{}", usage()))?,
                );
            }
            "-h" | "--help" => return Err(usage().to_owned()),
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`\n{}", usage()));
            }
            other => positional.push(other.to_owned()),
        }
    }
    let mut positional = positional.into_iter();
    let bundle = positional
        .next()
        .ok_or_else(|| format!("missing the bundle path\n{}", usage()))?;
    if positional.next().is_some() {
        return Err(format!("too many arguments\n{}", usage()));
    }
    Ok(Args {
        bundle,
        secret: secret.ok_or_else(|| format!("missing --secret\n{}", usage()))?,
        subject: subject.unwrap_or_else(|| "reference".to_owned()),
        out,
    })
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("the event secret must be an even number of hex digits".to_owned());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    if out.is_empty() {
        return Err("the event secret is empty".to_owned());
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("the event secret must be hex digits".to_owned()),
    }
}
