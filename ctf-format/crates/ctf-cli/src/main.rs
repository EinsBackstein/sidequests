//! `ctf` — the command-line tool for `.ctf` bundles.
//!
//! Subcommands: `inspect`, `validate`, `pack`, `keygen`, `sign`. The rest of
//! design §10's table arrives with the phases that give it something to do —
//! `run` needs phase 4's gate, `seal`/`unseal`/`transfer` need the entitlement
//! chain and seal-release management.
//!
//! # What `inspect` will not print
//!
//! Bytes from a sealed section, in any mode. `--hex` dumps the fixed structures —
//! header, section table, footer — and the manifest, which R7 already requires to be
//! neither sealed nor player-visible. A hexdump tool that would happily dump a
//! sealed writeup on request is a decryption oracle with a friendly interface.

use std::process::ExitCode;

use ctf_format::authoring::ChallengeDoc;
use ctf_format::pack::{self, PackError};
use ctf_format::{
    Bundle, HEADER_LEN, HybridPublicKey, HybridSigningKey, SECTION_RECORD_LEN, SectionFlags,
    SectionKind, Signing,
};

const USAGE: &str = "\
usage: ctf inspect [--hex] [--verify] [--allow-unsigned] <file.ctf>
       ctf validate <challenge.yaml>
       ctf pack <challenge.yaml> --out <file.ctf> [--suite <id>]
       ctf keygen --out-key <signing.key> --out-pub <public.key> [--suite <id>]
       ctf sign <bundle.ctf> --key <signing.key> --pub <public.key> --out <signed.ctf>

  inspect  parse a bundle and print its structures
    --hex     annotated hexdump of the header, section table, and footer
    --verify  re-hash every inline section against its root (reads the whole file).
              Exits non-zero if any section's bytes are present but unreadable by
              this build. External payloads are reported, not counted as failures:
              their bytes are elsewhere by design.
    --allow-unsigned  accept a bundle that carries no signatures. Without it, a
              `--verify` run on an unsigned bundle reports it intact but not
              authentic and exits 2.
  validate  schema- and policy-check an authoring file, naming every offending key.
              Exits non-zero if the document is invalid.
  pack      compile a validated authoring file into an unsigned .ctf bundle.
    --out <file.ctf>  where to write the bundle (required)
    --suite <id>      crypto suite id (default 1)
  keygen    generate a hybrid signing keypair.
    --out-key <file>  where to write the signing key (required)
    --out-pub <file>  where to write the public key (required)
    --suite <id>      crypto suite id (default 1)
  sign      sign an unsigned .ctf bundle.
    --key <file>      signing key file (required)
    --pub <file>      public key file (required)
    --out <file.ctf>  where to write the signed bundle (required)

Key files are a local convenience, not a container format: two lines of lowercase
hex, the classical component first and the post-quantum component second.
Whitespace and blank lines are ignored.

exit codes:
  0  success
  1  usage, parse, or validation failure
  2  inspect --verify found an intact but unauthentic (unsigned) bundle
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    match cmd.as_str() {
        "inspect" => run_inspect(rest),
        "validate" => run_validate(rest),
        "pack" => run_pack(rest),
        "keygen" => run_keygen(rest),
        "sign" => run_sign(rest),
        other => {
            eprintln!("ctf: unknown command `{other}`");
            eprint!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run_inspect(args: &[String]) -> ExitCode {
    let mut hex = false;
    let mut verify = false;
    let mut allow_unsigned = false;
    let mut path: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--hex" => hex = true,
            "--verify" => verify = true,
            "--allow-unsigned" => allow_unsigned = true,
            other if other.starts_with('-') => {
                eprintln!("ctf: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            // Not `path = Some(...)` unconditionally: that silently inspected the
            // last of several paths, so `ctf inspect a.ctf b.ctf` reported on
            // `b.ctf` while the operator read the output as being about `a.ctf`.
            _ if path.is_some() => {
                eprintln!("ctf: inspect takes one file; got `{a}` as well");
                return ExitCode::FAILURE;
            }
            other => path = Some(other.to_owned()),
        }
    }
    let Some(path) = path else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    match inspect(&path, hex, verify, allow_unsigned) {
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
fn run_validate(args: &[String]) -> ExitCode {
    let mut path: Option<String> = None;
    for a in args {
        if a.starts_with('-') {
            eprintln!("ctf: unknown option `{a}`");
            return ExitCode::FAILURE;
        }
        if path.is_some() {
            eprintln!("ctf: validate takes one file; got `{a}` as well");
            return ExitCode::FAILURE;
        }
        path = Some(a.clone());
    }
    let Some(path) = path else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let text = match std::fs::read_to_string(&path) {
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
    if issues.is_empty() {
        println!("{path}: ok");
        return ExitCode::SUCCESS;
    }
    for issue in &issues {
        eprintln!("ctf: {path}: {issue}");
    }
    eprintln!("ctf: {path}: {} problem(s) found", issues.len());
    ExitCode::FAILURE
}

/// `ctf pack`: compile an authoring file into an unsigned bundle.
///
/// Validation happens inside [`pack_with_suite`] — the same schema and policy
/// checks `ctf validate` runs — so an invalid document is refused here with the key
/// named, before a byte is written.
fn run_pack(args: &[String]) -> ExitCode {
    let mut path: Option<String> = None;
    let mut out: Option<String> = None;
    let mut suite = pack::DEFAULT_SUITE_ID;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => match it.next() {
                Some(v) => out = Some(v.clone()),
                None => {
                    eprintln!("ctf: --out needs a file");
                    return ExitCode::FAILURE;
                }
            },
            "--suite" => {
                let Some(v) = it.next() else {
                    eprintln!("ctf: --suite needs an id");
                    return ExitCode::FAILURE;
                };
                match v.parse::<u16>() {
                    Ok(n) => suite = n,
                    Err(_) => {
                        eprintln!("ctf: --suite must be a number; got `{v}`");
                        return ExitCode::FAILURE;
                    }
                }
            }
            other if other.starts_with('-') => {
                eprintln!("ctf: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            other if path.is_some() => {
                eprintln!("ctf: pack takes one file; got `{other}` as well");
                return ExitCode::FAILURE;
            }
            other => path = Some(other.to_owned()),
        }
    }
    let (Some(path), Some(out)) = (path, out) else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let text = match std::fs::read_to_string(&path) {
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
    let file = match pack::pack_with_suite(&doc, suite) {
        Ok(f) => f,
        Err(PackError::Invalid(issues)) => {
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
    if let Err(e) = std::fs::write(&out, &file) {
        eprintln!("ctf: {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "{out}: {} bytes, manifest {}, suite {suite} (unsigned)",
        file.len(),
        doc.id
    );
    ExitCode::SUCCESS
}

/// `ctf keygen`: write a fresh hybrid keypair as two hex key files.
fn run_keygen(args: &[String]) -> ExitCode {
    let mut key_path: Option<String> = None;
    let mut pub_path: Option<String> = None;
    let mut suite = pack::DEFAULT_SUITE_ID;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out-key" => match it.next() {
                Some(v) => key_path = Some(v.clone()),
                None => {
                    eprintln!("ctf: --out-key needs a file");
                    return ExitCode::FAILURE;
                }
            },
            "--out-pub" => match it.next() {
                Some(v) => pub_path = Some(v.clone()),
                None => {
                    eprintln!("ctf: --out-pub needs a file");
                    return ExitCode::FAILURE;
                }
            },
            "--suite" => {
                let Some(v) = it.next() else {
                    eprintln!("ctf: --suite needs an id");
                    return ExitCode::FAILURE;
                };
                match v.parse::<u16>() {
                    Ok(n) => suite = n,
                    Err(_) => {
                        eprintln!("ctf: --suite must be a number; got `{v}`");
                        return ExitCode::FAILURE;
                    }
                }
            }
            other if other.starts_with('-') => {
                eprintln!("ctf: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            other => {
                eprintln!("ctf: keygen takes no positional arguments; got `{other}`");
                return ExitCode::FAILURE;
            }
        }
    }
    let (Some(key_path), Some(pub_path)) = (key_path, pub_path) else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let (signing_key, public_key) = match keypair(suite) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ctf: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_key_file(
        &key_path,
        &hex_encode(&signing_key.classical),
        &hex_encode(&signing_key.pq),
    ) {
        eprintln!("ctf: {key_path}: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_key_file(
        &pub_path,
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

/// `ctf sign`: append both hybrid signatures to an unsigned bundle.
fn run_sign(args: &[String]) -> ExitCode {
    let mut bundle: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut pub_path: Option<String> = None;
    let mut out: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key" => match it.next() {
                Some(v) => key_path = Some(v.clone()),
                None => {
                    eprintln!("ctf: --key needs a file");
                    return ExitCode::FAILURE;
                }
            },
            "--pub" => match it.next() {
                Some(v) => pub_path = Some(v.clone()),
                None => {
                    eprintln!("ctf: --pub needs a file");
                    return ExitCode::FAILURE;
                }
            },
            "--out" => match it.next() {
                Some(v) => out = Some(v.clone()),
                None => {
                    eprintln!("ctf: --out needs a file");
                    return ExitCode::FAILURE;
                }
            },
            other if other.starts_with('-') => {
                eprintln!("ctf: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            other if bundle.is_some() => {
                eprintln!("ctf: sign takes one file; got `{other}` as well");
                return ExitCode::FAILURE;
            }
            other => bundle = Some(other.to_owned()),
        }
    }
    let (Some(bundle), Some(key_path), Some(pub_path), Some(out)) =
        (bundle, key_path, pub_path, out)
    else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let file = match std::fs::read(&bundle) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ctf: {bundle}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signing_key = match read_key_file(&key_path) {
        Ok((classical, pq)) => HybridSigningKey { classical, pq },
        Err(e) => {
            eprintln!("ctf: {key_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let public_key = match read_key_file(&pub_path) {
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
    if let Err(e) = std::fs::write(&out, &signed) {
        eprintln!("ctf: {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!("{out}: {} bytes, signed", signed.len());
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

fn inspect(
    path: &str,
    hex: bool,
    verify: bool,
    allow_unsigned: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let file = std::fs::read(path)?;
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
