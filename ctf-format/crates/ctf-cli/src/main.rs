//! `ctf` — the command-line tool for `.ctf` bundles.
//!
//! One subcommand so far: `inspect`. The rest of design §10's table arrives with
//! the phases that give it something to do — `pack` needs the authoring surface,
//! `seal` needs phase 2's crypto, `run` needs phase 4's gate.
//!
//! # What `inspect` will not print
//!
//! Bytes from a sealed section, in any mode. `--hex` dumps the fixed structures —
//! header, section table, footer — and the manifest, which R7 already requires to be
//! neither sealed nor player-visible. A hexdump tool that would happily dump a
//! sealed writeup on request is a decryption oracle with a friendly interface.

use std::process::ExitCode;

use ctf_format::{Bundle, HEADER_LEN, SECTION_RECORD_LEN, SectionFlags, SectionKind, Signing};

const USAGE: &str = "\
usage: ctf inspect [--hex] [--verify] <file.ctf>

  --hex     annotated hexdump of the header, section table, and footer
  --verify  re-hash every inline section against its root (reads the whole file)
";

fn main() -> ExitCode {
    let mut hex = false;
    let mut verify = false;
    let mut path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if cmd != "inspect" {
        eprintln!("ctf: unknown command `{cmd}`");
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    }
    for a in args {
        match a.as_str() {
            "--hex" => hex = true,
            "--verify" => verify = true,
            other if other.starts_with('-') => {
                eprintln!("ctf: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            other => path = Some(other.to_owned()),
        }
    }
    let Some(path) = path else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    match inspect(&path, hex, verify) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ctf: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(path: &str, hex: bool, verify: bool) -> Result<(), Box<dyn std::error::Error>> {
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
                "{} + {} bytes, NOT VERIFIED (phase 2)",
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
    if let Some(c) = b.manifest.category() {
        println!("              category {c}");
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
        if let Some(ext) = b.manifest.external(r.name_id) {
            for m in &ext.mirrors {
                println!("      mirror  {m}");
            }
        }
        if r.chunk_size != 0 {
            println!(
                "      chunks  {} × {} bytes, index at {}",
                b.chunk_index(r)?.map_or(0, |i| i.entries().len()),
                r.chunk_size,
                r.chunk_index_off
            );
        }
    }

    if verify {
        println!();
        let n = b.verify_inline_sections()?;
        println!("verified      {n} inline section(s) against their roots");
        println!("              external payloads are not here; stream them separately");
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
                b.section_bytes(r)?,
            );
        }
    }
    Ok(())
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
