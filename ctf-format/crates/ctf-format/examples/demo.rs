//! Writes a demo `.ctf` for trying the CLI against: `cargo run --example demo -- out.ctf`
//!
//! Covers the three archetypes phase 1 supports — a manifest, an inline chunked
//! artifact, and a 40 GB external payload described by hash and mirror alone.
#![allow(clippy::unwrap_used)]

use ctf_format::{
    Compression, Manifest, Payload, SectionFlags, SectionKind, SectionSpec, cbor::Value,
    write_bundle,
};

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "demo.ctf".into());

    let manifest = Manifest::decode(
        &Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(1)),
            (
                Value::Text("id".into()),
                Value::Text("workstation-triage".into()),
            ),
            (
                Value::Text("name".into()),
                Value::Text("Workstation Triage".into()),
            ),
            (
                Value::Text("category".into()),
                Value::Text("forensics".into()),
            ),
            (Value::Text("version".into()), Value::Uint(3)),
            (
                Value::Text("description".into()),
                Value::Text("Find what the intruder exfiltrated.".into()),
            ),
            (
                Value::Text("names".into()),
                Value::Array(vec![
                    Value::Text("manifest".into()),
                    Value::Text("notes.md".into()),
                    Value::Text("workstation.E01".into()),
                ]),
            ),
            (
                Value::Text("external".into()),
                Value::Map(vec![(
                    Value::Uint(2),
                    Value::Map(vec![
                        (Value::Text("size".into()), Value::Uint(41_231_986_688)),
                        (Value::Text("root".into()), Value::Bytes(vec![0x33; 32])),
                        (
                            Value::Text("mirrors".into()),
                            Value::Array(vec![Value::Text(
                                "https://mirror.example/workstation.E01".into(),
                            )]),
                        ),
                    ]),
                )]),
            ),
        ])
        .encode()
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();

    let notes = b"# Triage notes\n\nStart with the browser history.\n".repeat(200);
    let file = write_bundle(
        1,
        &[
            SectionSpec::inline(SectionKind::Manifest, 0, SectionFlags::empty(), &manifest),
            SectionSpec::inline(
                SectionKind::Artifact,
                1,
                SectionFlags(SectionFlags::PLAYER_VISIBLE),
                &notes,
            )
            .chunked(4096),
            SectionSpec {
                kind: SectionKind::Artifact,
                name_id: 2,
                flags: SectionFlags(SectionFlags::EXTERNAL | SectionFlags::PLAYER_VISIBLE),
                chunk_size: 0,
                comp: Compression::None,
                payload: Payload::External {
                    len_plain: 41_231_986_688,
                    root: [0x33; 32],
                },
                chunk_index: None,
                encryption: None,
            },
        ],
    )
    .unwrap();

    std::fs::write(&out, &file).unwrap();
    println!("wrote {out} ({} bytes)", file.len());
}
