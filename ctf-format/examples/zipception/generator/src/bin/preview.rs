//! Render the archive a player would receive for one seed.
//!
//! This is a development convenience: the deployment path runs the same code as a
//! WebAssembly module inside the gate. It takes a 32-byte seed as hex and writes
//! the archive, so the reference solver can be pointed at a real file.
//!
//! ```text
//! cargo run --bin preview -- <64 hex digits> inception.zip
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(seed_hex), Some(output)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: preview <seed-hex> <out.zip>");
        return ExitCode::from(2);
    };

    let Some(seed) = hex_decode(seed_hex) else {
        eprintln!("preview: the seed must be an even number of hex digits");
        return ExitCode::from(2);
    };
    let (flag, archive) = match zipception_generator::build(&seed) {
        Ok(built) => built,
        Err(message) => {
            eprintln!("preview: {message}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::write(output, &archive) {
        eprintln!("preview: {output}: {error}");
        return ExitCode::FAILURE;
    }
    println!("flag: {flag}");
    println!("archive: {output} ({} bytes)", archive.len());
    ExitCode::SUCCESS
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_digit(pair.first().copied()?)?;
        let low = hex_digit(pair.get(1).copied()?)?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
