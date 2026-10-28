//! Zipception's gate solver: unwrap a nested archive entirely in memory.
//!
//! Spec §25.1 gives a solver no clock, network, filesystem, or randomness; its
//! whole world is the artifact block of §25.3. That is exactly enough for this
//! challenge, because the intended solve never touches a filesystem path: read
//! each archive, take its one file entry, feed the bytes back in, and stop when the
//! bytes are no longer a ZIP. The upstream writeup calls this "stream through
//! memory".
//!
//! The entries are stored (method 0), so no decompressor is needed. A module that
//! cannot read an entry returns a failure rather than a guess, which makes the gate
//! fail instead of passing a solver that did not solve anything.

use std::sync::Mutex;

/// Safety ceiling, well above the 150 layers the generator builds.
const MAX_DEPTH: usize = 10_000;

/// The last output block (`u32_le flag_len ‖ flag`, spec §25.4).
static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Hand the host a buffer to write the artifact block into.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_alloc(len: u32) -> *mut u8 {
    let mut buffer = vec![0u8; len as usize];
    let pointer = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    pointer
}

/// Recover the flag from the artifact block and return the output block's pointer.
///
/// The arguments are `u32` rather than `*const u8`, exactly as §25.2 writes the
/// ABI: on `wasm32` a pointer is a `u32`, and taking the integer makes the
/// "the host guarantees this address" contract explicit at the boundary.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_solve(input_ptr: u32, input_len: u32) -> u32 {
    if input_ptr == 0 {
        return 0;
    }
    // SAFETY: the host wrote `input_len` bytes at `input_ptr` after a successful
    // `ctf_alloc` for exactly that length, and every read below is bounds-checked
    // against this slice.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };

    let Some(archive) = first_artifact(input) else {
        return 0;
    };
    let Some(flag) = unwrap_nested(archive) else {
        return 0;
    };

    let mut block = Vec::with_capacity(4 + flag.len());
    block.extend_from_slice(&(flag.len() as u32).to_le_bytes());
    block.extend_from_slice(&flag);

    let Ok(mut output) = OUTPUT.lock() else {
        return 0;
    };
    *output = block;
    // The block lives in the static, so the pointer stays valid after the guard
    // drops; nothing writes it again until the next `ctf_solve`.
    output.as_ptr() as u32
}

/// Byte length of the block the last `ctf_solve` produced.
#[unsafe(no_mangle)]
pub extern "C" fn ctf_output_len() -> u32 {
    match OUTPUT.lock() {
        Ok(output) => output.len() as u32,
        Err(_) => 0,
    }
}

/// The first artifact in the block of §25.3, preferring a `.zip` name.
///
/// `u32_le count`, then `count × { u32_le name_len; name; u32_le data_len; data }`.
fn first_artifact(input: &[u8]) -> Option<&[u8]> {
    let count = u32_at(input, 0)?;
    let mut offset = 4usize;
    let mut fallback: Option<&[u8]> = None;
    for _ in 0..count {
        let name_len = u32_at(input, offset)? as usize;
        offset = offset.checked_add(4)?;
        let name = input.get(offset..offset.checked_add(name_len)?)?;
        offset = offset.checked_add(name_len)?;
        let data_len = u32_at(input, offset)? as usize;
        offset = offset.checked_add(4)?;
        let data = input.get(offset..offset.checked_add(data_len)?)?;
        offset = offset.checked_add(data_len)?;

        if name.to_ascii_lowercase().ends_with(b".zip") {
            return Some(data);
        }
        if fallback.is_none() {
            fallback = Some(data);
        }
    }
    fallback
}

/// Follow one-entry archives until the payload is no longer one.
fn unwrap_nested(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut depth = 0usize;
    while let Some(inner) = first_entry(data) {
        data = inner;
        depth += 1;
        if depth > MAX_DEPTH {
            return None;
        }
    }
    if depth == 0 {
        return None;
    }
    Some(data.to_vec())
}

/// The stored bytes of a ZIP archive's single file entry.
fn first_entry(data: &[u8]) -> Option<&[u8]> {
    let eocd = find_eocd(data)?;
    let entries = u16_at(data, eocd.checked_add(10)?)?;
    if entries == 0 {
        return None;
    }
    let central = u32_at(data, eocd.checked_add(16)?)? as usize;
    if u32_at(data, central)? != 0x0201_4b50 {
        return None;
    }
    let method = u16_at(data, central.checked_add(10)?)?;
    if method != 0 {
        // A compressed entry would need a DEFLATE decoder; declining is honest.
        return None;
    }
    let compressed_size = u32_at(data, central.checked_add(20)?)? as usize;
    let local = u32_at(data, central.checked_add(42)?)? as usize;
    if u32_at(data, local)? != 0x0403_4b50 {
        return None;
    }
    let name_len = u16_at(data, local.checked_add(26)?)? as usize;
    let extra_len = u16_at(data, local.checked_add(28)?)? as usize;
    let start = local
        .checked_add(30)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    let end = start.checked_add(compressed_size)?;
    data.get(start..end)
}

/// Offset of the end-of-central-directory record, verifying the comment length so
/// an accidental `PK\x05\x06` inside stored data cannot be mistaken for it.
fn find_eocd(data: &[u8]) -> Option<usize> {
    const EOCD_LEN: usize = 22;
    const MAX_COMMENT: usize = 65_535;
    if data.len() < EOCD_LEN {
        return None;
    }
    let last = data.len() - EOCD_LEN;
    let earliest = last.saturating_sub(MAX_COMMENT);
    (earliest..=last).rev().find(|&offset| {
        u32_at(data, offset) == Some(0x0605_4b50)
            && u16_at(data, offset + 20)
                .and_then(|comment| offset.checked_add(EOCD_LEN)?.checked_add(comment as usize))
                == Some(data.len())
    })
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *bytes.first()?,
        *bytes.get(1)?,
        *bytes.get(2)?,
        *bytes.get(3)?,
    ]))
}
