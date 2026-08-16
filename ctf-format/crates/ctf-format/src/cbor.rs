//! Canonical CBOR: the manifest's encoding.
//!
//! Normative: `spec/SPEC.md` §7. This is RFC 8949 §4.2.1 *core deterministic
//! encoding*, restricted further to the subset the manifest needs, and — this is
//! the part a general-purpose CBOR library does not give you — **enforced on
//! decode as well as on encode**.
//!
//! # Why decode has to check
//!
//! The commitment in design pillar 3 is byte-exact: a section's `root` covers the
//! manifest's plaintext bytes, not its meaning. If two encodings of the same map
//! were both accepted, two writers could produce different roots for the same
//! challenge, and a rewriter that re-emitted a manifest would change the bundle's
//! identity without changing anything an author wrote. Accepting only one encoding
//! per value makes "same manifest" and "same bytes" the same statement, which is
//! what lets [`Value`] round-trip byte-for-byte and what makes the fuzz oracle
//! (design §14) meaningful.
//!
//! It also closes a parser differential. Duplicate map keys are the classic case:
//! last-wins and first-wins are both defensible, so two conforming readers can
//! disagree about the manifest of a file both accepted. Here they cannot occur —
//! keys must be strictly increasing in encoded-byte order, so a duplicate is a
//! decode error rather than a policy question.
//!
//! # The subset
//!
//! Major types 0 (unsigned), 1 (negative), 2 (byte string), 3 (text string),
//! 4 (array), 5 (map), and exactly three simple values: `false`, `true`, `null`.
//!
//! Rejected outright: indefinite lengths, tags, floats, `undefined`, every other
//! simple value, and the reserved additional-information values 28–30.
//!
//! Floats are excluded deliberately rather than for want of a use: deterministic
//! float encoding is a known footgun (NaN payloads, the shortest-form rule across
//! three widths), and nothing in a challenge manifest is a real number. A future
//! manifest key that needs one needs a new major version, not a looser decoder.
//!
//! The subset is wide enough to hold a value this build has never seen, which is
//! what the manifest's `crit` mechanism (spec §7.3) requires: an unknown key that
//! is not critical must be *carried*, and carrying it means decoding, holding, and
//! re-encoding its value byte-for-byte without understanding it.

use crate::{Error, Result};

/// Maximum nesting depth. Unbounded recursion over attacker-controlled nesting is
/// a stack-overflow DoS (design §14); this is the cap that stops it.
///
/// The deepest structure the manifest schema defines nests four levels
/// (`external` → entry map → `mirrors` → text), so 16 is generous for growth while
/// staying far below anything that could exhaust a stack.
pub const MAX_DEPTH: u32 = 16;

/// A CBOR value in the manifest subset.
///
/// `Nint(n)` encodes the negative integer `-1 - n`, which is CBOR major type 1's
/// own representation. Keeping it in the encoded form rather than converting to
/// `i64` is lossless for the whole range — `-1 - u64::MAX` does not fit in `i64` —
/// and a value this build only carries must survive exactly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    Uint(u64),
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in canonical key order: keys strictly increasing by encoded bytes.
    /// [`Value::encode`] establishes the order and [`Value::decode`] enforces it,
    /// so a `Map` that has been through either is canonical.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// Decode one canonical CBOR value from exactly `b`.
    ///
    /// Trailing bytes are an error: a manifest section's bytes are entirely the
    /// manifest, and anything after the value would sit inside the commitment
    /// while belonging to no structure.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder { b, pos: 0 };
        let v = d.value(0)?;
        if d.pos != b.len() {
            return Err(Error::CborTrailing {
                at: d.pos,
                len: b.len(),
            });
        }
        Ok(v)
    }

    /// Encode canonically. Round-trips [`Value::decode`] byte-for-byte.
    ///
    /// Map entries are sorted here rather than assumed sorted, so a caller that
    /// builds a manifest in whatever order reads naturally still gets canonical
    /// bytes. Duplicate keys are an error, not a silent last-wins.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out, 0)?;
        Ok(out)
    }

    /// Look up a key in a map. `None` for a non-map or an absent key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(k, _)| matches!(k, Self::Text(t) if t == key))
            .map(|(_, v)| v)
    }

    /// The value as a `u64`, or `None` if it is not an unsigned integer.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            _ => None,
        }
    }

    /// The value as text, or `None` if it is not a text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The value as a byte string, or `None` if it is not one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v),
            _ => None,
        }
    }

    /// The value as an array, or `None` if it is not one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }

    /// The entries of a map, or `None` if it is not one.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(v) => Some(v),
            _ => None,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>, depth: u32) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::CborTooDeep { max: MAX_DEPTH });
        }
        match self {
            Self::Uint(n) => put_head(out, 0, *n),
            Self::Nint(n) => put_head(out, 1, *n),
            Self::Bytes(v) => {
                put_head(out, 2, v.len() as u64);
                out.extend_from_slice(v);
            }
            Self::Text(t) => {
                put_head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Self::Array(items) => {
                put_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out, depth + 1)?;
                }
            }
            Self::Map(entries) => {
                // Sort by encoded key bytes — RFC 8949 §4.2.1's ordering, which is
                // bytewise lexicographic over the encoded key, not over its value.
                let mut encoded: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    let mut kb = Vec::new();
                    k.encode_into(&mut kb, depth + 1)?;
                    encoded.push((kb, v));
                }
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                if encoded.windows(2).any(|w| match (w.first(), w.get(1)) {
                    (Some(a), Some(b)) => a.0 == b.0,
                    _ => false,
                }) {
                    return Err(Error::CborDuplicateKey);
                }
                put_head(out, 5, entries.len() as u64);
                for (kb, v) in encoded {
                    out.extend_from_slice(&kb);
                    v.encode_into(out, depth + 1)?;
                }
            }
            Self::Bool(false) => out.push(0xf4),
            Self::Bool(true) => out.push(0xf5),
            Self::Null => out.push(0xf6),
        }
        Ok(())
    }
}

/// Write a CBOR head: major type in the top 3 bits, shortest-form argument.
fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.pos).ok_or(Error::CborTruncated)?;
        self.pos += 1;
        Ok(v)
    }

    fn take(&mut self, n: u64) -> Result<&[u8]> {
        let n = usize::try_from(n).map_err(|_| Error::CborTruncated)?;
        let end = self.pos.checked_add(n).ok_or(Error::CborTruncated)?;
        let s = self.b.get(self.pos..end).ok_or(Error::CborTruncated)?;
        self.pos = end;
        Ok(s)
    }

    /// Read a head, returning `(major, argument)`.
    ///
    /// Rejects every non-shortest encoding of the argument. This is what makes the
    /// encoding injective: without it `1` has five spellings and a rewriter could
    /// change a bundle's commitment root without changing its meaning.
    fn head(&mut self) -> Result<(u8, u64)> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(Error::CborNotShortest);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().map_err(|_| Error::CborTruncated)?,
                ));
                if v <= 0xff {
                    return Err(Error::CborNotShortest);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().map_err(|_| Error::CborTruncated)?,
                ));
                if v <= 0xffff {
                    return Err(Error::CborNotShortest);
                }
                v
            }
            27 => {
                let v =
                    u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::CborTruncated)?);
                if v <= 0xffff_ffff {
                    return Err(Error::CborNotShortest);
                }
                v
            }
            // 31 is indefinite length, which has no canonical form at all; 28–30
            // are reserved. Both are rejects rather than something to skip.
            _ => return Err(Error::CborUnsupported { initial: ib }),
        };
        Ok((major, arg))
    }

    fn value(&mut self, depth: u32) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::CborTooDeep { max: MAX_DEPTH });
        }
        let start = self.pos;
        let (major, arg) = self.head()?;
        Ok(match major {
            0 => Value::Uint(arg),
            1 => Value::Nint(arg),
            2 => Value::Bytes(self.take(arg)?.to_vec()),
            3 => {
                let s = self.take(arg)?;
                Value::Text(
                    core::str::from_utf8(s)
                        .map_err(|_| Error::CborBadUtf8)?
                        .to_owned(),
                )
            }
            4 => {
                // Deliberately not `with_capacity(arg)`: `arg` is attacker
                // controlled and every element costs at least one input byte, so
                // letting the `Vec` grow bounds the allocation by the input size.
                // Sizing from a length field before consuming it is design §14's
                // first rule.
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let mut entries: Vec<(Value, Value)> = Vec::new();
                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..arg {
                    let key_start = self.pos;
                    let k = self.value(depth + 1)?;
                    let key_bytes = self
                        .b
                        .get(key_start..self.pos)
                        .ok_or(Error::CborTruncated)?;
                    // Strictly increasing, so duplicates cannot be expressed and
                    // "which duplicate wins" never becomes a policy difference
                    // between two readers.
                    if let Some(prev) = prev_key {
                        match key_bytes.cmp(prev) {
                            core::cmp::Ordering::Greater => {}
                            core::cmp::Ordering::Equal => return Err(Error::CborDuplicateKey),
                            core::cmp::Ordering::Less => return Err(Error::CborUnsortedKeys),
                        }
                    }
                    prev_key = Some(key_bytes);
                    let v = self.value(depth + 1)?;
                    entries.push((k, v));
                }
                Value::Map(entries)
            }
            7 => match arg {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                // 23 is `undefined`; 24 is the one-byte simple-value escape; 25–27
                // are the three float widths. None has a place in a manifest, and
                // admitting floats would mean adopting their determinism problems.
                _ => {
                    return Err(Error::CborUnsupported {
                        initial: *self.b.get(start).unwrap_or(&0),
                    });
                }
            },
            // Major type 6 is a tag. A tag changes how the value it wraps must be
            // interpreted, so an unknown one is exactly the kind of thing a reader
            // must not carry blindly.
            _ => {
                return Err(Error::CborUnsupported {
                    initial: *self.b.get(start).unwrap_or(&0),
                });
            }
        })
    }
}
