//! The manifest: what the bundle *means*, in canonical CBOR.
//!
//! Normative: `spec/SPEC.md` §7, rules M1–M21.
//!
//! Exactly one section of kind `manifest` exists per bundle (T1), it is never
//! sealed, player-visible, or external (R7–R9), and its plaintext is a single
//! canonical CBOR map ([`crate::cbor`]).
//!
//! # The name table
//!
//! `names` is the array `name_id` indexes. It is the only place a section acquires
//! a human name — the section record carries a number, deliberately, because the
//! number is also the section's cryptographic identity (design §7) and a name is
//! not something an AEAD nonce should depend on.
//!
//! Names are checked for path shapes here rather than wherever a section is
//! eventually written to disk. A name containing a separator has no legitimate use
//! and one extraction path forgetting to re-check is all it takes, so separators
//! are rejected outright at the format boundary (design §14).
//!
//! # Unknown keys, and why they are not simply rejected
//!
//! Rejecting the unknown is the rule everywhere else in this format, and rejecting
//! unknown *manifest* keys was the original plan. It is wrong here for one reason:
//! the manifest is where the schema grows, so a bare "reject unknown keys" would
//! make it the one unextendable part of an extensible format.
//!
//! The mechanism is COSE's, and it is strictly stronger than either extreme. A
//! `crit` array names the keys a reader must understand. An unknown key listed in
//! `crit` is a hard reject; an unknown key not listed is carried and ignored. A
//! typo is still caught, because a typo appears in neither place — which is the
//! failure design §10 actually cares about, an author writing `visibilty` and
//! silently publishing a hidden challenge.
//!
//! Carrying means byte-exact: an ignored key survives a decode/encode round trip
//! unchanged, so a rewriter cannot destroy what it does not understand.
//!
//! # `spec` versus the container version
//!
//! `spec` versions this schema and is independent of `version_major.minor`, which
//! versions the bytes. Neither implies the other. A reader MUST NOT reject a
//! manifest solely because `spec` is higher than the one it was written against —
//! that is what `crit` decides — for the same reason `version_minor` is not
//! validated (spec §2.3).

use crate::{Error, Result, SectionRecord, cbor::Value, footer::ROOT_LEN, section::SectionFlags};

/// The manifest schema version this build implements.
pub const MANIFEST_SPEC: u64 = 1;

/// Longest legal entry in the name table.
pub const MAX_NAME_LEN: usize = 255;

/// Longest legal mirror URL.
pub const MAX_MIRROR_LEN: usize = 2048;

/// Longest legal challenge `id`.
pub const MAX_ID_LEN: usize = 64;

/// Entries the name table may hold: the whole `name_id` space. A longer table has
/// entries no section could ever refer to.
pub const MAX_NAMES: usize = u16::MAX as usize + 1;

/// Keys this build understands. A `crit` entry outside this list is a hard reject;
/// an unknown key outside it is carried untouched.
const KNOWN_KEYS: &[&str] = &[
    "category",
    "crit",
    "description",
    "external",
    "id",
    "name",
    "names",
    "spec",
    "version",
];

/// Mirror metadata for an `EXTERNAL` section.
///
/// The record is authoritative for `size` and `root` (spec §5.7); these copies
/// exist so a fetcher can work from the manifest alone, and
/// [`Manifest::validate_against`] rejects the file if the two disagree rather than
/// resolving in favour of either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External<'a> {
    /// Plaintext size of the payload; must equal the record's `len_plain`.
    pub size: u64,
    /// BLAKE3 root of the payload; must equal the record's `root`.
    pub root: [u8; ROOT_LEN],
    /// Where the payload can be fetched. Who serves these is the downstream
    /// orchestrator's problem (design §2), not this format's.
    pub mirrors: Vec<&'a str>,
}

/// A decoded, schema-checked manifest.
///
/// Holds the whole CBOR value, not just the fields this build names, so that
/// [`Manifest::encode`] reproduces the input byte-for-byte — including keys it does
/// not understand. Since the manifest's `root` commits to those bytes, anything
/// less would mean a rewriter silently changing the bundle's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    value: Value,
}

impl Manifest {
    /// Decode and schema-check a manifest section's plaintext.
    ///
    /// Checks the manifest against itself only. Cross-checks against the section
    /// table — the name table covering every section, external metadata agreeing
    /// with the records — are [`Manifest::validate_against`]'s job, because they
    /// need the table.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let value = Value::decode(b)?;
        let entries = value.as_map().ok_or(Error::Manifest {
            what: "manifest is not a CBOR map",
        })?;

        // Every key at the top level must be text. A non-text key has no meaning in
        // this schema and would make `crit` unable to name it.
        for (k, _) in entries {
            if k.as_text().is_none() {
                return Err(Error::Manifest {
                    what: "manifest map key is not text",
                });
            }
        }

        let spec = value
            .get("spec")
            .and_then(Value::as_uint)
            .ok_or(Error::Manifest {
                what: "manifest is missing `spec`, or it is not an unsigned integer",
            })?;
        if spec == 0 {
            return Err(Error::Manifest {
                what: "manifest `spec` must be at least 1",
            });
        }

        // `crit` first: if this manifest requires an understanding this build does
        // not have, every other diagnostic below is noise about a schema that was
        // never meant for it.
        if let Some(crit) = value.get("crit") {
            let list = crit.as_array().ok_or(Error::Manifest {
                what: "manifest `crit` is not an array",
            })?;
            for item in list {
                let key = item.as_text().ok_or(Error::Manifest {
                    what: "manifest `crit` entry is not text",
                })?;
                if !KNOWN_KEYS.contains(&key) {
                    return Err(Error::Manifest {
                        what: "manifest marks a key critical that this build does not implement",
                    });
                }
                if value.get(key).is_none() {
                    return Err(Error::Manifest {
                        what: "manifest `crit` names a key that is not present",
                    });
                }
            }
        }

        let id = value
            .get("id")
            .and_then(Value::as_text)
            .ok_or(Error::Manifest {
                what: "manifest is missing `id`, or it is not text",
            })?;
        check_id(id)?;

        if value.get("name").and_then(Value::as_text).is_none() {
            return Err(Error::Manifest {
                what: "manifest is missing `name`, or it is not text",
            });
        }

        for optional in ["category", "description"] {
            if let Some(v) = value.get(optional)
                && v.as_text().is_none()
            {
                return Err(Error::Manifest {
                    what: "manifest `category` or `description` is not text",
                });
            }
        }
        if let Some(v) = value.get("version")
            && v.as_uint().is_none()
        {
            return Err(Error::Manifest {
                what: "manifest `version` is not an unsigned integer",
            });
        }

        let names = value
            .get("names")
            .and_then(Value::as_array)
            .ok_or(Error::Manifest {
                what: "manifest is missing `names`, or it is not an array",
            })?;
        if names.len() > MAX_NAMES {
            return Err(Error::Manifest {
                what: "manifest `names` is longer than the `name_id` space",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(names.len());
        for entry in names {
            let n = entry.as_text().ok_or(Error::Manifest {
                what: "manifest `names` entry is not text",
            })?;
            check_name(n)?;
            seen.push(n);
        }
        seen.sort_unstable();
        if seen.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(Error::Manifest {
                what: "manifest `names` contains a duplicate",
            });
        }

        if let Some(ext) = value.get("external") {
            let entries = ext.as_map().ok_or(Error::Manifest {
                what: "manifest `external` is not a map",
            })?;
            for (k, v) in entries {
                let id = k.as_uint().ok_or(Error::Manifest {
                    what: "manifest `external` key is not an unsigned integer",
                })?;
                if u16::try_from(id).is_err() {
                    return Err(Error::Manifest {
                        what: "manifest `external` key is outside the `name_id` space",
                    });
                }
                parse_external(v)?;
            }
        }

        Ok(Self { value })
    }

    /// Encode canonically. Byte-for-byte identical to the input of
    /// [`Manifest::decode`], including carried keys.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.value.encode()
    }

    /// The whole CBOR value, for a caller that needs a key this build does not name.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The manifest schema version. Always at least 1.
    pub fn spec(&self) -> u64 {
        self.value.get("spec").and_then(Value::as_uint).unwrap_or(0)
    }

    /// The challenge identifier.
    pub fn id(&self) -> &str {
        self.value.get("id").and_then(Value::as_text).unwrap_or("")
    }

    /// The human-readable challenge title.
    pub fn name(&self) -> &str {
        self.value
            .get("name")
            .and_then(Value::as_text)
            .unwrap_or("")
    }

    /// The challenge version. `0` when absent — a challenge that has never been
    /// re-packed.
    pub fn version(&self) -> u64 {
        self.value
            .get("version")
            .and_then(Value::as_uint)
            .unwrap_or(0)
    }

    /// The category, if the author gave one.
    pub fn category(&self) -> Option<&str> {
        self.value.get("category").and_then(Value::as_text)
    }

    /// The description, if the author gave one.
    pub fn description(&self) -> Option<&str> {
        self.value.get("description").and_then(Value::as_text)
    }

    /// The name table. Index is `name_id`.
    pub fn names(&self) -> Vec<&str> {
        self.value
            .get("names")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_text).collect())
            .unwrap_or_default()
    }

    /// The name of the section identified by `name_id`.
    pub fn name_of(&self, name_id: u16) -> Option<&str> {
        self.value
            .get("names")
            .and_then(Value::as_array)
            .and_then(|a| a.get(usize::from(name_id)))
            .and_then(Value::as_text)
    }

    /// Mirror metadata for an external section.
    pub fn external(&self, name_id: u16) -> Option<External<'_>> {
        let entries = self.value.get("external").and_then(Value::as_map)?;
        let (_, v) = entries
            .iter()
            .find(|(k, _)| k.as_uint() == Some(u64::from(name_id)))?;
        parse_external(v).ok()
    }

    /// Cross-check the manifest against the section table.
    ///
    /// Four things the manifest alone cannot know:
    ///
    /// - every section's `name_id` indexes a real entry in the name table, so no
    ///   section is nameless;
    /// - every external section has mirror metadata, so a payload that lives
    ///   elsewhere can actually be found;
    /// - no metadata describes a section that is not external, which would
    ///   otherwise be an unreachable claim about a payload inside the file;
    /// - the metadata's `size` and `root` agree with the record's. **The record
    ///   wins and a mismatch rejects** (spec §5.7): two carriers of one fact with
    ///   no precedence is how one implementation verifies a payload against the
    ///   record while another verifies it against the manifest, and an attacker
    ///   who can edit either chooses which one is wrong.
    pub fn validate_against(&self, records: &[SectionRecord]) -> Result<()> {
        let names = self.names();
        for r in records {
            if usize::from(r.name_id) >= names.len() {
                return Err(Error::Manifest {
                    what: "a section's name_id is past the end of the manifest name table",
                });
            }
        }

        let entries = self
            .value
            .get("external")
            .and_then(Value::as_map)
            .unwrap_or(&[]);
        for r in records {
            let declared = entries
                .iter()
                .find(|(k, _)| k.as_uint() == Some(u64::from(r.name_id)));
            match (r.flags.contains(SectionFlags::EXTERNAL), declared) {
                (true, None) => {
                    return Err(Error::Manifest {
                        what: "an EXTERNAL section has no entry in the manifest's `external` map",
                    });
                }
                (false, Some(_)) => {
                    return Err(Error::Manifest {
                        what: "the manifest declares external metadata for a section that is not EXTERNAL",
                    });
                }
                (false, None) => {}
                (true, Some((_, v))) => {
                    let ext = parse_external(v)?;
                    if ext.size != r.len_plain || ext.root != r.root {
                        return Err(Error::Inconsistent {
                            what: "manifest external metadata disagrees with the section record",
                        });
                    }
                }
            }
        }

        // An entry naming a `name_id` no section uses describes nothing. Caught
        // separately from the loop above, which only walks sections.
        for (k, _) in entries {
            let id = k.as_uint().unwrap_or(u64::MAX);
            if !records
                .iter()
                .any(|r| u64::from(r.name_id) == id && r.flags.contains(SectionFlags::EXTERNAL))
            {
                return Err(Error::Manifest {
                    what: "the manifest's `external` map names a section that does not exist",
                });
            }
        }
        Ok(())
    }

    /// Build the minimal valid manifest: the four required keys and nothing else.
    ///
    /// This is what an OSINT challenge with no artifacts actually needs, which is
    /// the shape R6 is measured against.
    pub fn minimal(id: &str, name: &str, names: &[&str]) -> Result<Self> {
        let value = Value::Map(vec![
            (Value::Text("spec".into()), Value::Uint(MANIFEST_SPEC)),
            (Value::Text("id".into()), Value::Text(id.into())),
            (Value::Text("name".into()), Value::Text(name.into())),
            (
                Value::Text("names".into()),
                Value::Array(names.iter().map(|n| Value::Text((*n).into())).collect()),
            ),
        ]);
        // Round-trip through the canonical encoder so the stored value is in
        // canonical key order and has passed every schema check, exactly as if it
        // had been read from a file.
        Self::decode(&value.encode()?)
    }
}

fn parse_external(v: &Value) -> Result<External<'_>> {
    let size = v
        .get("size")
        .and_then(Value::as_uint)
        .ok_or(Error::Manifest {
            what: "external entry is missing `size`, or it is not an unsigned integer",
        })?;
    let root: [u8; ROOT_LEN] = v
        .get("root")
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Manifest {
            what: "external entry is missing `root`, or it is not a 32-byte string",
        })?;
    let list = v
        .get("mirrors")
        .and_then(Value::as_array)
        .ok_or(Error::Manifest {
            what: "external entry is missing `mirrors`, or it is not an array",
        })?;
    if list.is_empty() {
        return Err(Error::Manifest {
            what: "external entry has an empty `mirrors` list",
        });
    }
    let mut mirrors = Vec::with_capacity(list.len());
    for m in list {
        let s = m.as_text().ok_or(Error::Manifest {
            what: "external entry `mirrors` contains a non-text value",
        })?;
        if s.is_empty() || s.len() > MAX_MIRROR_LEN {
            return Err(Error::Manifest {
                what: "external entry mirror URL is empty or too long",
            });
        }
        mirrors.push(s);
    }
    Ok(External {
        size,
        root,
        mirrors,
    })
}

/// `id` is used in the seed derivation (design §7) and in operator-facing output,
/// so it is restricted to a shape that is unambiguous in both: lowercase ASCII
/// alphanumerics and interior hyphens.
fn check_id(id: &str) -> Result<()> {
    let bad = id.is_empty()
        || id.len() > MAX_ID_LEN
        || id.starts_with('-')
        || id.ends_with('-')
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if bad {
        return Err(Error::Manifest {
            what: "manifest `id` must be 1-64 bytes of lowercase ASCII, digits and interior hyphens",
        });
    }
    Ok(())
}

/// The explicit Unicode bidirectional formatting characters: U+202A–U+202E, the
/// embeddings and overrides, and U+2066–U+2069, the isolates.
///
/// **Not right-to-left script.** Arabic and Hebrew names remain legal, because the
/// characters that spell a word carry their direction implicitly. These nine carry
/// no content at all: they reorder how the text *around* them is displayed, which is
/// how `chal-gnp.exe` renders as `chal-exe.png` in a terminal, a file manager, and a
/// TUI alike.
///
/// The byte tests in [`check_name`] cannot catch them — every byte of their UTF-8 is
/// `≥ 0x80`, so `c < 0x20` and `c == 0x7f` both miss — which is why this is a `char`
/// test and not another byte in that list.
const fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// A name may become a filename when a section is extracted, so every shape that
/// could escape a directory *or misrepresent itself* is rejected here — separators
/// outright, rather than after normalization, because a name with a separator has no
/// legitimate use and a rejected name cannot be normalized wrong.
///
/// Bidi controls are rejected for the same reason at one remove: display escaping in
/// one tool does not help when the name is written to disk, and a filename that
/// renders as a different extension than it has is the classic version of this
/// attack. Rejecting at the format boundary covers every consumer, including the
/// ones not written yet.
fn check_name(n: &str) -> Result<()> {
    let bad = n.is_empty()
        || n.len() > MAX_NAME_LEN
        || n == "."
        || n == ".."
        || n.bytes()
            .any(|c| c == b'/' || c == b'\\' || c < 0x20 || c == 0x7f)
        || n.chars().any(is_bidi_control);
    if bad {
        return Err(Error::Manifest {
            what: "manifest name is empty, too long, path-like, or contains a control character",
        });
    }
    Ok(())
}
