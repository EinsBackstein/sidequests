//! Whole-file reading and writing: the outside-in order, in one place.
//!
//! Normative: `spec/SPEC.md` §10, the reader conformance procedure. Everything
//! below is the sequence that document mandates, and the sequence matters — each
//! stage depends on values the previous one validated, so a reader that reorders
//! them is checking one structure against another structure's unvalidated claims.

use crate::{
    Error, HEADER_LEN, Header, Result, SECTION_RECORD_LEN, SectionFlags, SectionKind,
    SectionRecord,
    chunk::{self, ChunkIndex},
    footer::{Footer, MIN_FOOTER_LEN, ROOT_LEN, Signing, commitment_root},
    manifest::Manifest,
    section::{parse_table, validate_layout},
};

/// A parsed bundle, borrowing the file it was parsed from.
///
/// Holding the bytes is what lets [`Bundle::section_bytes`] verify a section's root
/// before handing anything back. Design §6 is explicit that no API returns
/// unverified bytes, and an API that returned offsets for the caller to slice would
/// be exactly that API with the check made optional.
#[derive(Debug, Clone)]
pub struct Bundle<'a> {
    file: &'a [u8],
    /// The 64-byte header.
    pub header: Header,
    /// Every section record, in table order. Order carries no meaning (spec §3).
    pub sections: Vec<SectionRecord>,
    /// The footer, with its commitment root already checked against the file.
    pub footer: Footer,
    /// The decoded manifest, already cross-checked against the section table.
    pub manifest: Manifest,
}

impl<'a> Bundle<'a> {
    /// Parse and structurally verify a whole `.ctf` file.
    ///
    /// On success the bundle is **intact**: its commitment root matches its own
    /// header and section table, its manifest matches its root and agrees with the
    /// table, and it has no trailing bytes. It is *not* authentic — see
    /// [`Bundle::signing`].
    pub fn parse(file: &'a [u8]) -> Result<Self> {
        let file_len = file.len() as u64;

        // 1-2. Header, then the two rules that need the real file length.
        let header = Header::parse(file)?;
        header.check_file_len(file_len)?;

        // A 0.1 or 0.2 file has no footer, no manifest schema, and a chunk index of
        // undefined length — spec 0.2 §10.2 forbade inventing any of them. Its
        // header and section table still parse, which is why `Header::parse` accepts
        // it; there is simply nothing here for the rest of this function to read.
        //
        // Note the direction. This is not H14 — the bit is one this build *does*
        // implement, and the file is missing it. `Header::parse` is the backward
        // compatible path and accepts such a file; only the whole-container read
        // needs a container.
        if header.feat_ro_compat & crate::FEAT_RO_COMPAT_CONTAINER_V1 == 0 {
            return Err(Error::FeatureRequired {
                class: "ro_compat",
                bits: crate::FEAT_RO_COMPAT_CONTAINER_V1,
            });
        }

        // 3-4. Section table, per-record then whole-table.
        let (table_start, table_end) = header.table_range()?;
        let table_bytes = slice(file, table_start, table_end, "section table")?;
        let sections = parse_table(table_bytes, header.section_table_count)?;
        validate_layout(&sections, &header, file_len)?;

        // 5. Footer: total_len equality, no trailing bytes, no slack.
        let footer = Footer::parse(file, header.footer_off)?;

        // 6. The commitment root, over the header and table bytes exactly as they
        //    appear in the file — not as re-serialized from the parsed structs,
        //    which would hash what this build believes rather than what is there.
        let header_bytes = slice(file, 0, u64::from(HEADER_LEN), "header")?;
        if commitment_root(header_bytes, table_bytes) != footer.root {
            return Err(Error::RootMismatch {
                at: "commitment root",
            });
        }

        // 7. The manifest, verified against its own section root before a single
        //    byte of it is decoded. Design §14: nothing acts on unauthenticated
        //    content, and CBOR decoding is acting on it.
        let record = sections
            .iter()
            .find(|r| r.kind == SectionKind::Manifest)
            .ok_or(Error::ManifestCount { got: 0 })?;
        let bytes = Self::verified_bytes(file, record)?;
        let manifest = Manifest::decode(bytes)?;
        manifest.validate_against(&sections)?;

        Ok(Self {
            file,
            header,
            sections,
            footer,
            manifest,
        })
    }

    /// Whether the bundle carries signatures at all.
    ///
    /// [`Signing::Present`] means present, **not verified**: the suite registry and
    /// both verifiers land in phase 2. A caller that must not act on unauthenticated
    /// content has nothing here that lets it, which is deliberate.
    pub fn signing(&self) -> Signing {
        self.footer.signing()
    }

    /// The transcript both signatures cover.
    pub fn sig_input(&self) -> Vec<u8> {
        self.footer.sig_input(self.header.suite_id)
    }

    /// The section record with this `name_id`, which is a section's identity
    /// (spec §5.1) — never its position in the table.
    pub fn section(&self, name_id: u16) -> Option<&SectionRecord> {
        self.sections.iter().find(|r| r.name_id == name_id)
    }

    /// A section's plaintext, verified against its `root` before it is returned.
    ///
    /// `Err` for an external section (its bytes are not here — stream them through
    /// [`chunk::verify_stream`]), and for an encrypted or compressed one, whose
    /// transforms land in phase 2 along with the decompression limits that make
    /// running them on untrusted input safe.
    pub fn section_bytes(&self, record: &SectionRecord) -> Result<&'a [u8]> {
        Self::verified_bytes(self.file, record)
    }

    /// A section's chunk index, verified against the section's `root`.
    ///
    /// `Ok(None)` when the section has no index. The root check happens here rather
    /// than being left to the caller because an unchecked index is worse than none:
    /// per-chunk verification against an attacker's index proves nothing.
    pub fn chunk_index(&self, record: &SectionRecord) -> Result<Option<ChunkIndex>> {
        let Some((start, end)) = record.index_range()? else {
            return Ok(None);
        };
        let bytes = slice(self.file, start, end, "chunk index")?;
        let count = chunk::chunk_count(record.len_plain, record.chunk_size)?;
        let index = ChunkIndex::parse(bytes, count)?;
        index.verify_root(&record.root)?;
        Ok(Some(index))
    }

    /// Verify every inline, unencrypted, uncompressed section against its root.
    ///
    /// Not part of [`Bundle::parse`]: a bundle referencing gigabytes of inline
    /// payload should not be hashed merely to open it, so the cost is the caller's
    /// to ask for.
    ///
    /// Returns a [`VerifyReport`] rather than a count, because a count cannot
    /// distinguish "checked everything" from "checked what I could". See that
    /// type for why the difference is the whole point.
    pub fn verify_inline_sections(&self) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        for r in &self.sections {
            if r.flags.contains(SectionFlags::EXTERNAL) {
                report.external += 1;
                continue;
            }
            if !is_plain(r) {
                report.unverifiable += 1;
                continue;
            }
            Self::verified_bytes(self.file, r)?;
            report.verified += 1;
        }
        Ok(report)
    }

    fn verified_bytes(file: &'a [u8], record: &SectionRecord) -> Result<&'a [u8]> {
        if record.flags.contains(SectionFlags::EXTERNAL) {
            return Err(Error::Inconsistent {
                what: "an EXTERNAL section's bytes are not in the file",
            });
        }
        if !is_plain(record) {
            return Err(Error::Inconsistent {
                what: "encrypted and compressed sections are not readable in this version",
            });
        }
        let end = record
            .offset
            .checked_add(record.len_stored)
            .ok_or(Error::LengthOverflow {
                at: "section range",
            })?;
        let bytes = slice(file, record.offset, end, "section payload")?;
        if blake3::hash(bytes).as_bytes() != &record.root {
            return Err(Error::RootMismatch { at: "section" });
        }
        Ok(bytes)
    }
}

/// What a pass over the inline sections actually established.
///
/// Three counts rather than one, because "not verified" has two meanings and
/// collapsing them is how a tool reports success it did not earn. An `external`
/// section's bytes are absent by design, so skipping it is the normal case and
/// says nothing is wrong. An `unverifiable` section's bytes are *right here* and
/// this build cannot check them — encrypted or compressed, both of which land in
/// phase 2 — and that is a reason for a caller to fail rather than to shrug.
///
/// The distinction is what keeps a non-zero exit meaningful: a bundle describing a
/// 40 GB external image is perfectly good and would otherwise fail every run.
///
/// The policy stays with the caller. This type reports; it does not decide, because
/// a phase 2 caller holding the content key can verify exactly what this build
/// counts as unverifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyReport {
    /// Sections hashed and matched against their `root`.
    pub verified: usize,
    /// `EXTERNAL` sections, whose bytes are not in this file. Stream them through
    /// [`chunk::verify_stream`].
    pub external: usize,
    /// Sections whose bytes are in this file and which this build cannot check.
    /// Non-zero means the file was **not** fully verified.
    pub unverifiable: usize,
}

/// A section whose stored bytes are its plaintext.
fn is_plain(r: &SectionRecord) -> bool {
    r.enc == crate::Encryption::None && r.comp == crate::Compression::None
}

fn slice<'a>(file: &'a [u8], start: u64, end: u64, what: &'static str) -> Result<&'a [u8]> {
    let (s, e) = (usize::try_from(start), usize::try_from(end));
    let (Ok(s), Ok(e)) = (s, e) else {
        return Err(Error::ExceedsFile {
            at: what,
            end,
            file_len: file.len() as u64,
        });
    };
    file.get(s..e).ok_or(Error::ExceedsFile {
        at: what,
        end,
        file_len: file.len() as u64,
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Where a section's bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// Stored in the file.
    Inline(&'a [u8]),
    /// Stored elsewhere. The writer never sees the bytes, only what commits to
    /// them — which is the whole point: a `.ctf` describing a 40 GB image stays
    /// small enough to mail.
    External {
        len_plain: u64,
        root: [u8; ROOT_LEN],
    },
}

/// One section to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSpec<'a> {
    pub kind: SectionKind,
    /// The section's identity. Must index the manifest's name table and must be
    /// unique; a rewriter must never reassign it (spec §5.1).
    pub name_id: u16,
    pub flags: SectionFlags,
    /// `0` for a single unit. A non-zero value emits a chunk index whenever the
    /// section spans two chunks or more.
    pub chunk_size: u32,
    pub payload: Payload<'a>,
}

impl<'a> SectionSpec<'a> {
    /// An inline, unencrypted, uncompressed section — everything phase 1 writes.
    pub fn inline(kind: SectionKind, name_id: u16, flags: SectionFlags, bytes: &'a [u8]) -> Self {
        Self {
            kind,
            name_id,
            flags,
            chunk_size: 0,
            payload: Payload::Inline(bytes),
        }
    }

    /// Chunk this section, so it carries a verified-streaming index.
    pub fn chunked(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

/// Write a complete, unsigned `.ctf` file.
///
/// Layout: header, payloads on 4096-byte boundaries, chunk indices, section table,
/// footer. That order is a writer's choice, not a rule — spec §3 leaves layout free
/// precisely so a writer streaming a multi-gigabyte payload need not buffer to learn
/// sizes.
///
/// The result is parsed back before it is returned. A writer that can emit a file
/// its own reader rejects is a bug generator for every downstream implementation,
/// and the check costs one pass over a file already in memory.
///
/// **The output is unsigned.** Both signature slots are empty, so
/// [`Bundle::signing`] reports [`Signing::Unsigned`] and nothing may treat the
/// result as authentic. Signing is phase 2.
pub fn write_bundle(suite_id: u16, sections: &[SectionSpec<'_>]) -> Result<Vec<u8>> {
    if sections.len() > crate::MAX_SECTIONS as usize {
        return Err(Error::TooManySections {
            got: sections.len() as u32,
            max: crate::MAX_SECTIONS,
        });
    }

    // Pass 1: place payloads and build the records.
    let mut body: Vec<u8> = Vec::new();
    let mut records: Vec<SectionRecord> = Vec::with_capacity(sections.len());
    let mut indices: Vec<(usize, ChunkIndex)> = Vec::new();

    for s in sections {
        let (offset, len_stored, len_plain, root) = match s.payload {
            Payload::External { len_plain, root } => (0, 0, len_plain, root),
            Payload::Inline(bytes) => {
                pad_to(&mut body, crate::PAYLOAD_ALIGN)?;
                let offset = u64::from(HEADER_LEN) + body.len() as u64;
                body.extend_from_slice(bytes);
                let len = bytes.len() as u64;
                (offset, len, len, *blake3::hash(bytes).as_bytes())
            }
        };
        if s.chunk_size != 0
            && chunk::chunk_count(len_plain, s.chunk_size)? >= 2
            && let Payload::Inline(bytes) = s.payload
        {
            indices.push((records.len(), ChunkIndex::build(bytes, s.chunk_size)?));
        }
        records.push(SectionRecord {
            kind: s.kind,
            name_id: s.name_id,
            flags: s.flags,
            enc: crate::Encryption::None,
            comp: crate::Compression::None,
            offset,
            len_stored,
            len_plain,
            chunk_size: s.chunk_size,
            chunk_index_off: 0,
            root,
        });
    }

    // Pass 2: the chunk indices, after the payloads so a streaming writer could
    // emit them once it knows each section's length.
    for (i, index) in &indices {
        pad_to(&mut body, crate::TABLE_ALIGN)?;
        let off = u64::from(HEADER_LEN) + body.len() as u64;
        body.extend_from_slice(&index.to_bytes());
        records
            .get_mut(*i)
            .ok_or(Error::Inconsistent {
                what: "chunk index refers to a section that was not written",
            })?
            .chunk_index_off = off;
    }

    // Pass 3: the table, then the footer, then the commitment over both.
    pad_to(&mut body, crate::TABLE_ALIGN)?;
    let section_table_off = u64::from(HEADER_LEN) + body.len() as u64;
    let mut table_bytes = Vec::with_capacity(records.len() * SECTION_RECORD_LEN);
    for r in &records {
        table_bytes.extend_from_slice(&r.to_bytes());
    }
    body.extend_from_slice(&table_bytes);

    let footer_off = u64::from(HEADER_LEN) + body.len() as u64;
    let header = Header {
        version_major: crate::VERSION_MAJOR,
        version_minor: crate::VERSION_MINOR,
        suite_id,
        flags: 0,
        section_table_count: records.len() as u32,
        section_table_off,
        footer_off,
        feat_incompat: 0,
        feat_ro_compat: crate::FEAT_RO_COMPAT_CONTAINER_V1,
    };
    let header_bytes = header.to_bytes();
    let footer = Footer {
        root: commitment_root(&header_bytes, &table_bytes),
        sig_classical: Vec::new(),
        sig_pq: Vec::new(),
        total_len: footer_off + MIN_FOOTER_LEN,
    };

    let mut file = Vec::with_capacity(footer.total_len as usize);
    file.extend_from_slice(&header_bytes);
    file.extend_from_slice(&body);
    file.extend_from_slice(&footer.to_bytes()?);

    Bundle::parse(&file)?;
    Ok(file)
}

/// Zero-pad `body` so the next byte written lands on `align`, counting from the
/// start of the file — hence the `HEADER_LEN` offset. Padding is zeroed rather than
/// left uninitialized because spec §3 says a writer SHOULD zero bytes belonging to
/// no structure, and uninitialized padding is how files leak heap.
fn pad_to(body: &mut Vec<u8>, align: u64) -> Result<()> {
    let pos = u64::from(HEADER_LEN)
        .checked_add(body.len() as u64)
        .ok_or(Error::LengthOverflow { at: "file length" })?;
    let rem = pos % align;
    if rem != 0 {
        let pad = usize::try_from(align - rem)
            .map_err(|_| Error::LengthOverflow { at: "file length" })?;
        body.resize(body.len() + pad, 0);
    }
    Ok(())
}
