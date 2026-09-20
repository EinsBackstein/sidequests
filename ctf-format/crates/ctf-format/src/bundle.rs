//! Whole-file reading and writing: the outside-in order, in one place.
//!
//! Normative: `spec/SPEC.md` §10, the reader conformance procedure. Everything
//! below is the sequence that document mandates, and the sequence matters — each
//! stage depends on values the previous one validated, so a reader that reorders
//! them is checking one structure against another structure's unvalidated claims.

use crate::{
    Compression, Error, HEADER_LEN, Header, Result, SECTION_RECORD_LEN, SectionFlags, SectionKind,
    SectionRecord,
    chunk::{self, ChunkIndex, VerifiedChunkIndex},
    compress,
    crypto::sign,
    footer::{Footer, MIN_FOOTER_LEN, ROOT_LEN, Signing, commitment_root},
    manifest::Manifest,
    section::{parse_table, validate_layout},
    suite::{HybridPublicKey, HybridSigningKey},
};

use std::borrow::Cow;

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
        validate_layout(&sections, &header, file)?;

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
        let manifest = Manifest::decode(&bytes)?;
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
    /// [`Signing::Present`] means present, **not verified**. Authenticity comes only
    /// from [`Bundle::verify_signatures`], which needs a trusted public key the
    /// bundle does not carry (spec §8.2).
    pub fn signing(&self) -> Signing {
        self.footer.signing()
    }

    /// Verify both hybrid signatures over the §8.4 transcript with a trusted public
    /// key, returning [`Authentication`](crate::Authentication) only on success.
    ///
    /// This is step 9 of the spec §10 procedure. The trusted key is an input, never
    /// read from the file; an unsigned bundle returns an error rather than a token.
    /// A failure of either component is a failure of the whole.
    pub fn verify_signatures(
        &self,
        public_key: &crate::HybridPublicKey,
    ) -> core::result::Result<crate::Authentication, crate::suite::SuiteError> {
        crate::crypto::sign::verify_footer(self.header.suite_id, &self.footer, public_key)
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
    /// This is the **serving boundary**, and the two guards below are here rather
    /// than in [`Bundle::verified_bytes`] on purpose — see that function for why the
    /// distinction is not pedantry.
    ///
    /// `Err` for an external section (its bytes are not here — stream them through
    /// [`chunk::verify_stream`]), for an encrypted one, whose transforms land in
    /// phase 2 along with the key envelopes that make reading it meaningful, for a
    /// section whose kind this build does not implement, and for a sealed section.
    ///
    /// A compressed section is decompressed transparently: the returned [`Cow`]
    /// borrows the file for an uncompressed section and owns the decoded bytes for
    /// one with `comp = 1`. The root check runs over the plaintext either way, so
    /// the caller never sees bytes that were not verified.
    pub fn section_bytes(&self, record: &SectionRecord) -> Result<Cow<'a, [u8]>> {
        // Spec §10, normative: "A reader MUST NOT serve, execute, decompress, or
        // decrypt a section whose kind it does not implement (§5.2)." §5.2 is
        // equally explicit that `PLAYER_VISIBLE` on an unknown kind "confers nothing
        // on a reader that does not understand it" — so an `OPTIONAL` section with
        // a future kind, plain inline bytes and a valid root must not come back from
        // here merely because it parses.
        if !record.kind.is_known() {
            return Err(Error::Inconsistent {
                what: "a section of a kind this build does not implement is not servable",
            });
        }
        // Belt and braces behind R21. R21 makes `SEALED` with `enc = 0`
        // unrepresentable, so this is unreachable through `Bundle::parse` today —
        // which is exactly why it is cheap to keep. A reader can never legitimately
        // return sealed plaintext, and stating that at the boundary means a future
        // relaxation of R21 cannot silently turn this into a leak.
        if record.flags.sealed() {
            return Err(Error::Inconsistent {
                what: "a SEALED section's plaintext is not readable in this version",
            });
        }
        Self::verified_bytes(self.file, record)
    }

    /// A section's chunk index, verified against the section's `root`.
    ///
    /// `Ok(None)` when the section has no index. The root check happens here rather
    /// than being left to the caller because an unchecked index is worse than none:
    /// per-chunk verification against an attacker's index proves nothing.
    ///
    /// Returns a [`VerifiedChunkIndex`], which is the only type that can check a
    /// chunk — so the ordering C6 requires (reduce the index to the root, then check
    /// chunks) cannot be reversed, and the `chunk_size` the record fixed travels with
    /// the index instead of being re-supplied per call.
    ///
    /// **The index is refused for a section the serving boundary refuses (C8).** An
    /// entry is a chaining value of the section's *plaintext* (spec §9.1), so it is
    /// information about contents a reader must not serve: exposing it for a `SEALED`
    /// section, or for a kind this build does not implement, would hand out a
    /// plaintext-derived guess-confirmation oracle while `section_bytes` refuses the
    /// bytes themselves. This mirrors the guards in [`Bundle::section_bytes`].
    pub fn chunk_index(&self, record: &SectionRecord) -> Result<Option<VerifiedChunkIndex>> {
        if !record.kind.is_known() {
            return Err(Error::Inconsistent {
                what: "a section of a kind this build does not implement has no readable chunk index",
            });
        }
        if record.flags.sealed() {
            return Err(Error::Inconsistent {
                what: "a SEALED section's chunk index is not readable in this version",
            });
        }
        let Some((start, end)) = record.index_range()? else {
            return Ok(None);
        };
        let bytes = slice(self.file, start, end, "chunk index")?;
        let count = chunk::chunk_count(record.len_plain, record.chunk_size)?;
        let index = ChunkIndex::parse(bytes, count)?;
        Ok(Some(index.verify_root(&record.root, record.chunk_size)?))
    }

    /// Verify every inline, unencrypted section against its root.
    ///
    /// Not part of [`Bundle::parse`]: a bundle referencing gigabytes of inline
    /// payload should not be hashed merely to open it, so the cost is the caller's
    /// to ask for.
    ///
    /// A compressed section is decompressed and checked here too — the caps of
    /// [`compress::check_caps`] run before the decoder, so verifying untrusted input
    /// is safe. Only an *encrypted* section is unverifiable by this build.
    ///
    /// Returns a [`VerifyReport`] rather than a count, because a count cannot
    /// distinguish "checked everything" from "checked what I could". See that
    /// type for why the difference is the whole point.
    ///
    /// **Chunk indices are not part of this pass.** C1–C7 are *on-use* rules
    /// (spec §10): a reader evaluates them when it hands out or relies on an index,
    /// which is [`Bundle::chunk_index`], not while parsing or hashing a file. The
    /// report discloses the number of sections that carry one
    /// ([`VerifyReport::chunk_indices`]) so a caller is not left assuming this pass
    /// checked them.
    pub fn verify_inline_sections(&self) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        for r in &self.sections {
            if r.chunk_index_off != 0 {
                report.chunk_indices += 1;
            }
            if r.flags.contains(SectionFlags::EXTERNAL) {
                report.external += 1;
                continue;
            }
            if r.enc != crate::Encryption::None {
                report.unverifiable += 1;
                continue;
            }
            Self::verified_bytes(self.file, r)?;
            report.verified += 1;
        }
        Ok(report)
    }

    /// Hash a section's plaintext and check it against its `root`.
    ///
    /// **Integrity only.** This deliberately does *not* refuse an unknown section
    /// kind, and [`Bundle::section_bytes`] carries that guard instead. Spec §10
    /// forbids serving, executing, decompressing, or decrypting a kind a reader does
    /// not implement — hashing a section against the root the footer already commits
    /// to is none of those four, and refusing to do it would make a bundle *less*
    /// verified for no gain in safety. §5.2's whole point is that a skipped section
    /// is still bounds-checked, still overlap-checked, and still committed; checking
    /// that the commitment actually holds is the follow-through, not a violation.
    ///
    /// Consequence: [`Bundle::verify_inline_sections`] verifies unknown-kind
    /// sections and counts them as verified, while [`Bundle::section_bytes`] refuses
    /// to hand them to a caller.
    fn verified_bytes(file: &'a [u8], record: &SectionRecord) -> Result<Cow<'a, [u8]>> {
        if record.flags.contains(SectionFlags::EXTERNAL) {
            return Err(Error::Inconsistent {
                what: "an EXTERNAL section's bytes are not in the file",
            });
        }
        if record.enc != crate::Encryption::None {
            return Err(Error::Inconsistent {
                what: "encrypted sections are not readable in this version",
            });
        }
        let end = record
            .offset
            .checked_add(record.len_stored)
            .ok_or(Error::LengthOverflow {
                at: "section range",
            })?;
        let stored = slice(file, record.offset, end, "section payload")?;
        let plain: Cow<'a, [u8]> = match record.comp {
            Compression::None => Cow::Borrowed(stored),
            Compression::Zstd => Cow::Owned(compress::decompress(stored, record.len_plain)?),
        };
        if blake3::hash(&plain).as_bytes() != &record.root {
            return Err(Error::RootMismatch { at: "section" });
        }
        Ok(plain)
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
    /// Sections carrying a chunk index. C1–C7 are **on-use** rules (spec §9.3,
    /// §10): this pass does not evaluate them — [`Bundle::chunk_index`] does, when
    /// a caller asks for the index. Non-zero here is therefore not a failure, only
    /// a disclosure that index integrity was outside this report.
    pub chunk_indices: usize,
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
    /// zstd compression of the inline payload (spec §5.4). [`Compression::Zstd`]
    /// frames per chunk, so a chunk decodes without its predecessors. The manifest
    /// must never use it (R20); the writer's parse-back catches that.
    pub comp: Compression,
    pub payload: Payload<'a>,
    /// A precomputed chunk index, as raw `count × 32` chaining-value bytes
    /// (`spec/SPEC.md` §9.1). Only meaningful for an `EXTERNAL` section, whose
    /// payload the writer never sees and therefore cannot index itself; the index
    /// is what lets a mirror transfer be verified per chunk (§9.4). The writer
    /// parses it, checks it reduces to `root`, and emits it.
    ///
    /// `None` for an inline section (the writer indexes the payload itself) and for
    /// an external section with no index.
    pub chunk_index: Option<&'a [u8]>,
}

impl<'a> SectionSpec<'a> {
    /// An inline, unencrypted, uncompressed section.
    pub fn inline(kind: SectionKind, name_id: u16, flags: SectionFlags, bytes: &'a [u8]) -> Self {
        Self {
            kind,
            name_id,
            flags,
            chunk_size: 0,
            comp: Compression::None,
            payload: Payload::Inline(bytes),
            chunk_index: None,
        }
    }

    /// Chunk this section, so it carries a verified-streaming index.
    pub fn chunked(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    /// Compress this section's inline payload with zstd.
    pub fn compressed(mut self) -> Self {
        self.comp = Compression::Zstd;
        self
    }

    /// Attach a precomputed chunk index to an `EXTERNAL` section.
    ///
    /// The bytes are the raw entry array of `spec/SPEC.md` §9.1. The writer parses
    /// them and requires that they reduce to the section's `root`, so a caller
    /// cannot emit an index the reader would reject at use.
    pub fn with_chunk_index(mut self, index: &'a [u8]) -> Self {
        self.chunk_index = Some(index);
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
/// result as authentic. An unsigned bundle is a valid intermediate state; sign it
/// with [`sign_bundle`] or produce a signed file directly with
/// [`write_signed_bundle`].
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
        // A precomputed index belongs to an EXTERNAL section: an inline section's
        // payload is right here and the writer indexes it itself.
        if s.chunk_index.is_some() && matches!(s.payload, Payload::Inline(_)) {
            return Err(Error::Inconsistent {
                what: "a precomputed chunk index was supplied for an inline section",
            });
        }

        // The chunk index, when there is one, is built or adopted here and written
        // in pass 2. It is also where `root` comes from: the merge of the entries
        // *is* `BLAKE3(plaintext)` (spec §9.2), so hashing the plaintext again
        // would be the same work done twice (ticket 85).
        let mut index: Option<ChunkIndex> = None;
        let (offset, len_stored, len_plain, root) = match s.payload {
            Payload::External { len_plain, root } => {
                if let Some(bytes) = s.chunk_index {
                    let count = chunk::chunk_count(len_plain, s.chunk_size)?;
                    let parsed = ChunkIndex::parse(bytes, count)?;
                    // Refuse to emit an index a reader would reject at use: the
                    // writer's own parse-back does not apply C4 (the C rules are
                    // on-use, spec §10), so the check belongs here.
                    parsed.clone().verify_root(&root, s.chunk_size)?;
                    index = Some(parsed);
                }
                (0, 0, len_plain, root)
            }
            Payload::Inline(bytes) => {
                // Compress before placing: `len_plain` stays the pre-compression
                // length and `root` commits to the plaintext (spec §5.4), so
                // compression is invisible to the commitment.
                let stored: Cow<'_, [u8]> = match s.comp {
                    Compression::None => Cow::Borrowed(bytes),
                    Compression::Zstd => Cow::Owned(compress::compress(bytes, s.chunk_size)?),
                };
                pad_to(&mut body, crate::PAYLOAD_ALIGN)?;
                let offset = u64::from(HEADER_LEN) + body.len() as u64;
                body.extend_from_slice(&stored);
                let len_plain = bytes.len() as u64;
                let (root, built) = if s.chunk_size != 0
                    && chunk::chunk_count(len_plain, s.chunk_size)? >= 2
                {
                    let idx = ChunkIndex::build(bytes, s.chunk_size)?;
                    let root = chunk::root_from_cvs(idx.entries()).ok_or(Error::Inconsistent {
                        what: "a chunked section's index did not reduce to a root",
                    })?;
                    (root, Some(idx))
                } else {
                    (*blake3::hash(bytes).as_bytes(), None)
                };
                index = built;
                (offset, stored.len() as u64, len_plain, root)
            }
        };
        if let Some(idx) = index {
            indices.push((records.len(), idx));
        }
        records.push(SectionRecord {
            kind: s.kind,
            name_id: s.name_id,
            flags: s.flags,
            enc: crate::Encryption::None,
            comp: s.comp,
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

/// Sign an unsigned bundle in place: produce both hybrid signatures over the §8.4
/// transcript and append them to the footer.
///
/// The result changes no byte outside the footer. The header, the section table, and
/// every payload are copied verbatim, so the commitment root — which covers the
/// header and table — is unchanged. The footer necessarily grows: its two length
/// fields locate the signature slots, and `total_len` grows with them. All three are
/// inside the transcript (spec §8.4), which is why signing is a two-pass operation:
/// the lengths must be fixed before the bytes they describe can be signed.
///
/// `public_key` is taken so the output can be verified before it is returned. A
/// writer that can emit a file a verifier rejects is the same bug generator
/// [`write_bundle`] refuses to be, and a mismatched keypair is the one way signing
/// itself can go wrong.
///
/// An already-signed bundle is rejected rather than re-signed: re-signing would have
/// to strip the old signatures first, and a caller who wants that is really asking
/// for a rewrite, which spec §4.4 governs.
pub fn sign_bundle(
    file: &[u8],
    signing_key: &HybridSigningKey,
    public_key: &HybridPublicKey,
) -> Result<Vec<u8>> {
    let bundle = Bundle::parse(file)?;
    if bundle.signing() != Signing::Unsigned {
        return Err(Error::Inconsistent {
            what: "bundle already carries signatures",
        });
    }

    let suite = crate::suite::suite(bundle.header.suite_id)?;
    let role = suite.signature()?;
    let cls = u32::try_from(role.classical_signature_len()).map_err(|_| Error::LengthOverflow {
        at: "signature length",
    })?;
    let pq = u32::try_from(role.pq_signature_len()).map_err(|_| Error::LengthOverflow {
        at: "signature length",
    })?;

    let footer_off = bundle.header.footer_off;
    let total_len = footer_off
        .checked_add(MIN_FOOTER_LEN)
        .and_then(|n| n.checked_add(u64::from(cls)))
        .and_then(|n| n.checked_add(u64::from(pq)))
        .ok_or(Error::LengthOverflow {
            at: "signed file length",
        })?;

    let signature = sign::sign_footer(
        bundle.header.suite_id,
        &bundle.footer.root,
        total_len,
        cls,
        pq,
        signing_key,
    )?;
    let footer = Footer {
        root: bundle.footer.root,
        sig_classical: signature.classical,
        sig_pq: signature.pq,
        total_len,
    };

    let split = usize::try_from(footer_off).map_err(|_| Error::LengthOverflow {
        at: "signed file length",
    })?;
    let mut out = Vec::with_capacity(total_len as usize);
    out.extend_from_slice(file.get(..split).ok_or(Error::ExceedsFile {
        at: "footer",
        end: footer_off,
        file_len: file.len() as u64,
    })?);
    out.extend_from_slice(&footer.to_bytes()?);

    // Parse-back and verify, exactly as `write_bundle` parses its own output: a
    // signer that can emit a file a verifier rejects is worse than no signer.
    let signed = Bundle::parse(&out)?;
    signed.verify_signatures(public_key)?;
    Ok(out)
}

/// Write a complete, signed `.ctf` file: [`write_bundle`] followed by
/// [`sign_bundle`].
///
/// The unsigned form remains a valid intermediate state and is what
/// [`write_bundle`] emits; this is the convenience for a caller that already holds
/// the signing key.
pub fn write_signed_bundle(
    suite_id: u16,
    sections: &[SectionSpec<'_>],
    signing_key: &HybridSigningKey,
    public_key: &HybridPublicKey,
) -> Result<Vec<u8>> {
    let unsigned = write_bundle(suite_id, sections)?;
    sign_bundle(&unsigned, signing_key, public_key)
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
