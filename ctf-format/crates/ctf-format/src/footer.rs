//! The footer: the commitment root, the signatures over it, and the end of the file.
//!
//! Normative layout, little-endian. Unlike the header and the section record, the
//! footer is **variable width**, because a signature's size is a property of the
//! crypto suite and suite 3 (design §7) roughly doubles it:
//!
//! ```text
//! off          size  field
//!   0            32  root                BLAKE3 commitment root
//!  32             4  sig_classical_len   u32
//!  36             4  sig_pq_len          u32
//!  40             N  sig_classical
//!  40+N           M  sig_pq
//!  footer_len-16  8  total_len           u64, == the real file length
//!  footer_len-8   8  magic               the file signature, repeated
//! ```
//!
//! `footer_len` is not a field: the footer runs from `footer_off` to the end of the
//! file, so its length is `file_len - footer_off`. Storing it as well would be a
//! second carrier of one fact, which spec §5.7 has already ruled out — and the one
//! it would duplicate, `total_len`, is in the signed transcript.
//!
//! **`footer_len` MUST equal `56 + N + M` exactly.** No padding, no slack. Padding
//! would be bytes inside the file, outside every structure, and outside the
//! commitment root — which is precisely the trailing-data ambiguity spec §3 exists
//! to close, moved eight bytes to the left.
//!
//! Normative: `spec/SPEC.md` §8, rules F1–F9.
//!
//! # Alignment
//!
//! The footer's fields are *not* naturally aligned in the file, because 0.2 froze
//! `footer_off` with no alignment requirement and narrowing that now would need a
//! `feat_incompat` bit (spec §15) to reject files that are legal today. Nothing is
//! lost: every field here is decoded through the little-endian helpers, which are
//! alignment-independent. A writer SHOULD still align `footer_off` to 8.
//!
//! # What a footer does and does not establish
//!
//! This module computes and checks `root`: a bundle whose root matches is *intact*.
//! It does not verify the signatures, because that needs a trusted public key the
//! bundle does not carry — [`crate::crypto::sign::verify_footer`] does, over the
//! §8.4 transcript, and yields the [`crate::Authentication`] token only on success.
//! [`Signing`] reports whether signatures are *present*, never whether they are
//! valid, which is why there is no `Footer::is_valid`.

use crate::{Error, HEADER_LEN, MAGIC, Result, u32_at, u64_at};

/// Domain-separated label for the commitment root. Design §6, fixed in 0.2.
const ROOT_LABEL: &[u8] = b"ctf/root/v1";

/// Domain-separated label for the signature transcript. The label is what stops a
/// footer signature being replayed against an entitlement record, which is signed
/// with the same keys (design §9).
///
/// `v2` binds the two signature-slot lengths, which `v1` did not. Without them the
/// split between the classical and post-quantum slots was constrained only by F3–F5
/// (range, parity, and sum), so neither signature covered it.
const SIG_LABEL: &[u8] = b"ctf/footer-sig/v2";

const OFF_ROOT: usize = 0;
/// Length of the commitment root, and of every section `root`. 32 bytes in the
/// frozen layout, so every present and future suite must use a 32-byte digest.
pub const ROOT_LEN: usize = 32;
const OFF_SIG_CLASSICAL_LEN: usize = 32;
const OFF_SIG_PQ_LEN: usize = 36;
const OFF_SIGS: usize = 40;
/// `total_len` and the repeated magic.
const TRAILER_LEN: u64 = 16;

/// Smallest legal footer: the fixed prefix plus the trailer, with no signatures.
pub const MIN_FOOTER_LEN: u64 = OFF_SIGS as u64 + TRAILER_LEN;

/// Cap on either signature. The largest primitive in the planned registry is
/// SLH-DSA-256f at under 50 KiB (design §7, suite 3); this leaves headroom without
/// letting a length field describe a footer larger than any real bundle.
pub const MAX_SIG_LEN: u32 = 65536;

/// Whether a bundle carries signatures at all.
///
/// Deliberately not a boolean called `verified`. A phase 1 reader can establish
/// that a bundle is *intact* — its commitment root matches its own bytes — and
/// nothing more; verifying the signatures needs phase 2's suite registry. Naming
/// the state [`Signing::Unsigned`] rather than returning `false` from something
/// called "verified" keeps a caller from reading "not verified yet" as "verified".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signing {
    /// Both signature slots are empty. The bundle authenticates nothing and MUST
    /// NOT be served, executed, or trusted.
    Unsigned,
    /// Both signatures are present but unverified by this build.
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// `BLAKE3("ctf/root/v1" ‖ header[0,64) ‖ section_table_bytes)`.
    pub root: [u8; ROOT_LEN],
    /// Classical signature over [`sig_input`]. Empty in an unsigned bundle.
    pub sig_classical: Vec<u8>,
    /// Post-quantum signature over the *identical* transcript. Both must verify
    /// (F4); carrying one without the other is rejected as a downgrade.
    pub sig_pq: Vec<u8>,
    /// The total length of the file, which must equal its real length.
    pub total_len: u64,
}

impl Footer {
    /// Parse the footer out of a whole file.
    ///
    /// Takes the entire file rather than a slice at `footer_off` on purpose: three
    /// of the rules here — `total_len` equality, the trailing-byte rule, and the
    /// exact-length rule — are statements about where the file *ends*, and a
    /// function handed only the tail cannot check any of them.
    pub fn parse(file: &[u8], footer_off: u64) -> Result<Self> {
        let file_len = file.len() as u64;
        if footer_off < u64::from(HEADER_LEN) {
            return Err(Error::BadOffset {
                at: "header.footer_off",
                got: footer_off,
            });
        }
        let footer_len = file_len.checked_sub(footer_off).ok_or(Error::ExceedsFile {
            at: "footer",
            end: footer_off,
            file_len,
        })?;
        if footer_len < MIN_FOOTER_LEN {
            return Err(Error::Truncated {
                need: MIN_FOOTER_LEN as usize,
                got: footer_len as usize,
            });
        }
        let start = usize::try_from(footer_off).map_err(|_| Error::ExceedsFile {
            at: "footer",
            end: footer_off,
            file_len,
        })?;
        let b = file.get(start..).ok_or(Error::Truncated {
            need: MIN_FOOTER_LEN as usize,
            got: 0,
        })?;
        let trunc = || Error::Truncated {
            need: MIN_FOOTER_LEN as usize,
            got: b.len(),
        };

        // The fixed-offset fields first. They are anchored at `footer_off`, so they
        // are the only part of the footer whose position is unaffected by bytes
        // being appended to or removed from the end — which makes the length rule
        // below the accurate diagnostic for exactly that tampering. Reading the
        // trailer first would instead report a magic mismatch, which is true but
        // says nothing about what is wrong.
        let sig_classical_len = u32_at(b, OFF_SIG_CLASSICAL_LEN).ok_or_else(trunc)?;
        let sig_pq_len = u32_at(b, OFF_SIG_PQ_LEN).ok_or_else(trunc)?;
        if sig_classical_len > MAX_SIG_LEN || sig_pq_len > MAX_SIG_LEN {
            return Err(Error::SignatureTooLong {
                got: sig_classical_len.max(sig_pq_len),
                max: MAX_SIG_LEN,
            });
        }
        // Hybrid means both or neither (F4). One signature alone is a downgrade
        // dressed as a partial file, so it is rejected rather than read as
        // "classically signed".
        if (sig_classical_len == 0) != (sig_pq_len == 0) {
            return Err(Error::Inconsistent {
                what: "footer carries one signature of a hybrid pair",
            });
        }
        // Exact, not "at least": a footer longer than its contents would carry
        // bytes belonging to no structure and covered by no commitment.
        let want = MIN_FOOTER_LEN + u64::from(sig_classical_len) + u64::from(sig_pq_len);
        if footer_len != want {
            return Err(Error::BadFooterLen {
                got: footer_len,
                want,
            });
        }

        // The trailer, now that the footer is known to be exactly as long as its
        // contents say. This is what ties the structure to the real end of the file.
        let trailer = b
            .len()
            .checked_sub(TRAILER_LEN as usize)
            .ok_or_else(trunc)?;
        let magic: [u8; 8] = b
            .get(trailer + 8..trailer + 16)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(trunc)?;
        if magic != MAGIC {
            return Err(Error::BadMagic { got: magic });
        }
        let total_len = u64_at(b, trailer).ok_or_else(trunc)?;
        if total_len != file_len {
            return Err(Error::BadTotalLen {
                declared: total_len,
                file_len,
            });
        }

        let root: [u8; ROOT_LEN] = b
            .get(OFF_ROOT..OFF_ROOT + ROOT_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(trunc)?;
        let cls_end = OFF_SIGS + sig_classical_len as usize;
        let pq_end = cls_end + sig_pq_len as usize;
        let sig_classical = b.get(OFF_SIGS..cls_end).ok_or_else(trunc)?.to_vec();
        let sig_pq = b.get(cls_end..pq_end).ok_or_else(trunc)?.to_vec();

        Ok(Self {
            root,
            sig_classical,
            sig_pq,
            total_len,
        })
    }

    /// Whether the bundle carries a hybrid signature pair at all.
    pub fn signing(&self) -> Signing {
        if self.sig_classical.is_empty() {
            Signing::Unsigned
        } else {
            Signing::Present
        }
    }

    /// Serialize. Round-trips [`Footer::parse`] byte-for-byte.
    ///
    /// `Err` when a signature exceeds [`MAX_SIG_LEN`] or only one of the pair is
    /// present — the writer refuses to emit a footer its own parser would reject.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let cls = u32::try_from(self.sig_classical.len()).unwrap_or(u32::MAX);
        let pq = u32::try_from(self.sig_pq.len()).unwrap_or(u32::MAX);
        if cls > MAX_SIG_LEN || pq > MAX_SIG_LEN {
            return Err(Error::SignatureTooLong {
                got: cls.max(pq),
                max: MAX_SIG_LEN,
            });
        }
        if self.sig_classical.is_empty() != self.sig_pq.is_empty() {
            return Err(Error::Inconsistent {
                what: "footer carries one signature of a hybrid pair",
            });
        }
        let mut b = Vec::with_capacity(MIN_FOOTER_LEN as usize + cls as usize + pq as usize);
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&cls.to_le_bytes());
        b.extend_from_slice(&pq.to_le_bytes());
        b.extend_from_slice(&self.sig_classical);
        b.extend_from_slice(&self.sig_pq);
        b.extend_from_slice(&self.total_len.to_le_bytes());
        b.extend_from_slice(&MAGIC);
        Ok(b)
    }

    /// The transcript both signatures are computed over. Phase 2 signs and verifies
    /// this; phase 1 can already produce it, which is what lets a test pin it.
    ///
    /// The two signature lengths are taken from the slots this footer actually
    /// carries, so the transcript binds the split between them (see [`sig_input`]).
    pub fn sig_input(&self, suite_id: u16) -> Vec<u8> {
        sig_input(
            suite_id,
            u32::try_from(self.sig_classical.len()).unwrap_or(u32::MAX),
            u32::try_from(self.sig_pq.len()).unwrap_or(u32::MAX),
            &self.root,
            self.total_len,
        )
    }
}

/// `"ctf/footer-sig/v2" ‖ u16_le(suite_id) ‖ u32_le(sig_classical_len) ‖
/// u32_le(sig_pq_len) ‖ root ‖ u64_le(total_len)`.
///
/// Every element after the label is fixed width, so the concatenation is unambiguous
/// without length prefixes (design §7's `LP` rule applies to inputs with a
/// variable-width element). The transcript is 67 bytes.
///
/// `suite_id` is inside the transcript so a signature cannot be replayed under a
/// downgraded suite, and `total_len` is inside it so the no-trailing-bytes rule is
/// enforceable rather than advisory.
///
/// **The two slot lengths are inside it too, and that is the v2 change.** F3–F5
/// bound each length, require both-or-neither, and fix their sum, but leave the
/// split between the two slots free. §8.1 locates the slots from those fields, so
/// without binding them the same bytes could be read with two different slot
/// boundaries. Signing the lengths removes the ambiguity: any change to the split
/// invalidates both signatures.
///
/// `v1` was 59 bytes (`label ‖ suite_id ‖ root ‖ total_len`) and is not produced or
/// accepted by this version.
pub fn sig_input(
    suite_id: u16,
    sig_classical_len: u32,
    sig_pq_len: u32,
    root: &[u8; ROOT_LEN],
    total_len: u64,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_LABEL.len() + 2 + 4 + 4 + ROOT_LEN + 8);
    v.extend_from_slice(SIG_LABEL);
    v.extend_from_slice(&suite_id.to_le_bytes());
    v.extend_from_slice(&sig_classical_len.to_le_bytes());
    v.extend_from_slice(&sig_pq_len.to_le_bytes());
    v.extend_from_slice(root);
    v.extend_from_slice(&total_len.to_le_bytes());
    v
}

/// `BLAKE3("ctf/root/v1" ‖ header[0,64) ‖ section_table_bytes)`.
///
/// Two properties, both load-bearing and both fixed in 0.2:
///
/// - **The header is inside the root.** Otherwise the feature words are
///   strippable: clear the bits that tell an old reader to refuse the file and its
///   refusal becomes a misparse. A compatibility signal outside the commitment is
///   not a signal.
/// - **The table is hashed as bytes, once.** Every section's own `root` already
///   lives in those bytes, so this covers all of them without a second pass whose
///   order would have to be defined — and two conforming writers disagreeing about
///   that order is enough to produce two roots for one bundle.
///
/// The chunk indices are *not* hashed here. They do not need to be: an index is
/// verified by reducing it to its section's `root`, which is already inside the
/// table bytes (see [`crate::chunk`]). Committing them twice would add a second
/// carrier of one fact.
pub fn commitment_root(header_bytes: &[u8], table_bytes: &[u8]) -> [u8; ROOT_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(ROOT_LABEL);
    h.update(header_bytes);
    h.update(table_bytes);
    *h.finalize().as_bytes()
}
