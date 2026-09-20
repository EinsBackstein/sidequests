use core::fmt;

/// Everything that can be wrong with a `.ctf` byte stream.
///
/// Errors carry the offending value where a human debugging a hand-built bundle
/// would want it. They never carry the input bytes themselves: an error string
/// from a sealed section must not become a decryption oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the structure being parsed requires.
    Truncated { need: usize, got: usize },
    /// Signature mismatch. Not a `.ctf` file, or mangled in transit.
    BadMagic { got: [u8; 8] },
    /// `header_len` is not the value this version mandates.
    BadHeaderLen { got: u32 },
    /// Major version this build does not implement.
    UnsupportedVersion { major: u16, minor: u16 },
    /// A reserved field was non-zero. Reserved means reserved: tolerating
    /// garbage here forecloses every future use of the field.
    ReservedNotZero { at: &'static str },
    /// A byte between two structures was non-zero (T8). Padding is covered by no
    /// commitment, so a non-zero byte there is a channel that survives signing.
    ///
    /// `at` is a file offset — a number, not attacker-controlled text — so naming it
    /// does not turn this error into an oracle for section content.
    PaddingNotZero { at: u64 },
    /// A flag bit with no assigned meaning was set. Unknown keys are rejected,
    /// never ignored (design §10).
    UnknownFlagBits { at: &'static str, bits: u16 },
    /// Enum discriminant outside the registry.
    UnknownDiscriminant { at: &'static str, got: u8 },
    /// Section kind 0, which is never valid. Usually a zero-filled record.
    InvalidSectionKind { got: u16 },
    /// Section count above the hard cap. Checked *before* allocating, which is
    /// the single most common format-parser bug (design §14).
    TooManySections { got: u32, max: u32 },
    /// An offset that would read inside the header, backwards, or past the end.
    BadOffset { at: &'static str, got: u64 },
    /// An offset that is not on its required alignment boundary.
    Misaligned {
        at: &'static str,
        got: u64,
        align: u64,
    },
    /// Arithmetic on untrusted lengths overflowed.
    LengthOverflow { at: &'static str },
    /// A structure claims to extend beyond the end of the file.
    ExceedsFile {
        at: &'static str,
        end: u64,
        file_len: u64,
    },
    /// The file requires a feature this build does not implement. Carries the
    /// unsupported bits so a diagnostic can name what is missing rather than
    /// reporting the confusing structural error the unknown bytes would cause.
    UnsupportedFeature { class: &'static str, bits: u32 },
    /// The file does not declare a feature this operation needs. The mirror image
    /// of [`Error::UnsupportedFeature`]: there the file asks for more than the
    /// reader has, here the reader asks for more than the file offers.
    FeatureRequired { class: &'static str, bits: u32 },
    /// Two sections claim overlapping byte ranges. Ambiguity here becomes a
    /// parser-differential exploit.
    OverlappingSections { a: u16, b: u16 },
    /// A section's payload lies over the section table. Distinct from
    /// [`Error::OverlappingSections`] so that a real section with
    /// `name_id == u16::MAX` cannot be confused with the table in a diagnostic.
    OverlapsSectionTable { name_id: u16 },
    /// Two sections share a `name_id`.
    DuplicateSectionName { name_id: u16 },
    /// Exactly one manifest section is required.
    ManifestCount { got: usize },
    /// `chunk_size` is not a power of two within the permitted range.
    BadChunkSize { got: u32 },
    /// A combination of fields that is individually well-formed but jointly
    /// meaningless or unsafe.
    Inconsistent { what: &'static str },
    /// The footer's `total_len` is not the file's real length. Either the file has
    /// bytes appended after its commitment — the classic archive-format ambiguity —
    /// or it was truncated.
    BadTotalLen { declared: u64, file_len: u64 },
    /// The footer's length is not exactly what its signature lengths imply. Slack
    /// in the footer would be bytes inside the file, outside every structure, and
    /// outside the commitment.
    BadFooterLen { got: u64, want: u64 },
    /// A signature length beyond what any suite in the registry can produce.
    SignatureTooLong { got: u32, max: u32 },
    /// A recomputed BLAKE3 root does not match the one the file claims. The file
    /// is corrupt or has been tampered with; which, this error cannot say.
    RootMismatch { at: &'static str },
    /// The manifest violates the schema of `spec/SPEC.md` §7.
    ///
    /// Carries a static description and never the offending text: a manifest is
    /// attacker-controlled input like everything else, and an error string is not a
    /// place to echo it.
    Manifest { what: &'static str },
    /// A manifest rule violation tied to a specific entry.
    ///
    /// The same no-oracle rule as [`Error::Manifest`], and the reason the position is
    /// a *number* rather than the offending name or URL: an index into `names`, a
    /// `name_id`, and a mirror's position are all safe to report, while the text they
    /// point at is attacker-controlled. This is what turns "names entry is not text"
    /// into a diagnostic an operator can act on across a 50-artifact bundle.
    ManifestEntry {
        what: &'static str,
        /// Position in the `names` or `mirrors` array, when the rule is about a list.
        index: Option<usize>,
        /// The `name_id` the entry belongs to, when the rule is about an `external`
        /// entry or a section named in the table.
        name_id: Option<u64>,
    },
    /// CBOR input ended inside a value.
    CborTruncated,
    /// CBOR input has bytes after the value. A manifest section is entirely the
    /// manifest.
    CborTrailing { at: usize, len: usize },
    /// A structure was handed more bytes than its derived length accounts for.
    /// Accepting the excess and dropping it on re-encode would be a second spelling
    /// of one structure, which the commitment cannot tolerate.
    TrailingBytes { at: usize, len: usize },
    /// An integer argument was not encoded in the shortest form RFC 8949 §4.2.1
    /// requires. Admitting the longer forms would give one value several encodings
    /// and so several commitment roots.
    CborNotShortest,
    /// A CBOR feature outside the manifest subset: indefinite length, a tag, a
    /// float, `undefined`, or a reserved additional-information value.
    CborUnsupported { initial: u8 },
    /// Two map keys are equal. Last-wins and first-wins are both defensible, which
    /// is exactly why this is rejected instead of resolved.
    CborDuplicateKey,
    /// Map keys are not in canonical order.
    CborUnsortedKeys,
    /// A CBOR text string is not valid UTF-8.
    CborBadUtf8,
    /// CBOR nesting past the depth cap. Unbounded recursion over attacker-supplied
    /// nesting is a stack-overflow DoS.
    CborTooDeep { max: u32 },
    /// A compressed section's declared plaintext exceeds the absolute output cap
    /// (spec §5.4). Checked before any decompression runs.
    CompressionOutputTooLarge { got: u64, max: u64 },
    /// A compressed section's declared plaintext is more than the permitted multiple
    /// of its stored size (spec §5.4). Checked before any decompression runs.
    CompressionRatioExceeded { plain: u64, stored: u64, max: u64 },
    /// The input was not a valid zstd stream, or it ended before producing the
    /// declared plaintext length.
    DecompressionFailed,
    /// A decompressed section produced a different number of bytes than its record
    /// declares. The plaintext length is committed (the root is over the plaintext),
    /// so a mismatch means the stored bytes do not decode to what was signed.
    DecompressedLength { got: u64, want: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, got } => {
                write!(f, "truncated: need {need} bytes, got {got}")
            }
            Self::BadMagic { got } => write!(f, "bad magic: {got:02x?}"),
            Self::BadHeaderLen { got } => {
                write!(f, "bad header_len: {got}, expected {}", crate::HEADER_LEN)
            }
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported format version {major}.{minor}")
            }
            Self::ReservedNotZero { at } => write!(f, "reserved field not zero at {at}"),
            Self::PaddingNotZero { at } => {
                write!(f, "padding byte at offset {at} is not zero")
            }
            Self::UnknownFlagBits { at, bits } => {
                write!(f, "unknown flag bits {bits:#06x} at {at}")
            }
            Self::UnknownDiscriminant { at, got } => {
                write!(f, "unknown discriminant {got} at {at}")
            }
            Self::InvalidSectionKind { got } => write!(f, "invalid section kind {got}"),
            Self::TooManySections { got, max } => {
                write!(f, "section count {got} exceeds cap {max}")
            }
            Self::BadOffset { at, got } => write!(f, "bad offset {got} at {at}"),
            Self::Misaligned { at, got, align } => {
                write!(f, "offset {got} at {at} is not {align}-byte aligned")
            }
            Self::LengthOverflow { at } => write!(f, "length arithmetic overflowed at {at}"),
            Self::ExceedsFile { at, end, file_len } => {
                write!(f, "{at} ends at {end}, past file length {file_len}")
            }
            Self::UnsupportedFeature { class, bits } => {
                write!(
                    f,
                    "file requires unsupported {class} feature bits {bits:#010x}"
                )
            }
            Self::FeatureRequired { class, bits } => {
                write!(
                    f,
                    "file does not declare {class} feature bits {bits:#010x}, which this operation needs"
                )
            }
            Self::OverlappingSections { a, b } => {
                write!(f, "sections {a} and {b} overlap")
            }
            Self::OverlapsSectionTable { name_id } => {
                write!(f, "section {name_id} overlaps the section table")
            }
            Self::DuplicateSectionName { name_id } => {
                write!(f, "duplicate section name_id {name_id}")
            }
            Self::ManifestCount { got } => {
                write!(f, "expected exactly one manifest section, found {got}")
            }
            Self::BadChunkSize { got } => write!(f, "bad chunk_size {got}"),
            Self::Inconsistent { what } => write!(f, "inconsistent: {what}"),
            Self::BadTotalLen { declared, file_len } => write!(
                f,
                "footer declares total_len {declared}, file is {file_len} bytes"
            ),
            Self::BadFooterLen { got, want } => {
                write!(f, "footer is {got} bytes, its contents imply {want}")
            }
            Self::SignatureTooLong { got, max } => {
                write!(f, "signature length {got} exceeds cap {max}")
            }
            Self::RootMismatch { at } => write!(f, "BLAKE3 root mismatch at {at}"),
            Self::Manifest { what } => write!(f, "manifest: {what}"),
            Self::ManifestEntry {
                what,
                index,
                name_id,
            } => {
                write!(f, "manifest: {what}")?;
                match (name_id, index) {
                    (Some(n), Some(i)) => write!(f, " (name_id {n}, entry {i})"),
                    (Some(n), None) => write!(f, " (name_id {n})"),
                    (None, Some(i)) => write!(f, " (entry {i})"),
                    (None, None) => Ok(()),
                }
            }
            Self::CborTruncated => write!(f, "cbor: input ended inside a value"),
            Self::CborTrailing { at, len } => {
                write!(f, "cbor: value ends at {at}, input is {len} bytes")
            }
            Self::TrailingBytes { at, len } => {
                write!(f, "structure ends at {at}, input is {len} bytes")
            }
            Self::CborNotShortest => write!(f, "cbor: integer is not in shortest form"),
            Self::CborUnsupported { initial } => {
                write!(f, "cbor: unsupported item, initial byte {initial:#04x}")
            }
            Self::CborDuplicateKey => write!(f, "cbor: duplicate map key"),
            Self::CborUnsortedKeys => write!(f, "cbor: map keys are not in canonical order"),
            Self::CborBadUtf8 => write!(f, "cbor: text string is not valid UTF-8"),
            Self::CborTooDeep { max } => write!(f, "cbor: nesting deeper than {max}"),
            Self::CompressionOutputTooLarge { got, max } => write!(
                f,
                "compressed section would decompress to {got} bytes, above the {max}-byte cap"
            ),
            Self::CompressionRatioExceeded { plain, stored, max } => write!(
                f,
                "compressed section declares {plain} plaintext bytes from {stored} stored, above the {max}:1 ratio cap"
            ),
            Self::DecompressionFailed => write!(f, "compressed section did not decode as zstd"),
            Self::DecompressedLength { got, want } => write!(
                f,
                "compressed section decompressed to {got} bytes, record declares {want}"
            ),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
