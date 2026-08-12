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
    /// Two sections claim overlapping byte ranges. Ambiguity here becomes a
    /// parser-differential exploit.
    OverlappingSections { a: u16, b: u16 },
    /// Two sections share a `name_id`.
    DuplicateSectionName { name_id: u16 },
    /// Exactly one manifest section is required.
    ManifestCount { got: usize },
    /// `chunk_size` is not a power of two within the permitted range.
    BadChunkSize { got: u32 },
    /// A combination of fields that is individually well-formed but jointly
    /// meaningless or unsafe.
    Inconsistent { what: &'static str },
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
            Self::OverlappingSections { a, b } => {
                write!(f, "sections {a} and {b} overlap")
            }
            Self::DuplicateSectionName { name_id } => {
                write!(f, "duplicate section name_id {name_id}")
            }
            Self::ManifestCount { got } => {
                write!(f, "expected exactly one manifest section, found {got}")
            }
            Self::BadChunkSize { got } => write!(f, "bad chunk_size {got}"),
            Self::Inconsistent { what } => write!(f, "inconsistent: {what}"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
