// Package ctf implements the .ctf container format specified by
// ctf-format/spec/SPEC.md. It is an independent implementation written from the
// specification text; see ../README.md and ../AMBIGUITIES.md.
package ctf

// Fixed sizes and limits from spec §12.
const (
	HeaderLen              = 64
	SectionRecordLen       = 128
	TableAlign             = 8
	PayloadAlign           = 4096
	MaxSections            = 4096
	MinChunkSize           = 4096
	MaxChunkSize           = 64 << 20
	RootLen                = 32
	MinFooterLen           = 56
	MaxSigLen              = 65536
	MaxDecompressedSection = 64 << 30 // 64 GiB
	MaxDecompressionRatio  = 65536
	MaxCBORDepth           = 16
	MaxNameLen             = 255
	MaxPathLen             = 4096
	MaxIDLen               = 64
	MaxMirrorLen           = 2048
	MaxNames               = 65536
	ManifestSpec           = 1
)

// Header values.
const (
	VersionMajor = 0
	VersionMinor = 3
	SuiteDefault = 1
	// containerV1Minor is the first minor that required the CONTAINER_V1
	// ro_compat bit. It is a fixed era boundary, not the writer's current
	// minor: a missing bit on such a file is a feature error at any later
	// minor, while an earlier file is genuinely an older format (§2.3).
	containerV1Minor = 3
)

// Feature bits.
const (
	FeatROCompatContainerV1 uint32 = 0x00000001
	SupportedIncompat       uint32 = 0
	SupportedROCompat       uint32 = 0x00000001
)

// Section kinds (§5.2).
const (
	KindManifest    uint16 = 1
	KindArtifact    uint16 = 2
	KindGenerator   uint16 = 3
	KindSolver      uint16 = 4
	KindWriteup     uint16 = 5
	KindEntitlement uint16 = 6
	KindKeys        uint16 = 7
	KindProgress    uint16 = 8
)

// Section flags (§5.3).
const (
	FlagSealed        uint16 = 0x0001
	FlagPlayerVisible uint16 = 0x0002
	FlagExternal      uint16 = 0x0004
	FlagOptional      uint16 = 0x0008
	flagAssignedMask  uint16 = 0x000f
)

// Encoding discriminants (§5.4).
const (
	EncNone   uint8 = 0
	EncStream uint8 = 1

	CompNone uint8 = 0
	CompZstd uint8 = 1
)

// Magic is the 8-byte file signature (§4.2).
var Magic = [8]byte{0x89, 'C', 'T', 'F', 0x0d, 0x0a, 0x1a, 0x0a}

// Domain separation labels and construction sizes (§8, §20-§24).
const (
	rootLabel            = "ctf/root/v1"
	footerSigLabelV2     = "ctf/footer-sig/v2"
	kemLabel             = "ctf/kem/v1"
	streamLabel          = "ctf/stream/v1"
	envelopeLabel        = "ctf/envelope/v1"
	seedLabel            = "ctf/seed/v1"
	flagLabel            = "ctf/flag/v1"
	stageLabel           = "ctf/stage/v1"
	progressLabel        = "ctf/progress/v1"
	entitlementSigLabel  = "ctf/entitlement-sig/v1"
	recordIDLabel        = "ctf/entitlement/record/v1"
	holderHashLabel      = "ctf/holder-hash/v1"
	generatorOutputLabel = "ctf/generator-output/v1"
)

// MediaType is the OCI media type of a .ctf bundle (§12, §30.1).
const MediaType = "application/vnd.ctf.bundle.v1"
