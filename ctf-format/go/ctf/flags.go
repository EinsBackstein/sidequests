package ctf

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// DeriveSeed computes the per-subject seed of spec §22.2.
func DeriveSeed(eventSecret []byte, challengeID string, challengeVersion uint64, subject string) ([]byte, error) {
	info := make([]byte, 0, len(challengeID)+len(subject)+12)
	info = lp(info, []byte(challengeID))
	info = binary.LittleEndian.AppendUint64(info, challengeVersion)
	info = lp(info, []byte(subject))
	return hkdf.Key(sha256.New, eventSecret, []byte(seedLabel), string(info), 32)
}

const base32Lower = "abcdefghijklmnopqrstuvwxyz234567"

// base32LowerNoPad encodes b with RFC 4648 §6's alphabet, lowercase, without
// '=' padding.
func base32LowerNoPad(b []byte) string {
	var sb strings.Builder
	sb.Grow((len(b)*8 + 4) / 5)
	var acc uint64
	var bits uint
	for _, c := range b {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(base32Lower[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(base32Lower[(acc<<(5-bits))&31])
	}
	return sb.String()
}

// DeriveFlag computes flag(seed) per §22.3. The default derivation truncates the
// HMAC tag to 10 bytes, yielding exactly 16 lower-case base32 symbols.
func DeriveFlag(seed []byte) string {
	return DeriveFlagBytes(seed, 10)
}

// DeriveFlagBytes is the per-challenge length choice of §22.3. n must be 1..32;
// the flag can never carry more entropy than the HMAC tag.
func DeriveFlagBytes(seed []byte, n int) string {
	if n < 1 || n > 32 {
		n = 10
	}
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(flagLabel))
	tag := mac.Sum(nil)
	return base32LowerNoPad(tag[:n])
}

// StageKey derives the content key for stage N from stage N-1's flag (§22.4).
func StageKey(previousFlag string, stage uint32) ([]byte, error) {
	if stage == 0 {
		return nil, errf(CatUsage, "DF4", "stage numbers start at 1")
	}
	info := binary.LittleEndian.AppendUint32(nil, stage)
	return hkdf.Key(sha256.New, []byte(previousFlag), []byte(stageLabel), string(info), 32)
}

// FlagIsDerived reports whether a manifest flag declaration names a derivation
// with entropy (§22.5). An unknown derivation is static: it cannot be assumed to
// contribute entropy.
func FlagIsDerived(flag Value) bool {
	switch flag.Kind {
	case ValueText:
		return flag.T == "derived"
	case ValueMap:
		for _, p := range flag.M {
			if p.Key.Kind == ValueText && p.Key.T == "derive" && p.Val.Kind == ValueText {
				return p.Val.T == "derived" || p.Val.T == "hkdf-sha256"
			}
		}
	}
	return false
}

// ValidateStageGate implements DF5: stage_gate is valid only on a derived flag.
func ValidateStageGate(m *Manifest) error {
	flag, ok := m.Get("flag")
	if !ok || flag.Kind != ValueMap {
		return nil
	}
	gate := false
	for _, p := range flag.M {
		if p.Key.Kind == ValueText && p.Key.T == "stage_gate" && p.Val.Kind == ValueBool && p.Val.U != 0 {
			gate = true
		}
	}
	if gate && !FlagIsDerived(flag) {
		return errf(CatManifest, "DF5", "stage_gate on a static flag")
	}
	return nil
}
