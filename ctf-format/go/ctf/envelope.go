package ctf

import (
	"crypto/rand"
	"encoding/binary"
)

// Envelope is one hybrid-KEM key envelope (§21.1, §21.3).
type Envelope struct {
	NameID  uint16
	Context string
	CT      []byte
	Wrapped []byte
}

func envelopeAAD(suiteID uint16, context string) []byte {
	aad := make([]byte, 0, len(envelopeLabel)+2+4+len(context))
	aad = append(aad, envelopeLabel...)
	aad = binary.LittleEndian.AppendUint16(aad, suiteID)
	return lp(aad, []byte(context))
}

// SealEnvelope wraps contentKey to a hybrid public key under a recipient
// context. The AEAD nonce is the suite's nonce_len zero bytes (§21.1).
func SealEnvelope(suiteID, versionMajor uint16, recipientPK []byte, context string, contentKey []byte) (Envelope, error) {
	if len(contentKey) != 32 {
		return Envelope{}, errf(CatUsage, "", "content key is %d bytes, need 32", len(contentKey))
	}
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return Envelope{}, err
	}
	ct, kek, err := HybridEncapsulate(recipientPK, KemContext{SuiteID: suiteID, VersionMajor: versionMajor, Label: context})
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, suite.NonceLen)
	wrapped, err := SealAEAD(suiteID, kek, nonce, contentKey, envelopeAAD(suiteID, context))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Context: context, CT: ct, Wrapped: wrapped}, nil
}

// OpenEnvelope applies EN1–EN4. EN1 refuses a context mismatch before any key is
// derived; EN3 binds the context into the KEM combiner as well.
func OpenEnvelope(suiteID, versionMajor uint16, recipientSK []byte, env Envelope, expectedContext string) ([]byte, error) {
	if env.Context != expectedContext {
		return nil, errf(CatUsage, "EN1", "envelope context does not match")
	}
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	if len(env.CT) != 32+1088 {
		return nil, errf(CatUsage, "EN2", "KEM ciphertext is %d bytes, need 1120", len(env.CT))
	}
	kek, err := HybridDecapsulate(recipientSK, env.CT, KemContext{SuiteID: suiteID, VersionMajor: versionMajor, Label: env.Context})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, suite.NonceLen)
	key, err := OpenAEAD(suiteID, kek, nonce, env.Wrapped, envelopeAAD(suiteID, env.Context))
	if err != nil {
		return nil, errf(CatUsage, "EN4", "envelope does not authenticate")
	}
	if len(key) != 32 {
		return nil, errf(CatUsage, "EN4", "unwrapped key is %d bytes, need 32", len(key))
	}
	return key, nil
}

// EncodeKeysSection encodes envelopes as the canonical CBOR array that a `keys`
// section carries (§21.3).
func EncodeKeysSection(envs []Envelope) ([]byte, error) {
	arr := make([]Value, 0, len(envs))
	for _, e := range envs {
		arr = append(arr, MapValue(
			Pair{Key: Text("name_id"), Val: Uint(uint64(e.NameID))},
			Pair{Key: Text("context"), Val: Text(e.Context)},
			Pair{Key: Text("ct"), Val: Bytes(e.CT)},
			Pair{Key: Text("wrapped"), Val: Bytes(e.Wrapped)},
		))
	}
	v, err := canonicalize(Value{Kind: ValueArray, A: arr})
	if err != nil {
		return nil, err
	}
	return encodeValue(v)
}

// DecodeKeysSection validates EN5 and returns the envelopes.
func DecodeKeysSection(plaintext []byte) ([]Envelope, error) {
	v, err := decodeCBOR(plaintext)
	if err != nil {
		return nil, err
	}
	if v.Kind != ValueArray {
		return nil, errf(CatManifest, "EN5", "keys section is not an array")
	}
	envs := make([]Envelope, 0, len(v.A))
	for i, e := range v.A {
		env, err := decodeEnvelopeValue(e, i, CatManifest, "EN5")
		if err != nil {
			return nil, err
		}
		envs = append(envs, env)
	}
	return envs, nil
}

// decodeEnvelopeValue decodes the four-key §21.3 envelope map. A `keys`
// section (EN5) and a progress payload (P1) carry the same shape.
func decodeEnvelopeValue(e Value, i int, cat Category, rule string) (Envelope, error) {
	if e.Kind != ValueMap || len(e.M) != 4 {
		return Envelope{}, errf(cat, rule, "envelope %d is not a four-key map", i)
	}
	var env Envelope
	var haveName, haveCtx, haveCT, haveWrapped bool
	for _, p := range e.M {
		if p.Key.Kind != ValueText {
			return Envelope{}, errf(cat, rule, "envelope %d has a non-text key", i)
		}
		switch p.Key.T {
		case "name_id":
			if p.Val.Kind != ValueUint || p.Val.U > 0xffff {
				return Envelope{}, errf(cat, rule, "envelope %d name_id out of range", i)
			}
			env.NameID = uint16(p.Val.U)
			haveName = true
		case "context":
			if p.Val.Kind != ValueText {
				return Envelope{}, errf(cat, rule, "envelope %d context is not text", i)
			}
			env.Context = p.Val.T
			haveCtx = true
		case "ct":
			if p.Val.Kind != ValueBytes {
				return Envelope{}, errf(cat, rule, "envelope %d ct is not bytes", i)
			}
			env.CT = p.Val.B
			haveCT = true
		case "wrapped":
			if p.Val.Kind != ValueBytes {
				return Envelope{}, errf(cat, rule, "envelope %d wrapped is not bytes", i)
			}
			env.Wrapped = p.Val.B
			haveWrapped = true
		default:
			return Envelope{}, errf(cat, rule, "envelope %d has an extra key", i)
		}
	}
	if !haveName || !haveCtx || !haveCT || !haveWrapped {
		return Envelope{}, errf(cat, rule, "envelope %d is missing a key", i)
	}
	return env, nil
}

// ProgressPayload is the §24.1 shape of a progress record's payload.
type ProgressPayload struct {
	Envelope Envelope
	CT       []byte
}

func progressAAD(suiteID uint16, challenge, subject string) []byte {
	aad := make([]byte, 0, len(progressLabel)+2+len(challenge)+len(subject)+8)
	aad = append(aad, progressLabel...)
	aad = binary.LittleEndian.AppendUint16(aad, suiteID)
	aad = lp(aad, []byte(challenge))
	return lp(aad, []byte(subject))
}

// SealProgress seals a progress plaintext to a new holder. The content key is a
// fresh 32-byte key drawn per payload (§24.1, §24.2), and the envelope's
// name_id is 0.
func SealProgress(suiteID uint16, recipientPK []byte, challenge, subject string, plaintext []byte) (*ProgressPayload, error) {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, errf(CatUsage, "", "could not draw a progress content key")
	}
	env, err := SealEnvelope(suiteID, VersionMajor, recipientPK, "holder", contentKey)
	if err != nil {
		return nil, err
	}
	env.NameID = 0
	nonce := make([]byte, suite.NonceLen)
	ct, err := SealAEAD(suiteID, contentKey, nonce, plaintext, progressAAD(suiteID, challenge, subject))
	if err != nil {
		return nil, err
	}
	return &ProgressPayload{Envelope: env, CT: ct}, nil
}

// OpenProgress applies P1–P3.
func (p *ProgressPayload) Open(suiteID uint16, recipientSK []byte, challenge, subject string) ([]byte, error) {
	if p.Envelope.NameID != 0 {
		return nil, errf(CatUsage, "P1", "progress envelope name_id is %d, need 0 (§24.1)", p.Envelope.NameID)
	}
	if p.Envelope.Context != "holder" {
		return nil, errf(CatUsage, "P2", "progress envelope context is not holder")
	}
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	key, err := OpenEnvelope(suiteID, VersionMajor, recipientSK, p.Envelope, "holder")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, suite.NonceLen)
	pt, err := OpenAEAD(suiteID, key, nonce, p.CT, progressAAD(suiteID, challenge, subject))
	if err != nil {
		return nil, errf(CatUsage, "P3", "progress ciphertext does not authenticate")
	}
	return pt, nil
}

// Encode encodes the §24.1 canonical CBOR payload.
func (p *ProgressPayload) Encode() ([]byte, error) {
	v := MapValue(
		Pair{Key: Text("envelope"), Val: MapValue(
			Pair{Key: Text("name_id"), Val: Uint(uint64(p.Envelope.NameID))},
			Pair{Key: Text("context"), Val: Text(p.Envelope.Context)},
			Pair{Key: Text("ct"), Val: Bytes(p.Envelope.CT)},
			Pair{Key: Text("wrapped"), Val: Bytes(p.Envelope.Wrapped)},
		)},
		Pair{Key: Text("ct"), Val: Bytes(p.CT)},
	)
	cv, err := canonicalize(v)
	if err != nil {
		return nil, err
	}
	return encodeValue(cv)
}

// DecodeProgress applies P1 and returns the payload.
//
// §24.1 fixes the shape: one canonical CBOR map with exactly `envelope` and
// `ct`, the envelope being the §21.3 four-key map, and the envelope's name_id
// is 0 because a progress payload wraps a content key rather than a section's.
func DecodeProgress(payload []byte) (*ProgressPayload, error) {
	v, err := decodeCBOR(payload)
	if err != nil {
		return nil, err
	}
	if v.Kind != ValueMap || len(v.M) != 2 {
		return nil, errf(CatCBOR, "P1", "progress payload is not a two-key map (§24.1)")
	}
	var p ProgressPayload
	var haveEnv, haveCT bool
	for _, entry := range v.M {
		if entry.Key.Kind != ValueText {
			return nil, errf(CatCBOR, "P1", "progress payload has a non-text key (§24.1)")
		}
		switch entry.Key.T {
		case "envelope":
			env, err := decodeEnvelopeValue(entry.Val, 0, CatCBOR, "P1")
			if err != nil {
				return nil, err
			}
			p.Envelope = env
			haveEnv = true
		case "ct":
			if entry.Val.Kind != ValueBytes {
				return nil, errf(CatCBOR, "P1", "progress payload ct is not bytes (§24.1)")
			}
			p.CT = entry.Val.B
			haveCT = true
		default:
			return nil, errf(CatCBOR, "P1", "progress payload has an extra key (§24.1)")
		}
	}
	if !haveEnv || !haveCT {
		return nil, errf(CatCBOR, "P1", "progress payload is not a two-key map (§24.1)")
	}
	if p.Envelope.NameID != 0 {
		return nil, errf(CatCBOR, "P1", "progress envelope name_id is %d, need 0 (§24.1)", p.Envelope.NameID)
	}
	return &p, nil
}
