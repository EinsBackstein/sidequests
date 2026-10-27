package ctf

import "encoding/binary"

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
		if e.Kind != ValueMap || len(e.M) != 4 {
			return nil, errf(CatManifest, "EN5", "envelope %d is not a four-key map", i)
		}
		var env Envelope
		var haveName, haveCtx, haveCT, haveWrapped bool
		for _, p := range e.M {
			if p.Key.Kind != ValueText {
				return nil, errf(CatManifest, "EN5", "envelope %d has a non-text key", i)
			}
			switch p.Key.T {
			case "name_id":
				if p.Val.Kind != ValueUint || p.Val.U > 0xffff {
					return nil, errf(CatManifest, "EN5", "envelope %d name_id out of range", i)
				}
				env.NameID = uint16(p.Val.U)
				haveName = true
			case "context":
				if p.Val.Kind != ValueText {
					return nil, errf(CatManifest, "EN5", "envelope %d context is not text", i)
				}
				env.Context = p.Val.T
				haveCtx = true
			case "ct":
				if p.Val.Kind != ValueBytes {
					return nil, errf(CatManifest, "EN5", "envelope %d ct is not bytes", i)
				}
				env.CT = p.Val.B
				haveCT = true
			case "wrapped":
				if p.Val.Kind != ValueBytes {
					return nil, errf(CatManifest, "EN5", "envelope %d wrapped is not bytes", i)
				}
				env.Wrapped = p.Val.B
				haveWrapped = true
			default:
				return nil, errf(CatManifest, "EN5", "envelope %d has an extra key", i)
			}
		}
		if !haveName || !haveCtx || !haveCT || !haveWrapped {
			return nil, errf(CatManifest, "EN5", "envelope %d is missing a key", i)
		}
		envs = append(envs, env)
	}
	return envs, nil
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

// SealProgress seals a progress plaintext to a new holder. The envelope's
// name_id is 0 (§24.1).
func SealProgress(suiteID uint16, contentKey, recipientPK []byte, challenge, subject string, plaintext []byte) (*ProgressPayload, error) {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
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
