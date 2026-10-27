package ctf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Suite is one row of the crypto suite registry (§19.1).
type Suite struct {
	ID       uint16
	AEAD     string // "aes-256-gcm" or "xchacha20-poly1305"
	NonceLen int
	PQSigLen int // 3309 for suites 1 and 2; 11165 for suite 3
	// HasSLHDSA marks suite 3's signature role. This build does not implement
	// SLH-DSA (§19.1), so the role resolves to ErrNotImplemented and the suite's
	// slot lengths are not a parse-time check (F10, §8.2).
	HasSLHDSA bool
}

// ImplementsSignatureRole reports whether this build can verify the suite's
// signature role. F10 is limited to a suite the reader implements (§8.2), and
// suite 3's SLH-DSA half is `ErrNotImplemented`.
func (s Suite) ImplementsSignatureRole() bool { return !s.HasSLHDSA }

// LookupSuite resolves a suite_id at the point a primitive is needed (S2, S3).
func LookupSuite(id uint16) (Suite, error) {
	switch id {
	case 1:
		return Suite{ID: 1, AEAD: "aes-256-gcm", NonceLen: 12, PQSigLen: 3309}, nil
	case 2:
		return Suite{ID: 2, AEAD: "xchacha20-poly1305", NonceLen: 24, PQSigLen: 3309}, nil
	case 3:
		return Suite{ID: 3, AEAD: "aes-256-gcm", NonceLen: 12, PQSigLen: 11165, HasSLHDSA: true}, nil
	default:
		return Suite{}, errf(CatUsage, "S3", "unknown suite_id %d", id)
	}
}

// SuiteName is a human-readable suite label for diagnostics and tests.
func SuiteName(id uint16) string {
	switch id {
	case 1:
		return "suite-1-aes-256-gcm"
	case 2:
		return "suite-2-xchacha20-poly1305"
	case 3:
		return "suite-3-archive"
	}
	return "unknown-suite"
}

// X25519PublicKey derives pk = X25519(sk, basepoint).
func X25519PublicKey(sk []byte) ([]byte, error) {
	pk, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return nil, errf(CatUsage, "", "invalid X25519 secret key")
	}
	return pk, nil
}

func (s Suite) aead(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errf(CatUsage, "", "AEAD key is %d bytes, need 32", len(key))
	}
	if len(nonce) != s.NonceLen {
		return nil, errf(CatUsage, "", "AEAD nonce is %d bytes, need %d", len(nonce), s.NonceLen)
	}
	switch s.ID {
	case 1, 3:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case 2:
		return chacha20poly1305.NewX(key)
	}
	return nil, errf(CatUsage, "S3", "unknown suite_id %d", s.ID)
}

// SealAEAD encrypts plaintext with the suite's AEAD. The returned slice is
// ciphertext ‖ tag.
func SealAEAD(suiteID uint16, key, nonce, plaintext, aad []byte) ([]byte, error) {
	s, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	a, err := s.aead(key, nonce)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

// OpenAEAD decrypts and authenticates a ciphertext ‖ tag.
func OpenAEAD(suiteID uint16, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	s, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	a, err := s.aead(key, nonce)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ciphertext, aad)
}

// lp appends the §20 length prefix LP(x).
func lp(dst, x []byte) []byte {
	dst = append(dst, byte(len(x)), byte(len(x)>>8), byte(len(x)>>16), byte(len(x)>>24))
	return append(dst, x...)
}

// KemContext is the transcript context of the §20.1 combiner.
type KemContext struct {
	SuiteID      uint16
	VersionMajor uint16
	Label        string
}

func combinerKey(ssX, ssM, ctX, ctM, pkX, pkM []byte, ctx KemContext) ([]byte, error) {
	if ctx.SuiteID == 0 {
		return nil, errf(CatUsage, "", "KEM context suite_id is zero")
	}
	ikm := make([]byte, 0, len(ssX)+len(ssM))
	ikm = append(ikm, ssX...)
	ikm = append(ikm, ssM...)

	salt := make([]byte, 0, len(kemLabel)+4)
	salt = append(salt, kemLabel...)
	salt = binary.LittleEndian.AppendUint16(salt, ctx.SuiteID)
	salt = binary.LittleEndian.AppendUint16(salt, ctx.VersionMajor)

	info := make([]byte, 0, len(ctX)+len(ctM)+len(pkX)+len(pkM)+len(ctx.Label)+20)
	info = lp(info, ctX)
	info = lp(info, ctM)
	info = lp(info, pkX)
	info = lp(info, pkM)
	info = lp(info, []byte(ctx.Label))

	return hkdf.Key(sha256.New, ikm, salt, string(info), 32)
}

// HybridEncapsulate produces (ct_x25519 ‖ ct_mlkem, content_key) for a hybrid
// public key (pk_x25519 ‖ ek_mlkem).
func HybridEncapsulate(pk []byte, ctx KemContext) (ct, key []byte, err error) {
	if len(pk) != 32+1184 {
		return nil, nil, errf(CatUsage, "", "hybrid public key is %d bytes, need 1216", len(pk))
	}
	pkX := pk[:32]
	pkM := pk[32:]

	ek, err := mlkem.NewEncapsulationKey768(pkM)
	if err != nil {
		return nil, nil, errf(CatUsage, "", "bad ML-KEM encapsulation key")
	}
	ssM, ctM := ek.Encapsulate()

	// X25519 with a fresh ephemeral scalar.
	for attempt := 0; attempt < 8; attempt++ {
		eph := make([]byte, 32)
		if _, err := rand.Read(eph); err != nil {
			return nil, nil, err
		}
		ctX, err := curve25519.X25519(eph, curve25519.Basepoint)
		if err != nil {
			continue
		}
		ssX, err := curve25519.X25519(eph, pkX)
		if err != nil {
			return nil, nil, errf(CatUsage, "", "X25519 shared secret is zero")
		}
		key, err := combinerKey(ssX, ssM, ctX, ctM, pkX, pkM, ctx)
		if err != nil {
			return nil, nil, err
		}
		out := make([]byte, 0, 32+1088)
		out = append(out, ctX...)
		out = append(out, ctM...)
		return out, key, nil
	}
	return nil, nil, errf(CatUsage, "", "X25519 ephemeral generation failed")
}

// HybridDecapsulate reverses HybridEncapsulate. The hybrid secret key is
// sk_x25519 ‖ dk_mlkem (32 + 64 bytes) and the ciphertext is
// ct_x25519 ‖ ct_mlkem (32 + 1088 bytes).
func HybridDecapsulate(sk, ct []byte, ctx KemContext) ([]byte, error) {
	if len(sk) != 96 {
		return nil, errf(CatUsage, "", "hybrid secret key is %d bytes, need 96", len(sk))
	}
	if len(ct) != 32+1088 {
		return nil, errf(CatUsage, "", "hybrid ciphertext is %d bytes, need 1120", len(ct))
	}
	skX := sk[:32]
	seed := sk[32:]
	ctX := ct[:32]
	ctM := ct[32:]

	ssX, err := curve25519.X25519(skX, ctX)
	if err != nil {
		return nil, errf(CatUsage, "", "X25519 decapsulation failed")
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, errf(CatUsage, "", "bad ML-KEM decapsulation seed")
	}
	ssM, err := dk.Decapsulate(ctM)
	if err != nil {
		return nil, errf(CatUsage, "", "ML-KEM decapsulation failed")
	}
	pkX, err := curve25519.X25519(skX, curve25519.Basepoint)
	if err != nil {
		return nil, errf(CatUsage, "", "X25519 public key derivation failed")
	}
	pkM := dk.EncapsulationKey().Bytes()
	return combinerKey(ssX, ssM, ctX, ctM, pkX, pkM, ctx)
}

// ---- AEAD-STREAM (§20.2) ----

// streamNonce builds the per-chunk STREAM nonce.
func streamNonce(suite Suite, sectionID uint16, chunkIndex uint32, final bool) []byte {
	nonce := make([]byte, suite.NonceLen)
	binary.LittleEndian.PutUint16(nonce[0:2], sectionID)
	binary.BigEndian.PutUint32(nonce[suite.NonceLen-5:suite.NonceLen-1], chunkIndex)
	if final {
		nonce[suite.NonceLen-1] = 0x01
	} else {
		nonce[suite.NonceLen-1] = 0x00
	}
	return nonce
}

// streamAAD builds the per-chunk STREAM additional authenticated data.
func streamAAD(sectionID uint16, chunkIndex uint32, lenPlain uint64, suiteID uint16) []byte {
	aad := make([]byte, 0, len(streamLabel)+2+4+8+2)
	aad = append(aad, streamLabel...)
	aad = binary.LittleEndian.AppendUint16(aad, sectionID)
	aad = binary.LittleEndian.AppendUint32(aad, chunkIndex)
	aad = binary.LittleEndian.AppendUint64(aad, lenPlain)
	aad = binary.LittleEndian.AppendUint16(aad, suiteID)
	return aad
}

// SealStream encrypts a plaintext into the STREAM body format
// (u32_le(ct_len) ‖ ct)* for an unencoded (comp = 0) section. chunkSize must be
// non-zero and a legal power of two.
func SealStream(suiteID, sectionID uint16, chunkSize uint32, contentKey, plaintext []byte) ([]byte, error) {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize || chunkSize&(chunkSize-1) != 0 {
		return nil, errf(CatUsage, "R14", "illegal chunk_size %d", chunkSize)
	}
	count, ok := chunkCount(uint64(len(plaintext)), uint64(chunkSize))
	if !ok {
		return nil, errf(CatUsage, "", "chunk count overflows")
	}
	if count < 1 {
		count = 1 // empty plaintext still has one final chunk
	}
	body := make([]byte, 0, len(plaintext)+int(count)*(16+4))
	for i := uint64(0); i < count; i++ {
		start := i * uint64(chunkSize)
		end := start + uint64(chunkSize)
		if end > uint64(len(plaintext)) {
			end = uint64(len(plaintext))
		}
		final := i == count-1
		nonce := streamNonce(suite, sectionID, uint32(i), final)
		aad := streamAAD(sectionID, uint32(i), uint64(len(plaintext)), suiteID)
		ct, err := SealAEAD(suiteID, contentKey, nonce, plaintext[start:end], aad)
		if err != nil {
			return nil, err
		}
		if len(ct) < 16 {
			return nil, errf(CatUsage, "", "AEAD output shorter than its tag")
		}
		body = binary.LittleEndian.AppendUint32(body, uint32(len(ct)))
		body = append(body, ct...)
	}
	return body, nil
}

// OpenStream verifies and decrypts a STREAM body. Every chunk is authenticated
// before any plaintext is returned (C7).
func OpenStream(suiteID, sectionID uint16, chunkSize uint32, lenPlain uint64, contentKey, body []byte) ([]byte, error) {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, err
	}
	var out []byte
	pos := 0
	for i := uint32(0); ; i++ {
		if pos+4 > len(body) {
			return nil, errf(CatSection, "§20.2", "truncated chunk length prefix")
		}
		ctLen := binary.LittleEndian.Uint32(body[pos:])
		pos += 4
		if ctLen < 16 {
			return nil, errf(CatSection, "§20.2", "chunk %d ct_len %d below tag length", i, ctLen)
		}
		if uint64(pos)+uint64(ctLen) > uint64(len(body)) {
			return nil, errf(CatSection, "§20.2", "chunk %d extends beyond body", i)
		}
		ct := body[pos : pos+int(ctLen)]
		pos += int(ctLen)
		final := pos == len(body)
		nonce := streamNonce(suite, sectionID, i, final)
		aad := streamAAD(sectionID, i, lenPlain, suiteID)
		pt, err := OpenAEAD(suiteID, contentKey, nonce, ct, aad)
		if err != nil {
			return nil, errf(CatSection, "§20.2", "chunk %d tag does not verify", i)
		}
		out = append(out, pt...)
		if final {
			break
		}
	}
	if uint64(len(out)) != lenPlain {
		return nil, errf(CatSection, "§20.2", "plaintext length %d != declared %d", len(out), lenPlain)
	}
	return out, nil
}

// ---- Hybrid signatures (§20.3) ----

// HybridPublicKey is Ed25519 ‖ ML-DSA-65 (32 + 1952 bytes).
type HybridPublicKey struct {
	Ed    []byte
	MLDSA []byte
}

// HybridPrivateKey is the pair of signing keys.
type HybridPrivateKey struct {
	Ed    []byte
	MLDSA *mldsa.PrivateKey
}

// GenerateHybridKey generates an Ed25519 key and an ML-DSA-65 key.
func GenerateHybridKey() (*HybridPrivateKey, *HybridPublicKey, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	mpriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, nil, err
	}
	return &HybridPrivateKey{Ed: edPriv, MLDSA: mpriv},
		&HybridPublicKey{Ed: edPub, MLDSA: mpriv.PublicKey().Bytes()}, nil
}

// SignHybrid signs the transcript with both components. Suites 1 and 2 are
// supported; suite 3 is reported as not implemented rather than reduced (S5).
func SignHybrid(suiteID uint16, key *HybridPrivateKey, transcript []byte) (classical, pq []byte, err error) {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return nil, nil, err
	}
	if suite.HasSLHDSA {
		return nil, nil, errf(CatUsage, "", "suite %d adds SLH-DSA, which is not implemented", suiteID)
	}
	classical = ed25519.Sign(key.Ed, transcript)
	pq, err = key.MLDSA.Sign(nil, transcript, nil)
	if err != nil {
		return nil, nil, err
	}
	return classical, pq, nil
}

// VerifyHybrid verifies both components over the identical transcript. A
// failure of either is a failure of the whole.
func VerifyHybrid(suiteID uint16, pk *HybridPublicKey, transcript, classical, pq []byte) error {
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return err
	}
	if suite.HasSLHDSA {
		return errf(CatUsage, "", "suite %d adds SLH-DSA, which is not implemented", suiteID)
	}
	if len(classical) != 64 {
		return errf(CatUsage, "§20.3", "classical signature is %d bytes, need 64", len(classical))
	}
	if len(pq) != suite.PQSigLen {
		return errf(CatUsage, "§20.3", "PQ signature is %d bytes, need %d", len(pq), suite.PQSigLen)
	}
	if !ed25519.Verify(pk.Ed, transcript, classical) {
		return errf(CatUsage, "§20.3", "Ed25519 component does not verify")
	}
	mpk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pk.MLDSA)
	if err != nil {
		return errf(CatUsage, "§20.3", "bad ML-DSA public key")
	}
	if err := mldsa.Verify(mpk, transcript, pq, nil); err != nil {
		return errf(CatUsage, "§20.3", "ML-DSA-65 component does not verify")
	}
	return nil
}

// FooterTranscript builds the 67-byte §8.4 signature transcript.
func FooterTranscript(suiteID uint16, sigClassicalLen, sigPQLen uint32, root [RootLen]byte, totalLen uint64) []byte {
	out := make([]byte, 0, 67)
	out = append(out, footerSigLabelV2...)
	out = binary.LittleEndian.AppendUint16(out, suiteID)
	out = binary.LittleEndian.AppendUint32(out, sigClassicalLen)
	out = binary.LittleEndian.AppendUint32(out, sigPQLen)
	out = append(out, root[:]...)
	out = binary.LittleEndian.AppendUint64(out, totalLen)
	return out
}

// SignatureSlotLengths returns the suite-fixed slot lengths (§20.3). A verifier
// derives boundaries from the suite, never from the footer's length fields.
func SignatureSlotLengths(suiteID uint16) (classical, pq int, err error) {
	s, err := LookupSuite(suiteID)
	if err != nil {
		return 0, 0, err
	}
	return 64, s.PQSigLen, nil
}

// ErrNotImplemented marks a role this implementation does not provide.
var ErrNotImplemented = errors.New("not implemented")

// EntitlementTranscript builds the 60-byte §18.3 signature transcript.
func EntitlementTranscript(suiteID uint16, seq uint32, recordID [RootLen]byte) []byte {
	out := make([]byte, 0, 60)
	out = append(out, entitlementSigLabel...)
	out = binary.LittleEndian.AppendUint16(out, suiteID)
	out = binary.LittleEndian.AppendUint32(out, seq)
	out = append(out, recordID[:]...)
	return out
}
