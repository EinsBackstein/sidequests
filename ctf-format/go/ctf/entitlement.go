package ctf

import (
	"bytes"

	"lukechampine.com/blake3"
)

// Entitlement chains are the append-only, hash-chained, hybrid-signed log of
// spec §18. An `entitlement` section (kind 6) carries one canonical CBOR array
// of record maps.
//
// E1–E8 are structural and need no keys. E9 requires a TrustSet (§34), which is
// always a caller input and never read from a bundle (KD1). A chain that has
// passed E1–E8 is intact, not authentic: VerifySignatures is the separate step
// that runs E9.

// EntitlementType is the `type` field of a record (§18.1).
type EntitlementType string

// The four record types (§18.1). Anything else is E4.
const (
	EntitlementGrant    EntitlementType = "grant"
	EntitlementTransfer EntitlementType = "transfer"
	EntitlementRevoke   EntitlementType = "revoke"
	EntitlementProgress EntitlementType = "progress"
)

// EntitlementTimestamp is the advisory `timestamp` field. Negative holds the
// CBOR major-type-1 argument n, whose mathematical value is -1-n, so every
// representable integer round-trips. §18.2 forbids using it for ordering or
// validation.
type EntitlementTimestamp struct {
	Negative bool
	N        uint64
}

// EntitlementSignature is one hybrid signature map with exactly the keys
// `classical` and `pq` (§18.1).
type EntitlementSignature struct {
	Classical []byte
	PQ        []byte
}

// EntitlementRecord is one §18.1 record. The 32-byte fields are arrays, so a
// wrong length cannot be constructed; the decoder still enforces it with E2.
type EntitlementRecord struct {
	Seq       uint32
	Type      EntitlementType
	Challenge string
	Subject   string
	Holder    [RootLen]byte
	Prev      [RootLen]byte
	Root      *[RootLen]byte // genesis only; absent otherwise (E5, E6)
	Timestamp *EntitlementTimestamp
	Payload   []byte
	// HasPayload distinguishes an absent `payload` from a present empty one.
	HasPayload  bool
	SigHolder   *EntitlementSignature // required for transfer, absent otherwise (E8)
	SigPlatform *EntitlementSignature // always required (E8)
}

// EntitlementChain is an ordered array of records. Record order is the chain
// order; `seq` is the authoritative field and must agree with it (E3).
type EntitlementChain struct {
	Records []EntitlementRecord
}

var entitlementRecordKeys = []string{
	"seq", "type", "challenge", "subject", "holder", "prev", "root",
	"timestamp", "payload", "sig_holder", "sig_platform",
}

func validEntitlementType(t EntitlementType) bool {
	switch t {
	case EntitlementGrant, EntitlementTransfer, EntitlementRevoke, EntitlementProgress:
		return true
	}
	return false
}

func (s *EntitlementSignature) value() Value {
	return MapValue(
		Pair{Key: Text("classical"), Val: Bytes(s.Classical)},
		Pair{Key: Text("pq"), Val: Bytes(s.PQ)},
	)
}

func (t *EntitlementTimestamp) value() Value {
	if t.Negative {
		return Nint(t.N)
	}
	return Uint(t.N)
}

// recordValue builds the canonical CBOR map for a record. includeSignatures is
// false for the record-id preimage, which removes both sig_* keys (§18.2).
func (r *EntitlementRecord) recordValue(includeSignatures bool) (Value, error) {
	pairs := []Pair{
		{Key: Text("seq"), Val: Uint(uint64(r.Seq))},
		{Key: Text("type"), Val: Text(string(r.Type))},
		{Key: Text("challenge"), Val: Text(r.Challenge)},
		{Key: Text("subject"), Val: Text(r.Subject)},
		{Key: Text("holder"), Val: Bytes(r.Holder[:])},
		{Key: Text("prev"), Val: Bytes(r.Prev[:])},
	}
	if r.Root != nil {
		pairs = append(pairs, Pair{Key: Text("root"), Val: Bytes(r.Root[:])})
	}
	if r.Timestamp != nil {
		pairs = append(pairs, Pair{Key: Text("timestamp"), Val: r.Timestamp.value()})
	}
	if r.HasPayload {
		pairs = append(pairs, Pair{Key: Text("payload"), Val: Bytes(r.Payload)})
	}
	if includeSignatures {
		if r.SigHolder != nil {
			pairs = append(pairs, Pair{Key: Text("sig_holder"), Val: r.SigHolder.value()})
		}
		if r.SigPlatform != nil {
			pairs = append(pairs, Pair{Key: Text("sig_platform"), Val: r.SigPlatform.value()})
		}
	}
	return canonicalize(MapValue(pairs...))
}

// RecordID returns BLAKE3("ctf/entitlement/record/v1" ‖ cbor), where cbor is
// the canonical encoding of the record with both sig_* keys removed (§18.2).
// Removing the signatures is what lets the id appear inside the transcript
// both signatures cover.
func (r *EntitlementRecord) RecordID() ([RootLen]byte, error) {
	var out [RootLen]byte
	v, err := r.recordValue(false)
	if err != nil {
		return out, err
	}
	cbor, err := encodeValue(v)
	if err != nil {
		return out, err
	}
	h := blake3.New(RootLen, nil)
	h.Write([]byte(recordIDLabel))
	h.Write(cbor)
	copy(out[:], h.Sum(nil))
	return out, nil
}

// checkStructure applies the per-record rules that do not depend on position:
// E2's types (enforced by the typed fields), E4, and E8's signature pairing.
func (r *EntitlementRecord) checkStructure() error {
	if !validEntitlementType(r.Type) {
		return errf(CatEntitlement, "E4", "record %d: type is not one of grant, transfer, revoke, progress", r.Seq)
	}
	if r.SigPlatform == nil {
		return errf(CatEntitlement, "E8", "record %d: sig_platform is absent", r.Seq)
	}
	if r.Type == EntitlementTransfer {
		if r.SigHolder == nil {
			return errf(CatEntitlement, "E8", "record %d: transfer is missing sig_holder", r.Seq)
		}
	} else if r.SigHolder != nil {
		return errf(CatEntitlement, "E8", "record %d: non-transfer carries sig_holder", r.Seq)
	}
	return nil
}

// Validate applies E1–E8. The plaintext's canonical-CBOR half of E1 is applied
// by DecodeEntitlementChain; this function checks the array's structure and the
// chain rules for both decoded and hand-built chains.
func (c *EntitlementChain) Validate() error {
	if len(c.Records) == 0 {
		return errf(CatEntitlement, "E5", "chain is empty; a genesis grant is required")
	}
	for n := range c.Records {
		r := &c.Records[n]
		if err := r.checkStructure(); err != nil {
			return err
		}
		if r.Seq != uint32(n) {
			return errf(CatEntitlement, "E3", "record %d has seq %d, want %d", n, r.Seq, n)
		}
		if n == 0 {
			if r.Type != EntitlementGrant {
				return errf(CatEntitlement, "E5", "genesis record is not a grant")
			}
			if r.Root == nil {
				return errf(CatEntitlement, "E5", "genesis record does not carry root")
			}
			var zero [RootLen]byte
			if r.Prev != zero {
				return errf(CatEntitlement, "E5", "genesis record has a non-zero prev")
			}
			continue
		}
		if r.Root != nil {
			return errf(CatEntitlement, "E6", "record %d carries root after genesis", n)
		}
		prevID, err := c.Records[n-1].RecordID()
		if err != nil {
			return errf(CatEntitlement, "E7", "record %d: predecessor id could not be computed", n)
		}
		if r.Prev != prevID {
			return errf(CatEntitlement, "E7", "record %d: prev does not equal the predecessor record id", n)
		}
	}
	return nil
}

// DecodeEntitlementChain decodes and validates a section plaintext: canonical
// CBOR (E1), every record's fields (E2, E4, E8), and the chain rules (E3,
// E5–E7). It does not run E9.
func DecodeEntitlementChain(plaintext []byte) (*EntitlementChain, error) {
	v, err := decodeCBOR(plaintext)
	if err != nil {
		return nil, errf(CatEntitlement, "E1", "plaintext is not canonical CBOR: %v", err)
	}
	// §18 requires the plaintext to be canonical CBOR under §7.1, exactly as the
	// manifest does: re-encoding an accepted value must reproduce the input.
	again, err := encodeValue(v)
	if err != nil {
		return nil, errf(CatEntitlement, "E1", "plaintext is not canonical CBOR")
	}
	if !bytes.Equal(again, plaintext) {
		return nil, errf(CatEntitlement, "E1", "plaintext does not re-encode to its input bytes")
	}
	if v.Kind != ValueArray {
		return nil, errf(CatEntitlement, "E1", "plaintext is not a CBOR array")
	}
	chain := &EntitlementChain{Records: make([]EntitlementRecord, 0, len(v.A))}
	for i := range v.A {
		r, err := decodeEntitlementRecord(v.A[i], i)
		if err != nil {
			return nil, err
		}
		chain.Records = append(chain.Records, r)
	}
	if err := chain.Validate(); err != nil {
		return nil, err
	}
	return chain, nil
}

func decodeEntitlementRecord(v Value, index int) (EntitlementRecord, error) {
	var r EntitlementRecord
	if v.Kind != ValueMap {
		return r, errf(CatEntitlement, "E2", "record %d is not a map", index)
	}
	for _, pair := range v.M {
		if pair.Key.Kind != ValueText {
			return r, errf(CatEntitlement, "E2", "record %d has a non-text key", index)
		}
		known := false
		for _, k := range entitlementRecordKeys {
			if pair.Key.T == k {
				known = true
				break
			}
		}
		if !known {
			return r, errf(CatEntitlement, "E2", "record %d has an unknown key", index)
		}
	}

	get := func(key string) (Value, bool) {
		for _, pair := range v.M {
			if pair.Key.T == key {
				return pair.Val, true
			}
		}
		return Value{}, false
	}
	requiredText := func(key string) (string, error) {
		val, ok := get(key)
		if !ok || val.Kind != ValueText {
			return "", errf(CatEntitlement, "E2", "record %d: %s is absent or not text", index, key)
		}
		return val.T, nil
	}
	required32 := func(key string) ([RootLen]byte, error) {
		var out [RootLen]byte
		val, ok := get(key)
		if !ok || val.Kind != ValueBytes || len(val.B) != RootLen {
			return out, errf(CatEntitlement, "E2", "record %d: %s is not a 32-byte string", index, key)
		}
		copy(out[:], val.B)
		return out, nil
	}

	seq, ok := get("seq")
	if !ok || seq.Kind != ValueUint || seq.U > 0xffffffff {
		return r, errf(CatEntitlement, "E2", "record %d: seq is absent or not a uint32", index)
	}
	r.Seq = uint32(seq.U)

	typ, err := requiredText("type")
	if err != nil {
		return r, err
	}
	r.Type = EntitlementType(typ)
	if !validEntitlementType(r.Type) {
		return r, errf(CatEntitlement, "E4", "record %d: type is not one of grant, transfer, revoke, progress", index)
	}
	if r.Challenge, err = requiredText("challenge"); err != nil {
		return r, err
	}
	if r.Subject, err = requiredText("subject"); err != nil {
		return r, err
	}
	if r.Holder, err = required32("holder"); err != nil {
		return r, err
	}
	if r.Prev, err = required32("prev"); err != nil {
		return r, err
	}

	if root, ok := get("root"); ok {
		if root.Kind != ValueBytes || len(root.B) != RootLen {
			return r, errf(CatEntitlement, "E2", "record %d: root is not a 32-byte string", index)
		}
		var fixed [RootLen]byte
		copy(fixed[:], root.B)
		r.Root = &fixed
	}
	if ts, ok := get("timestamp"); ok {
		switch ts.Kind {
		case ValueUint:
			r.Timestamp = &EntitlementTimestamp{N: ts.U}
		case ValueNint:
			r.Timestamp = &EntitlementTimestamp{Negative: true, N: ts.U}
		default:
			return r, errf(CatEntitlement, "E2", "record %d: timestamp is not an integer", index)
		}
	}
	if payload, ok := get("payload"); ok {
		if payload.Kind != ValueBytes {
			return r, errf(CatEntitlement, "E2", "record %d: payload is not a byte string", index)
		}
		r.Payload = payload.B
		r.HasPayload = true
	}
	if sig, ok := get("sig_holder"); ok {
		s, err := decodeEntitlementSignature(sig, index, "sig_holder")
		if err != nil {
			return r, err
		}
		r.SigHolder = s
	}
	if sig, ok := get("sig_platform"); ok {
		s, err := decodeEntitlementSignature(sig, index, "sig_platform")
		if err != nil {
			return r, err
		}
		r.SigPlatform = s
	}
	if err := r.checkStructure(); err != nil {
		return r, err
	}
	return r, nil
}

func decodeEntitlementSignature(v Value, index int, which string) (*EntitlementSignature, error) {
	if v.Kind != ValueMap {
		return nil, errf(CatEntitlement, "E2", "record %d: %s is not a map", index, which)
	}
	var sig EntitlementSignature
	var haveClassical, havePQ bool
	for _, pair := range v.M {
		if pair.Key.Kind != ValueText {
			return nil, errf(CatEntitlement, "E2", "record %d: %s has a non-text key", index, which)
		}
		switch pair.Key.T {
		case "classical":
			if pair.Val.Kind != ValueBytes {
				return nil, errf(CatEntitlement, "E2", "record %d: %s classical is not bytes", index, which)
			}
			sig.Classical = pair.Val.B
			haveClassical = true
		case "pq":
			if pair.Val.Kind != ValueBytes {
				return nil, errf(CatEntitlement, "E2", "record %d: %s pq is not bytes", index, which)
			}
			sig.PQ = pair.Val.B
			havePQ = true
		default:
			return nil, errf(CatEntitlement, "E2", "record %d: %s has an unknown key", index, which)
		}
	}
	if !haveClassical || !havePQ || len(v.M) != 2 {
		return nil, errf(CatEntitlement, "E2", "record %d: %s is not exactly classical and pq", index, which)
	}
	return &sig, nil
}

// Encode validates E1–E8 and returns the canonical CBOR array a section carries.
func (c *EntitlementChain) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	items := make([]Value, 0, len(c.Records))
	for i := range c.Records {
		v, err := c.Records[i].recordValue(true)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	cv, err := canonicalize(Value{Kind: ValueArray, A: items})
	if err != nil {
		return nil, err
	}
	return encodeValue(cv)
}

// SignRecord signs record n over the §18.3 transcript: the platform signature
// always, and for a transfer the current holder's signature. A non-transfer's
// sig_holder is cleared so signing cannot leave an unauthenticated map behind.
func (c *EntitlementChain) SignRecord(n int, suiteID uint16, platform, holder *HybridPrivateKey) error {
	if n < 0 || n >= len(c.Records) {
		return errf(CatEntitlement, "E2", "record index %d is out of range", n)
	}
	r := &c.Records[n]
	recordID, err := r.RecordID()
	if err != nil {
		return err
	}
	transcript := EntitlementTranscript(suiteID, r.Seq, recordID)
	classical, pq, err := SignHybrid(suiteID, platform, transcript)
	if err != nil {
		return err
	}
	r.SigPlatform = &EntitlementSignature{Classical: classical, PQ: pq}
	if r.Type == EntitlementTransfer {
		if holder == nil {
			return errf(CatEntitlement, "E9", "transfer record %d requires the current holder's signing key", n)
		}
		classical, pq, err = SignHybrid(suiteID, holder, transcript)
		if err != nil {
			return err
		}
		r.SigHolder = &EntitlementSignature{Classical: classical, PQ: pq}
	} else {
		r.SigHolder = nil
	}
	return nil
}

// ---- §34 trust set ----

// TrustRole is a key role of §34.2. Roles are not interchangeable (KD4).
type TrustRole string

const (
	TrustRoleRoot     TrustRole = "root"
	TrustRolePlatform TrustRole = "platform"
	TrustRoleHolder   TrustRole = "holder"
)

// TrustSet is the verifier's out-of-band key input (KD1). Each role has its own
// lookup, so a key supplied for one role is never accepted for another (KD4).
type TrustSet struct {
	Root     []HybridPublicKey
	Platform []HybridPublicKey
	holders  map[[RootLen]byte]HybridPublicKey
}

// NewTrustSet returns an empty trust set. An empty set trusts nothing.
func NewTrustSet() *TrustSet {
	return &TrustSet{holders: make(map[[RootLen]byte]HybridPublicKey)}
}

// AddRoot trusts pk for the footer signature role.
func (t *TrustSet) AddRoot(pk HybridPublicKey) { t.Root = append(t.Root, pk) }

// AddPlatform trusts pk for sig_platform on every entitlement record.
func (t *TrustSet) AddPlatform(pk HybridPublicKey) { t.Platform = append(t.Platform, pk) }

// AddHolder trusts pk for a transfer's sig_holder under the §34.1 holder hash.
// The hash is computed from the key, never supplied by the caller (KD2), so a
// registration cannot vouch for a key under a hash it does not hash to.
func (t *TrustSet) AddHolder(suiteID uint16, pk HybridPublicKey) error {
	if t.holders == nil {
		t.holders = make(map[[RootLen]byte]HybridPublicKey)
	}
	h, err := HolderHash(suiteID, &pk)
	if err != nil {
		return err
	}
	t.holders[h] = pk
	return nil
}

// holderKey resolves a record's holder field through the trusted holder keys.
// A miss is an E9 failure, not a structural one (§34.1).
func (t *TrustSet) holderKey(h [RootLen]byte) (HybridPublicKey, bool) {
	pk, ok := t.holders[h]
	return pk, ok
}

// HolderHash builds the §34.1 holder public-key hash:
// BLAKE3("ctf/holder-hash/v1" ‖ pk_classical ‖ pk_pq). For suite 3, pk_pq is
// ML-DSA-65 ‖ SLH-DSA-SHA2-128s, in the §20.3 slot order.
func HolderHash(suiteID uint16, pk *HybridPublicKey) ([RootLen]byte, error) {
	var out [RootLen]byte
	suite, err := LookupSuite(suiteID)
	if err != nil {
		return out, err
	}
	if pk == nil || len(pk.Ed) != Ed25519PublicKeyLen {
		return out, errf(CatUsage, "KD2", "holder Ed25519 public key is not %d bytes", Ed25519PublicKeyLen)
	}
	if len(pk.MLDSA) != MLDSA65PublicKeyLen {
		return out, errf(CatUsage, "KD2", "holder ML-DSA-65 public key is not %d bytes", MLDSA65PublicKeyLen)
	}
	h := blake3.New(RootLen, nil)
	h.Write([]byte(holderHashLabel))
	h.Write(pk.Ed)
	h.Write(pk.MLDSA)
	if suite.HasSLHDSA {
		if len(pk.SLH) != SLHDSA128sPublicKeyLen {
			return out, errf(CatUsage, "KD2", "holder SLH-DSA-SHA2-128s public key is not %d bytes", SLHDSA128sPublicKeyLen)
		}
		h.Write(pk.SLH)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifySignatures runs E9 over the whole chain. E1–E8 must already have
// passed. The platform key is required for every record; a transfer's
// sig_holder is verified against the key the predecessor's holder resolves to
// (KD3). Both components of each signature must verify; a failure of either is
// a failure of the whole.
//
// This does not establish that a chain's genesis `root` names the bundle version
// being checked. §18.5 requires a verifier that holds that version to compare
// against it; Use ValidateAgainstRoot for that separate check.
func (c *EntitlementChain) VerifySignatures(suiteID uint16, trust *TrustSet) error {
	if _, err := LookupSuite(suiteID); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if trust == nil || len(trust.Platform) == 0 {
		return errf(CatEntitlement, "E9", "no trusted platform key")
	}
	for n := range c.Records {
		r := &c.Records[n]
		recordID, err := r.RecordID()
		if err != nil {
			return errf(CatEntitlement, "E9", "record %d: record id could not be computed", n)
		}
		transcript := EntitlementTranscript(suiteID, r.Seq, recordID)
		if r.SigPlatform == nil {
			return errf(CatEntitlement, "E8", "record %d: sig_platform is absent", n)
		}
		if !verifyUnderAny(suiteID, trust.Platform, transcript, r.SigPlatform) {
			return errf(CatEntitlement, "E9", "record %d: sig_platform does not verify under a trusted platform key", n)
		}
		if r.Type != EntitlementTransfer {
			continue
		}
		if n == 0 {
			return errf(CatEntitlement, "E9", "record %d: transfer has no predecessor to name the current holder", n)
		}
		holder, ok := trust.holderKey(c.Records[n-1].Holder)
		if !ok {
			return errf(CatEntitlement, "E9", "record %d: holder is not resolved by a trusted holder key", n)
		}
		if r.SigHolder == nil {
			return errf(CatEntitlement, "E8", "record %d: transfer is missing sig_holder", n)
		}
		if err := VerifyHybrid(suiteID, &holder, transcript, r.SigHolder.Classical, r.SigHolder.PQ); err != nil {
			return errf(CatEntitlement, "E9", "record %d: sig_holder does not verify under the current holder's trusted key", n)
		}
	}
	return nil
}

func verifyUnderAny(suiteID uint16, keys []HybridPublicKey, transcript []byte, sig *EntitlementSignature) bool {
	for i := range keys {
		if VerifyHybrid(suiteID, &keys[i], transcript, sig.Classical, sig.PQ) == nil {
			return true
		}
	}
	return false
}

// VerifyFooterSignature verifies a §8.4 footer signature against the root role
// only. It exists so the root role is usable without borrowing a platform or
// holder key (KD4).
func (t *TrustSet) VerifyFooterSignature(suiteID uint16, transcript, classical, pq []byte) error {
	if t == nil || len(t.Root) == 0 {
		return errf(CatUsage, "KD4", "no trusted root key")
	}
	sig := &EntitlementSignature{Classical: classical, PQ: pq}
	if !verifyUnderAny(suiteID, t.Root, transcript, sig) {
		return errf(CatUsage, "KD4", "footer signature does not verify under a trusted root key")
	}
	return nil
}

// ValidateAgainstRoot additionally requires the genesis grant's root to equal
// commitmentRoot, the commitment root of the bundle version the grant was issued
// for (§18.2, §18.5). It must not be the root of the file carrying the chain,
// which no chain can name.
func (c *EntitlementChain) ValidateAgainstRoot(commitmentRoot [RootLen]byte) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Records[0].Root == nil || *c.Records[0].Root != commitmentRoot {
		return errf(CatEntitlement, "E5", "genesis root does not equal the bundle commitment root")
	}
	return nil
}

// EntitlementSection decodes an entitlement section's plaintext and returns the
// chain. The section's root must already have verified (SectionPlaintext does
// that); this function only applies E1–E8.
func (b *Bundle) EntitlementSection(nameID uint16) (*EntitlementChain, error) {
	plain, err := b.SectionPlaintext(nameID, nil)
	if err != nil {
		return nil, err
	}
	return DecodeEntitlementChain(plain)
}
