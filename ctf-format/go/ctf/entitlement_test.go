package ctf

import (
	"bytes"
	"errors"
	"testing"
)

type entitlementFixture struct {
	chain      *EntitlementChain
	platform   *HybridPrivateKey
	holder1    *HybridPrivateKey
	holder2    *HybridPrivateKey
	trust      *TrustSet
	commitment [RootLen]byte
}

// newEntitlementFixture builds grant → transfer → progress, signed with suite 1.
// Timestamps descend on purpose: §18.2 makes them advisory, so ordering must
// follow seq, not time.
func newEntitlementFixture(t *testing.T) *entitlementFixture {
	t.Helper()
	platformPriv, platformPub, err := GenerateHybridKey()
	if err != nil {
		t.Fatal(err)
	}
	h1Priv, h1Pub, err := GenerateHybridKey()
	if err != nil {
		t.Fatal(err)
	}
	h2Priv, h2Pub, err := GenerateHybridKey()
	if err != nil {
		t.Fatal(err)
	}
	h1, err := HolderHash(1, h1Pub)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HolderHash(1, h2Pub)
	if err != nil {
		t.Fatal(err)
	}

	commitment := [RootLen]byte{0xaa}
	root := commitment
	chain := &EntitlementChain{Records: []EntitlementRecord{{
		Seq:       0,
		Type:      EntitlementGrant,
		Challenge: "whos-that-bird",
		Subject:   "alice",
		Holder:    h1,
		Root:      &root,
		Timestamp: &EntitlementTimestamp{N: 9000},
	}}}
	id0, err := chain.Records[0].RecordID()
	if err != nil {
		t.Fatal(err)
	}
	chain.Records = append(chain.Records, EntitlementRecord{
		Seq:       1,
		Type:      EntitlementTransfer,
		Challenge: "whos-that-bird",
		Subject:   "alice",
		Holder:    h2,
		Prev:      id0,
		Timestamp: &EntitlementTimestamp{N: 10},
	})
	id1, err := chain.Records[1].RecordID()
	if err != nil {
		t.Fatal(err)
	}
	chain.Records = append(chain.Records, EntitlementRecord{
		Seq:        2,
		Type:       EntitlementProgress,
		Challenge:  "whos-that-bird",
		Subject:    "alice",
		Holder:     h2,
		Prev:       id1,
		Timestamp:  &EntitlementTimestamp{Negative: true, N: 7},
		Payload:    []byte{0xde, 0xad, 0xbe, 0xef},
		HasPayload: true,
	})
	if err := chain.SignRecord(0, 1, platformPriv, nil); err != nil {
		t.Fatal(err)
	}
	if err := chain.SignRecord(1, 1, platformPriv, h1Priv); err != nil {
		t.Fatal(err)
	}
	if err := chain.SignRecord(2, 1, platformPriv, nil); err != nil {
		t.Fatal(err)
	}
	trust := NewTrustSet()
	trust.AddPlatform(*platformPub)
	trust.AddRoot(*platformPub)
	if err := trust.AddHolder(1, *h1Pub); err != nil {
		t.Fatal(err)
	}
	if err := trust.AddHolder(1, *h2Pub); err != nil {
		t.Fatal(err)
	}
	return &entitlementFixture{
		chain:      chain,
		platform:   platformPriv,
		holder1:    h1Priv,
		holder2:    h2Priv,
		trust:      trust,
		commitment: commitment,
	}
}

func TestEntitlementChainValidRoundTripAndE9(t *testing.T) {
	f := newEntitlementFixture(t)
	if err := f.chain.Validate(); err != nil {
		t.Fatalf("E1–E8: %v", err)
	}
	encoded, err := f.chain.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeEntitlementChain(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Records) != 3 {
		t.Fatalf("decoded %d records", len(decoded.Records))
	}
	again, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(again, encoded) {
		t.Fatal("chain does not round-trip byte-for-byte")
	}
	if err := decoded.ValidateAgainstRoot(f.commitment); err != nil {
		t.Fatalf("genesis root binding: %v", err)
	}
	if err := decoded.VerifySignatures(1, f.trust); err != nil {
		t.Fatalf("E9: %v", err)
	}
	// Progress payload survives the round trip, including the present-but-empty
	// distinction.
	last := decoded.Records[2]
	if !last.HasPayload || !bytes.Equal(last.Payload, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("progress payload was not preserved: %+v", last)
	}
	if last.Timestamp == nil || !last.Timestamp.Negative || last.Timestamp.N != 7 {
		t.Fatalf("negative timestamp was not preserved: %+v", last.Timestamp)
	}
	// Timestamps descend while seq ascends; ordering is seq (E3), not the clock.
	if decoded.Records[0].Seq != 0 || decoded.Records[1].Seq != 1 || decoded.Records[2].Seq != 2 {
		t.Fatal("records are not ordered by seq")
	}
}

func TestEntitlementE1E2E3Mutations(t *testing.T) {
	f := newEntitlementFixture(t)
	encoded, err := f.chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rule string
		raw  []byte
	}{
		{"E1-trailing-byte", "E1", append(append([]byte(nil), encoded...), 0x00)},
		{"E1-not-array", "E1", mustCBOR(t, Value{Kind: ValueMap})},
		{"E1-non-canonical", "E1", append([]byte{0x9f}, append(encoded, 0xff)...)},
		{"E2-seq-wrong-type", "E2", mutateRecord(t, encoded, 0, func(v *Value) {
			pairValue(v, "seq").Kind = ValueText
			pairValue(v, "seq").T = "zero"
		})},
		{"E2-unknown-key", "E2", mutateRecord(t, encoded, 0, func(v *Value) {
			v.M = append(v.M, Pair{Key: Text("extra"), Val: Uint(0)})
		})},
		{"E2-holder-wrong-length", "E2", mutateRecord(t, encoded, 0, func(v *Value) {
			pairValue(v, "holder").B = pairValue(v, "holder").B[:31]
		})},
		{"E2-signature-extra-key", "E2", mutateRecord(t, encoded, 1, func(v *Value) {
			sig := pairValue(v, "sig_platform")
			sig.M = append(sig.M, Pair{Key: Text("extra"), Val: Bytes([]byte{1})})
		})},
		{"E2-signature-missing-pq", "E2", mutateRecord(t, encoded, 1, func(v *Value) {
			sig := pairValue(v, "sig_platform")
			kept := sig.M[:0]
			for _, p := range sig.M {
				if p.Key.T != "pq" {
					kept = append(kept, p)
				}
			}
			sig.M = kept
		})},
		{"E3-seq-gap", "E3", mutateRecord(t, encoded, 1, func(v *Value) {
			*pairValue(v, "seq") = Uint(5)
		})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeEntitlementChain(tc.raw)
			wantEntitlementRule(t, err, tc.rule)
		})
	}
}

func TestEntitlementE4E8Mutations(t *testing.T) {
	f := newEntitlementFixture(t)
	encoded, err := f.chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rule string
		raw  []byte
	}{
		{"E4-unknown-type", "E4", mutateRecord(t, encoded, 1, func(v *Value) {
			*pairValue(v, "type") = Text("bogus")
		})},
		{"E8-missing-platform", "E8", mutateRecord(t, encoded, 0, func(v *Value) {
			removeKey(v, "sig_platform")
		})},
		{"E8-transfer-missing-holder", "E8", mutateRecord(t, encoded, 1, func(v *Value) {
			removeKey(v, "sig_holder")
		})},
		{"E8-non-transfer-holder", "E8", mutateRecord(t, encoded, 2, func(v *Value) {
			v.M = append(v.M, Pair{Key: Text("sig_holder"), Val: *pairValue(v, "sig_platform")})
		})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeEntitlementChain(tc.raw)
			wantEntitlementRule(t, err, tc.rule)
		})
	}
}

func TestEntitlementE5E6E7Mutations(t *testing.T) {
	f := newEntitlementFixture(t)
	encoded, err := f.chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rule string
		raw  []byte
	}{
		{"E5-genesis-not-grant", "E5", mutateRecord(t, encoded, 0, func(v *Value) {
			*pairValue(v, "type") = Text("revoke")
		})},
		{"E5-genesis-no-root", "E5", mutateRecord(t, encoded, 0, func(v *Value) {
			removeKey(v, "root")
		})},
		{"E5-genesis-nonzero-prev", "E5", mutateRecord(t, encoded, 0, func(v *Value) {
			pairValue(v, "prev").B = bytes.Repeat([]byte{1}, RootLen)
		})},
		{"E6-root-after-genesis", "E6", mutateRecord(t, encoded, 1, func(v *Value) {
			v.M = append(v.M, Pair{Key: Text("root"), Val: Bytes(bytes.Repeat([]byte{2}, RootLen))})
		})},
		{"E7-prev-mismatch", "E7", mutateRecord(t, encoded, 1, func(v *Value) {
			pairValue(v, "prev").B = bytes.Repeat([]byte{3}, RootLen)
		})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeEntitlementChain(tc.raw)
			wantEntitlementRule(t, err, tc.rule)
		})
	}
}

func TestEntitlementE9Failures(t *testing.T) {
	f := newEntitlementFixture(t)

	// An unresolved holder is an E9 failure, not a structural one.
	noHolder := NewTrustSet()
	noHolder.AddPlatform(*f.trust.Platform[0].copy())
	if err := f.chain.Validate(); err != nil {
		t.Fatalf("structure must not depend on the trust set: %v", err)
	}
	wantEntitlementRule(t, f.chain.VerifySignatures(1, noHolder), "E9")

	// A tampered platform signature.
	tamperedPlatform := cloneChain(f.chain)
	tamperedPlatform.Records[1].SigPlatform.Classical[0] ^= 0xff
	wantEntitlementRule(t, tamperedPlatform.VerifySignatures(1, f.trust), "E9")

	// A tampered holder signature.
	tamperedHolder := cloneChain(f.chain)
	tamperedHolder.Records[1].SigHolder.PQ[0] ^= 0xff
	wantEntitlementRule(t, tamperedHolder.VerifySignatures(1, f.trust), "E9")

	// A tampered ML-DSA half of the platform signature.
	tamperedPQ := cloneChain(f.chain)
	tamperedPQ.Records[0].SigPlatform.PQ[100] ^= 0xff
	wantEntitlementRule(t, tamperedPQ.VerifySignatures(1, f.trust), "E9")

	// The unsigned (empty) trust set trusts nothing (KD1).
	wantEntitlementRule(t, f.chain.VerifySignatures(1, NewTrustSet()), "E9")
}

// KD4: a key trusted for one role is not accepted for another. Root, platform,
// and holder lookups are separate, even when the same bytes are enrolled
// elsewhere.
func TestEntitlementTrustRolesAreSeparate(t *testing.T) {
	f := newEntitlementFixture(t)

	// The platform key enrolled only as root cannot verify a platform record.
	rootOnly := NewTrustSet()
	rootOnly.AddRoot(*f.trust.Platform[0].copy())
	wantEntitlementRule(t, f.chain.VerifySignatures(1, rootOnly), "E9")

	// A holder key enrolled as the platform key cannot verify sig_platform.
	holderAsPlatform := NewTrustSet()
	h1Pub := f.trust.holders[f.chain.Records[0].Holder]
	holderAsPlatform.AddPlatform(*h1Pub.copy())
	for _, pk := range f.trust.holders {
		if err := holderAsPlatform.AddHolder(1, *pk.copy()); err != nil {
			t.Fatal(err)
		}
	}
	wantEntitlementRule(t, f.chain.VerifySignatures(1, holderAsPlatform), "E9")

	// The root role verifies a footer transcript; the platform role does not.
	transcript := FooterTranscript(1, 64, 3309, f.commitment, 4096)
	classical, pq, err := SignHybrid(1, f.platform, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.trust.VerifyFooterSignature(1, transcript, classical, pq); err != nil {
		t.Fatalf("root role footer verification: %v", err)
	}
	platformOnly := NewTrustSet()
	platformOnly.AddPlatform(*f.trust.Platform[0].copy())
	if err := platformOnly.VerifyFooterSignature(1, transcript, classical, pq); err == nil {
		t.Fatal("a platform key was accepted as a root key")
	}

	// An unresolved holder in a transfer still passes E1–E8.
	if err := f.chain.Validate(); err != nil {
		t.Fatalf("structure: %v", err)
	}
}

func TestEntitlementSectionIntegration(t *testing.T) {
	f := newEntitlementFixture(t)
	encoded, err := f.chain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManifest()
	m.Set("id", Text("entitlement-demo"))
	m.Set("name", Text("Entitlement Demo"))
	m.Set("names", Array(Text("manifest"), Text("entitlement")))
	m.Set("spec", Uint(1))
	data, err := WriteBundle(m, []Section{{
		Kind:      KindEntitlement,
		NameID:    1,
		Plaintext: encoded,
	}}, WriteOptions{})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	b, err := Parse(data)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	chain, err := b.EntitlementSection(1)
	if err != nil {
		t.Fatalf("decode entitlement section: %v", err)
	}
	if err := chain.VerifySignatures(1, f.trust); err != nil {
		t.Fatalf("E9 in a bundle: %v", err)
	}
}

// ---- helpers ----

func (k *HybridPublicKey) copy() *HybridPublicKey {
	out := *k
	out.Ed = append([]byte(nil), k.Ed...)
	out.MLDSA = append([]byte(nil), k.MLDSA...)
	out.SLH = append([]byte(nil), k.SLH...)
	return &out
}

func cloneChain(c *EntitlementChain) *EntitlementChain {
	out := &EntitlementChain{Records: make([]EntitlementRecord, len(c.Records))}
	for i := range c.Records {
		out.Records[i] = c.Records[i]
		if c.Records[i].Root != nil {
			r := *c.Records[i].Root
			out.Records[i].Root = &r
		}
		if c.Records[i].Timestamp != nil {
			ts := *c.Records[i].Timestamp
			out.Records[i].Timestamp = &ts
		}
		out.Records[i].Payload = append([]byte(nil), c.Records[i].Payload...)
		if c.Records[i].SigPlatform != nil {
			s := *c.Records[i].SigPlatform
			s.Classical = append([]byte(nil), s.Classical...)
			s.PQ = append([]byte(nil), s.PQ...)
			out.Records[i].SigPlatform = &s
		}
		if c.Records[i].SigHolder != nil {
			s := *c.Records[i].SigHolder
			s.Classical = append([]byte(nil), s.Classical...)
			s.PQ = append([]byte(nil), s.PQ...)
			out.Records[i].SigHolder = &s
		}
	}
	return out
}

func mutateRecord(t *testing.T, encoded []byte, index int, f func(*Value)) []byte {
	t.Helper()
	v, err := decodeCBOR(encoded)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if index >= len(v.A) {
		t.Fatalf("record %d absent", index)
	}
	f(&v.A[index])
	cv, err := canonicalize(v)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	out, err := encodeValue(cv)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

func pairValue(v *Value, key string) *Value {
	for i := range v.M {
		if v.M[i].Key.Kind == ValueText && v.M[i].Key.T == key {
			return &v.M[i].Val
		}
	}
	panic("test fixture: key " + key + " absent")
}

func removeKey(v *Value, key string) {
	kept := v.M[:0]
	for _, p := range v.M {
		if !(p.Key.Kind == ValueText && p.Key.T == key) {
			kept = append(kept, p)
		}
	}
	v.M = kept
}

func mustCBOR(t *testing.T, v Value) []byte {
	t.Helper()
	cv, err := canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeValue(cv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wantEntitlementRule(t *testing.T, err error, rule string) {
	t.Helper()
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want rule %s, got %v", rule, err)
	}
	if ce.Rule != rule {
		t.Fatalf("want rule %s, got %s (%v)", rule, ce.Rule, err)
	}
}
