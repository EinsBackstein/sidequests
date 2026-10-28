package ctf

import (
	"bytes"
	"testing"
)

// §20.3: suite 3's pq slot is ML-DSA-65 ‖ SLH-DSA-SHA2-128s, and all three
// components must verify. A tampered component is a failure of the whole.
func TestSuite3HybridSignatureRoundTrip(t *testing.T) {
	priv, pub, err := GenerateHybridKeyForSuite(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.Ed) != Ed25519PublicKeyLen {
		t.Fatalf("Ed25519 public key is %d bytes", len(pub.Ed))
	}
	if len(pub.MLDSA) != MLDSA65PublicKeyLen {
		t.Fatalf("ML-DSA-65 public key is %d bytes", len(pub.MLDSA))
	}
	if len(pub.SLH) != SLHDSA128sPublicKeyLen {
		t.Fatalf("SLH-DSA-SHA2-128s public key is %d bytes", len(pub.SLH))
	}
	classical, pq, err := SignatureSlotLengths(3)
	if err != nil {
		t.Fatal(err)
	}
	if classical != 64 || pq != 11165 {
		t.Fatalf("suite 3 slots are %d/%d, want 64/11165", classical, pq)
	}

	root := [RootLen]byte{9, 8, 7}
	transcript := FooterTranscript(3, 64, 11165, root, 2048)
	sigClassical, sigPQ, err := SignHybrid(3, priv, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigClassical) != 64 || len(sigPQ) != 11165 {
		t.Fatalf("signature sizes %d/%d, want 64/11165", len(sigClassical), len(sigPQ))
	}
	if err := VerifyHybrid(3, pub, transcript, sigClassical, sigPQ); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tamper each component in turn: Ed25519, the ML-DSA-65 half, and the
	// SLH-DSA half. Each must fail the whole.
	cases := map[string]struct {
		classical []byte
		pq        []byte
	}{
		"ed25519": {tamper(sigClassical, 0), sigPQ},
		"ml-dsa":  {sigClassical, tamper(sigPQ, 0)},
		"slh-dsa": {sigClassical, tamper(sigPQ, MLDSA65SignatureLen)},
	}
	for name, tc := range cases {
		tc := tc
		t.Run("tamper-"+name, func(t *testing.T) {
			if err := VerifyHybrid(3, pub, transcript, tc.classical, tc.pq); err == nil {
				t.Fatal("accepted a tampered signature component")
			}
		})
	}

	// Wrong-length components and keys name the role and the expected/got sizes.
	shortClassical := append([]byte(nil), sigClassical[:63]...)
	if err := VerifyHybrid(3, pub, transcript, shortClassical, sigPQ); err == nil {
		t.Fatal("accepted a 63-byte Ed25519 signature")
	} else if !containsAll(err.Error(), "Ed25519 signature", "63", "64") {
		t.Fatalf("length error does not name the role and sizes: %v", err)
	}
	if err := VerifyHybrid(3, pub, transcript, sigClassical, sigPQ[:11164]); err == nil {
		t.Fatal("accepted a 11164-byte pq slot")
	} else if !containsAll(err.Error(), "pq signature slot", "11164", "11165") {
		t.Fatalf("pq length error does not name the role and sizes: %v", err)
	}
	if err := VerifyHybrid(3, pub, transcript, sigClassical, sigPQ[:MLDSA65SignatureLen]); err == nil {
		t.Fatal("accepted a pq slot with the SLH-DSA half missing")
	}
	badPK := *pub
	badPK.SLH = pub.SLH[:31]
	if err := VerifyHybrid(3, &badPK, transcript, sigClassical, sigPQ); err == nil {
		t.Fatal("accepted a 31-byte SLH-DSA public key")
	} else if !containsAll(err.Error(), "SLH-DSA-SHA2-128s public key", "31", "32") {
		t.Fatalf("key length error does not name the role and sizes: %v", err)
	}

	if _, err := HolderHash(3, &badPK); err == nil {
		t.Fatal("HolderHash accepted a 31-byte SLH-DSA key")
	}
	if _, err := HolderHash(3, pub); err != nil {
		t.Fatalf("HolderHash for suite 3: %v", err)
	}
}

// Suites 1 and 2 keep the original two-component layout and lengths.
func TestSuite1And2SignatureLayoutUnchanged(t *testing.T) {
	for _, suiteID := range []uint16{1, 2} {
		classical, pq, err := SignatureSlotLengths(suiteID)
		if err != nil {
			t.Fatal(err)
		}
		if classical != 64 || pq != 3309 {
			t.Fatalf("suite %d slots are %d/%d, want 64/3309", suiteID, classical, pq)
		}
		priv, pub, err := GenerateHybridKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(pub.SLH) != 0 {
			t.Fatalf("suite %d key unexpectedly carries an SLH-DSA component", suiteID)
		}
		transcript := []byte("suite layout transcript")
		c, p, err := SignHybrid(suiteID, priv, transcript)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 64 || len(p) != 3309 {
			t.Fatalf("suite %d signature sizes %d/%d", suiteID, len(c), len(p))
		}
		if err := VerifyHybrid(suiteID, pub, transcript, c, p); err != nil {
			t.Fatalf("suite %d verify: %v", suiteID, err)
		}
	}
}

// A suite-3 signature must not verify under a suite-1 transcript layout even
// with the same keys: the suite is part of the registry and of the slot sizes.
func TestSuite3SignatureSplitLengthsAreNamed(t *testing.T) {
	if _, _, err := SignatureSlotLengths(99); err == nil {
		t.Fatal("unknown suite resolved")
	}
}

func tamper(b []byte, at int) []byte {
	out := append([]byte(nil), b...)
	out[at] ^= 0xff
	return out
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !bytes.Contains([]byte(s), []byte(p)) {
			return false
		}
	}
	return true
}
