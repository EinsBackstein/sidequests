package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	cf "github.com/EinsBackstein/sidequests/ctf-format/go/ctf"
	"lukechampine.com/blake3"
)

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	Role         string   `json:"role"`
	Name         string   `json:"name"`
	Suite        int      `json:"suite"`
	Source       string   `json:"source"`
	Inputs       []string `json:"inputs"`
	Expected     string   `json:"expected"`
	ReverseCheck string   `json:"reverse_check"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("../../spec/vectors/primitives.json")
	if err != nil {
		t.Fatalf("read primitives.json: %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode primitives.json: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("primitives.json contains no vectors")
	}
	return f.Vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestPrimitiveVectors(t *testing.T) {
	vectors := loadVectors(t)
	executed := 0
	skipped := map[string]string{}
	for _, v := range vectors {
		v := v
		t.Run(v.Role+"/"+v.Name, func(t *testing.T) {
			inputs := make([][]byte, len(v.Inputs))
			for i, s := range v.Inputs {
				inputs[i] = mustHex(t, s)
			}
			switch v.Role {
			case "hash":
				if len(inputs) != 1 {
					t.Fatalf("hash vector has %d inputs", len(inputs))
				}
				sum := blake3.Sum256(inputs[0])
				if got, want := hex.EncodeToString(sum[:]), v.Expected; got != want {
					t.Fatalf("BLAKE3 = %s, want %s", got, want)
				}
				executed++
			case "kdf":
				if len(inputs) != 3 {
					t.Fatalf("kdf vector has %d inputs", len(inputs))
				}
				want := mustHex(t, v.Expected)
				got, err := hkdf.Key(sha256.New, inputs[0], inputs[1], string(inputs[2]), len(want))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("HKDF = %x, want %s", got, v.Expected)
				}
				executed++
			case "aead":
				if len(inputs) != 4 {
					t.Fatalf("aead vector has %d inputs", len(inputs))
				}
				key, nonce, aad, plaintext := inputs[0], inputs[1], inputs[2], inputs[3]
				want := mustHex(t, v.Expected)
				got, err := cf.SealAEAD(uint16(v.Suite), key, nonce, plaintext, aad)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("AEAD seal = %x, want %s", got, v.Expected)
				}
				back, err := cf.OpenAEAD(uint16(v.Suite), key, nonce, got, aad)
				if err != nil {
					t.Fatalf("AEAD open: %v", err)
				}
				if !bytes.Equal(back, plaintext) {
					t.Fatal("AEAD round-trip mismatch")
				}
				executed++
			case "kem":
				if len(inputs) != 3 {
					t.Fatalf("kem vector has %d inputs", len(inputs))
				}
				sk, ct, context := inputs[0], inputs[1], string(inputs[2])
				if len(sk) != 96 || len(ct) != 1120 {
					t.Fatalf("kem inputs are %d/%d bytes, want 96/1120", len(sk), len(ct))
				}
				want := mustHex(t, v.Expected)
				got, err := cf.HybridDecapsulate(sk, ct, cf.KemContext{
					SuiteID: uint16(v.Suite), VersionMajor: 0, Label: context,
				})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("combiner = %x, want %s", got, v.Expected)
				}
				executed++
			case "signature":
				// The committed signature vector has an empty `expected` and its
				// reverse_check names a crate-produced signature. Consuming it
				// would use a Rust-derived value, which this implementation must
				// not do. Round-trip tests below cover both signature roles
				// independently.
				if v.Expected != "" {
					t.Fatalf("signature vector unexpectedly has an expected value; refusing to use a Rust-derived signature")
				}
				skipped[v.Name] = "Rust-derived signature, no expected value; see round-trip tests"
				t.Logf("SKIP: %s", skipped[v.Name])
			default:
				t.Fatalf("unknown vector role %q", v.Role)
			}
		})
	}
	t.Logf("executed %d primitive vectors", executed)
	for name, reason := range skipped {
		t.Logf("skipped %s: %s", name, reason)
	}
}

func TestEd25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("ctf/vectors/v1 signature transcript")
	sig := ed25519.Sign(priv, msg)
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes", len(sig))
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("Ed25519 verify failed")
	}
	msg[0] ^= 1
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("Ed25519 accepted a modified message")
	}
}

func TestMLKEM768RoundTrip(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	if len(ek.Bytes()) != 1184 || len(dk.Bytes()) != 64 {
		t.Fatalf("ML-KEM-768 sizes: ek=%d dk=%d", len(ek.Bytes()), len(dk.Bytes()))
	}
	ss1, ct := ek.Encapsulate()
	if len(ct) != 1088 {
		t.Fatalf("ciphertext is %d bytes", len(ct))
	}
	ss2, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("ML-KEM shared secrets differ")
	}
}

func TestMLDSA65RoundTrip(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	if len(pk.Bytes()) != 1952 {
		t.Fatalf("ML-DSA-65 public key is %d bytes", len(pk.Bytes()))
	}
	msg := []byte("ctf/vectors/v1 signature transcript")
	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 3309 {
		t.Fatalf("ML-DSA-65 signature is %d bytes", len(sig))
	}
	if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
		t.Fatal(err)
	}
	msg[0] ^= 1
	if err := mldsa.Verify(pk, msg, sig, nil); err == nil {
		t.Fatal("ML-DSA-65 accepted a modified message")
	}
}

func TestHybridSignatureRoundTrip(t *testing.T) {
	for _, suiteID := range []uint16{1, 2, 3} {
		suiteID := suiteID
		t.Run(cf.SuiteName(suiteID), func(t *testing.T) {
			priv, pub, err := cf.GenerateHybridKeyForSuite(suiteID)
			if err != nil {
				t.Fatal(err)
			}
			wantPQ := 3309
			if suiteID == 3 {
				wantPQ = 11165
			}
			root := [32]byte{1, 2, 3}
			transcript := cf.FooterTranscript(suiteID, 64, uint32(wantPQ), root, 4344)
			if len(transcript) != 67 {
				t.Fatalf("transcript is %d bytes, want 67", len(transcript))
			}
			classical, pq, err := cf.SignHybrid(suiteID, priv, transcript)
			if err != nil {
				t.Fatal(err)
			}
			if len(classical) != 64 || len(pq) != wantPQ {
				t.Fatalf("signature sizes %d/%d", len(classical), len(pq))
			}
			if err := cf.VerifyHybrid(suiteID, pub, transcript, classical, pq); err != nil {
				t.Fatalf("verify: %v", err)
			}
			bad := append([]byte(nil), transcript...)
			bad[0] ^= 1
			if err := cf.VerifyHybrid(suiteID, pub, bad, classical, pq); err == nil {
				t.Fatal("verified a modified transcript")
			}
		})
	}
}

func TestHybridKEMRoundTrip(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	skX := make([]byte, 32)
	if _, err := rand.Read(skX); err != nil {
		t.Fatal(err)
	}
	pkX, err := cf.X25519PublicKey(skX)
	if err != nil {
		t.Fatal(err)
	}
	sk := append(append([]byte{}, skX...), dk.Bytes()...)
	pk := append(append([]byte{}, pkX...), dk.EncapsulationKey().Bytes()...)
	ctx := cf.KemContext{SuiteID: 1, VersionMajor: 0, Label: "storage"}
	ct, key1, err := cf.HybridEncapsulate(pk, ctx)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := cf.HybridDecapsulate(sk, ct, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("combiner keys differ")
	}
	// A different context label must derive a different key.
	key3, err := cf.HybridDecapsulate(sk, ct, cf.KemContext{SuiteID: 1, VersionMajor: 0, Label: "seal"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("context label is not bound")
	}
}

func TestAEADStreamRoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("stream chunk payload "), 900)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, suiteID := range []uint16{1, 2} {
		body, err := cf.SealStream(suiteID, 7, 4096, key, plaintext)
		if err != nil {
			t.Fatalf("suite %d seal: %v", suiteID, err)
		}
		got, err := cf.OpenStream(suiteID, 7, 4096, uint64(len(plaintext)), key, body)
		if err != nil {
			t.Fatalf("suite %d open: %v", suiteID, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("suite %d round-trip mismatch", suiteID)
		}
		// Truncation must fail: the last chunk is no longer final.
		if len(body) > 8 {
			if _, err := cf.OpenStream(suiteID, 7, 4096, uint64(len(plaintext)), key, body[:len(body)-1]); err == nil {
				t.Fatalf("suite %d accepted a truncated body", suiteID)
			}
		}
		// A swapped chunk must fail: position is in the nonce and AAD.
		swapped := append([]byte(nil), body...)
		copy(swapped, body[4:]) // not a well-formed reorder, but must not open
		if _, err := cf.OpenStream(suiteID, 7, 4096, uint64(len(plaintext)), key, swapped); err == nil {
			t.Fatalf("suite %d accepted a corrupted body", suiteID)
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	skX := make([]byte, 32)
	if _, err := rand.Read(skX); err != nil {
		t.Fatal(err)
	}
	pkX, err := cf.X25519PublicKey(skX)
	if err != nil {
		t.Fatal(err)
	}
	sk := append(append([]byte{}, skX...), dk.Bytes()...)
	pk := append(append([]byte{}, pkX...), dk.EncapsulationKey().Bytes()...)
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	env, err := cf.SealEnvelope(1, 0, pk, "storage", contentKey)
	if err != nil {
		t.Fatal(err)
	}
	env.NameID = 42
	got, err := cf.OpenEnvelope(1, 0, sk, env, "storage")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, contentKey) {
		t.Fatal("unwrapped key differs")
	}
	if _, err := cf.OpenEnvelope(1, 0, sk, env, "seal"); err == nil {
		t.Fatal("accepted a wrong context")
	}
	encoded, err := cf.EncodeKeysSection([]cf.Envelope{env})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cf.DecodeKeysSection(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].NameID != 42 || decoded[0].Context != "storage" {
		t.Fatalf("keys section round-trip: %+v", decoded)
	}
}

func TestDerivedFlagShape(t *testing.T) {
	seed, err := cf.DeriveSeed([]byte("event-secret"), "chal-id", 3, "player-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 {
		t.Fatalf("seed is %d bytes", len(seed))
	}
	flag := cf.DeriveFlag(seed)
	if len(flag) != 16 {
		t.Fatalf("flag %q has %d symbols", flag, len(flag))
	}
	for _, c := range flag {
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			t.Fatalf("flag %q is not lowercase base32", flag)
		}
	}
	seed2, _ := cf.DeriveSeed([]byte("event-secret"), "chal-id", 3, "player-2")
	if cf.DeriveFlag(seed2) == flag {
		t.Fatal("different subjects derived the same flag")
	}
	k1, err := cf.StageKey(flag, 2)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := cf.StageKey(flag, 2)
	if !bytes.Equal(k1, k2) || len(k1) != 32 {
		t.Fatal("stage key is not deterministic 32 bytes")
	}
}

// §20.2 divides a comp = 0 plaintext into ceil(len_plain / chunk_size) chunks.
// The empty plaintext therefore has zero chunks, and a body whose chunk count or
// chunk sizes disagree with the declared fields is malformed even when every tag
// verifies. The reference reader enforces both; this one must agree.
func TestAEADStreamEmptyAndChunkDivision(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, suiteID := range []uint16{1, 2} {
		body, err := cf.SealStream(suiteID, 7, 4096, key, nil)
		if err != nil {
			t.Fatalf("suite %d seal empty: %v", suiteID, err)
		}
		if len(body) != 0 {
			t.Fatalf("suite %d sealed an empty plaintext as %d bytes; want zero chunks", suiteID, len(body))
		}
		got, err := cf.OpenStream(suiteID, 7, 4096, 0, key, body)
		if err != nil || len(got) != 0 {
			t.Fatalf("suite %d open empty: got %d bytes, err %v", suiteID, len(got), err)
		}
		if _, err := cf.OpenStream(suiteID, 7, 4096, 1, key, body); err == nil {
			t.Fatalf("suite %d accepted an empty body for a 1-byte plaintext", suiteID)
		}
		// Sealed as one 8 KiB chunk, opened while declaring 4 KiB chunks: the
		// chunk sizes no longer divide the plaintext as §20.2 requires.
		big, err := cf.SealStream(suiteID, 7, 8192, key, bytes.Repeat([]byte("x"), 5000))
		if err != nil {
			t.Fatalf("suite %d seal big: %v", suiteID, err)
		}
		if _, err := cf.OpenStream(suiteID, 7, 4096, 5000, key, big); err == nil {
			t.Fatalf("suite %d accepted a body whose chunk sizes exceed chunk_size", suiteID)
		}
		// A plaintext that is not a multiple of chunk_size ends in a short final
		// chunk: 4097 bytes at 4096 is two chunks, 4096 and 1.
		odd := make([]byte, 4097)
		for i := range odd {
			odd[i] = byte(i)
		}
		oddBody, err := cf.SealStream(suiteID, 7, 4096, key, odd)
		if err != nil {
			t.Fatalf("suite %d seal odd: %v", suiteID, err)
		}
		got, err = cf.OpenStream(suiteID, 7, 4096, uint64(len(odd)), key, oddBody)
		if err != nil || !bytes.Equal(got, odd) {
			t.Fatalf("suite %d odd-length round-trip: err %v", suiteID, err)
		}
		// A chunk size outside the legal range is refused before any work, even
		// for an empty body, where no chunk would otherwise reveal it.
		for _, bad := range []uint32{0, 2048, 1 << 30} {
			if _, err := cf.OpenStream(suiteID, 7, bad, 0, key, nil); err == nil {
				t.Fatalf("suite %d accepted an illegal chunk_size %d", suiteID, bad)
			}
		}
	}
}
