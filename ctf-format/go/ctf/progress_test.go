package ctf

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// progressRecipient returns a fresh hybrid KEM keypair in the package's
// pk||ek / sk||seed layout.
func progressRecipient(t *testing.T) (pk, sk []byte) {
	t.Helper()
	skX := make([]byte, 32)
	if _, err := rand.Read(skX); err != nil {
		t.Fatal(err)
	}
	pkX, err := curve25519.X25519(skX, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	pk = append(append([]byte{}, pkX...), dk.EncapsulationKey().Bytes()...)
	sk = append(append([]byte{}, skX...), dk.Bytes()...)
	return pk, sk
}

// §24.2: the zero nonce is safe only because every payload draws a fresh
// content key. Two seals of the same plaintext must therefore use different
// keys.
func TestSealProgressDrawsAFreshContentKey(t *testing.T) {
	pk, sk := progressRecipient(t)
	const plaintext = "stage-1 earned"
	first, err := SealProgress(SuiteDefault, pk, "bird-v1", "team-a", []byte(plaintext))
	if err != nil {
		t.Fatalf("seal 1: %v", err)
	}
	second, err := SealProgress(SuiteDefault, pk, "bird-v1", "team-a", []byte(plaintext))
	if err != nil {
		t.Fatalf("seal 2: %v", err)
	}
	key1, err := OpenEnvelope(SuiteDefault, VersionMajor, sk, first.Envelope, "holder")
	if err != nil {
		t.Fatalf("open envelope 1: %v", err)
	}
	key2, err := OpenEnvelope(SuiteDefault, VersionMajor, sk, second.Envelope, "holder")
	if err != nil {
		t.Fatalf("open envelope 2: %v", err)
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("two seals reused one content key; the zero nonce would repeat")
	}
}

// §24.1: the envelope's name_id is 0, and Open enforces it before unwrapping.
func TestOpenProgressRejectsANonZeroNameID(t *testing.T) {
	pk, sk := progressRecipient(t)
	p, err := SealProgress(SuiteDefault, pk, "bird-v1", "team-a", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Envelope.NameID != 0 {
		t.Fatalf("sealed name_id = %d, need 0", p.Envelope.NameID)
	}
	p.Envelope.NameID = 99
	_, err = p.Open(SuiteDefault, sk, "bird-v1", "team-a")
	if err == nil {
		t.Fatal("Open accepted a payload whose envelope name_id is 99")
	}
	if !strings.Contains(err.Error(), "24.1") {
		t.Fatalf("error must name §24.1: %v", err)
	}
}

// §24.1 P1: the payload is one canonical CBOR map with exactly `envelope` and
// `ct`, the envelope is the §21.3 four-key map, and name_id is 0.
func TestDecodeProgressEnforcesTheShape(t *testing.T) {
	pk, _ := progressRecipient(t)
	p, err := SealProgress(SuiteDefault, pk, "bird-v1", "team-a", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProgress(encoded)
	if err != nil {
		t.Fatalf("decode the encoder's own output: %v", err)
	}
	if !bytes.Equal(decoded.CT, p.CT) || decoded.Envelope.NameID != 0 {
		t.Fatalf("round trip lost data: %+v", decoded)
	}
	echo, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, encoded) {
		t.Fatal("decode/encode is not byte-identical")
	}

	envelope := func(nameID uint64) Value {
		return MapValue(
			Pair{Key: Text("name_id"), Val: Uint(nameID)},
			Pair{Key: Text("context"), Val: Text("holder")},
			Pair{Key: Text("ct"), Val: Bytes(make([]byte, 1120))},
			Pair{Key: Text("wrapped"), Val: Bytes(make([]byte, 48))},
		)
	}
	encode := func(v Value) []byte {
		cv, err := canonicalize(v)
		if err != nil {
			t.Fatal(err)
		}
		b, err := encodeValue(cv)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cases := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "extra outer key",
			body: encode(MapValue(
				Pair{Key: Text("envelope"), Val: envelope(0)},
				Pair{Key: Text("ct"), Val: Bytes([]byte{1})},
				Pair{Key: Text("extra"), Val: Uint(1)},
			)),
			want: "two-key",
		},
		{
			name: "missing ct",
			body: encode(MapValue(
				Pair{Key: Text("envelope"), Val: envelope(0)},
			)),
			want: "two-key",
		},
		{
			name: "envelope missing wrapped",
			body: encode(MapValue(
				Pair{Key: Text("envelope"), Val: MapValue(
					Pair{Key: Text("name_id"), Val: Uint(0)},
					Pair{Key: Text("context"), Val: Text("holder")},
					Pair{Key: Text("ct"), Val: Bytes(make([]byte, 1120))},
				)},
				Pair{Key: Text("ct"), Val: Bytes([]byte{1})},
			)),
			want: "four-key",
		},
		{
			name: "envelope with an extra key",
			body: encode(MapValue(
				Pair{Key: Text("envelope"), Val: MapValue(
					Pair{Key: Text("name_id"), Val: Uint(0)},
					Pair{Key: Text("context"), Val: Text("holder")},
					Pair{Key: Text("ct"), Val: Bytes(make([]byte, 1120))},
					Pair{Key: Text("wrapped"), Val: Bytes(make([]byte, 48))},
					Pair{Key: Text("extra"), Val: Uint(1)},
				)},
				Pair{Key: Text("ct"), Val: Bytes([]byte{1})},
			)),
			want: "four-key",
		},
		{
			name: "name_id 99",
			body: encode(MapValue(
				Pair{Key: Text("envelope"), Val: envelope(99)},
				Pair{Key: Text("ct"), Val: Bytes([]byte{1})},
			)),
			want: "24.1",
		},
		{
			name: "not a map",
			body: encode(Array(Uint(1))),
			want: "map",
		},
	}
	for _, tc := range cases {
		if _, err := DecodeProgress(tc.body); err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v does not mention %q", tc.name, err, tc.want)
		}
	}
}

// Non-canonical bytes are rejected too: DecodeProgress is a §7.1 decoder, not
// a permissive parser.
func TestDecodeProgressRejectsNonCanonicalCBOR(t *testing.T) {
	trailing := []byte{0xa0, 0x00} // an empty map followed by one byte
	if _, err := DecodeProgress(trailing); err == nil {
		t.Fatal("accepted trailing bytes after the payload map")
	}
	// Duplicate outer keys are not canonical either.
	duplicate := []byte{0xa2, 0x63, 'c', 't', 0x40, 0x63, 'c', 't', 0x40}
	if _, err := DecodeProgress(duplicate); err == nil {
		t.Fatal("accepted a duplicate map key")
	}
}
