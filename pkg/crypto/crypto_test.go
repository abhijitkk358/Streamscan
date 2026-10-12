package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"streamscan/pkg/model"
)

var sampleFinding = model.Finding{
	Type:      "credit_card",
	Value:     "4111111111111111",
	Line:      42,
	Offset:    1337,
	Validated: true,
}

func mustKeys(t testing.TB) (kek, idx []byte) {
	t.Helper()
	kek, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return kek, DeriveIndexKey(kek)
}

func clone(r EncryptedRecord) EncryptedRecord {
	return EncryptedRecord{
		WrappedDEK: append([]byte(nil), r.WrappedDEK...),
		DEKNonce:   append([]byte(nil), r.DEKNonce...),
		Payload:    append([]byte(nil), r.Payload...),
		Nonce:      append([]byte(nil), r.Nonce...),
		BlindIndex: r.BlindIndex,
	}
}

func TestRoundTrip(t *testing.T) {
	kek, idx := mustKeys(t)
	rec, err := EncryptFinding(kek, idx, sampleFinding)
	if err != nil {
		t.Fatal(err)
	}

	// Shape of the record.
	if len(rec.Nonce) != NonceSize || len(rec.DEKNonce) != NonceSize {
		t.Errorf("nonce sizes: %d, %d; want %d", len(rec.Nonce), len(rec.DEKNonce), NonceSize)
	}
	if len(rec.WrappedDEK) != KeySize+16 { // 32-byte DEK + 16-byte GCM tag
		t.Errorf("wrapped DEK length = %d, want %d", len(rec.WrappedDEK), KeySize+16)
	}
	if len(rec.BlindIndex) != 64 {
		t.Errorf("blind index should be 64 hex chars, got %d", len(rec.BlindIndex))
	}

	// The serialized record must not contain the secret in the clear.
	raw, _ := json.Marshal(rec)
	if bytes.Contains(raw, []byte(sampleFinding.Value)) {
		t.Fatal("plaintext secret leaked into the serialized record")
	}

	got, err := DecryptRecord(kek, rec)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if *got != sampleFinding {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v", *got, sampleFinding)
	}
}

func TestRoundTripThroughJSON(t *testing.T) {
	// The CLI stores records as JSON and reads them back, so test that path.
	kek, idx := mustKeys(t)
	rec, _ := EncryptFinding(kek, idx, sampleFinding)
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var back EncryptedRecord
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, err := DecryptRecord(kek, back)
	if err != nil || *got != sampleFinding {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

// Flipping any single bit anywhere in the authenticated data must be detected.
func TestTamperDetected(t *testing.T) {
	kek, idx := mustKeys(t)
	orig, _ := EncryptFinding(kek, idx, sampleFinding)

	// Every byte of the ciphertexts (this includes the 16-byte GCM tag at the end).
	for _, field := range []string{"Payload", "WrappedDEK"} {
		n := len(orig.Payload)
		if field == "WrappedDEK" {
			n = len(orig.WrappedDEK)
		}
		for i := 0; i < n; i++ {
			rec := clone(orig)
			if field == "Payload" {
				rec.Payload[i] ^= 0x01
			} else {
				rec.WrappedDEK[i] ^= 0x01
			}
			if _, err := DecryptRecord(kek, rec); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("flipping bit in %s[%d]: err = %v, want ErrAuthentication", field, i, err)
			}
		}
	}

	// Nonces, the blind index (bound via AAD), and the GCM tag specifically.
	cases := map[string]func(*EncryptedRecord){
		"Nonce":         func(r *EncryptedRecord) { r.Nonce[0] ^= 0x80 },
		"DEKNonce":      func(r *EncryptedRecord) { r.DEKNonce[11] ^= 0x01 },
		"BlindIndex":    func(r *EncryptedRecord) { r.BlindIndex = flipLastHexChar(r.BlindIndex) },
		"PayloadTag":    func(r *EncryptedRecord) { r.Payload[len(r.Payload)-1] ^= 0xFF },
		"WrappedDEKTag": func(r *EncryptedRecord) { r.WrappedDEK[len(r.WrappedDEK)-1] ^= 0xFF },
	}
	for name, mutate := range cases {
		rec := clone(orig)
		mutate(&rec)
		if _, err := DecryptRecord(kek, rec); !errors.Is(err, ErrAuthentication) {
			t.Errorf("tampering with %s: err = %v, want ErrAuthentication", name, err)
		}
	}
}

func flipLastHexChar(s string) string {
	b := []byte(s)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	return string(b)
}

func TestTruncatedPayloadAndSwappedFieldsRejected(t *testing.T) {
	kek, idx := mustKeys(t)
	a, _ := EncryptFinding(kek, idx, sampleFinding)
	other := sampleFinding
	other.Value = "5500005555555559"
	b, _ := EncryptFinding(kek, idx, other)

	trunc := clone(a)
	trunc.Payload = trunc.Payload[:len(trunc.Payload)-1]
	if _, err := DecryptRecord(kek, trunc); !errors.Is(err, ErrAuthentication) {
		t.Errorf("truncated payload: %v", err)
	}

	// Splice record B's payload+nonce into record A: wrong DEK, must fail.
	swapped := clone(a)
	swapped.Payload, swapped.Nonce = b.Payload, b.Nonce
	if _, err := DecryptRecord(kek, swapped); !errors.Is(err, ErrAuthentication) {
		t.Errorf("swapped payload: %v", err)
	}
}

func TestWrongKEKFails(t *testing.T) {
	kek, idx := mustKeys(t)
	rec, _ := EncryptFinding(kek, idx, sampleFinding)
	other, _ := GenerateKey()
	if _, err := DecryptRecord(other, rec); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v, want ErrAuthentication", err)
	}
}

// Malformed input must produce an error, never a panic (cipher.AEAD.Open
// panics on a wrong-length nonce, so this is a real hazard).
func TestMalformedRecordsDoNotPanic(t *testing.T) {
	kek, idx := mustKeys(t)
	good, _ := EncryptFinding(kek, idx, sampleFinding)

	cases := map[string]func(*EncryptedRecord){
		"short nonce":   func(r *EncryptedRecord) { r.Nonce = r.Nonce[:5] },
		"long nonce":    func(r *EncryptedRecord) { r.Nonce = append(r.Nonce, 0) },
		"nil dek nonce": func(r *EncryptedRecord) { r.DEKNonce = nil },
		"empty payload": func(r *EncryptedRecord) { r.Payload = nil },
		"empty wrapped": func(r *EncryptedRecord) { r.WrappedDEK = nil },
		"tiny wrapped":  func(r *EncryptedRecord) { r.WrappedDEK = []byte{1, 2, 3} },
		"zero value":    func(r *EncryptedRecord) { *r = EncryptedRecord{} },
	}
	for name, mutate := range cases {
		rec := clone(good)
		mutate(&rec)
		if _, err := DecryptRecord(kek, rec); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := DecryptRecord([]byte("short"), good); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short kek: %v", err)
	}
	if _, err := EncryptFinding([]byte("short"), idx, sampleFinding); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short kek on encrypt: %v", err)
	}
}

// Encrypts 10,000 records and checks that no nonce repeats. With random 96-bit
// nonces a collision is astronomically unlikely, so this test is a tripwire for
// real bugs (constant/zero nonce, a reused buffer, a broken RNG) rather than a
// proof; the proof is the birthday bound, discussed in the README.
func TestNonceUniqueness(t *testing.T) {
	const n = 10_000
	kek, idx := mustKeys(t)

	nonces := make(map[string]struct{}, 2*n)
	wrapped := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		f := model.Finding{Type: "credit_card", Value: fmt.Sprintf("41111111%08d", i), Line: i, Offset: int64(i)}
		rec, err := EncryptFinding(kek, idx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, nc := range [][]byte{rec.Nonce, rec.DEKNonce} {
			if len(nc) != NonceSize {
				t.Fatalf("record %d: nonce length %d", i, len(nc))
			}
			if _, dup := nonces[string(nc)]; dup {
				t.Fatalf("nonce collision at record %d: %x", i, nc)
			}
			nonces[string(nc)] = struct{}{}
		}
		if _, dup := wrapped[string(rec.WrappedDEK)]; dup {
			t.Fatalf("identical wrapped DEK at record %d (DEK or nonce reused)", i)
		}
		wrapped[string(rec.WrappedDEK)] = struct{}{}
	}
	if len(nonces) != 2*n {
		t.Fatalf("expected %d unique nonces, got %d", 2*n, len(nonces))
	}
}

func TestEncryptingSameFindingTwiceDiffers(t *testing.T) {
	kek, idx := mustKeys(t)
	a, _ := EncryptFinding(kek, idx, sampleFinding)
	b, _ := EncryptFinding(kek, idx, sampleFinding)
	if bytes.Equal(a.Payload, b.Payload) || bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("two encryptions of the same finding must not produce identical ciphertext")
	}
	if a.BlindIndex != b.BlindIndex {
		t.Fatal("blind index must be deterministic so duplicates can be counted")
	}
}

func TestBlindIndex(t *testing.T) {
	// Known-answer test: RFC 4231, HMAC-SHA-256 test case 2.
	got := ComputeBlindIndex([]byte("Jefe"), "what do ya want for nothing?")
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got != want {
		t.Fatalf("HMAC-SHA256 KAT failed:\n got  %s\n want %s", got, want)
	}

	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	if ComputeBlindIndex(k1, "secret") != ComputeBlindIndex(k1, "secret") {
		t.Error("same key + value must give the same index")
	}
	if ComputeBlindIndex(k1, "secret") == ComputeBlindIndex(k1, "Secret") {
		t.Error("different values must give different indexes")
	}
	if ComputeBlindIndex(k1, "secret") == ComputeBlindIndex(k2, "secret") {
		t.Error("different keys must give different indexes (keyed, not a plain hash)")
	}
}

func TestDeriveIndexKey(t *testing.T) {
	kek, _ := GenerateKey()
	d1, d2 := DeriveIndexKey(kek), DeriveIndexKey(kek)
	if !bytes.Equal(d1, d2) {
		t.Error("derivation must be deterministic")
	}
	if bytes.Equal(d1, kek) {
		t.Error("index key must differ from the KEK")
	}
	if len(d1) != KeySize {
		t.Errorf("derived key length %d", len(d1))
	}
}

func BenchmarkEncryptFinding(b *testing.B) {
	kek, idx := mustKeys(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptFinding(kek, idx, sampleFinding); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptRecord(b *testing.B) {
	kek, idx := mustKeys(b)
	rec, _ := EncryptFinding(kek, idx, sampleFinding)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DecryptRecord(kek, rec); err != nil {
			b.Fatal(err)
		}
	}
}
