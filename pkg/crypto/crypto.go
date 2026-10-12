// Package crypto protects scan findings so that the report never contains a
// plaintext secret.
//
// Design (all primitives from the Go standard library):
//
//   - Envelope encryption. Every finding gets its own random 32-byte data
//     encryption key (DEK). The finding is encrypted with the DEK using
//     AES-256-GCM, then the DEK is "wrapped" (encrypted) with the master key
//     (KEK), again with AES-256-GCM. Rotating the KEK only means re-wrapping
//     small 32-byte DEKs, not re-encrypting every payload.
//   - Fresh random 12-byte nonce for every GCM operation.
//   - Associated data (AAD) binds ciphertexts to their purpose and binds the
//     payload to the record's blind index, so swapping fields between records
//     or editing the blind index is detected.
//   - Blind index = HMAC-SHA256(indexKey, secret). It lets you count and
//     de-duplicate identical secrets without being able to read them. HMAC
//     (keyed) is used instead of a plain hash because low-entropy secrets such
//     as card numbers can be brute-forced from an unkeyed hash.
//
// Not audited. This demonstrates correct use of standard primitives; it is not
// a replacement for a KMS/HSM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"streamscan/pkg/model"
)

const (
	// KeySize is the size in bytes of the KEK, the DEKs and the index key (AES-256).
	KeySize = 32
	// NonceSize is the standard GCM nonce size in bytes.
	NonceSize = 12
)

var (
	// ErrInvalidKey is returned when a key is not exactly KeySize bytes.
	ErrInvalidKey = errors.New("crypto: key must be exactly 32 bytes")
	// ErrInvalidRecord is returned for structurally broken records (bad nonce length etc.).
	ErrInvalidRecord = errors.New("crypto: malformed encrypted record")
	// ErrAuthentication is returned when GCM authentication fails: wrong key or
	// modified ciphertext, nonce, tag, or associated data.
	ErrAuthentication = errors.New("crypto: authentication failed (wrong key or tampered data)")
)

var (
	dekWrapAAD     = []byte("streamscan/v1/dek-wrap")
	payloadAADBase = "streamscan/v1/payload|"
	indexKeyLabel  = []byte("streamscan/v1/blind-index-key")
)

// EncryptedRecord is the stored form of one finding.
type EncryptedRecord struct {
	WrappedDEK []byte `json:"wrapped_dek"` // DEK encrypted under the KEK (ciphertext || GCM tag)
	DEKNonce   []byte `json:"dek_nonce"`   // nonce used to wrap the DEK
	Payload    []byte `json:"payload"`     // JSON(Finding) encrypted under the DEK (ciphertext || GCM tag)
	Nonce      []byte `json:"nonce"`       // nonce used for the payload
	BlindIndex string `json:"blind_index"` // hex HMAC-SHA256 of the secret value
}

// GenerateKey returns 32 cryptographically secure random bytes.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("crypto: reading random bytes: %w", err)
	}
	return k, nil
}

// DeriveIndexKey derives the blind-index key from the KEK so the two keys are
// never the same value (key separation). HMAC-SHA256 with a fixed label is a
// sound derivation for an already-uniformly-random 256-bit key.
//
// Consequence: rotating the KEK changes every blind index. If you need
// de-duplication to survive rotation, store a separate long-lived index key.
func DeriveIndexKey(kek []byte) []byte {
	mac := hmac.New(sha256.New, kek)
	mac.Write(indexKeyLabel)
	return mac.Sum(nil)
}

// ComputeBlindIndex returns hex(HMAC-SHA256(indexKey, secretValue)). The same
// secret always gives the same index under the same key, so exact-match
// counting and de-duplication work without decrypting anything.
func ComputeBlindIndex(indexKey []byte, secretValue string) string {
	mac := hmac.New(sha256.New, indexKey)
	mac.Write([]byte(secretValue))
	return hex.EncodeToString(mac.Sum(nil))
}

// EncryptFinding encrypts f using envelope encryption and attaches its blind
// index. kek wraps the per-record DEK; indexKey keys the blind index.
func EncryptFinding(kek, indexKey []byte, f model.Finding) (EncryptedRecord, error) {
	if len(kek) != KeySize || len(indexKey) == 0 {
		return EncryptedRecord{}, ErrInvalidKey
	}
	plaintext, err := json.Marshal(f)
	if err != nil {
		return EncryptedRecord{}, fmt.Errorf("crypto: encoding finding: %w", err)
	}

	dek, err := GenerateKey()
	if err != nil {
		return EncryptedRecord{}, err
	}
	defer zero(dek)

	blind := ComputeBlindIndex(indexKey, f.Value)

	nonce, payload, err := seal(dek, plaintext, payloadAAD(blind))
	if err != nil {
		return EncryptedRecord{}, err
	}
	dekNonce, wrapped, err := seal(kek, dek, dekWrapAAD)
	if err != nil {
		return EncryptedRecord{}, err
	}
	return EncryptedRecord{
		WrappedDEK: wrapped,
		DEKNonce:   dekNonce,
		Payload:    payload,
		Nonce:      nonce,
		BlindIndex: blind,
	}, nil
}

// DecryptRecord unwraps the record's DEK with kek, decrypts the payload and
// returns the original finding. Any modification of the record, or the wrong
// kek, yields an error wrapping ErrAuthentication; malformed records yield
// ErrInvalidRecord.
func DecryptRecord(kek []byte, rec EncryptedRecord) (*model.Finding, error) {
	if len(kek) != KeySize {
		return nil, ErrInvalidKey
	}
	dek, err := open(kek, rec.DEKNonce, rec.WrappedDEK, dekWrapAAD)
	if err != nil {
		return nil, fmt.Errorf("unwrapping data key: %w", err)
	}
	defer zero(dek)
	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: unwrapped key has length %d", ErrInvalidRecord, len(dek))
	}

	plaintext, err := open(dek, rec.Nonce, rec.Payload, payloadAAD(rec.BlindIndex))
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}
	var f model.Finding
	if err := json.Unmarshal(plaintext, &f); err != nil {
		return nil, fmt.Errorf("%w: payload is not a finding: %v", ErrInvalidRecord, err)
	}
	return &f, nil
}

func payloadAAD(blindIndex string) []byte {
	return []byte(payloadAADBase + blindIndex)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key) // 32-byte key selects AES-256
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block) // standard 12-byte nonce, 16-byte tag
}

// seal encrypts plaintext under key with a fresh random nonce.
func seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: generating nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// open authenticates and decrypts. The nonce length is checked first because
// cipher.AEAD.Open PANICS on a wrong-length nonce, and records come from
// untrusted JSON.
func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce length %d, want %d", ErrInvalidRecord, len(nonce), gcm.NonceSize())
	}
	if len(ciphertext) < gcm.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext shorter than the GCM tag", ErrInvalidRecord)
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
