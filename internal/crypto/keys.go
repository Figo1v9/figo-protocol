// Package crypto provides internal cryptographic utilities for FGXP.
// It wraps standard library primitives and provides protocol-specific
// key derivation functions. No custom cryptography is implemented.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey uses HKDF-SHA256 to derive a key from a master secret.
//
//	secret: the input keying material (e.g., PSK)
//	label:  a protocol-specific label (e.g., "fgxp auth")
//	context: optional context data (e.g., session ID)
//	length: desired output key length in bytes
func DeriveKey(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// HKDF-Expand with SHA-256 as the hash function.
	// The "info" parameter is constructed as: label || context
	info := append([]byte(label), context...)
	reader := hkdf.New(sha256.New, secret, nil, info)

	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("fgxp/crypto: hkdf derive: %w", err)
	}
	return key, nil
}

// DeriveAuthKey derives the authentication key from a PSK.
func DeriveAuthKey(psk []byte) ([]byte, error) {
	return DeriveKey(psk, "fgxp auth", nil, 32)
}

// DeriveSessionKey derives a session-specific key.
func DeriveSessionKey(psk, sessionID []byte) ([]byte, error) {
	return DeriveKey(psk, "fgxp session", sessionID, 32)
}

// DeriveResumptionKey derives a resumption token key.
func DeriveResumptionKey(psk, sessionID []byte, timestamp []byte) ([]byte, error) {
	ctx := append(sessionID, timestamp...)
	return DeriveKey(psk, "fgxp resume", ctx, 32)
}

// ComputeHMAC computes HMAC-SHA256 over the given data using the key.
func ComputeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC verifies an HMAC-SHA256 in constant time.
// Returns true if the provided mac matches the computed mac.
func VerifyHMAC(key, data, providedMAC []byte) bool {
	expected := ComputeHMAC(key, data)
	return hmac.Equal(expected, providedMAC)
}

// ComputeKeyID computes the 8-byte key ID from a PSK: SHA256(PSK)[0:8].
func ComputeKeyID(psk []byte) []byte {
	hash := sha256.Sum256(psk)
	id := make([]byte, 8)
	copy(id, hash[:8])
	return id
}

// CreateCTRStream creates a cipher.Stream using AES-256-CTR for stream obfuscation.
func CreateCTRStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fgxp/crypto: new aes cipher: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}

