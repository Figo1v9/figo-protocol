package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// GenerateNonce generates a cryptographically random nonce of the given length.
func GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("fgxp/crypto: generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateSessionID generates a random 16-byte session ID.
func GenerateSessionID() ([]byte, error) {
	return GenerateNonce(16)
}

// GenerateResumptionToken generates a random 32-byte resumption token.
func GenerateResumptionToken() ([]byte, error) {
	return GenerateNonce(32)
}

// TimestampBytes returns the current time as an 8-byte big-endian
// Unix millisecond timestamp.
func TimestampBytes() []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UnixMilli()))
	return ts
}

// ParseTimestamp parses an 8-byte big-endian Unix millisecond timestamp.
func ParseTimestamp(data []byte) time.Time {
	if len(data) < 8 {
		return time.Time{}
	}
	ms := binary.BigEndian.Uint64(data)
	return time.UnixMilli(int64(ms))
}
