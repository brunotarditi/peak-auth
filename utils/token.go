package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func GenerateToken(n int) (string, []byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	plain := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(plain))
	return plain, hash[:], nil
}
