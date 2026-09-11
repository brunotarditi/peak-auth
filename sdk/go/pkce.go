package peakauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GeneratePKCE crea un par code_verifier y code_challenge (S256) criptográficamente seguro.
// El tamaño por defecto es de 64 bytes (longitud típica recomendada por RFC 7636).
func GeneratePKCE(length ...int) (*PKCEPair, error) {
	size := 64
	if len(length) > 0 && length[0] >= 43 && length[0] <= 128 {
		size = length[0]
	}

	randomBytes := make([]byte, size)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("error generando bytes aleatorios: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(randomBytes)
	if len(verifier) > 128 {
		verifier = verifier[:128]
	}

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEPair{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}, nil
}
