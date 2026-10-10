package peakauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

// GenerateState genera un valor 'state' criptográficamente seguro para mitigar CSRF en flujos OAuth.
// El valor debe guardarse en una sesión segura temporal y consumirse de forma única.
func GenerateState(length ...int) (string, error) {
	size := 32
	if len(length) > 0 && length[0] >= 16 && length[0] <= 128 {
		size = length[0]
	}

	randomBytes := make([]byte, size)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("error generando state aleatorio: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// ValidateState compara dos estados en tiempo constante para mitigar ataques de temporización (timing attacks).
// Devuelve true únicamente si coinciden exactamente y no están vacíos.
func ValidateState(expectedState, actualState string) bool {
	if expectedState == "" || actualState == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expectedState), []byte(actualState)) == 1
}
