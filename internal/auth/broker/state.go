package broker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidStateFormat = errors.New("formato de estado de relay inválido")
	ErrInvalidSignature   = errors.New("firma criptográfica de estado inválida o alterada")
	ErrExpiredState       = errors.New("el estado de relay ha expirado")
)

// RelayState empaqueta el contexto del flujo OAuth 2.0 PKCE para preservarlo durante el viaje de ida y vuelta al proveedor externo
type RelayState struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Provider            string `json:"provider"`
	Timestamp           int64  `json:"ts"`
	Nonce               string `json:"nonce"`
}

// GenerateNonce genera un identificador criptográfico pseudo-aleatorio de 32 caracteres hexadecimales (16 bytes)
func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("error generando nonce aleatorio: %w", err)
	}
	return hex.EncodeToString(nonceBytes), nil
}

// GenerateRelayState serializa y firma criptográficamente el estado con HMAC-SHA256
func GenerateRelayState(params RelayState, secretKey string) (string, error) {
	if secretKey == "" {
		return "", errors.New("secretKey requerida para firmar el estado de relay")
	}

	if params.Timestamp == 0 {
		params.Timestamp = time.Now().Unix()
	}

	if params.Nonce == "" {
		nonce, err := GenerateNonce()
		if err != nil {
			return "", err
		}
		params.Nonce = nonce
	}

	payloadJSON, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("error serializando estado de relay: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payloadB64, sigB64), nil
}

// ValidateRelayState verifica la firma HMAC y la vigencia temporal del estado de relay
func ValidateRelayState(rawState string, secretKey string, maxAge time.Duration) (*RelayState, error) {
	if secretKey == "" {
		return nil, errors.New("secretKey requerida para validar el estado de relay")
	}

	parts := strings.Split(rawState, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidStateFormat
	}

	payloadB64 := parts[0]
	sigB64 := parts[1]

	expectedSigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidStateFormat
	}

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payloadB64))
	computedSig := mac.Sum(nil)

	if !hmac.Equal(computedSig, expectedSigBytes) {
		return nil, ErrInvalidSignature
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidStateFormat
	}

	var state RelayState
	if err := json.Unmarshal(payloadJSON, &state); err != nil {
		return nil, ErrInvalidStateFormat
	}

	now := time.Now().Unix()
	// Verificación de expiración (por defecto máx 10 minutos)
	if now-state.Timestamp > int64(maxAge.Seconds()) {
		return nil, ErrExpiredState
	}

	// Tolerancia de 60s hacia el futuro para desfases de reloj
	if state.Timestamp > now+60 {
		return nil, ErrInvalidStateFormat
	}

	return &state, nil
}

// ExtractRelayState deserializa el payload del estado de relay sin verificar firma
// Útil exclusivamente para recuperar parámetros de navegación al redirigir ante errores
func ExtractRelayState(rawState string) (*RelayState, error) {
	parts := strings.Split(rawState, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidStateFormat
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidStateFormat
	}
	var state RelayState
	if err := json.Unmarshal(payloadJSON, &state); err != nil {
		return nil, ErrInvalidStateFormat
	}
	return &state, nil
}
