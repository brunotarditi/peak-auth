package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// EncryptAESGCM cifra un texto plano con AES-256-GCM usando la clave de entorno MFA_ENCRYPTION_KEY.
func EncryptAESGCM(plaintext string) (string, error) {
	key, err := GetMfaEncryptionKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creando cipher AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creando GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("error generando nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCM descifra un texto cifrado con AES-256-GCM.
func DecryptAESGCM(encrypted string) (string, error) {
	key, err := GetMfaEncryptionKey()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("error decodificando base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creando cipher AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creando GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("datos cifrados demasiado cortos")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("error descifrando: %w", err)
	}

	return string(plaintext), nil
}

// GenerateRecoveryCodes genera n códigos de recuperación alfanuméricos de 8 caracteres
// en formato XXXX-XXXX para facilitar la lectura.
func GenerateRecoveryCodes(n int) ([]string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Sin I, O, 0, 1 para evitar confusión
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for j := 0; j < 8; j++ {
			if j == 4 {
				sb.WriteByte('-')
			}
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, fmt.Errorf("error generando código de recuperación: %w", err)
			}
			sb.WriteByte(charset[idx.Int64()])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

func GetMfaEncryptionKey() ([]byte, error) {
	keyB64 := os.Getenv("MFA_ENCRYPTION_KEY")
	if keyB64 == "" {
		return nil, fmt.Errorf("la variable de entorno MFA_ENCRYPTION_KEY no está definida. Debe ser una cadena Base64 de 32 bytes")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("MFA_ENCRYPTION_KEY no es base64 válido: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("MFA_ENCRYPTION_KEY debe ser de 32 bytes (256 bits), se recibieron %d bytes", len(key))
	}
	return key, nil
}
