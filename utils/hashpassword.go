package utils

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashea una contraseña usando bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compara una contraseña con su hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CheckTokenSHA256 compara un token con su hash
func CheckTokenSHA256(plainToken string, hashFromDB []byte) bool {
	hashedToken := sha256.Sum256([]byte(plainToken))
	return hmac.Equal(hashedToken[:], hashFromDB)
}
