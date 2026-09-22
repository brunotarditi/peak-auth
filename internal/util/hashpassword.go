package util

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

// dummyBcryptHash es un hash bcrypt precalculado con DefaultCost (10).
// Se utiliza para mitigar timing attacks y user enumeration cuando una cuenta no existe.
const dummyBcryptHash = "$2a$10$FKTUgxnqSnUp8kDjnTFlyOn3s165yiYmcLxXeNv7NavMY3DH19IIq"

// PerformDummyPasswordCheck ejecuta una comparación bcrypt en tiempo constante contra un hash ficticio.
// Esto garantiza que el tiempo de respuesta sea indistinguible entre usuarios existentes e inexistentes
// (defensa contra enumeración de cuentas por análisis de tiempos de respuesta - OWASP).
func PerformDummyPasswordCheck() {
	_ = CheckPasswordHash("dummy", dummyBcryptHash)
}

