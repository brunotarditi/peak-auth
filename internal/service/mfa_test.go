package service

import (
	"peak-auth/internal/util"
	"testing"
)

func TestRecoveryCodeHashingAndVerification(t *testing.T) {
	code := "ABCD-1234"

	// 1. Verificar hash SHA-256
	hash := hashRecoveryCode(code)
	if len(hash) <= 7 || hash[:7] != "sha256:" {
		t.Fatalf("se esperaba prefijo sha256:, obtenido: %s", hash)
	}

	// 2. Verificación exitosa con SHA-256 (variaciones de formato)
	testCases := []string{
		"ABCD-1234",
		"abcd-1234",
		"ABCD1234",
		"abcd1234",
		"  ABCD-1234  ",
	}
	for _, tc := range testCases {
		if !verifyRecoveryCodeHash(tc, hash) {
			t.Errorf("falló verificación de código válido con formato: %s", tc)
		}
	}

	// 3. Verificación fallida con código incorrecto o vacío
	if verifyRecoveryCodeHash("WXYZ-9999", hash) {
		t.Errorf("código incorrecto fue aceptado")
	}
	if verifyRecoveryCodeHash("", hash) {
		t.Errorf("código vacío fue aceptado")
	}
	if verifyRecoveryCodeHash("   ", hash) {
		t.Errorf("código con solo espacios fue aceptado")
	}
	if verifyRecoveryCodeHash("ABCD-1234", "") {
		t.Errorf("código con hash almacenado vacío fue aceptado")
	}

	// 4. Retrocompatibilidad con hashes legados de bcrypt
	legacyBcryptHash, err := util.HashPassword("ABCD-1234")
	if err != nil {
		t.Fatalf("error generando hash bcrypt de prueba: %v", err)
	}

	if !verifyRecoveryCodeHash("ABCD-1234", legacyBcryptHash) {
		t.Errorf("falló retrocompatibilidad con hash bcrypt legado")
	}

	if !verifyRecoveryCodeHash("abcd1234", legacyBcryptHash) {
		t.Errorf("falló retrocompatibilidad con hash bcrypt legado normalizado")
	}

	if verifyRecoveryCodeHash("FAIL-0000", legacyBcryptHash) {
		t.Errorf("código erróneo fue aceptado en hash bcrypt legado")
	}
}
