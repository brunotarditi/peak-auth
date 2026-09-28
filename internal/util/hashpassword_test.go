package util

import (
	"crypto/sha256"
	"testing"
)

func TestHashPasswordAndCheck(t *testing.T) {
	pass := "MySecureP@ssw0rd123"

	hashed, err := HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	if !CheckPasswordHash(pass, hashed) {
		t.Errorf("CheckPasswordHash failed with correct password")
	}

	if CheckPasswordHash("WrongPassword", hashed) {
		t.Errorf("CheckPasswordHash succeeded with wrong password")
	}
}

func TestCheckTokenSHA256(t *testing.T) {
	token := "random-secure-token-value"
	hash := sha256.Sum256([]byte(token))

	if !CheckTokenSHA256(token, hash[:]) {
		t.Errorf("CheckTokenSHA256 failed with correct token")
	}

	if CheckTokenSHA256("wrong-token", hash[:]) {
		t.Errorf("CheckTokenSHA256 succeeded with wrong token")
	}
}

func TestPerformDummyPasswordCheck(t *testing.T) {
	// Must execute without panic or error
	PerformDummyPasswordCheck()
}
