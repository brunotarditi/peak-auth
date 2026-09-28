package util

import (
	"crypto/sha256"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	lengths := []int{16, 32, 64}

	for _, l := range lengths {
		plain, hash, err := GenerateToken(l)
		if err != nil {
			t.Fatalf("GenerateToken(%d) error: %v", l, err)
		}
		if len(plain) == 0 {
			t.Errorf("expected non-empty plain token")
		}
		if len(hash) != sha256.Size {
			t.Errorf("expected hash length %d, got %d", sha256.Size, len(hash))
		}

		expectedHash := sha256.Sum256([]byte(plain))
		if string(hash) != string(expectedHash[:]) {
			t.Errorf("hash does not match sha256 of plain token")
		}
	}

	// Distinct tokens
	t1, _, _ := GenerateToken(32)
	t2, _, _ := GenerateToken(32)
	if t1 == t2 {
		t.Errorf("expected consecutive tokens to be distinct")
	}
}
