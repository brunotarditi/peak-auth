package util

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGetMfaEncryptionKey(t *testing.T) {
	t.Run("missing env", func(t *testing.T) {
		t.Setenv("MFA_ENCRYPTION_KEY", "")
		_, err := GetMfaEncryptionKey()
		if err == nil {
			t.Fatal("expected error for missing MFA_ENCRYPTION_KEY")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		t.Setenv("MFA_ENCRYPTION_KEY", "not-base-64!!!")
		_, err := GetMfaEncryptionKey()
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("wrong byte length", func(t *testing.T) {
		shortKey := base64.StdEncoding.EncodeToString([]byte("too-short-key"))
		t.Setenv("MFA_ENCRYPTION_KEY", shortKey)
		_, err := GetMfaEncryptionKey()
		if err == nil {
			t.Fatal("expected error for key length != 32 bytes")
		}
	})

	t.Run("valid 32-byte key", func(t *testing.T) {
		validKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
		t.Setenv("MFA_ENCRYPTION_KEY", validKey)
		key, err := GetMfaEncryptionKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(key) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(key))
		}
	})
}

func TestEncryptAndDecryptAESGCM(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	t.Setenv("MFA_ENCRYPTION_KEY", validKey)

	plaintext := "JBSWY3DPEHPK3PXP-SUPER-SECRET-TOTP"

	encrypted, err := EncryptAESGCM(plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("ciphertext should not match plaintext")
	}

	decrypted, err := DecryptAESGCM(encrypted)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}

	t.Run("tampered ciphertext fails decryption", func(t *testing.T) {
		data, _ := base64.StdEncoding.DecodeString(encrypted)
		data[len(data)-1] ^= 0xFF // flip bit
		tampered := base64.StdEncoding.EncodeToString(data)

		_, err := DecryptAESGCM(tampered)
		if err == nil {
			t.Fatal("expected decryption error on tampered ciphertext")
		}
	})

	t.Run("short ciphertext fails", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := DecryptAESGCM(short)
		if err == nil {
			t.Fatal("expected error on short ciphertext")
		}
	})
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("unexpected error generating recovery codes: %v", err)
	}

	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	for _, c := range codes {
		if len(c) != 9 { // 4 chars + '-' + 4 chars = 9
			t.Errorf("unexpected code format length: %s", c)
		}
		if c[4] != '-' {
			t.Errorf("code missing hyphen at position 4: %s", c)
		}
		if strings.ContainsAny(c, "IO01") {
			t.Errorf("code contains ambiguous characters (I, O, 0, 1): %s", c)
		}
	}
}
