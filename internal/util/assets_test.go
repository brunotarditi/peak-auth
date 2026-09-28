package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetAssetHash_And_Asset(t *testing.T) {
	tempDir := t.TempDir()
	testFile := "test.css"
	testContent := "body { background: #000; }"

	err := os.WriteFile(filepath.Join(tempDir, testFile), []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hash1 := GetAssetHash(tempDir, testFile)
	if hash1 == "1" || len(hash1) != 8 {
		t.Fatalf("unexpected hash: %s", hash1)
	}

	// Repeated call should hit cache and return identical hash
	hash2 := GetAssetHash(tempDir, testFile)
	if hash1 != hash2 {
		t.Fatalf("expected identical cached hash, got %s and %s", hash1, hash2)
	}

	// Non-existent file fallback
	hashMissing := GetAssetHash(tempDir, "missing.css")
	if hashMissing != "1" {
		t.Errorf("expected fallback hash '1' for missing file, got %s", hashMissing)
	}
}

func TestJS(t *testing.T) {
	t.Run("development mode", func(t *testing.T) {
		t.Setenv("ENV", "development")
		res := JS("app.js")
		if !strings.HasPrefix(res, "/static/js/app.js?v=") {
			t.Errorf("unexpected JS path in dev mode: %s", res)
		}
	})

	t.Run("production mode", func(t *testing.T) {
		t.Setenv("ENV", "production")
		res := JS("app.js")
		if !strings.HasPrefix(res, "/static/js/dist/app.min.js?v=") {
			t.Errorf("unexpected JS path in prod mode: %s", res)
		}
	})
}
