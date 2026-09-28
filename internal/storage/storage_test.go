package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Magic bytes mínimos para simular imágenes válidas en tests
var (
	pngHeader  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D}
	jpegHeader = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	svgContent = []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>`)
)

func TestLocalStorageService_UploadAndValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "peak-auth-storage-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	svc, err := NewLocalStorageService(tempDir)
	if err != nil {
		t.Fatalf("NewLocalStorageService failed: %v", err)
	}
	ctx := context.Background()

	t.Run("Upload valid PNG succeeds", func(t *testing.T) {
		url, err := svc.Upload(ctx, bytes.NewReader(pngHeader), "logo.png", FolderLogos)
		if err != nil {
			t.Fatalf("expected upload to succeed, got: %v", err)
		}
		if !strings.HasPrefix(url, "/static/uploads/logos/") || !strings.HasSuffix(url, ".png") {
			t.Errorf("unexpected url format: %s", url)
		}

		// Verify file exists on disk
		cleanPath := filepath.Join(tempDir, strings.TrimPrefix(url, "/static/uploads/"))
		if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
			t.Errorf("expected file to exist at %s", cleanPath)
		}
	})

	t.Run("Upload valid SVG succeeds", func(t *testing.T) {
		url, err := svc.Upload(ctx, bytes.NewReader(svgContent), "brand.svg", FolderLogos)
		if err != nil {
			t.Fatalf("expected upload to succeed, got: %v", err)
		}
		if !strings.HasPrefix(url, "/static/uploads/logos/") || !strings.HasSuffix(url, ".svg") {
			t.Errorf("unexpected url format: %s", url)
		}
	})

	t.Run("Upload valid JPEG avatar succeeds", func(t *testing.T) {
		url, err := svc.Upload(ctx, bytes.NewReader(jpegHeader), "avatar.jpg", FolderAvatars)
		if err != nil {
			t.Fatalf("expected upload to succeed, got: %v", err)
		}
		if !strings.HasPrefix(url, "/static/uploads/avatars/") || !strings.HasSuffix(url, ".jpg") {
			t.Errorf("unexpected url format: %s", url)
		}
	})

	t.Run("Upload empty file fails", func(t *testing.T) {
		_, err := svc.Upload(ctx, bytes.NewReader([]byte{}), "empty.png", FolderLogos)
		if err != ErrEmptyFile {
			t.Errorf("expected ErrEmptyFile, got: %v", err)
		}
	})

	t.Run("Upload file exceeding 5MB for logo fails", func(t *testing.T) {
		oversized := make([]byte, MaxLogoSize+10)
		copy(oversized, pngHeader)

		_, err := svc.Upload(ctx, bytes.NewReader(oversized), "big.png", FolderLogos)
		if err != ErrLogoTooLarge {
			t.Errorf("expected ErrLogoTooLarge, got: %v", err)
		}
	})

	t.Run("Upload file exceeding 2MB for favicon fails", func(t *testing.T) {
		oversized := make([]byte, MaxFaviconSize+10)
		copy(oversized, pngHeader)

		_, err := svc.Upload(ctx, bytes.NewReader(oversized), "big.png", FolderFavicon)
		if err != ErrFaviconTooLarge {
			t.Errorf("expected ErrFaviconTooLarge, got: %v", err)
		}
	})

	t.Run("Upload executable or HTML disguised as image fails", func(t *testing.T) {
		fakeImage := []byte("<script>alert('xss')</script>")
		_, err := svc.Upload(ctx, bytes.NewReader(fakeImage), "malicious.png", FolderLogos)
		if err != ErrInvalidFileType {
			t.Errorf("expected ErrInvalidFileType, got: %v", err)
		}
	})

	t.Run("Upload to invalid folder fails", func(t *testing.T) {
		_, err := svc.Upload(ctx, bytes.NewReader(pngHeader), "logo.png", "sensitive_folder")
		if err != ErrInvalidFolder {
			t.Errorf("expected ErrInvalidFolder, got: %v", err)
		}
	})

	t.Run("Delete removes file from disk", func(t *testing.T) {
		url, err := svc.Upload(ctx, bytes.NewReader(pngHeader), "to_delete.png", FolderLogos)
		if err != nil {
			t.Fatalf("upload failed: %v", err)
		}

		cleanPath := filepath.Join(tempDir, strings.TrimPrefix(url, "/static/uploads/"))
		if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
			t.Fatalf("file should exist before delete")
		}

		if err := svc.Delete(ctx, url); err != nil {
			t.Fatalf("delete failed: %v", err)
		}

		if _, err := os.Stat(cleanPath); !os.IsNotExist(err) {
			t.Errorf("file should not exist after delete")
		}
	})

	t.Run("Delete with path traversal is blocked", func(t *testing.T) {
		err := svc.Delete(ctx, "/static/uploads/logos/../../etc/passwd")
		if err == nil || !strings.Contains(err.Error(), "inválida") {
			t.Errorf("expected path traversal to be rejected, got: %v", err)
		}
	})
}
