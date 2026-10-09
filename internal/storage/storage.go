package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// MaxLogoSize define el tamaño máximo permitido para logos de aplicaciones (5 MB).
	MaxLogoSize int64 = 5 * 1024 * 1024
	// MaxFaviconSize define el tamaño máximo para favicons (2 MB).
	MaxFaviconSize int64 = 2 * 1024 * 1024
	// MaxAvatarSize define el tamaño máximo para avatares de usuario (5 MB).
	MaxAvatarSize int64 = 5 * 1024 * 1024
	// MaxFileSize define el tamaño máximo genérico por defecto (5 MB).
	MaxFileSize int64 = 5 * 1024 * 1024

	// Folders válidos para almacenamiento
	FolderLogos   = "logos"
	FolderAvatars = "avatars"
	FolderFavicon = "favicons"
)

var (
	ErrFileTooLarge     = errors.New("el archivo excede el tamaño máximo permitido")
	ErrLogoTooLarge     = errors.New("el logo excede el tamaño máximo permitido de 5 MB")
	ErrFaviconTooLarge  = errors.New("el favicon excede el tamaño máximo permitido de 2 MB")
	ErrAvatarTooLarge   = errors.New("el avatar excede el tamaño máximo permitido de 5 MB")
	ErrInvalidFileType  = errors.New("formato de imagen no permitido. Solo se aceptan PNG, JPG, WebP, SVG e ICO")
	ErrEmptyFile        = errors.New("el archivo está vacío")
	ErrInvalidFolder    = errors.New("directorio de almacenamiento inválido")
)

// AllowedMIMETypes mapea tipos MIME admitidos a su extensión canónica.
var AllowedMIMETypes = map[string]string{
	"image/jpeg":                ".jpg",
	"image/png":                 ".png",
	"image/webp":                ".webp",
	"image/svg+xml":             ".svg",
	"image/x-icon":              ".ico",
	"image/vnd.microsoft.icon":  ".ico",
}

// StorageService define la interfaz para el almacenamiento de archivos (logos, avatares, favicons).
type StorageService interface {
	Upload(ctx context.Context, r io.Reader, originalFilename string, folder string) (string, error)
	Delete(ctx context.Context, fileURL string) error
}

// LocalStorageService implementa StorageService almacenando en el sistema de archivos local.
type LocalStorageService struct {
	baseDir string
	mu      sync.RWMutex
}

// NewLocalStorageService crea una nueva instancia de almacenamiento local.
func NewLocalStorageService(baseDir string) (*LocalStorageService, error) {
	if baseDir == "" {
		baseDir = filepath.Join("web", "static", "uploads")
	}

	for _, folder := range []string{FolderLogos, FolderAvatars, FolderFavicon} {
		p := filepath.Join(baseDir, folder)
		if err := os.MkdirAll(p, 0755); err != nil {
			return nil, fmt.Errorf("no se pudo inicializar directorio de uploads %s: %w", p, err)
		}
	}

	return &LocalStorageService{baseDir: baseDir}, nil
}

func getFolderLimit(folder string) (int64, error) {
	switch folder {
	case FolderLogos:
		return MaxLogoSize, ErrLogoTooLarge
	case FolderFavicon:
		return MaxFaviconSize, ErrFaviconTooLarge
	case FolderAvatars:
		return MaxAvatarSize, ErrAvatarTooLarge
	default:
		return MaxFaviconSize, ErrFileTooLarge
	}
}

// Upload valida el archivo, verifica sus magic bytes y lo guarda en disco de manera segura.
func (s *LocalStorageService) Upload(ctx context.Context, r io.Reader, originalFilename string, folder string) (string, error) {
	if folder != FolderLogos && folder != FolderAvatars && folder != FolderFavicon {
		return "", ErrInvalidFolder
	}

	maxLimit, limitErr := getFolderLimit(folder)

	// Leer hasta maxLimit + 1 byte para detectar si excede el límite
	limitedReader := io.LimitReader(r, maxLimit+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("error al leer el archivo: %w", err)
	}

	if len(data) == 0 {
		return "", ErrEmptyFile
	}
	if int64(len(data)) > maxLimit {
		return "", limitErr
	}

	// Detectar tipo MIME a través de los primeros 512 bytes
	mimeType := detectMIMEType(data, originalFilename)
	ext, ok := AllowedMIMETypes[mimeType]
	if !ok {
		return "", ErrInvalidFileType
	}

	// Generar nombre de archivo criptográficamente único para evitar colisiones y path traversal
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("error al generar nombre seguro para el archivo: %w", err)
	}
	filename := hex.EncodeToString(randomBytes) + ext

	targetPath := filepath.Join(s.baseDir, folder, filename)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.WriteFile(targetPath, data, 0644); err != nil {
		return "", fmt.Errorf("error al guardar archivo en disco: %w", err)
	}

	// Retorna la ruta web pública
	publicURL := fmt.Sprintf("/static/uploads/%s/%s", folder, filename)
	return publicURL, nil
}

// Delete elimina un archivo previamente subido si se encuentra dentro del directorio de uploads.
func (s *LocalStorageService) Delete(ctx context.Context, fileURL string) error {
	if !strings.HasPrefix(fileURL, "/static/uploads/") {
		// URLs externas o no locales se ignoran de forma segura
		return nil
	}

	relPath := strings.TrimPrefix(fileURL, "/static/uploads/")
	cleanRel := filepath.Clean(relPath)
	if strings.Contains(cleanRel, "..") {
		return errors.New("ruta de archivo inválida")
	}

	fullPath := filepath.Join(s.baseDir, cleanRel)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error eliminando archivo local: %w", err)
	}

	return nil
}

// detectMIMEType inspecciona los magic bytes del archivo y la extensión para identificar el MIME exacto.
func detectMIMEType(data []byte, filename string) string {
	head := data
	if len(head) > 512 {
		head = head[:512]
	}

	detected := http.DetectContentType(head)
	lowerName := strings.ToLower(filename)

	// DetectContentType detecta SVG como "text/xml" o "text/plain; charset=utf-8"
	if strings.HasSuffix(lowerName, ".svg") {
		strHead := strings.ToLower(string(head))
		if strings.Contains(strHead, "<svg") || strings.Contains(strHead, "<?xml") {
			return "image/svg+xml"
		}
	}

	// DetectContentType a menudo detecta .ico como "image/x-icon" o "application/octet-stream"
	if strings.HasSuffix(lowerName, ".ico") {
		if bytes.HasPrefix(head, []byte{0x00, 0x00, 0x01, 0x00}) {
			return "image/x-icon"
		}
	}

	// Truncar parámetros como "; charset=utf-8"
	if idx := strings.Index(detected, ";"); idx != -1 {
		detected = detected[:idx]
	}

	return detected
}

// NewStorageService instancia el proveedor de almacenamiento según la configuración de entorno.
func NewStorageService() (StorageService, error) {
	driver := strings.ToLower(os.Getenv("STORAGE_DRIVER"))
	uploadsDir := os.Getenv("UPLOADS_DIR")

	switch driver {
	case "s3", "r2":
		accountID := os.Getenv("R2_ACCOUNT_ID")
		accessKey := os.Getenv("R2_ACCESS_KEY_ID")
		secretKey := os.Getenv("R2_SECRET_ACCESS_KEY")
		bucket := os.Getenv("R2_BUCKET_NAME")
		publicURL := os.Getenv("R2_PUBLIC_URL")

		if accountID != "" && accessKey != "" && secretKey != "" && bucket != "" {
			return NewR2StorageService(accountID, accessKey, secretKey, bucket, publicURL)
		}
		return NewLocalStorageService(uploadsDir)
	default:
		return NewLocalStorageService(uploadsDir)
	}
}
