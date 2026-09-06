package util

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	assetCache = make(map[string]string)
	cacheMutex sync.RWMutex
)

// GetAssetHash calcula un hash SHA256 corto basado en el contenido de un archivo usando os.Root para evitar Path Traversal
func GetAssetHash(baseDir, relativePath string) string {
	// Identificador único para el caché combinando ambos
	cacheKey := filepath.Join(baseDir, relativePath)
	
	cacheMutex.RLock()
	hash, exists := assetCache[cacheKey]
	cacheMutex.RUnlock()

	if exists {
		return hash
	}

	// Abrir el directorio base de forma segura (mitigación absoluta de Path Traversal)
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return "1"
	}
	defer root.Close()

	// Abrir el archivo relativo usando el entorno acotado (chroot-like)
	file, err := root.Open(relativePath)
	if err != nil {
		return "1"
	}
	defer file.Close()

	hashObj := sha256.New()
	if _, err := io.Copy(hashObj, file); err != nil {
		return "1"
	}

	// Tomamos los primeros 8 caracteres del hash
	calculatedHash := fmt.Sprintf("%x", hashObj.Sum(nil))[:8]

	cacheMutex.Lock()
	assetCache[cacheKey] = calculatedHash
	cacheMutex.Unlock()

	return calculatedHash
}

// Asset retorna la ruta de un asset con un hash de versión (ej: /static/css/style.css?v=abcdef12)
func Asset(path string) string {
	baseDir := AssetsDir()
	cleanPath := strings.TrimSpace(path)
	relativePath := strings.TrimPrefix(cleanPath, "/")

	hash := GetAssetHash(baseDir, relativePath)
	return fmt.Sprintf("%s?v=%s", cleanPath, hash)
}

// JS retorna la ruta de un script, permitiendo cargar versiones .min.js en producción
func JS(name string) string {
	isProd := IsProduction()
	cleanName := strings.TrimSpace(name)

	if isProd {
		// En producción, buscamos la versión minificada si existe en static/js/dist/
		minName := strings.Replace(cleanName, ".js", ".min.js", 1)
		return Asset("/static/js/dist/" + minName)
	}

	return Asset("/static/js/" + cleanName)
}
