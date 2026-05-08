package util

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// assetCache guarda los hashes ya calculados para no leer el disco en cada request
	assetCache = make(map[string]string)
	cacheMutex sync.RWMutex
)

// GetAssetHash calcula un hash MD5 corto basado en el contenido de un archivo
func GetAssetHash(filePath string) string {
	cacheMutex.RLock()
	hash, exists := assetCache[filePath]
	cacheMutex.RUnlock()

	if exists {
		return hash
	}

	// Si no está en cache, lo leemos del disco
	file, err := os.Open(filePath)
	if err != nil {
		return "1"
	}
	defer file.Close()

	hashObj := md5.New()
	if _, err := io.Copy(hashObj, file); err != nil {
		return "1"
	}

	// Tomamos los primeros 8 caracteres del hash
	calculatedHash := fmt.Sprintf("%x", hashObj.Sum(nil))[:8]

	cacheMutex.Lock()
	assetCache[filePath] = calculatedHash
	cacheMutex.Unlock()

	return calculatedHash
}

// Asset retorna la ruta de un asset con un hash de versión (ej: /static/css/style.css?v=abcdef12)
func Asset(path string) string {
	cleanPath := strings.TrimSpace(path)
	// Normalizar ruta para encontrar el archivo en el sistema de archivos
	filePath := filepath.Join(".", strings.TrimPrefix(cleanPath, "/"))

	hash := GetAssetHash(filePath)
	return fmt.Sprintf("%s?v=%s", cleanPath, hash)
}

// JS retorna la ruta de un script, permitiendo cargar versiones .min.js en producción
func JS(name string) string {
	isProd := os.Getenv("ENV") == "production"
	cleanName := strings.TrimSpace(name)

	if isProd {
		// En producción, buscamos la versión minificada si existe en static/js/dist/
		minName := strings.Replace(cleanName, ".js", ".min.js", 1)
		return Asset("/static/js/dist/" + minName)
	}

	return Asset("/static/js/" + cleanName)
}
