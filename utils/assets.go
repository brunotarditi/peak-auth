package utils

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
	assetCache = make(map[string]string)
	cacheMutex sync.RWMutex
)

// GetAssetHash calculating the MD5 hash of a file's content
func GetAssetHash(filePath string) string {
	cacheMutex.RLock()
	hash, exists := assetCache[filePath]
	cacheMutex.RUnlock()

	if exists {
		return hash
	}

	// Calculating the hash
	file, err := os.Open(filePath)
	if err != nil {
		return "1" 
	}
	defer file.Close()

	hashObj := md5.New()
	if _, err := io.Copy(hashObj, file); err != nil {
		return "1"
	}

	calculatedHash := fmt.Sprintf("%x", hashObj.Sum(nil))[:8]

	cacheMutex.Lock()
	assetCache[filePath] = calculatedHash
	cacheMutex.Unlock()

	return calculatedHash
}

// Asset returns the path to an asset with its version hash (e.g. /static/css/styles.css?v=abcdef12)
func Asset(path string) string {
	// Root dir for assets is "static" (without / prefix)
	// We handle the / prefix to find the file
	cleanPath := strings.TrimSpace(path)
	filePath := filepath.Join(".", strings.TrimPrefix(cleanPath, "/"))
	
	hash := GetAssetHash(filePath)
	return fmt.Sprintf("%s?v=%s", cleanPath, hash)
}

// JS returns the correct JS path depending on the environment
func JS(name string) string {
	isProd := os.Getenv("ENV") == "production"
	cleanName := strings.TrimSpace(name)
	
	if isProd {
		minName := strings.Replace(cleanName, ".js", ".min.js", 1)
		return Asset("/static/js/dist/" + minName)
	}
	
	return Asset("/static/js/" + cleanName)
}
