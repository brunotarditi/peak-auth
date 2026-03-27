package utils

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	cleanPath := filepath.Join(".", path)
	hash := GetAssetHash(cleanPath)
	return fmt.Sprintf("%s?v=%s", path, hash)
}
