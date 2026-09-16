package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequireHTTPSMiddleware_Development(t *testing.T) {
	// In development mode, HTTP should be allowed
	os.Setenv("ENV", "development")
	defer os.Unsetenv("ENV")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireHTTPSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestRequireHTTPSMiddleware_ProductionWithTLS(t *testing.T) {
	// In production with TLS, request should be allowed
	os.Setenv("ENV", "production")
	defer os.Unsetenv("ENV")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireHTTPSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate TLS connection
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestRequireHTTPSMiddleware_ProductionWithTrustedProxy(t *testing.T) {
	// In production with trusted proxy and X-Forwarded-Proto, request should be allowed
	os.Setenv("ENV", "production")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	defer os.Unsetenv("ENV")
	defer os.Unsetenv("TRUSTED_PROXIES")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireHTTPSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestRequireHTTPSMiddleware_ProductionWithoutTLS(t *testing.T) {
	// In production without TLS or trusted proxy, request should be rejected
	os.Setenv("ENV", "production")
	defer os.Unsetenv("ENV")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireHTTPSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "requires HTTPS")
}

func TestRequireHTTPSMiddleware_ProductionWithUntrustedProxy(t *testing.T) {
	// In production with X-Forwarded-Proto but no TRUSTED_PROXIES, request should be rejected
	os.Setenv("ENV", "production")
	defer os.Unsetenv("ENV")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequireHTTPSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "requires HTTPS")
}
