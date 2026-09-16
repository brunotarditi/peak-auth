package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Fatalf("expected OK, got %s", w.Body.String())
	}
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

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Fatalf("expected OK, got %s", w.Body.String())
	}
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

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Fatalf("expected OK, got %s", w.Body.String())
	}
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

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "requires HTTPS") {
		t.Fatalf("expected error message to contain 'requires HTTPS', got %s", w.Body.String())
	}
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

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "requires HTTPS") {
		t.Fatalf("expected error message to contain 'requires HTTPS', got %s", w.Body.String())
	}
}
