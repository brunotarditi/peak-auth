package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type mockOriginChecker struct {
	allowed map[string][]string
}

func (m *mockOriginChecker) IsOriginAllowed(appID string, origin string) bool {
	origins, ok := m.allowed[appID]
	if !ok {
		return false
	}
	for _, o := range origins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

func TestCORS_AppSpecificAllowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	checker := &mockOriginChecker{
		allowed: map[string][]string{
			"libreria-mariela": {"http://localhost:3000", "http://localhost:4200"},
		},
	}

	r := gin.New()
	r.Use(CORSMiddleware(checker))
	r.POST("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Origin", "http://localhost:4200")
	req.Header.Set("X-App-ID", "libreria-mariela")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:4200" {
		t.Errorf("expected Access-Control-Allow-Origin to be 'http://localhost:4200', got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials to be 'true'")
	}
}

func TestCORS_AppSpecificDisallowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	checker := &mockOriginChecker{
		allowed: map[string][]string{
			"libreria-mariela": {"http://localhost:4200"},
		},
	}

	t.Setenv("FRONTEND_URL", "https://auth.peakauth.com")

	r := gin.New()
	r.Use(CORSMiddleware(checker))
	r.POST("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Origin", "https://malicious-site.com")
	req.Header.Set("X-App-ID", "libreria-mariela")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected Access-Control-Allow-Origin to be empty for disallowed origin, got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORS_PreflightOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	checker := &mockOriginChecker{
		allowed: map[string][]string{
			"libreria-mariela": {"http://localhost:4200"},
		},
	}

	r := gin.New()
	r.Use(CORSMiddleware(checker))
	r.OPTIONS("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodOptions, "/api/test", nil)
	req.Header.Set("Origin", "http://localhost:4200")
	req.Header.Set("X-App-ID", "libreria-mariela")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected HTTP 204 No Content for preflight OPTIONS, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:4200" {
		t.Errorf("expected Access-Control-Allow-Origin to be reflected on preflight, got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
}
