package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"peak-auth/internal/auth"
	"peak-auth/internal/util"
)

func init() { gin.SetMode(gin.TestMode) }

func csrfRouter() *gin.Engine {
	r := gin.New()
	r.Use(AdminCSRFMiddleware())
	r.GET("/form", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/do", func(c *gin.Context) { c.String(200, "done") })
	return r
}

func TestCSRF_GetIssuesCookie(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/form", nil)
	csrfRouter().ServeHTTP(w, req)
	if !strings.Contains(w.Header().Get("Set-Cookie"), "csrf_token=") {
		t.Fatalf("se esperaba cookie csrf_token, headers: %v", w.Header())
	}
}

func TestCSRF_PostNoOriginRejected(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403, se obtuvo %d", w.Code)
	}
}

func TestCSRF_PostValidPasses(t *testing.T) {
	token := "tok123ABC"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestCSRF_PostMismatchRejected(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "good"})
	req.Header.Set("X-CSRF-Token", "evil")
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403, se obtuvo %d", w.Code)
	}
}

func TestCSRF_PostCrossOriginRejected(t *testing.T) {
	token := "abc"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 por origen cruzado, se obtuvo %d", w.Code)
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.allowed.com")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("no se esperaba ACAO para origen no permitido, se obtuvo %q", got)
	}
}

func TestCORS_AllowedOriginWithCredentials(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.allowed.com")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://app.allowed.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.allowed.com" {
		t.Fatalf("ACAO incorrecto: %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("se esperaba credenciales true, got %q", got)
	}
}

// El comodín "*" nunca debe combinarse con credenciales.
func TestCORS_WildcardNoCredentials(t *testing.T) {
	t.Setenv("FRONTEND_URL", "")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://anything.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("se esperaba '*', got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Fatal("'*' no debe combinarse con Allow-Credentials: true")
	}
}

func TestRateLimit_BlocksAfterLimit(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware(3, time.Minute))
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })

	doReq := func() int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/x", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 0; i < 3; i++ {
		if code := doReq(); code != http.StatusOK {
			t.Fatalf("petición %d debería pasar, got %d", i+1, code)
		}
	}
	if code := doReq(); code != http.StatusTooManyRequests {
		t.Fatalf("la 4ª petición debería ser 429, got %d", code)
	}
}

func TestAuthMiddleware_RejectsMfaPendingToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	manager, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("error creando JWTManager: %v", err)
	}

	r := gin.New()
	r.Use(AuthMiddleware(manager))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "welcome")
	})

	// 1. Probar con token pendiente de MFA -> DEBE ser rechazado (403 Forbidden)
	mfaPendingToken, err := manager.GenerateMFAPendingToken(123, "admin@peakauth.com", util.AppIdPeakAuth)
	if err != nil {
		t.Fatalf("error generando mfaPendingToken: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+mfaPendingToken)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba status 403 Forbidden para token MFA-pending, se obtuvo %d", w.Code)
	}

	// 2. Probar con token verificado -> DEBE ser aceptado (200 OK)
	validToken, err := manager.GenerateToken(123, "admin@peakauth.com", util.AppIdPeakAuth, []string{"ADMIN"}, time.Hour, true)
	if err != nil {
		t.Fatalf("error generando validToken: %v", err)
	}

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+validToken)
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("se esperaba status 200 OK para token verificado, se obtuvo %d", w2.Code)
	}
}
