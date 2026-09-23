package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"peak-auth/internal/app"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestApp(t *testing.T) (*gin.Engine, *app.App) {
	t.Helper()

	// Generar clave privada RSA para el test
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error al generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth-test")
	t.Setenv("APP_BASE_URL", "http://localhost:8080")

	tm, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("error creando TokenManager: %v", err)
	}

	testApp := &app.App{
		TokenManager:  tm,
		HealthService: service.NewHealthService(nil, tm),
	}

	r := gin.New()
	SetRoutes(r, testApp)

	return r, testApp
}

func TestOpenIDConfigurationEndpoint(t *testing.T) {
	r, _ := setupTestApp(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba status 200, obtenido: %d", w.Code)
	}

	if allowOrigin := w.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "*" {
		t.Errorf("se esperaba Access-Control-Allow-Origin: *, obtenido: %q", allowOrigin)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("no se pudo decodificar json: %v", err)
	}

	if resp["issuer"] != "peak-auth-test" {
		t.Errorf("se esperaba issuer 'peak-auth-test', obtenido: %v", resp["issuer"])
	}
	if resp["authorization_endpoint"] != "http://localhost:8080/oauth/authorize" {
		t.Errorf("authorization_endpoint incorrecto: %v", resp["authorization_endpoint"])
	}
	if resp["token_endpoint"] != "http://localhost:8080/oauth/token" {
		t.Errorf("token_endpoint incorrecto: %v", resp["token_endpoint"])
	}
	if resp["jwks_uri"] != "http://localhost:8080/.well-known/jwks.json" {
		t.Errorf("jwks_uri incorrecto: %v", resp["jwks_uri"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	r, _ := setupTestApp(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba status 200, obtenido: %d", w.Code)
	}

	if allowOrigin := w.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "*" {
		t.Errorf("se esperaba Access-Control-Allow-Origin: *, obtenido: %q", allowOrigin)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("no se pudo decodificar json: %v", err)
	}

	keys, ok := resp["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("se esperaba array 'keys' no vacío, obtenido: %v", resp["keys"])
	}
}

func TestOAuthLoginRoute_CSRFProtection(t *testing.T) {
	r, _ := setupTestApp(t)

	t.Run("Rechaza POST sin Origin ni Referer", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader("email=test@example.com"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("se esperaba 403 Forbidden por falta de CSRF/Origin, obtenido: %d", w.Code)
		}
	})

	t.Run("Rechaza POST con Origin pero sin token CSRF", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader("email=test@example.com"))
		req.Host = "localhost:8080"
		req.Header.Set("Origin", "http://localhost:8080")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("se esperaba 403 Forbidden por falta de token CSRF, obtenido: %d", w.Code)
		}
	})

	t.Run("GET emite cookie csrf_token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/login", nil)
		r.ServeHTTP(w, req)

		cookieHeader := w.Header().Get("Set-Cookie")
		if !strings.Contains(cookieHeader, "csrf_token=") {
			t.Fatalf("se esperaba que GET /oauth/login establezca cookie csrf_token, obtenido: %q", cookieHeader)
		}
	})
}

func TestVerifyRoute_RequiresHTTPS(t *testing.T) {
	t.Setenv("ENV", "production")
	r, _ := setupTestApp(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/verify?token=dummy-token", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 Forbidden para /verify sin HTTPS en producción, obtenido: %d", w.Code)
	}
}

func TestHealthRoutes(t *testing.T) {
	r, _ := setupTestApp(t)

	t.Run("/health retorna 200 OK", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK en /health, obtenido: %d", w.Code)
		}
	})

	t.Run("/ready responde con estructura de checks", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
		r.ServeHTTP(w, req)

		// Sin DB en setupTestApp, responde 503 pero el payload debe ser json válido
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("error parseando JSON de /ready: %v", err)
		}
		if resp["status"] == nil || resp["checks"] == nil {
			t.Fatalf("respuesta /ready incompleta: %v", resp)
		}
	})
}

func TestRootRoute_RedirectsToAdmin(t *testing.T) {
	r, _ := setupTestApp(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 See Other para GET /, obtenido: %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/admin" {
		t.Fatalf("se esperaba redirección a /admin, obtenido: %s", loc)
	}
}

