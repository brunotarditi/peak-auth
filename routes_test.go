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
		TokenManager: tm,
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
