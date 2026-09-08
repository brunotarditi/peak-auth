package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// newTestManager construye un JWTManager con una clave RSA efímera para tests.
func newTestManager(t *testing.T) *JWTManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	m, err := NewJWTManager()
	if err != nil {
		t.Fatalf("NewJWTManager falló: %v", err)
	}
	return m
}

func TestGenerateAndVerifyToken(t *testing.T) {
	m := newTestManager(t)
	tok, err := m.GenerateToken(42, "user@example.com", "mi-app", []string{"USER"}, time.Hour, true)
	if err != nil {
		t.Fatalf("GenerateToken falló: %v", err)
	}

	claims, err := m.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken falló: %v", err)
	}
	if claims.AppID != "mi-app" || claims.Subject != "42" {
		t.Fatalf("claims inesperados: %+v", claims)
	}
}

// Un token emitido para "app-a" no debe validar como audiencia "app-b".
func TestVerifyTokenForApp_AudienceMismatch(t *testing.T) {
	m := newTestManager(t)
	tok, _ := m.GenerateToken(1, "u@e.com", "app-a", nil, time.Hour, true)

	if _, err := m.VerifyTokenForApp(tok, "app-b"); err == nil {
		t.Fatal("se esperaba error por audiencia incorrecta (app-b)")
	}
	if _, err := m.VerifyTokenForApp(tok, "app-a"); err != nil {
		t.Fatalf("la audiencia correcta (app-a) debería validar: %v", err)
	}
}

// Un token expirado debe ser rechazado.
func TestVerifyToken_Expired(t *testing.T) {
	m := newTestManager(t)
	tok, _ := m.GenerateToken(1, "u@e.com", "app-a", nil, -time.Minute, true)
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("se esperaba error por token expirado")
	}
}

// Un token de otro issuer debe ser rechazado.
func TestVerifyToken_WrongIssuer(t *testing.T) {
	m := newTestManager(t)
	tok, _ := m.GenerateToken(1, "u@e.com", "app-a", nil, time.Hour, true)

	// Cambiamos el issuer esperado: el token tiene "peak-auth", ahora exigimos otro.
	t.Setenv("JWT_ISSUER", "otro-emisor")
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("se esperaba error por issuer incorrecto")
	}
}

func TestMFAPendingToken(t *testing.T) {
	m := newTestManager(t)
	tok, err := m.GenerateMFAPendingToken(42, "user@example.com", "mi-app")
	if err != nil {
		t.Fatalf("GenerateMFAPendingToken falló: %v", err)
	}

	claims, err := m.VerifyMFAPendingToken(tok, "mi-app")
	if err != nil {
		t.Fatalf("VerifyMFAPendingToken falló: %v", err)
	}

	if claims.Subject != "42" || claims.AppID != "mi-app" || claims.TokenType != "mfa_pending" || claims.MfaVerified {
		t.Fatalf("claims incorrectos para MFA_PENDING: %+v", claims)
	}

	// VerifyMFAPendingToken debe rechazar tokens normales de acceso
	normalTok, _ := m.GenerateToken(42, "user@example.com", "mi-app", []string{"USER"}, time.Hour, true)
	if _, err := m.VerifyMFAPendingToken(normalTok, "mi-app"); err == nil {
		t.Fatal("VerifyMFAPendingToken debería rechazar un token normal")
	}
}
