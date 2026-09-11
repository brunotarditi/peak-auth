package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestGetJWKS_And_TokenKidHeader(t *testing.T) {
	m := newTestManager(t)

	// 1. Verificar que el token emitido incluya el header "kid" correspondiente
	tok, err := m.GenerateToken(10, "admin@example.com", "app-test", []string{"ADMIN"}, time.Hour, true)
	if err != nil {
		t.Fatalf("GenerateToken falló: %v", err)
	}

	parser := jwt.NewParser()
	parsedToken, _, err := parser.ParseUnverified(tok, &CustomClaims{})
	if err != nil {
		t.Fatalf("no se pudo parsear el token: %v", err)
	}

	kid, ok := parsedToken.Header["kid"].(string)
	if !ok || kid != defaultKeyID {
		t.Fatalf("se esperaba kid '%s' en el header del token, obtenido: '%v'", defaultKeyID, parsedToken.Header["kid"])
	}

	// 2. Verificar estructura y contenido del JWKS (RFC 7517)
	jwks := m.GetJWKS()
	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("se esperaba un array 'keys' con 1 elemento, obtenido: %+v", jwks)
	}

	firstKey := keys[0]
	if firstKey["kty"] != "RSA" {
		t.Errorf("se esperaba kty 'RSA', obtenido: %v", firstKey["kty"])
	}
	if firstKey["alg"] != "RS256" {
		t.Errorf("se esperaba alg 'RS256', obtenido: %v", firstKey["alg"])
	}
	if firstKey["use"] != "sig" {
		t.Errorf("se esperaba use 'sig', obtenido: %v", firstKey["use"])
	}
	if firstKey["kid"] != defaultKeyID {
		t.Errorf("se esperaba kid '%s', obtenido: %v", defaultKeyID, firstKey["kid"])
	}
	if n, ok := firstKey["n"].(string); !ok || n == "" {
		t.Errorf("módulo 'n' inválido o vacío: %v", firstKey["n"])
	}
	if e, ok := firstKey["e"].(string); !ok || e == "" {
		t.Errorf("exponente 'e' inválido o vacío: %v", firstKey["e"])
	}
}

func TestMultiKeyRotation_GracePeriod(t *testing.T) {
	// 1. Iniciar con Clave 1
	m := newTestManager(t)

	// Emitir token con Clave 1
	tok1, err := m.GenerateToken(1, "user1@example.com", "app-1", []string{"USER"}, time.Hour, true)
	if err != nil {
		t.Fatalf("GenerateToken con clave 1 falló: %v", err)
	}

	claims1, err := m.VerifyToken(tok1)
	if err != nil {
		t.Fatalf("VerifyToken tok1 falló antes de la rotación: %v", err)
	}
	if claims1.Username != "user1@example.com" {
		t.Errorf("claims inesperados: %v", claims1)
	}

	// 2. Generar Clave 2 y rotar en caliente preservando Clave 1 para grace period
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave RSA 2: %v", err)
	}
	m.SetActiveKey("peak-auth-key-2", key2, true)

	if m.ActiveKeyID() != "peak-auth-key-2" {
		t.Fatalf("activeKeyID esperado 'peak-auth-key-2', obtenido '%s'", m.ActiveKeyID())
	}

	// 3. Emitir token con la nueva Clave 2
	tok2, err := m.GenerateToken(2, "user2@example.com", "app-1", []string{"ADMIN"}, time.Hour, true)
	if err != nil {
		t.Fatalf("GenerateToken con clave 2 falló: %v", err)
	}

	// Verificar token 2 firmado con Clave 2
	claims2, err := m.VerifyToken(tok2)
	if err != nil {
		t.Fatalf("VerifyToken tok2 falló: %v", err)
	}
	if claims2.Username != "user2@example.com" {
		t.Errorf("claims inesperados: %v", claims2)
	}

	// 4. Token 1 (firmado con Clave 1) DEBE seguir siendo válido durante el período de gracia
	claims1After, err := m.VerifyToken(tok1)
	if err != nil {
		t.Fatalf("VerifyToken tok1 falló durante período de gracia: %v", err)
	}
	if claims1After.Username != "user1@example.com" {
		t.Errorf("claims inesperados tras rotación: %v", claims1After)
	}

	// 5. El JWKS debe contener ambas claves públicas
	jwks := m.GetJWKS()
	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok || len(keys) != 2 {
		t.Fatalf("se esperaban 2 claves en JWKS tras rotación, obtenidas: %d", len(keys))
	}

	kids := make(map[string]bool)
	for _, k := range keys {
		kids[k["kid"].(string)] = true
	}
	if !kids[defaultKeyID] || !kids["peak-auth-key-2"] {
		t.Fatalf("JWKS no contiene las claves esperadas: %+v", kids)
	}

	// 6. Token con kid desconocido o clave externa no registrada debe fallar (Fail-Closed)
	key3, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokForeign := jwt.NewWithClaims(jwt.SigningMethodRS256, CustomClaims{
		Username: "rogue@example.com",
		AppID:    "app-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "999",
			Issuer:    tokenIssuer(),
			Audience:  jwt.ClaimStrings{"app-1"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokForeign.Header["kid"] = "unknown-kid-999"
	signedForeign, _ := tokForeign.SignedString(key3)

	if _, err := m.VerifyToken(signedForeign); err == nil {
		t.Fatal("VerifyToken debería haber fallado para token con kid desconocido / clave no registrada")
	}

	// 7. Retirar Clave 1 del período de gracia (fin de ventana de gracia)
	m.RemovePreviousPublicKey(defaultKeyID)

	// Token 1 debe ser rechazado ahora
	if _, err := m.VerifyToken(tok1); err == nil {
		t.Fatal("Token 1 debería fallar una vez retirada la clave previa del período de gracia")
	}

	// Token 2 debe seguir funcionando
	if _, err := m.VerifyToken(tok2); err != nil {
		t.Fatalf("Token 2 debería seguir siendo válido: %v", err)
	}

	// El JWKS ahora solo debe tener la clave activa
	jwksAfter := m.GetJWKS()
	keysAfter := jwksAfter["keys"].([]map[string]interface{})
	if len(keysAfter) != 1 || keysAfter[0]["kid"] != "peak-auth-key-2" {
		t.Fatalf("se esperaba 1 clave en JWKS tras remover gracia, obtenido: %+v", keysAfter)
	}
}

func TestNewJWTManager_MalformedPreviousKeysEnv(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_PREVIOUS_KEYS", "not-a-valid-json-string")

	_, err := NewJWTManager()
	if err == nil {
		t.Fatal("se esperaba error al iniciar JWTManager con JWT_PREVIOUS_KEYS malformado")
	}
}


