package peakauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGeneratePKCE(t *testing.T) {
	pkce, err := GeneratePKCE(64)
	if err != nil {
		t.Fatalf("GeneratePKCE falló: %v", err)
	}

	if pkce.CodeVerifier == "" {
		t.Fatal("CodeVerifier no debe estar vacío")
	}
	if pkce.CodeChallenge == "" {
		t.Fatal("CodeChallenge no debe estar vacío")
	}
	if len(pkce.CodeVerifier) < 43 {
		t.Fatalf("CodeVerifier demasiado corto: %d", len(pkce.CodeVerifier))
	}
}

func TestGetAuthorizationURL(t *testing.T) {
	client, err := New(Config{
		IssuerURL:   "https://auth.example.com",
		ClientID:    "test-app",
		RedirectURI: "https://my-app.com/callback",
	})
	if err != nil {
		t.Fatalf("New falló: %v", err)
	}

	u, err := client.GetAuthorizationURL("state-123", "challenge-456")
	if err != nil {
		t.Fatalf("GetAuthorizationURL falló: %v", err)
	}

	expected := "https://auth.example.com/oauth/authorize?client_id=test-app&code_challenge=challenge-456&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fmy-app.com%2Fcallback&response_type=code&state=state-123"
	if u != expected {
		t.Fatalf("URL generada inesperada.\nEsperada: %s\nObtenida: %s", expected, u)
	}
}

func TestVerifyTokenWithJWKS(t *testing.T) {
	// 1. Generar par de claves RSA para el test
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generando clave RSA: %v", err)
	}

	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes())
	kid := "test-key-id"

	// 2. Levantar servidor mock de Peak Auth que expone JWKS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwksResponse{
				Keys: []jwk{
					{
						Kty: "RSA",
						Alg: "RS256",
						Use: "sig",
						Kid: kid,
						N:   nStr,
						E:   eStr,
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := New(Config{
		IssuerURL:      server.URL,
		ClientID:       "my-app",
		ExpectedIssuer: "peak-auth",
	})
	if err != nil {
		t.Fatalf("New falló: %v", err)
	}

	// 3. Crear token válido
	claims := Claims{
		Username:    "bruno@example.com",
		AppID:       "my-app",
		Roles:       []string{"ADMIN", "USER"},
		MfaVerified: true,
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "101",
			Issuer:    "peak-auth",
			Audience:  jwt.ClaimStrings{"my-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("error firmando token: %v", err)
	}

	// 4. Validar token
	verifiedClaims, err := client.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyToken falló: %v", err)
	}

	if verifiedClaims.Subject != "101" || verifiedClaims.Username != "bruno@example.com" {
		t.Fatalf("claims incorrectos: %+v", verifiedClaims)
	}

	// 5. Validar que falle con audiencia equivocada
	wrongAudClaims := claims
	wrongAudClaims.Audience = jwt.ClaimStrings{"otra-app"}
	wrongToken := jwt.NewWithClaims(jwt.SigningMethodRS256, wrongAudClaims)
	wrongToken.Header["kid"] = kid
	wrongTokenStr, _ := wrongToken.SignedString(privKey)

	if _, err := client.VerifyToken(wrongTokenStr); err == nil {
		t.Fatal("VerifyToken debía fallar por mismatch de audiencia")
	}
}

func TestGinAndHTTPMiddleware(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse{
			Keys: []jwk{
				{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "k1", N: nStr, E: eStr},
			},
		})
	}))
	defer server.Close()

	client, _ := New(Config{
		IssuerURL:      server.URL,
		ClientID:       "test-app",
		ExpectedIssuer: "peak-auth",
	})

	// Token con rol USER (no ADMIN)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		Username: "user1",
		AppID:    "test-app",
		Roles:    []string{"USER"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "1",
			Issuer:    "peak-auth",
			Audience:  jwt.ClaimStrings{"test-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	token.Header["kid"] = "k1"
	tokenStr, _ := token.SignedString(privKey)

	// Test Gin Middleware
	router := gin.New()
	router.GET("/admin", client.GinMiddleware("ADMIN"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.GET("/user", client.GinMiddleware("USER"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Petición a /admin debe dar 403 Forbidden
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 Forbidden para /admin, obtenido: %d", w.Code)
	}

	// Petición a /user debe dar 200 OK
	req2, _ := http.NewRequest(http.MethodGet, "/user", nil)
	req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK para /user, obtenido: %d", w2.Code)
	}

	// Test HTTP Middleware
	stdHandler := client.HTTPMiddleware("USER")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.Username != "user1" {
			http.Error(w, "error en claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
	stdHandler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK en HTTPMiddleware, obtenido: %d", w3.Code)
	}
}
