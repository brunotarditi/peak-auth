package peakauthgin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brunotarditi/peak-auth/sdk/go"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGinMiddleware(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generando clave RSA: %v", err)
	}

	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes())
	kid := "test-gin-kid"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]string{
					{
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"kid": kid,
						"n":   nStr,
						"e":   eStr,
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := peakauth.New(peakauth.Config{
		IssuerURL: server.URL,
		ClientID:  "gin-app",
	})
	if err != nil {
		t.Fatalf("New falló: %v", err)
	}

	r := gin.New()
	r.GET("/protected", Middleware(client, "ADMIN"), func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok || claims == nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": claims.Username})
	})

	// 1. Sin Authorization header -> 401
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("se esperaba 401 sin header, obtenido: %d", w1.Code)
	}

	// 2. Token con rol insuficiente -> 403
	claimsUser := peakauth.Claims{
		Username: "user@test.com",
		AppID:    "gin-app",
		Roles:    []string{"USER"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "peak-auth",
			Audience:  jwt.ClaimStrings{"gin-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tokUser := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsUser)
	tokUser.Header["kid"] = kid
	tokUserStr, _ := tokUser.SignedString(privKey)

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+tokUserStr)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("se esperaba 403 con permisos insuficientes, obtenido: %d", w2.Code)
	}

	// 3. Token con rol ADMIN -> 200 OK
	claimsAdmin := peakauth.Claims{
		Username: "admin@test.com",
		AppID:    "gin-app",
		Roles:    []string{"ADMIN"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "peak-auth",
			Audience:  jwt.ClaimStrings{"gin-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tokAdmin := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsAdmin)
	tokAdmin.Header["kid"] = kid
	tokAdminStr, _ := tokAdmin.SignedString(privKey)

	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req3.Header.Set("Authorization", "Bearer "+tokAdminStr)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("se esperaba 200 con admin token, obtenido: %d", w3.Code)
	}
}
