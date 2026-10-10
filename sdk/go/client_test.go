package peakauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

func TestGetLogoutURL(t *testing.T) {
	client, err := New(Config{
		IssuerURL:   "https://auth.example.com",
		ClientID:    "test-app",
		RedirectURI: "https://my-app.com/callback",
	})
	if err != nil {
		t.Fatalf("New falló: %v", err)
	}

	t.Run("con postLogoutRedirectURI por defecto", func(t *testing.T) {
		u, err := client.GetLogoutURL("")
		if err != nil {
			t.Fatalf("GetLogoutURL falló: %v", err)
		}
		expected := "https://auth.example.com/oauth/logout?client_id=test-app&post_logout_redirect_uri=https%3A%2F%2Fmy-app.com%2Fcallback"
		if u != expected {
			t.Fatalf("URL esperada: %s\nObtenida: %s", expected, u)
		}
	})

	t.Run("con postLogoutRedirectURI personalizada y extraParams", func(t *testing.T) {
		u, err := client.GetLogoutURL("https://my-app.com/auth/login", map[string]string{
			"state": "logout-state-456",
		})
		if err != nil {
			t.Fatalf("GetLogoutURL falló: %v", err)
		}
		expected := "https://auth.example.com/oauth/logout?client_id=test-app&post_logout_redirect_uri=https%3A%2F%2Fmy-app.com%2Fauth%2Flogin&state=logout-state-456"
		if u != expected {
			t.Fatalf("URL esperada: %s\nObtenida: %s", expected, u)
		}
	})
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
		IssuerURL:         server.URL,
		ClientID:          "my-app",
		ExpectedIssuer:    "peak-auth",
		InsecureAllowHTTP: true,
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
		IssuerURL:         server.URL,
		ClientID:          "test-app",
		ExpectedIssuer:    "peak-auth",
		InsecureAllowHTTP: true,
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

	// Test HTTP Middleware (Standard Library net/http)
	stdHandler := client.HTTPMiddleware("USER")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.Username != "user1" {
			http.Error(w, "error en claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Petición con rol adecuado (USER) -> 200 OK
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
	stdHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK en HTTPMiddleware, obtenido: %d", w1.Code)
	}

	// 2. Petición con rol faltante (ADMIN) -> 403 Forbidden
	adminHandler := client.HTTPMiddleware("ADMIN")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
	adminHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 Forbidden en HTTPMiddleware para rol ADMIN, obtenido: %d", w2.Code)
	}
}

func TestTransportSecurity(t *testing.T) {
	// 1. Emisor remoto con HTTP inseguro debe fallar siempre
	_, err := New(Config{
		IssuerURL: "http://auth.empresa.com",
		ClientID:  "test-app",
	})
	if err == nil {
		t.Fatal("se esperaba error para emisor remoto HTTP inseguro")
	}

	// 2. Emisor remoto con HTTP y flag InsecureAllowHTTP DEBE FALLAR TAMBIEN (HTTP remoto nunca permitido)
	_, err = New(Config{
		IssuerURL:         "http://auth.empresa.com",
		ClientID:          "test-app",
		InsecureAllowHTTP: true,
	})
	if err == nil {
		t.Fatal("InsecureAllowHTTP NUNCA debe permitir un emisor remoto con HTTP")
	}

	// 3. Emisores loopback con HTTP sin InsecureAllowHTTP deben fallar
	loopbacks := []string{
		"http://localhost:8080",
		"http://127.0.0.1:9009",
		"http://127.0.0.2:8080",
		"http://[::1]:8080",
	}
	for _, lb := range loopbacks {
		_, err := New(Config{
			IssuerURL: lb,
			ClientID:  "test-app",
		})
		if err == nil {
			t.Fatalf("loopback %s debía requerir InsecureAllowHTTP = true", lb)
		}
	}

	// 4. Emisores loopback con HTTP y con InsecureAllowHTTP deben permitirse
	for _, lb := range loopbacks {
		c, err := New(Config{
			IssuerURL:         lb,
			ClientID:          "test-app",
			InsecureAllowHTTP: true,
		})
		if err != nil || c == nil {
			t.Fatalf("loopback %s debía permitirse con InsecureAllowHTTP: %v", lb, err)
		}
	}

	// 5. Rechazar subdominios y direcciones IP privadas genéricas (incluso con InsecureAllowHTTP = true)
	rejectedNonLoopbacks := []string{
		"http://foo.localhost:8080",
		"http://app.localhost:9000",
		"http://10.0.0.1:8080",
		"http://192.168.1.1:8080",
		"http://172.16.0.1:8080",
	}
	for _, badHost := range rejectedNonLoopbacks {
		_, err := New(Config{
			IssuerURL:         badHost,
			ClientID:          "test-app",
			InsecureAllowHTTP: true,
		})
		if err == nil {
			t.Fatalf("host no loopback %s debía ser rechazado incluso con InsecureAllowHTTP = true", badHost)
		}
	}

	// 6. Rechazar URLs con credenciales, fragments o queries en el issuer
	badUrls := []string{
		"https://user:pass@auth.empresa.com",
		"http://user:pass@localhost:8080",
		"https://auth.empresa.com#fragment",
		"https://auth.empresa.com?param=value",
		"ftp://auth.empresa.com",
	}
	for _, bu := range badUrls {
		_, err := New(Config{
			IssuerURL:         bu,
			ClientID:          "test-app",
			InsecureAllowHTTP: true,
		})
		if err == nil {
			t.Fatalf("URL malformada %s debía ser rechazada", bu)
		}
	}
}

func TestJWKSValidationStrict(t *testing.T) {
	validKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	validN := base64.RawURLEncoding.EncodeToString(validKey.PublicKey.N.Bytes())
	validE := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())

	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakN := base64.RawURLEncoding.EncodeToString(weakKey.PublicKey.N.Bytes())

	cases := []struct {
		name       string
		jwk        jwk
		shouldPass bool
	}{
		{
			name:       "clave válida 2048-bit con e=65537",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "valid-1", N: validN, E: validE},
			shouldPass: true,
		},
		{
			name:       "alg ausente",
			jwk:        jwk{Kty: "RSA", Alg: "", Use: "sig", Kid: "no-alg", N: validN, E: validE},
			shouldPass: false,
		},
		{
			name:       "use ausente",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "", Kid: "no-use", N: validN, E: validE},
			shouldPass: false,
		},
		{
			name:       "alg incorrecto (HS256)",
			jwk:        jwk{Kty: "RSA", Alg: "HS256", Use: "sig", Kid: "hs256", N: validN, E: validE},
			shouldPass: false,
		},
		{
			name:       "use incorrecto (enc)",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "enc", Kid: "enc", N: validN, E: validE},
			shouldPass: false,
		},
		{
			name:       "RSA de menos de 2048 bits (1024 bits)",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "weak", N: weakN, E: validE},
			shouldPass: false,
		},
		{
			name:       "exponente 1",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "exp-1", N: validN, E: base64.RawURLEncoding.EncodeToString([]byte{1})},
			shouldPass: false,
		},
		{
			name:       "exponente 2",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "exp-2", N: validN, E: base64.RawURLEncoding.EncodeToString([]byte{2})},
			shouldPass: false,
		},
		{
			name:       "exponente par (4)",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "exp-even-4", N: validN, E: base64.RawURLEncoding.EncodeToString([]byte{4})},
			shouldPass: false,
		},
		{
			name:       "exponente par (65536)",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "exp-even-65536", N: validN, E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0})},
			shouldPass: false,
		},
		{
			name:       "exponente gigante/overflow (> 4 bytes)",
			jwk:        jwk{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "exp-huge", N: validN, E: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4, 5})},
			shouldPass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(jwksResponse{
					Keys: []jwk{tc.jwk},
				})
			}))
			defer server.Close()

			client, err := New(Config{
				IssuerURL:         server.URL,
				ClientID:          "test-app",
				InsecureAllowHTTP: true,
			})
			if err != nil {
				t.Fatalf("New falló: %v", err)
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
				Username: "user@test.com",
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "peak-auth",
					Audience:  jwt.ClaimStrings{"test-app"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			})
			token.Header["kid"] = tc.jwk.Kid
			tokenStr, _ := token.SignedString(validKey)

			_, err = client.VerifyToken(tokenStr)
			if tc.shouldPass && err != nil {
				t.Fatalf("se esperaba éxito pero falló: %v", err)
			}
			if !tc.shouldPass && err == nil {
				t.Fatalf("se esperaba rechazo pero fue aceptado para caso %s", tc.name)
			}
		})
	}
}

func TestTokenMissingExp(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nStr := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse{
			Keys: []jwk{
				{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "k-exp", N: nStr, E: eStr},
			},
		})
	}))
	defer server.Close()

	client, _ := New(Config{
		IssuerURL:         server.URL,
		ClientID:          "test-app",
		InsecureAllowHTTP: true,
	})

	// Token SIN ExpiresAt (debe ser rechazado)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		Username: "user@test.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "peak-auth",
			Audience: jwt.ClaimStrings{"test-app"},
		},
	})
	token.Header["kid"] = "k-exp"
	tokenStr, _ := token.SignedString(privKey)

	_, err := client.VerifyToken(tokenStr)
	if err == nil {
		t.Fatal("VerifyToken debía fallar cuando exp está ausente")
	}
}

func TestPKCEMandatoryForPublicClient(t *testing.T) {
	client, _ := New(Config{
		IssuerURL:   "https://auth.example.com",
		ClientID:    "public-app",
		RedirectURI: "https://my-app.com/callback",
		// Sin ClientSecret -> cliente público
	})

	// 1. GetAuthorizationURL sin code_challenge debe fallar
	_, err := client.GetAuthorizationURL("state-123", "")
	if err == nil {
		t.Fatal("GetAuthorizationURL debía fallar sin code_challenge en cliente público")
	}

	// 2. ExchangeCode sin code_verifier debe fallar
	_, err = client.ExchangeCode(context.Background(), "auth-code", "")
	if err == nil {
		t.Fatal("ExchangeCode debía fallar sin code_verifier en cliente público")
	}

	// 3. Con PKCE debe tener éxito
	u, err := client.GetAuthorizationURL("state-123", "challenge-abc")
	if err != nil || u == "" {
		t.Fatalf("GetAuthorizationURL falló con PKCE: %v", err)
	}
}

func TestStateGenerationAndValidation(t *testing.T) {
	st1, err := GenerateState()
	if err != nil || st1 == "" {
		t.Fatalf("GenerateState falló: %v", err)
	}
	st2, err := GenerateState()
	if err != nil || st2 == "" {
		t.Fatalf("GenerateState falló: %v", err)
	}
	if st1 == st2 {
		t.Fatal("los states generados deben ser aleatorios y únicos")
	}

	if !ValidateState(st1, st1) {
		t.Fatal("ValidateState debía retornar true para estados idénticos")
	}
	if ValidateState(st1, st2) {
		t.Fatal("ValidateState debía retornar false para estados distintos")
	}
	if ValidateState(st1, "") || ValidateState("", st1) {
		t.Fatal("ValidateState debía retornar false con estados vacíos")
	}
}

func TestSingleFlightRefreshToken(t *testing.T) {
	var callCount int
	var countMu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/refresh" {
			countMu.Lock()
			callCount++
			countMu.Unlock()

			// Simular latencia de red
			time.Sleep(50 * time.Millisecond)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				ExpiresIn:    3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, _ := New(Config{
		IssuerURL:         server.URL,
		ClientID:          "test-app",
		InsecureAllowHTTP: true,
	})

	// Ejecutar 5 llamadas concurrentes con el mismo refresh token
	var wg sync.WaitGroup
	results := make([]*TokenResponse, 5)
	errors := make([]error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errors[idx] = client.RefreshToken(context.Background(), "same-refresh-token")
		}(i)
	}
	wg.Wait()

	for i := 0; i < 5; i++ {
		if errors[i] != nil {
			t.Fatalf("llamada concurrente %d falló: %v", i, errors[i])
		}
		if results[i].AccessToken != "new-access-token" {
			t.Fatalf("resultado inesperado en llamada concurrente %d", i)
		}
	}

	countMu.Lock()
	defer countMu.Unlock()
	if callCount != 1 {
		t.Fatalf("se esperaba exactamente 1 petición HTTP al servidor de refresh por single-flight, se hicieron: %d", callCount)
	}
}

func TestIntrospectionClaimsAndSafeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/introspect" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)

			if body["token"] == "active-token" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(IntrospectionResponse{
					Active:      true,
					Sub:         "user-999",
					Username:    "intro@empresa.com",
					Aud:         "test-app",
					Iss:         "peak-auth",
					Exp:         time.Now().Add(time.Hour).Unix(),
					Iat:         time.Now().Unix(),
					ClientID:    "test-app",
					TokenType:   "access",
					MfaVerified: true,
					Roles:       []string{"ADMIN"},
				})
				return
			}

			// Token inactivo o revocado
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(IntrospectionResponse{
				Active: false,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, _ := New(Config{
		IssuerURL:         server.URL,
		ClientID:          "test-app",
		ClientSecret:      "super-secret",
		InsecureAllowHTTP: true,
	})

	handler := client.HTTPMiddlewareWithOptions(HTTPMiddlewareOptions{
		UseIntrospection: true,
		RequiredRoles:    []string{"ADMIN"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			t.Fatal("ClaimsFromContext debía retornar claims válidos en modo introspección")
		}
		if claims.Username != "intro@empresa.com" || claims.Subject != "user-999" {
			t.Fatalf("datos de claims incorrectos: %+v", claims)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Token activo -> 200 OK
	rec1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("Authorization", "Bearer active-token")
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK con token activo, obtenido: %d", rec1.Code)
	}

	// 2. Token inactivo -> 401 Unauthorized sin detalles internos
	rec2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "Bearer inactive-token")
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("se esperaba 401 con token inactivo, obtenido: %d", rec2.Code)
	}
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "Token revocado o inválido") {
		t.Fatalf("mensaje esperado genérico no encontrado: %s", body2)
	}
	if strings.Contains(body2, server.URL) || strings.Contains(body2, "stack") {
		t.Fatalf("el cuerpo HTTP filtró información interna: %s", body2)
	}

	// 3. Ausencia de claims en contexto vacío
	emptyCtx := context.Background()
	if c, ok := ClaimsFromContext(emptyCtx); ok || c != nil {
		t.Fatal("ClaimsFromContext en contexto vacío debía retornar ok=false y nil")
	}
}

func TestOpenIDConfigurationValidationStrict(t *testing.T) {
	baseIssuer := "https://auth.empresa.com"

	cases := []struct {
		name      string
		discovery OpenIDConfiguration
	}{
		{
			name: "issuer host mismatch",
			discovery: OpenIDConfiguration{
				Issuer:                "https://attacker.com",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "issuer scheme mismatch (http vs https)",
			discovery: OpenIDConfiguration{
				Issuer:                "http://auth.empresa.com",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "issuer port mismatch",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com:8443",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "issuer path mismatch",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com/other-path",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "issuer con query parameter",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com?param=bad",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "issuer con fragment",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com#bad",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "authorization_endpoint vacío",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "token_endpoint relativo",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "/oauth/token",
				JwksURI:               "https://auth.empresa.com/.well-known/jwks.json",
			},
		},
		{
			name: "jwks_uri remoto HTTP inseguro",
			discovery: OpenIDConfiguration{
				Issuer:                "https://auth.empresa.com",
				AuthorizationEndpoint: "https://auth.empresa.com/oauth/authorize",
				TokenEndpoint:         "https://auth.empresa.com/oauth/token",
				JwksURI:               "http://auth.empresa.com/.well-known/jwks.json",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tc.discovery)
			}))
			defer server.Close()

			client, _ := New(Config{
				IssuerURL:         baseIssuer,
				ClientID:          "test-app",
				HTTPClient:        server.Client(),
				InsecureAllowHTTP: false,
			})
			// Apuntar el request al mock server modificando la IssuerURL en el client interno para test
			client.config.IssuerURL = server.URL
			client.config.InsecureAllowHTTP = true

			_, err := client.GetOpenIDConfiguration(context.Background())
			if err == nil {
				t.Fatalf("se esperaba rechazo para caso %s", tc.name)
			}
		})
	}
}
