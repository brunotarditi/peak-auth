package service

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"peak-auth/internal/store/model"
)

// --- Tests OAuth ---

func TestOAuthPKCEAndRedirectValidation(t *testing.T) {
	oauthRepo := newMockOAuthRepo()
	appRepo := newMockAppRepo()

	clientID := "test-client-app"
	clientSecret := "secret123"
	redirectURI := "https://myapp.com/callback"

	appRepo.apps[clientID] = &model.Application{
		AppID:       clientID,
		SecretKey:   clientSecret,
		RedirectURL: redirectURI,
		IsActive:    true,
	}

	oauthSvc := &oauthService{
		oauthRepo: oauthRepo,
		appRepo:   appRepo,
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code, err := oauthSvc.GenerateAuthorizationCode(42, clientID, redirectURI, challenge, "S256", true)
	if err != nil {
		t.Fatalf("error generando authorization code: %v", err)
	}

	savedCode := *oauthRepo.codes[code]
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "https://evil.com/callback", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por redirect_uri incorrecta")
	}

	oauthRepo.codes[code] = &savedCode
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por omitir redirect_uri")
	}

	oauthRepo.codes[code] = &savedCode
	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, "wrong-verifier-12345678901234567890")
	if err == nil {
		t.Fatalf("se esperaba error por code_verifier incorrecto")
	}

	oauthRepo.codes[code] = &savedCode
	userID, mfaCompleted, err := oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err != nil {
		t.Fatalf("error inesperado en canje válido: %v", err)
	}
	if userID != 42 {
		t.Fatalf("se esperaba userID 42, obtenido: %d", userID)
	}
	if !mfaCompleted {
		t.Fatalf("se esperaba mfaCompleted true, obtenido: %v", mfaCompleted)
	}

	_, _, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err == nil {
		t.Fatalf("se esperaba error al intentar reutilizar código ya consumido")
	}

	t.Run("Cliente público con PKCE puede canjear sin client_secret", func(t *testing.T) {
		publicCode, err := oauthSvc.GenerateAuthorizationCode(99, clientID, redirectURI, challenge, "S256", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		uID, mfa, err := oauthSvc.ExchangeCodeForToken(clientID, "", publicCode, redirectURI, verifier)
		if err != nil {
			t.Fatalf("cliente público con PKCE debería poder canjear sin client_secret, error: %v", err)
		}
		if uID != 99 {
			t.Fatalf("se esperaba userID 99, obtenido %d", uID)
		}
		if mfa {
			t.Fatalf("se esperaba mfa false, obtenido %v", mfa)
		}
	})

	t.Run("Cliente sin client_secret y sin PKCE es rechazado", func(t *testing.T) {
		noPkceCode, err := oauthSvc.GenerateAuthorizationCode(99, clientID, redirectURI, "", "", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		_, _, err = oauthSvc.ExchangeCodeForToken(clientID, "", noPkceCode, redirectURI, "")
		if err == nil {
			t.Fatalf("se esperaba rechazo al intentar canjear código sin PKCE y sin client_secret")
		}
	})

	t.Run("Cliente público con app desactivada es rechazado", func(t *testing.T) {
		inactiveClientID := "inactive-client"
		appRepo.apps[inactiveClientID] = &model.Application{
			AppID:       inactiveClientID,
			RedirectURL: redirectURI,
			IsActive:    true,
		}

		inactiveCode, err := oauthSvc.GenerateAuthorizationCode(99, inactiveClientID, redirectURI, challenge, "S256", false)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		// La aplicación se desactiva antes del canje
		appRepo.apps[inactiveClientID].IsActive = false

		_, _, err = oauthSvc.ExchangeCodeForToken(inactiveClientID, "", inactiveCode, redirectURI, verifier)
		if err == nil {
			t.Fatalf("se esperaba rechazo para aplicación desactivada")
		}
	})

	t.Run("Intento de canje con client_id ajeno no consume el código", func(t *testing.T) {
		otherClientID := "other-client-app"
		otherClientSecret := "othersecret123"
		appRepo.apps[otherClientID] = &model.Application{
			AppID:       otherClientID,
			SecretKey:   otherClientSecret,
			RedirectURL: "https://otherapp.com/callback",
			IsActive:    true,
		}

		dosCode, err := oauthSvc.GenerateAuthorizationCode(101, clientID, redirectURI, challenge, "S256", true)
		if err != nil {
			t.Fatalf("error generando código: %v", err)
		}

		// otherClientID intenta canjear el código perteneciente a clientID
		_, _, err = oauthSvc.ExchangeCodeForToken(otherClientID, otherClientSecret, dosCode, "https://otherapp.com/callback", verifier)
		if err == nil {
			t.Fatalf("se esperaba error al intentar canjear código con client_id ajeno")
		}

		// El código NO debió ser consumido y debe ser válido para el cliente legítimo
		uID, _, err := oauthSvc.ExchangeCodeForToken(clientID, clientSecret, dosCode, redirectURI, verifier)
		if err != nil {
			t.Fatalf("el código legítimo fue quemado/consumido indebidamente tras intento ajeno: %v", err)
		}
		if uID != 101 {
			t.Fatalf("se esperaba userID 101, obtenido %d", uID)
		}
	})
}


func TestOAuth_ValidateRedirectURISecurity(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"HTTPS standard", "https://example.com/callback", false},
		{"HTTPS with port and path", "https://portal.mycompany.com:8443/oauth/callback", false},
		{"HTTP localhost", "http://localhost:3000/callback", false},
		{"HTTP localhost with sub-domain", "http://app.localhost:8080/cb", false},
		{"HTTP 127.0.0.1", "http://127.0.0.1:8080/callback", false},
		{"HTTP 127.0.0.2", "http://127.0.0.2:8080/callback", false},
		{"HTTP IPv6 loopback", "http://[::1]:8080/callback", false},
		{"Custom mobile scheme RFC 8252 (myapp)", "myapp://oauth-callback", false},
		{"Custom mobile scheme RFC 8252 (reverse DNS)", "com.example.app:/oauth2redirect", false},
		{"HTTP external domain (insecure)", "http://example.com/callback", true},
		{"HTTP private LAN IP (insecure)", "http://192.168.1.100:3000/callback", true},
		{"HTTP 10.x LAN IP (insecure)", "http://10.0.0.1:3000/callback", true},
		{"Javascript scheme (dangerous)", "javascript:alert(1)", true},
		{"Data scheme (dangerous)", "data:text/html,test", true},
		{"File scheme (dangerous)", "file:///etc/passwd", true},
		{"URI with fragment RFC 6749 violation", "https://example.com/callback#token=abc", true},
		{"Empty string", "", true},
		{"Relative path without scheme", "/callback", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURISecurity(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRedirectURISecurity(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestOAuth_ValidateClientRedirect_Security(t *testing.T) {
	mockRepo := newMockOAuthRepo()
	mockApp := &mockAppRepo{
		apps: map[string]*model.Application{
			"valid-web": {
				AppID:       "valid-web",
				RedirectURL: "https://web.example.com/callback",
				IsActive:    true,
			},
			"valid-mobile": {
				AppID:       "valid-mobile",
				RedirectURL: "myapp://oauth/callback",
				IsActive:    true,
			},
			"insecure-app": {
				AppID:       "insecure-app",
				RedirectURL: "http://insecure.com/callback",
				IsActive:    true,
			},
		},
	}

	svc := NewOAuthService(mockRepo, mockApp)

	// Valid HTTPS redirect
	if err := svc.ValidateClientRedirect("valid-web", "https://web.example.com/callback"); err != nil {
		t.Fatalf("se esperaba éxito para URI HTTPS válida, error: %v", err)
	}

	// Valid mobile scheme redirect
	if err := svc.ValidateClientRedirect("valid-mobile", "myapp://oauth/callback"); err != nil {
		t.Fatalf("se esperaba éxito para URI de app móvil (RFC 8252), error: %v", err)
	}

	// Insecure HTTP to external host must be rejected even if matching registered app
	if err := svc.ValidateClientRedirect("insecure-app", "http://insecure.com/callback"); err == nil {
		t.Fatalf("se esperaba rechazo para URI HTTP no local")
	}

	// Mismatch redirect URI
	if err := svc.ValidateClientRedirect("valid-web", "https://web.example.com/other"); err == nil {
		t.Fatalf("se esperaba error por discordancia de redirect_uri")
	}
}



func TestOAuthService_AuthenticateClientCredentials(t *testing.T) {
	appRepo := newMockAppRepo()

	appRepo.apps["valid-m2m"] = &model.Application{
		ID:        1,
		AppID:     "valid-m2m",
		SecretKey: "supersecret",
		IsActive:  true,
	}

	appRepo.apps["inactive-m2m"] = &model.Application{
		ID:        2,
		AppID:     "inactive-m2m",
		SecretKey: "supersecret",
		IsActive:  false,
	}

	svc := &oauthService{
		appRepo: appRepo,
	}

	t.Run("Autenticación exitosa", func(t *testing.T) {
		app, err := svc.AuthenticateClientCredentials("valid-m2m", "supersecret")
		if err != nil {
			t.Fatalf("se esperaba éxito, obtenido: %v", err)
		}
		if app.AppID != "valid-m2m" {
			t.Errorf("se esperaba AppID valid-m2m, obtenido: %s", app.AppID)
		}
	})

	t.Run("Fallo por secreto incorrecto", func(t *testing.T) {
		_, err := svc.AuthenticateClientCredentials("valid-m2m", "wrongsecret")
		if err == nil {
			t.Fatalf("se esperaba error por secreto incorrecto")
		}
	})

	t.Run("Fallo por aplicación inactiva", func(t *testing.T) {
		_, err := svc.AuthenticateClientCredentials("inactive-m2m", "supersecret")
		if err == nil {
			t.Fatalf("se esperaba error por app inactiva")
		}
	})

	t.Run("Fallo por credenciales vacías", func(t *testing.T) {
		_, err := svc.AuthenticateClientCredentials("", "secret")
		if err == nil {
			t.Fatalf("se esperaba error por client_id vacío")
		}
		_, err = svc.AuthenticateClientCredentials("valid-m2m", "")
		if err == nil {
			t.Fatalf("se esperaba error por client_secret vacío")
		}
	})
}
