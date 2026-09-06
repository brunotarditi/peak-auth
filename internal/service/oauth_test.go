package service

import (
	"crypto/sha256"
	"encoding/base64"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"testing"
)

// mockOAuthRepo implementa repo.OAuthRepository para tests
type mockOAuthRepo struct {
	codes map[string]*model.OAuthCode
}

func newMockOAuthRepo() *mockOAuthRepo {
	return &mockOAuthRepo{codes: make(map[string]*model.OAuthCode)}
}

func (m *mockOAuthRepo) CreateCode(code *model.OAuthCode) error {
	m.codes[code.Code] = code
	return nil
}

func (m *mockOAuthRepo) GetAndConsumeCode(codeStr string) (*model.OAuthCode, error) {
	code, exists := m.codes[codeStr]
	if !exists {
		return nil, &testError{msg: "código no encontrado"}
	}
	delete(m.codes, codeStr) // One-time use
	return code, nil
}

func (m *mockOAuthRepo) DeleteExpiredCodes() error {
	return nil
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// mockAppRepo implementa repo.ApplicationRepository básico para tests
type mockAppRepo struct {
	apps map[string]*model.Application
}

func newMockAppRepo() *mockAppRepo {
	return &mockAppRepo{apps: make(map[string]*model.Application)}
}

func (m *mockAppRepo) FindByAppID(appID string) (model.Application, error) {
	app, exists := m.apps[appID]
	if !exists {
		return model.Application{}, &testError{msg: "app no encontrada"}
	}
	return *app, nil
}

func (m *mockAppRepo) ValidateSecret(appID, secret string) (model.Application, error) {
	app, exists := m.apps[appID]
	if !exists {
		return model.Application{}, &testError{msg: "app no encontrada"}
	}
	if app.SecretKey != secret {
		return model.Application{}, &testError{msg: "secreto incorrecto"}
	}
	return *app, nil
}

func (m *mockAppRepo) Create(app *model.Application) error                                  { return nil }
func (m *mockAppRepo) Update(app *model.Application) error                                  { return nil }
func (m *mockAppRepo) Delete(id uint) error                                                { return nil }
func (m *mockAppRepo) FindByID(id uint) (model.Application, error)                         { return model.Application{}, nil }
func (m *mockAppRepo) FindByName(name string) (model.Application, error)                   { return model.Application{}, nil }
func (m *mockAppRepo) GetAppsWithUserCount() ([]response.AppStatsResponse, error)          { return nil, nil }
func (m *mockAppRepo) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error)   { return nil, nil }

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

	// 1. Preparar parámetros PKCE: verifier y S256 challenge
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// 2. Generar Authorization Code con PKCE S256
	code, err := oauthSvc.GenerateAuthorizationCode(42, clientID, redirectURI, challenge, "S256")
	if err != nil {
		t.Fatalf("error generando authorization code: %v", err)
	}

	// 3. Intento de canje con redirect_uri errónea -> debe fallar
	savedCode := *oauthRepo.codes[code]
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "https://evil.com/callback", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por redirect_uri incorrecta")
	}

	// 3b. Intento de canje con redirect_uri omitida ("") -> debe fallar (RFC 6749 §4.1.3)
	oauthRepo.codes[code] = &savedCode
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, "", verifier)
	if err == nil {
		t.Fatalf("se esperaba error por omitir redirect_uri cuando el código tenía una asociada")
	}

	// Restaurar código en mock para siguiente prueba
	oauthRepo.codes[code] = &savedCode

	// 4. Intento de canje con code_verifier incorrecto -> debe fallar
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, "wrong-verifier-12345678901234567890")
	if err == nil {
		t.Fatalf("se esperaba error por code_verifier incorrecto")
	}

	// Restaurar código en mock
	oauthRepo.codes[code] = &savedCode

	// 5. Canje exitoso con parámetros correctos
	userID, err := oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err != nil {
		t.Fatalf("error inesperado en canje válido: %v", err)
	}
	if userID != 42 {
		t.Fatalf("se esperaba userID 42, obtenido: %d", userID)
	}

	// 6. Verificar que el código fue consumido (One-Time Use)
	_, err = oauthSvc.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI, verifier)
	if err == nil {
		t.Fatalf("se esperaba error al intentar reutilizar código de autorización")
	}
}
