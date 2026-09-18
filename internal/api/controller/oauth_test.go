package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"peak-auth/internal/api/response"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"
)

// --- Mocks para pruebas OAuth del Controller ---

type testOAuthRepo struct {
	codes    map[string]*model.OAuthCode
	consents map[string]bool // key: "userID:clientID"
}

func newTestOAuthRepo() *testOAuthRepo {
	return &testOAuthRepo{
		codes:    make(map[string]*model.OAuthCode),
		consents: make(map[string]bool),
	}
}

func (r *testOAuthRepo) CreateCode(code *model.OAuthCode) error {
	r.codes[code.Code] = code
	return nil
}

func (r *testOAuthRepo) GetAndConsumeCode(codeStr string) (*model.OAuthCode, error) {
	code, exists := r.codes[codeStr]
	if !exists {
		return nil, fmt.Errorf("código inválido o expirado")
	}
	delete(r.codes, codeStr)
	return code, nil
}

func (r *testOAuthRepo) DeleteExpiredCodes() error { return nil }

func (r *testOAuthRepo) HasValidConsent(userID uint, clientID string) (bool, error) {
	key := fmt.Sprintf("%d:%s", userID, clientID)
	return r.consents[key], nil
}

func (r *testOAuthRepo) CreateConsent(consent *model.UserConsent) error {
	key := fmt.Sprintf("%d:%s", consent.UserID, consent.ClientID)
	r.consents[key] = true
	return nil
}

func (r *testOAuthRepo) RevokeConsent(userID uint, clientID string) error {
	key := fmt.Sprintf("%d:%s", userID, clientID)
	delete(r.consents, key)
	return nil
}

type testAppRepo struct {
	apps map[string]*model.Application
}

func newTestAppRepo() *testAppRepo {
	return &testAppRepo{apps: make(map[string]*model.Application)}
}

func (r *testAppRepo) FindByAppID(appID string) (model.Application, error) {
	app, exists := r.apps[appID]
	if !exists {
		return model.Application{}, fmt.Errorf("app no encontrada")
	}
	return *app, nil
}

func (r *testAppRepo) ValidateSecret(appID, secret string) (model.Application, error) {
	app, exists := r.apps[appID]
	if !exists {
		return model.Application{}, fmt.Errorf("app no encontrada")
	}
	if !app.IsActive {
		return model.Application{}, fmt.Errorf("la aplicación está desactivada")
	}
	if app.SecretKey != secret {
		return model.Application{}, fmt.Errorf("secreto inválido")
	}
	return *app, nil
}

func (r *testAppRepo) Create(app *model.Application) error                          { return nil }
func (r *testAppRepo) Update(app *model.Application) error                          { return nil }
func (r *testAppRepo) Delete(id uint) error                                         { return nil }
func (r *testAppRepo) FindByID(id uint) (model.Application, error)                  { return model.Application{}, nil }
func (r *testAppRepo) FindByName(name string) (model.Application, error)            { return model.Application{}, nil }
func (r *testAppRepo) GetAppsWithUserCount() ([]response.AppStatsResponse, error)   { return nil, nil }
func (r *testAppRepo) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return nil, nil
}

var _ repo.ApplicationRepository = (*testAppRepo)(nil)

type testUserService struct {
	service.UserService
	completeLoginFn func(userID uint, publicAppID string, mfaCompleted bool) (response.TokenResponse, error)
	findUserFn      func(userID uint) (*model.User, error)
}

func (u *testUserService) CompleteLoginWithMfa(userID uint, publicAppID string, mfaCompleted bool) (response.TokenResponse, error) {
	if u.completeLoginFn != nil {
		return u.completeLoginFn(userID, publicAppID, mfaCompleted)
	}
	return response.TokenResponse{}, nil
}

func (u *testUserService) FindVerifiedUserByID(userID uint) (*model.User, error) {
	if u.findUserFn != nil {
		return u.findUserFn(userID)
	}
	return &model.User{
		Email:        "user@client.com",
		IsActive:     true,
		IsVerified:   true,
		AuthzVersion: 0,
	}, nil
}

func setupOAuthControllerTest(t *testing.T) (*gin.Engine, *auth.JWTManager, *testOAuthRepo, *testAppRepo) {
	return setupOAuthControllerTestWithUser(t, nil)
}

func setupOAuthControllerTestWithUser(t *testing.T, customUserSvc *testUserService) (*gin.Engine, *auth.JWTManager, *testOAuthRepo, *testAppRepo) {
	t.Helper()

	// Generar clave privada RSA para el test
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error al generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	tm, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("error creando TokenManager: %v", err)
	}

	appRepo := newTestAppRepo()
	appRepo.apps["client-portal"] = &model.Application{
		ID:          10,
		AppID:       "client-portal",
		SecretKey:   "client-portal-secret-12345",
		RedirectURL: "https://portal.client.com/oauth/callback",
		IsActive:    true,
	}

	oauthRepo := newTestOAuthRepo()
	oauthSvc := service.NewOAuthService(oauthRepo, appRepo)

	mockUserSvc := customUserSvc
	if mockUserSvc == nil {
		mockUserSvc = &testUserService{
			completeLoginFn: func(userID uint, publicAppID string, mfaCompleted bool) (response.TokenResponse, error) {
				token, err := tm.GenerateToken(userID, "user@client.com", publicAppID, []string{"USER"}, time.Hour, mfaCompleted, 0)
				if err != nil {
					return response.TokenResponse{}, err
				}
				return response.TokenResponse{
					AccessToken:  token,
					RefreshToken: "dummy_refresh_token",
					ExpiresIn:    3600,
				}, nil
			},
		}
	}

	ctrl := &OAuthController{
		OAuthService: oauthSvc,
		UserService:  mockUserSvc,
		TokenManager: tm,
	}

	r := gin.New()
	tmpl := template.Must(template.New("error.html").Parse("<html>{{.Title}}: {{.Message}}</html>"))
	r.SetHTMLTemplate(tmpl)

	oauth := r.Group("/oauth")
	{
		oauth.GET("/authorize", ctrl.AuthorizeEndpoint)
		oauth.POST("/token", ctrl.TokenEndpoint)
		oauth.OPTIONS("/token", ctrl.TokenEndpoint)
		oauth.GET("/logout", ctrl.LogoutEndpoint)
		oauth.POST("/logout", ctrl.LogoutEndpoint)
	}

	return r, tm, oauthRepo, appRepo
}

// TestOAuth_Authorize_RedirectsToLoginWhenNoSession verifica que sin sesión SSO se redirija a /oauth/login
func TestOAuth_Authorize_RedirectsToLoginWhenNoSession(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=state-123", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba status 302 Found, obtenido: %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/login") {
		t.Fatalf("se esperaba redirección a /oauth/login, obtenido: %s", location)
	}
	if !strings.Contains(location, "client_id=client-portal") || !strings.Contains(location, "state=state-123") {
		t.Fatalf("la redirección a login no preservó los parámetros requeridos: %s", location)
	}
}

// TestOAuth_Authorize_PasswordResetRevocation_RedirectsToLogin verifica que una sesión emitida previa a un cambio de contraseña sea invalidada
func TestOAuth_Authorize_PasswordResetRevocation_RedirectsToLogin(t *testing.T) {
	resetTime := time.Now().Add(10 * time.Minute)
	userSvc := &testUserService{
		findUserFn: func(userID uint) (*model.User, error) {
			return &model.User{
				Email:             "user@client.com",
				IsActive:          true,
				IsVerified:        true,
				PasswordChangedAt: &resetTime,
				AuthzVersion:      0,
			}, nil
		},
	}
	r, tm, _, _ := setupOAuthControllerTestWithUser(t, userSvc)

	// Token emitido antes del cambio de contraseña
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=state-123", nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found redirigiendo a login, obtenido: %d", w.Code)
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/login") {
		t.Fatalf("se esperaba redirección a /oauth/login por cambio de contraseña, obtenido: %s", location)
	}
}

// TestOAuth_Authorize_AuthzVersionMismatch_RedirectsToLogin verifica que un token con authz_version revocado sea invalidado
func TestOAuth_Authorize_AuthzVersionMismatch_RedirectsToLogin(t *testing.T) {
	userSvc := &testUserService{
		findUserFn: func(userID uint) (*model.User, error) {
			return &model.User{
				Email:        "user@client.com",
				IsActive:     true,
				IsVerified:   true,
				AuthzVersion: 5, // Usuario revocado con versión superior
			}, nil
		},
	}
	r, tm, _, _ := setupOAuthControllerTestWithUser(t, userSvc)

	// Token emitido con authz_version = 0
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=state-123", nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found redirigiendo a login, obtenido: %d", w.Code)
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/login") {
		t.Fatalf("se esperaba redirección a /oauth/login por authz_version mismatch, obtenido: %s", location)
	}
}

// TestOAuth_Authorize_InactiveUser_RedirectsToLogin verifica que un usuario desactivado no pueda continuar la sesión SSO
func TestOAuth_Authorize_InactiveUser_RedirectsToLogin(t *testing.T) {
	userSvc := &testUserService{
		findUserFn: func(userID uint) (*model.User, error) {
			return &model.User{
				Email:        "user@client.com",
				IsActive:     false, // Desactivado
				IsVerified:   true,
				AuthzVersion: 0,
			}, nil
		},
	}
	r, tm, _, _ := setupOAuthControllerTestWithUser(t, userSvc)

	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=state-123", nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found redirigiendo a login, obtenido: %d", w.Code)
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/login") {
		t.Fatalf("se esperaba redirección a /oauth/login por usuario inactivo, obtenido: %s", location)
	}
}

// TestOAuth_PKCE_FullFlow_And_ReplayProtection prueba el flujo E2E completo:
// authorize con sesión activa -> emite código -> canje por token con PKCE verifier -> rechazo en reintento (replay).
func TestOAuth_PKCE_FullFlow_And_ReplayProtection(t *testing.T) {
	r, tm, oauthRepo, _ := setupOAuthControllerTest(t)

	// 1. Crear sesión SSO válida de Peak Auth
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	// 1.5. Grant consent for the user to the client (simulating prior consent)
	oauthRepo.CreateConsent(&model.UserConsent{
		UserID:        42,
		ClientID:      "client-portal",
		ApplicationID: 10,
		GrantedAt:     time.Now(),
	})

	// 2. Generar PKCE verifier y challenge (S256)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk0123456789"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// 3. Solicitar autorización GET /oauth/authorize
	authURL := fmt.Sprintf("/oauth/authorize?client_id=client-portal&redirect_uri=%s&response_type=code&state=test-state-xyz&code_challenge=%s&code_challenge_method=S256",
		url.QueryEscape("https://portal.client.com/oauth/callback"),
		url.QueryEscape(codeChallenge),
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, authURL, nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found tras autorización con sesión, obtenido: %d, body: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "https://portal.client.com/oauth/callback") {
		t.Fatalf("redirección a callback inválida: %s", location)
	}

	redirectParsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("error parseando URL de callback: %v", err)
	}

	code := redirectParsed.Query().Get("code")
	if code == "" {
		t.Fatalf("el código de autorización no fue incluido en el callback: %s", location)
	}
	if redirectParsed.Query().Get("state") != "test-state-xyz" {
		t.Fatalf("el parámetro state no coincide: %s", redirectParsed.Query().Get("state"))
	}

	// 4. Intercambiar código por Access Token (POST /oauth/token)
	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-portal"},
		"client_secret": {"client-portal-secret-12345"},
		"code":          {code},
		"redirect_uri":  {"https://portal.client.com/oauth/callback"},
		"code_verifier": {codeVerifier},
	}

	wToken := httptest.NewRecorder()
	reqToken, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK en /oauth/token, obtenido: %d, body: %s", wToken.Code, wToken.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(wToken.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("error decodificando respuesta JSON: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("access_token no devuelto o vacío: %+v", tokenResp)
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type esperado 'Bearer', obtenido: %v", tokenResp["token_type"])
	}

	// 5. Validar que el token emitido sea verificado exitosamente para la app correspondiente
	claims, err := tm.VerifyTokenForApp(accessToken, "client-portal")
	if err != nil {
		t.Fatalf("el token emitido falló la verificación criptográfica: %v", err)
	}
	if claims.Subject != "42" {
		t.Errorf("subject esperado '42', obtenido: %s", claims.Subject)
	}
	if claims.AppID != "client-portal" {
		t.Errorf("app_id esperado 'client-portal', obtenido: %s", claims.AppID)
	}

	// 6. PROTECCIÓN CONTRA REPLAY: Reintentar canjear el mismo código debe ser rechazado inmediatamente
	wReplay := httptest.NewRecorder()
	reqReplay, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wReplay, reqReplay)

	if wReplay.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request al reutilizar código (replay attack), obtenido: %d", wReplay.Code)
	}

	var replayResp map[string]interface{}
	_ = json.Unmarshal(wReplay.Body.Bytes(), &replayResp)
	if replayResp["error"] != "invalid_grant" {
		t.Errorf("se esperaba error 'invalid_grant' en replay attack, obtenido: %v", replayResp["error"])
	}
}

// TestOAuth_PKCE_WrongVerifier_Rejected comprueba que un code_verifier incorrecto cause invalid_grant
func TestOAuth_PKCE_WrongVerifier_Rejected(t *testing.T) {
	r, tm, oauthRepo, _ := setupOAuthControllerTest(t)

	sessionToken, _ := tm.GenerateToken(10, "u@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)

	// Grant consent
	oauthRepo.CreateConsent(&model.UserConsent{
		UserID:        10,
		ClientID:      "client-portal",
		ApplicationID: 10,
		GrantedAt:     time.Now(),
	})

	codeVerifier := "legitimate-code-verifier-string-1234567890"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := fmt.Sprintf("/oauth/authorize?client_id=client-portal&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256",
		url.QueryEscape("https://portal.client.com/oauth/callback"),
		url.QueryEscape(codeChallenge),
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, authURL, nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	// Canje con code_verifier alterado/incorrecto
	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-portal"},
		"client_secret": {"client-portal-secret-12345"},
		"code":          {code},
		"redirect_uri":  {"https://portal.client.com/oauth/callback"},
		"code_verifier": {"wrong-altered-verifier-value-999999999999"},
	}

	wToken := httptest.NewRecorder()
	reqToken, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request por verifier alterado, obtenido: %d", wToken.Code)
	}
}

// TestOAuth_InvalidClientSecret_Rejected comprueba que credenciales inválidas impidan el canje
func TestOAuth_InvalidClientSecret_Rejected(t *testing.T) {
	r, tm, oauthRepo, _ := setupOAuthControllerTest(t)

	sessionToken, _ := tm.GenerateToken(10, "u@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)

	// Grant consent
	oauthRepo.CreateConsent(&model.UserConsent{
		UserID:        10,
		ClientID:      "client-portal",
		ApplicationID: 10,
		GrantedAt:     time.Now(),
	})

	authURL := fmt.Sprintf("/oauth/authorize?client_id=client-portal&redirect_uri=%s&response_type=code",
		url.QueryEscape("https://portal.client.com/oauth/callback"),
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, authURL, nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")

	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-portal"},
		"client_secret": {"incorrect-password-secret"},
		"code":          {code},
		"redirect_uri":  {"https://portal.client.com/oauth/callback"},
	}

	wToken := httptest.NewRecorder()
	reqToken, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request por secreto inválido, obtenido: %d", wToken.Code)
	}
}

// TestOAuth_Authorize_RedirectURIMismatch_Rejected comprueba que se rechace un redirect_uri no registrado
func TestOAuth_Authorize_RedirectURIMismatch_Rejected(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://evil-attacker.com/cb&response_type=code", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request por redirect_uri ajena, obtenido: %d", w.Code)
	}
}

// TestOAuth_Authorize_UnknownClientID_Rejected comprueba que se rechace un client_id inexistente
func TestOAuth_Authorize_UnknownClientID_Rejected(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=unknown-client-xyz&redirect_uri=https://portal.client.com/oauth/callback&response_type=code", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request por client_id desconocido, obtenido: %d", w.Code)
	}
}

// TestOAuth_Authorize_WithoutConsent_RedirectsToConsentPage verifica que sin consentimiento previo se redirija a la página de consentimiento
func TestOAuth_Authorize_WithoutConsent_RedirectsToConsentPage(t *testing.T) {
	r, tm, _, _ := setupOAuthControllerTest(t)

	// Create valid session but NO consent
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found redirigiendo a consent, obtenido: %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/consent") {
		t.Fatalf("se esperaba redirección a /oauth/consent, obtenido: %s", location)
	}

	// Verify OAuth parameters are preserved in redirect
	if !strings.Contains(location, "client_id=client-portal") {
		t.Fatalf("client_id no preservado en redirección a consent: %s", location)
	}
	if !strings.Contains(location, "state=test-state") {
		t.Fatalf("state no preservado en redirección a consent: %s", location)
	}
}

// TestOAuth_Authorize_WithConsent_IssuesCodeDirectly verifica que con consentimiento previo se emita el código directamente
func TestOAuth_Authorize_WithConsent_IssuesCodeDirectly(t *testing.T) {
	r, tm, oauthRepo, _ := setupOAuthControllerTest(t)

	// Create valid session AND grant consent
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true, 0)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

	oauthRepo.CreateConsent(&model.UserConsent{
		UserID:        42,
		ClientID:      "client-portal",
		ApplicationID: 10,
		GrantedAt:     time.Now(),
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback&response_type=code&state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: "peak_session", Value: sessionToken})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 Found redirigiendo a callback, obtenido: %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "https://portal.client.com/oauth/callback") {
		t.Fatalf("se esperaba redirección a callback con código, obtenido: %s", location)
	}

	// Verify code is present
	redirectParsed, _ := url.Parse(location)
	code := redirectParsed.Query().Get("code")
	if code == "" {
		t.Fatalf("código de autorización no incluido en callback: %s", location)
	}
}

// TestOAuth_Token_ExpiredCode_Rejected comprueba que un código expirado no pueda canjearse
func TestOAuth_Token_ExpiredCode_Rejected(t *testing.T) {
	r, _, oauthRepo, _ := setupOAuthControllerTest(t)

	expiredCode := "expired-test-code-12345"
	oauthRepo.codes[expiredCode] = &model.OAuthCode{
		Code:        expiredCode,
		UserID:      42,
		ClientID:    "client-portal",
		RedirectURI: "https://portal.client.com/oauth/callback",
		ExpiresAt:   time.Now().Add(-10 * time.Minute), // Expirado hace 10m
	}

	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-portal"},
		"client_secret": {"client-portal-secret-12345"},
		"code":          {expiredCode},
		"redirect_uri":  {"https://portal.client.com/oauth/callback"},
	}

	wToken := httptest.NewRecorder()
	reqToken, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 Bad Request por código expirado, obtenido: %d", wToken.Code)
	}
}

// TestOAuth_LogoutEndpoint comprueba que el endpoint de logout limpie la sesión SSO y soporte redirección
func TestOAuth_LogoutEndpoint(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	t.Run("Logout sin redirect_uri retorna JSON 200 y borra cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout", nil)
		req.AddCookie(&http.Cookie{Name: "peak_session", Value: "valid_session_token"})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
		}
		setCookie := w.Header().Get("Set-Cookie")
		if !strings.Contains(setCookie, "peak_session=") || !strings.Contains(setCookie, "Max-Age=0") {
			t.Fatalf("se esperaba que la cookie peak_session fuera borrada, Set-Cookie: %s", setCookie)
		}
	})

	t.Run("Logout con redirect_uri redirige 303 y borra cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout?client_id=client-portal&redirect_uri=https://portal.client.com/oauth/callback", nil)
		req.AddCookie(&http.Cookie{Name: "peak_session", Value: "valid_session_token"})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "https://portal.client.com/oauth/callback" {
			t.Fatalf("se esperaba redirección a https://portal.client.com/oauth/callback, obtenido: %s", loc)
		}
	})

	t.Run("Logout POST con post_logout_redirect_uri redirige 303", func(t *testing.T) {
		w := httptest.NewRecorder()
		form := url.Values{
			"client_id":                {"client-portal"},
			"post_logout_redirect_uri": {"https://portal.client.com/oauth/callback"},
		}
		req, _ := http.NewRequest(http.MethodPost, "/oauth/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "https://portal.client.com/oauth/callback" {
			t.Fatalf("se esperaba redirección a post_logout_redirect_uri, obtenido: %s", loc)
		}
	})
}

func TestOAuth_DeactivatedApp(t *testing.T) {
	r, _, _, appRepo := setupOAuthControllerTest(t)

	appRepo.apps["disabled-app"] = &model.Application{
		ID:          20,
		AppID:       "disabled-app",
		SecretKey:   "disabled-secret",
		RedirectURL: "https://disabled.com/callback",
		IsActive:    false,
	}

	t.Run("App desactivada no puede autorizar flujo OAuth", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?client_id=disabled-app&redirect_uri=https://disabled.com/callback&response_type=code", nil)
		r.ServeHTTP(w, req)

		if w.Code == http.StatusFound {
			t.Fatalf("App desactivada no debería permitir autorización, obtuvo redirect: %v", w.Header().Get("Location"))
		}
	})

	t.Run("App desactivada no puede intercambiar token", func(t *testing.T) {
		w := httptest.NewRecorder()
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"disabled-app"},
			"client_secret": {"disabled-secret"},
			"code":          {"any-code"},
			"redirect_uri":  {"https://disabled.com/callback"},
		}
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Fatalf("App desactivada no debe permitir intercambio de token, obtuvo 200 OK")
		}
	})
}

func TestOAuth_Logout_OpenRedirectPrevention(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	t.Run("Logout sin parámetros retorna 200 OK y limpia sesión", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
		}
		// Verificar que la cookie peak_session se eliminó (MaxAge < 0)
		cookies := w.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "peak_session" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil || sessionCookie.MaxAge >= 0 {
			t.Fatalf("se esperaba cookie peak_session expirada")
		}
	})

	t.Run("Logout con URL maliciosa externa sin client_id es bloqueado (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout?post_logout_redirect_uri=https://evil.com/phishing", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request por intento de Open Redirect, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Fatalf("no debió haber cabecera Location hacia sitio externo, obtenido: %s", loc)
		}
	})

	t.Run("Logout con client_id pero URL no registrada es bloqueado (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout?client_id=client-portal&post_logout_redirect_uri=https://evil.com/phishing", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request por redirect URI no registrada, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Fatalf("no debió haber cabecera Location hacia sitio externo, obtenido: %s", loc)
		}
	})

	t.Run("Logout con client_id y redirect_uri registrada redirige exitosamente (303)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/logout?client_id=client-portal&post_logout_redirect_uri=https://portal.client.com/oauth/callback", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "https://portal.client.com/oauth/callback" {
			t.Fatalf("se esperaba redirección a https://portal.client.com/oauth/callback, obtenido: %s", loc)
		}
	})
}

func TestOAuth_TokenEndpoint_ClientSecretBasic(t *testing.T) {
	r, _, oauthRepo, _ := setupOAuthControllerTest(t)

	clientID := "client-portal"
	clientSecret := "client-portal-secret-12345"
	redirectURI := "https://portal.client.com/oauth/callback"

	codeVerifier := "basic-auth-verifier-123456789012345678901234"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := "test-code-basic-123"
	oauthRepo.codes[code] = &model.OAuthCode{
		Code:                code,
		UserID:              42,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		MfaCompleted:        true,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	// Enviar solo code y redirect_uri en el body, credenciales en Authorization: Basic
	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK con client_secret_basic, obtenido: %d, body: %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("error parseando respuesta: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("no se recibió access_token válido")
	}

	// Verificar cabeceras de seguridad
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("se esperaba Cache-Control: no-store, obtenido: %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("se esperaba Pragma: no-cache, obtenido: %q", w.Header().Get("Pragma"))
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("se esperaba Access-Control-Allow-Origin: *, obtenido: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestOAuth_TokenEndpoint_PublicClientPKCE(t *testing.T) {
	r, _, oauthRepo, _ := setupOAuthControllerTest(t)

	clientID := "client-portal"
	redirectURI := "https://portal.client.com/oauth/callback"

	codeVerifier := "public-client-pkce-verifier-12345678901234567890"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := "test-code-public-123"
	oauthRepo.codes[code] = &model.OAuthCode{
		Code:                code,
		UserID:              42,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		MfaCompleted:        false,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	// Solicitud sin client_secret (método auth "none")
	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenReqBody.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK para cliente público con PKCE, obtenido: %d, body: %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("error parseando respuesta: %v", err)
	}

	if _, ok := tokenResp["access_token"].(string); !ok {
		t.Fatalf("access_token no devuelto")
	}
}

func TestOAuth_TokenEndpoint_CORSPreflight(t *testing.T) {
	r, _, _, _ := setupOAuthControllerTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/oauth/token", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("se esperaba status 204 No Content en preflight OPTIONS, obtenido: %d", w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("se esperaba Access-Control-Allow-Origin: *, obtenido: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(w.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("se esperaba POST en Access-Control-Allow-Methods, obtenido: %q", w.Header().Get("Access-Control-Allow-Methods"))
	}
}

