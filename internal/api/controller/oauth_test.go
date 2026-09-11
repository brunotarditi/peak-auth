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
	codes map[string]*model.OAuthCode
}

func newTestOAuthRepo() *testOAuthRepo {
	return &testOAuthRepo{codes: make(map[string]*model.OAuthCode)}
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
	completeLoginFn func(userID uint, publicAppID string) (response.TokenResponse, error)
}

func (u *testUserService) CompleteLoginWithMfa(userID uint, publicAppID string) (response.TokenResponse, error) {
	if u.completeLoginFn != nil {
		return u.completeLoginFn(userID, publicAppID)
	}
	return response.TokenResponse{}, nil
}

func setupOAuthControllerTest(t *testing.T) (*gin.Engine, *auth.JWTManager, *testOAuthRepo, *testAppRepo) {
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

	mockUserSvc := &testUserService{
		completeLoginFn: func(userID uint, publicAppID string) (response.TokenResponse, error) {
			token, err := tm.GenerateToken(userID, "user@client.com", publicAppID, []string{"USER"}, time.Hour, true)
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

// TestOAuth_PKCE_FullFlow_And_ReplayProtection prueba el flujo E2E completo:
// authorize con sesión activa -> emite código -> canje por token con PKCE verifier -> rechazo en reintento (replay).
func TestOAuth_PKCE_FullFlow_And_ReplayProtection(t *testing.T) {
	r, tm, _, _ := setupOAuthControllerTest(t)

	// 1. Crear sesión SSO válida de Peak Auth
	sessionToken, err := tm.GenerateToken(42, "user@client.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)
	if err != nil {
		t.Fatalf("error creando token de sesión: %v", err)
	}

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
	r, tm, _, _ := setupOAuthControllerTest(t)

	sessionToken, _ := tm.GenerateToken(10, "u@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)

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
	r, tm, _, _ := setupOAuthControllerTest(t)

	sessionToken, _ := tm.GenerateToken(10, "u@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)

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

