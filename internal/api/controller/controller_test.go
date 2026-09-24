package controller

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"peak-auth/internal/api/middleware"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestExtractMfaToken_RejectsQueryParam(t *testing.T) {
	ctrl := &BaseController{}
	var extracted string

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		extracted = ctrl.extractMfaToken(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test?mfa_token=secret_in_url", nil)
	r.ServeHTTP(w, req)

	if extracted != "" {
		t.Fatalf("Vulnerabilidad presente: se extrajo el token desde la URL query: %q", extracted)
	}
}

func TestSanitizeForLogging(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "user@example.com"},
		{"user@example.com\r\n[audit] fake entry", "user@example.com[audit] fake entry"},
		{"null\x00byte\x1bescape", "nullbyteescape"},
		{"clean_string_123", "clean_string_123"},
	}

	for _, tt := range tests {
		got := sanitizeForLogging(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeForLogging(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractMfaToken_AcceptsHttpOnlyCookie(t *testing.T) {
	ctrl := &BaseController{}
	var extracted string

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		extracted = ctrl.extractMfaToken(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: "jwt_cookie_token"})
	r.ServeHTTP(w, req)

	if extracted != "jwt_cookie_token" {
		t.Fatalf("Esperaba 'jwt_cookie_token', obtuvo: %q", extracted)
	}
}

func TestExtractMfaToken_AcceptsAuthorizationHeader(t *testing.T) {
	ctrl := &BaseController{}
	var extracted string

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		extracted = ctrl.extractMfaToken(c)
		c.Status(http.StatusOK)
	})

	// Bearer estándar
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer jwt_auth_header")
	r.ServeHTTP(w, req)

	if extracted != "jwt_auth_header" {
		t.Fatalf("Esperaba 'jwt_auth_header', obtuvo: %q", extracted)
	}

	// bearer en minúsculas
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "bearer jwt_auth_lower")
	r.ServeHTTP(w2, req2)

	if extracted != "jwt_auth_lower" {
		t.Fatalf("Esperaba 'jwt_auth_lower', obtuvo: %q", extracted)
	}
}

func TestExtractMfaToken_AcceptsPostForm(t *testing.T) {
	ctrl := &BaseController{}
	var extracted string

	r := gin.New()
	r.POST("/test", func(c *gin.Context) {
		extracted = ctrl.extractMfaToken(c)
		c.Status(http.StatusOK)
	})

	form := url.Values{}
	form.Set("mfa_token", "jwt_form_token")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if extracted != "jwt_form_token" {
		t.Fatalf("Esperaba 'jwt_form_token', obtuvo: %q", extracted)
	}
}

type mockAppService struct {
	app        model.Application
	isRoot     bool
	revoked    bool
	notBelongs bool
}

func (m *mockAppService) CreateApp(name, description, redirectURL string, isActive bool) (model.Application, string, error) {
	return model.Application{}, "", nil
}
func (m *mockAppService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	return nil
}
func (m *mockAppService) ValidateAppNameUnique(name string) error { return nil }
func (m *mockAppService) RegenerateSecret(appID string) (string, error) {
	return "", nil
}
func (m *mockAppService) RegisterUserInApp(userEmail, roleName string, app *model.Application) error {
	return nil
}
func (m *mockAppService) RevokeUserFromApp(userID, appID uint) error {
	m.revoked = true
	return nil
}
func (m *mockAppService) IsRootUser(userID, appID uint) bool { return m.isRoot }
func (m *mockAppService) UserBelongsToApp(userID, appID uint) (bool, error) {
	return !m.notBelongs, nil
}
func (m *mockAppService) GetAppDetails(appID string) (model.Application, error) {
	return m.app, nil
}
func (m *mockAppService) DeleteApp(appID string) error { return nil }
func (m *mockAppService) GetDashboardStats() ([]response.AppStatsResponse, error) {
	return nil, nil
}
func (m *mockAppService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return nil, nil
}

func TestRevokeUserAccess_ProtectsRootUser(t *testing.T) {
	appSvc := &mockAppService{
		app: model.Application{
			Name:  "Peak Auth",
			AppID: util.AppIdPeakAuth,
		},
		isRoot: true, // El usuario objetivo es ROOT
	}
	ctrl := &UserController{
		AppService: appSvc,
	}

	r := gin.New()
	r.DELETE("/admin/apps/:id/users/:user_id", func(c *gin.Context) {
		c.Set("user_id", uint(99)) // Administrador de plataforma que ejecuta la acción
		ctrl.RevokeUserAccess(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/admin/apps/peak-auth/users/1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Esperaba 403 Forbidden al intentar revocar al usuario ROOT, obtuvo %d", w.Code)
	}
	if appSvc.revoked {
		t.Fatalf("El acceso del usuario ROOT no debió haberse revocado")
	}
}

func TestRevokeUserAccess_AllowsRevokingRegularUser(t *testing.T) {
	appSvc := &mockAppService{
		app: model.Application{
			Name:  "Peak Auth",
			AppID: util.AppIdPeakAuth,
		},
		isRoot: false, // Usuario regular
	}
	ctrl := &UserController{
		AppService: appSvc,
	}

	r := gin.New()
	r.DELETE("/admin/apps/:id/users/:user_id", func(c *gin.Context) {
		c.Set("user_id", uint(99))
		ctrl.RevokeUserAccess(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/admin/apps/peak-auth/users/5", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK al revocar usuario regular, obtuvo %d", w.Code)
	}
	if !appSvc.revoked {
		t.Fatalf("El acceso debió haberse revocado")
	}
}

func TestRevokeUserAccess_UserNotInApp_ReturnsNotFound(t *testing.T) {
	appSvc := &mockAppService{
		app: model.Application{
			Name:  "Peak Auth",
			AppID: util.AppIdPeakAuth,
		},
		notBelongs: true,
	}
	ctrl := &UserController{
		AppService: appSvc,
	}

	r := gin.New()
	r.DELETE("/admin/apps/:id/users/:user_id", func(c *gin.Context) {
		c.Set("user_id", uint(99))
		ctrl.RevokeUserAccess(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/admin/apps/peak-auth/users/999", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Esperaba 404 NotFound cuando el usuario no pertenece a la app, obtuvo %d", w.Code)
	}
}

type mockUserServiceForStepUp struct {
	service.UserService
	user *model.User
}

func (m *mockUserServiceForStepUp) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.user != nil {
		return m.user, nil
	}
	return nil, fmt.Errorf("usuario no encontrado")
}

type mockMfaServiceForStepUp struct {
	service.MfaService
	mfaEnabled           bool
	disabled             bool
	totpCode             string
	disableErr           error
	finishWebAuthnRegErr error
}

func (m *mockMfaServiceForStepUp) IsMfaEnabled(userID uint) bool {
	return m.mfaEnabled
}

func (m *mockMfaServiceForStepUp) DisableMFA(userID uint) error {
	if m.disableErr != nil {
		return m.disableErr
	}
	m.disabled = true
	return nil
}

func (m *mockMfaServiceForStepUp) FinishWebAuthnRegistration(userID uint, session *webauthn.SessionData, r *http.Request, keyName ...string) error {
	if m.finishWebAuthnRegErr != nil {
		return m.finishWebAuthnRegErr
	}
	return nil
}

func (m *mockMfaServiceForStepUp) ListWebAuthnCredentials(userID uint) ([]response.WebAuthnKeyItem, error) {
	return nil, nil
}

func (m *mockMfaServiceForStepUp) DeleteWebAuthnCredential(userID uint, credID uint) error {
	return nil
}

func (m *mockMfaServiceForStepUp) ValidateTOTPCode(userID uint, code string) error {
	if m.totpCode != "" && m.totpCode == code {
		return nil
	}
	return fmt.Errorf("código inválido")
}

func (m *mockMfaServiceForStepUp) ValidateRecoveryCode(userID uint, code string) error {
	return fmt.Errorf("código inválido")
}

func (m *mockMfaServiceForStepUp) SetupTOTP(userID uint, userEmail string) (*response.TOTPSetupResponse, error) {
	return &response.TOTPSetupResponse{Secret: "TEST_MOCK_TOTP_KEY_ONLY"}, nil
}

func TestDisableMFA_RequiresAuthentication(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", ctrl.DisableMFA)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"pass"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Esperaba 401 Unauthorized sin sesión de usuario, obtuvo %d", w.Code)
	}
}

func TestDisableMFA_RequiresBothPasswordAndCode(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		ctrl.DisableMFA(c)
	})

	t.Run("Rechaza payload vacío (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Esperaba 400 Bad Request sin password ni code, obtuvo %d", w.Code)
		}
	})

	t.Run("Rechaza si solo envía contraseña (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"MyPassword123!"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Esperaba 400 Bad Request enviando solo password, obtuvo %d", w.Code)
		}
	})

	t.Run("Rechaza si solo envía código MFA (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"code":"123456"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Esperaba 400 Bad Request enviando solo código, obtuvo %d", w.Code)
		}
	})
}

func TestDisableMFA_RejectsWrongCredentials(t *testing.T) {
	passHash, _ := util.HashPassword("CorrectPassword123!")
	userSvc := &mockUserServiceForStepUp{
		user: &model.User{
			Password: passHash,
		},
	}
	mfaSvc := &mockMfaServiceForStepUp{
		totpCode: "123456",
	}

	ctrl := &UserController{
		UserService: userSvc,
		MfaService:  mfaSvc,
	}

	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		ctrl.DisableMFA(c)
	})

	t.Run("Rechaza si la contraseña es incorrecta (401)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"WrongPassword","code":"123456"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Esperaba 401 Unauthorized con contraseña incorrecta, obtuvo %d", w.Code)
		}
		if mfaSvc.disabled {
			t.Fatalf("MFA no debió haberse desactivado")
		}
	})

	t.Run("Rechaza si el código MFA es incorrecto (401)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"CorrectPassword123!","code":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Esperaba 401 Unauthorized con código MFA incorrecto, obtuvo %d", w.Code)
		}
		if mfaSvc.disabled {
			t.Fatalf("MFA no debió haberse desactivado")
		}
	})
}

func TestDisableMFA_SucceedsWithBothValidCredentials(t *testing.T) {
	passHash, _ := util.HashPassword("CorrectPassword123!")
	userSvc := &mockUserServiceForStepUp{
		user: &model.User{
			Password: passHash,
		},
	}
	mfaSvc := &mockMfaServiceForStepUp{
		mfaEnabled: true,
		totpCode:   "123456",
	}

	ctrl := &UserController{
		UserService: userSvc,
		MfaService:  mfaSvc,
	}

	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		ctrl.DisableMFA(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"CorrectPassword123!","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK con contraseña y código válidos, obtuvo %d: %s", w.Code, w.Body.String())
	}
	if !mfaSvc.disabled {
		t.Fatalf("MFA debió haberse desactivado")
	}
}

func TestDisableMFA_MasksInternalDatabaseError(t *testing.T) {
	passHash, _ := util.HashPassword("CorrectPassword123!")
	userSvc := &mockUserServiceForStepUp{
		user: &model.User{
			Password: passHash,
		},
	}
	mfaSvc := &mockMfaServiceForStepUp{
		mfaEnabled: true,
		totpCode:   "123456",
		disableErr: errors.New("pq: connection pool exhausted - relation users table locked"),
	}

	ctrl := &UserController{
		UserService: userSvc,
		MfaService:  mfaSvc,
	}

	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		ctrl.DisableMFA(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"CorrectPassword123!","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Esperaba 500 Internal Server Error ante fallo en base de datos, obtuvo %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "pq:") || strings.Contains(w.Body.String(), "relation users") {
		t.Fatalf("Vulnerabilidad presente: se expuso el error interno de base de datos al cliente: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "error interno") {
		t.Fatalf("Se esperaba mensaje genérico al cliente, obtenido: %s", w.Body.String())
	}
}

func TestSetupTOTPLogin_RejectsWhenMfaAlreadyEnabled(t *testing.T) {
	_, tm, _, _ := setupOAuthControllerTest(t)
	mfaToken, err := tm.GenerateMFAPendingToken(1, "user@test.com", "client-portal")
	if err != nil {
		t.Fatalf("Error generando token MFA: %v", err)
	}

	mfaSvc := &mockMfaServiceForStepUp{
		mfaEnabled: true, // Ya tiene MFA activo
	}

	loginCtrl := &LoginController{
		TokenManager: tm,
		MfaService:   mfaSvc,
	}

	r := gin.New()
	r.POST("/login/mfa/totp/setup", loginCtrl.SetupTOTPLogin)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login/mfa/totp/setup", nil)
	req.Header.Set("Authorization", "Bearer "+mfaToken)
	req.Header.Set("X-App-ID", "client-portal")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Esperaba 403 Forbidden al intentar re-enrolar MFA cuando ya está activo, obtuvo %d", w.Code)
	}
}

func TestGetResetPassword_ReadsFromCookieAndSetsDefensiveHeaders(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	tmpl := template.Must(template.New("reset_password.html").Parse("<html>Token:{{.token}}</html>"))
	r.SetHTMLTemplate(tmpl)
	r.GET("/reset-password", ctrl.GetResetPassword)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/reset-password", nil)
	req.AddCookie(&http.Cookie{Name: "reset_token", Value: "secure_cookie_token_123"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK con token en cookie, obtuvo %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "secure_cookie_token_123") {
		t.Fatalf("El template debió recibir el token desde la cookie, body: %s", w.Body.String())
	}
	// Validar cabeceras defensivas
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Esperaba Referrer-Policy: no-referrer, obtuvo: %s", w.Header().Get("Referrer-Policy"))
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Esperaba Cache-Control no-store, obtuvo: %s", w.Header().Get("Cache-Control"))
	}
}

func TestGetResetPassword_FallbackToQuery(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	tmpl := template.Must(template.New("reset_password.html").Parse("<html>Token:{{.token}}</html>"))
	r.SetHTMLTemplate(tmpl)
	r.GET("/reset-password", ctrl.GetResetPassword)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/reset-password?token=query_fallback_token_456", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK con token en query fallback, obtuvo %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "query_fallback_token_456") {
		t.Fatalf("El template debió recibir el token desde query param, body: %s", w.Body.String())
	}
}

func TestLogin_And_Refresh_CacheControlHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test Login Controller headers
	loginCtrl := &LoginController{}
	r := gin.New()
	r.POST("/api/v1/login", loginCtrl.Login)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("se esperaba Cache-Control: no-store en /api/v1/login, obtenido: %s", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("se esperaba Pragma: no-cache en /api/v1/login, obtenido: %s", w.Header().Get("Pragma"))
	}

	// Test Refresh Controller headers
	userCtrl := &UserController{}
	rUser := gin.New()
	rUser.POST("/api/v1/refresh", userCtrl.Refresh)

	wUser := httptest.NewRecorder()
	reqUser, _ := http.NewRequest(http.MethodPost, "/api/v1/refresh", strings.NewReader(`{}`))
	reqUser.Header.Set("Content-Type", "application/json")
	rUser.ServeHTTP(wUser, reqUser)

	if wUser.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("se esperaba Cache-Control: no-store en /api/v1/refresh, obtenido: %s", wUser.Header().Get("Cache-Control"))
	}
	if wUser.Header().Get("Pragma") != "no-cache" {
		t.Errorf("se esperaba Pragma: no-cache en /api/v1/refresh, obtenido: %s", wUser.Header().Get("Pragma"))
	}
}

type mockAppAdminService struct {
	service.ApplicationService
	createAppFn      func(name, description, redirectURL string, isActive bool) (model.Application, string, error)
	updateAppFn      func(appID string, description, redirectURL string, isActive bool) error
	validateUniqueFn func(name string) error
}

func (m *mockAppAdminService) ValidateAppNameUnique(name string) error {
	if m.validateUniqueFn != nil {
		return m.validateUniqueFn(name)
	}
	return nil
}

func (m *mockAppAdminService) CreateApp(name, description, redirectURL string, isActive bool) (model.Application, string, error) {
	if m.createAppFn != nil {
		return m.createAppFn(name, description, redirectURL, isActive)
	}
	return model.Application{Name: name, RedirectURL: redirectURL, IsActive: isActive}, "secret123", nil
}

func (m *mockAppAdminService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	if m.updateAppFn != nil {
		return m.updateAppFn(appID, description, redirectURL, isActive)
	}
	return nil
}

func (m *mockAppAdminService) GetAppDetails(appID string) (model.Application, error) {
	return model.Application{ID: 1, AppID: appID, Name: "Test App"}, nil
}

type mockRuleAdminService struct {
	service.ApplicationRuleService
	createDefaultRulesFn func(appID uint) error
	createRuleFn         func(appID uint, code string, val []byte) error
	updateRuleValueFn    func(appID uint, code string, val []byte) error
}

func (m *mockRuleAdminService) CreateDefaultRules(appID uint) error {
	if m.createDefaultRulesFn != nil {
		return m.createDefaultRulesFn(appID)
	}
	return nil
}

func (m *mockRuleAdminService) CreateRule(appID uint, code string, val []byte) error {
	if m.createRuleFn != nil {
		return m.createRuleFn(appID, code, val)
	}
	return nil
}

func (m *mockRuleAdminService) UpdateRuleValue(appID uint, code string, val []byte) error {
	if m.updateRuleValueFn != nil {
		return m.updateRuleValueFn(appID, code, val)
	}
	return nil
}

func TestPostFormApp_Validation(t *testing.T) {
	tmpl := template.Must(template.New("app_new.html").Parse("<html>app_new:error={{.Error}}|redirect_err={{.RedirectError}}|name={{.NameValue}}|desc={{.DescriptionValue}}</html>"))
	template.Must(tmpl.New("app_created.html").Parse("<html>app_created:{{.App.Name}}</html>"))

	t.Run("Empty app name returns 400 with inline error", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ruleSvc := &mockRuleAdminService{}
		ctrl := &ApplicationController{
			AppService:  appSvc,
			RuleService: ruleSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps", ctrl.PostFormApp)

		form := url.Values{}
		form.Set("name", "")
		form.Set("redirect_url", "https://example.com/callback")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "El nombre de la aplicación es requerido.") {
			t.Errorf("esperaba mensaje de nombre requerido, obtuvo: %s", w.Body.String())
		}
	})

	t.Run("Empty redirect_url returns 400 with inline error and preserves values", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ruleSvc := &mockRuleAdminService{}
		ctrl := &ApplicationController{
			AppService:  appSvc,
			RuleService: ruleSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps", ctrl.PostFormApp)

		form := url.Values{}
		form.Set("name", "My Cool App")
		form.Set("description", "A description here")
		form.Set("redirect_url", "")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "La URL de redirección es obligatoria.") {
			t.Errorf("esperaba error de redirección obligatoria, obtuvo: %s", body)
		}
		if !strings.Contains(body, "name=My Cool App") || !strings.Contains(body, "desc=A description here") {
			t.Errorf("esperaba que se preservaran los valores de name y desc, obtuvo: %s", body)
		}
	})

	t.Run("Insecure redirect_url (HTTP non-loopback) returns 400", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ruleSvc := &mockRuleAdminService{}
		ctrl := &ApplicationController{
			AppService:  appSvc,
			RuleService: ruleSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps", ctrl.PostFormApp)

		form := url.Values{}
		form.Set("name", "Insecure App")
		form.Set("redirect_url", "http://insecure.example.com/callback")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "redirect_uri debe usar HTTPS excepto para direcciones locales") {
			t.Errorf("esperaba error de HTTPS requerido, obtuvo: %s", w.Body.String())
		}
	})

	t.Run("Valid inputs create application successfully", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ruleSvc := &mockRuleAdminService{}
		ctrl := &ApplicationController{
			AppService:  appSvc,
			RuleService: ruleSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps", ctrl.PostFormApp)

		form := url.Values{}
		form.Set("name", "Valid App")
		form.Set("description", "Valid Description")
		form.Set("redirect_url", "https://valid.example.com/callback")
		form.Set("is_active", "on")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("esperaba 200 OK, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "app_created:Valid App") {
			t.Errorf("esperaba renderizado de app_created, obtuvo: %s", w.Body.String())
		}
	})
}

func TestUpdateFormApp_Validation(t *testing.T) {
	tmpl := template.Must(template.New("error.html").Parse("<html>error:{{.Title}}|{{.Message}}</html>"))

	t.Run("Empty redirect_url returns 400", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps/:id", ctrl.UpdateFormApp)

		form := url.Values{}
		form.Set("description", "Updated desc")
		form.Set("redirect_url", "")
		form.Set("is_active", "on")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/my-app", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "La URL de redirección es obligatoria.") {
			t.Errorf("esperaba error de redirección obligatoria, obtuvo: %s", w.Body.String())
		}
	})

	t.Run("Insecure redirect_url returns 400", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps/:id", ctrl.UpdateFormApp)

		form := url.Values{}
		form.Set("description", "Updated desc")
		form.Set("redirect_url", "http://insecure.example.com/oauth/callback")
		form.Set("is_active", "on")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/my-app", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "URL de Redirección Inválida") {
			t.Errorf("esperaba error de URL inválida, obtuvo: %s", w.Body.String())
		}
	})
}

func TestMfaChallengeKey(t *testing.T) {
	// 1. Con JTI presente, usa JTI
	key := mfaChallengeKey("oauth_mfa", 1, "jti-123", "1")
	if key != "oauth_mfa_1_jti-123" {
		t.Errorf("mfaChallengeKey con JTI inesperado: %s", key)
	}

	// 2. Sin JTI, fallback a Subject
	fallbackKey := mfaChallengeKey("oauth_mfa", 1, "", "1")
	if fallbackKey != "oauth_mfa_1_1" {
		t.Errorf("mfaChallengeKey fallback inesperado: %s", fallbackKey)
	}

	// 3. Dos tokens distintos producen claves distintas para el mismo usuario
	keyA := mfaChallengeKey("oauth_mfa", 1, "tok-aaa", "1")
	keyB := mfaChallengeKey("oauth_mfa", 1, "tok-bbb", "1")
	if keyA == keyB {
		t.Errorf("claves deben ser distintas: %s == %s", keyA, keyB)
	}
}

type mockUserDashboardService struct {
	service.UserService
	findVerifiedUserByIDFn func(id uint) (*model.User, error)
	sendResetEmailFn       func(user *model.User, appID uint) error
}

func (m *mockUserDashboardService) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.findVerifiedUserByIDFn != nil {
		return m.findVerifiedUserByIDFn(id)
	}
	u := &model.User{Email: "user@test.com", IsActive: true, IsVerified: true}
	u.ID = id
	return u, nil
}

func (m *mockUserDashboardService) SendResetEmail(user *model.User, appID uint) error {
	if m.sendResetEmailFn != nil {
		return m.sendResetEmailFn(user, appID)
	}
	return nil
}

type mockAppDashboardService struct {
	service.ApplicationService
	getAppDetailsFn    func(appID string) (model.Application, error)
	userBelongsToAppFn func(userID, appID uint) (bool, error)
}

func (m *mockAppDashboardService) GetAppDetails(appID string) (model.Application, error) {
	if m.getAppDetailsFn != nil {
		return m.getAppDetailsFn(appID)
	}
	app := model.Application{AppID: appID}
	app.ID = 1
	return app, nil
}

func (m *mockAppDashboardService) UserBelongsToApp(userID, appID uint) (bool, error) {
	if m.userBelongsToAppFn != nil {
		return m.userBelongsToAppFn(userID, appID)
	}
	return true, nil
}

func TestPostSendResetPassword_RateLimitingAndAtomicity(t *testing.T) {
	t.Run("Success sends email and returns 200", func(t *testing.T) {
		userSvc := &mockUserDashboardService{}
		appSvc := &mockAppDashboardService{}
		ctrl := &DashboardController{
			UserService: userSvc,
			AppService:  appSvc,
		}

		r := gin.New()
		r.POST("/apps/:id/users/:user_id/send-reset", ctrl.PostSendResetPassword)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/users/42/send-reset", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("esperaba 200 OK, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Email de recuperación enviado correctamente") {
			t.Errorf("respuesta inesperada: %s", w.Body.String())
		}
	})

	t.Run("Rate limit error from SendResetEmail returns 429 Too Many Requests", func(t *testing.T) {
		userSvc := &mockUserDashboardService{
			sendResetEmailFn: func(user *model.User, appID uint) error {
				return fmt.Errorf("debe esperar al menos 15 minutos entre solicitudes de reset")
			},
		}
		appSvc := &mockAppDashboardService{}
		ctrl := &DashboardController{
			UserService: userSvc,
			AppService:  appSvc,
		}

		r := gin.New()
		r.POST("/apps/:id/users/:user_id/send-reset", ctrl.PostSendResetPassword)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/users/42/send-reset", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("esperaba 429 Too Many Requests, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "debe esperar al menos 15 minutos") {
			t.Errorf("respuesta inesperada: %s", w.Body.String())
		}
	})
}

// --- Tests Two-Step Email Verification ---

type mockUserServiceForVerify struct {
	service.UserService
	verifyEmailFn        func(token string) (uint, uint, error)
	findVerifiedUserFn   func(id uint) (*model.User, error)
	generateResetTokenFn func(userID, appID uint) (string, []byte, error)
}

func (m *mockUserServiceForVerify) VerifyEmail(token string) (uint, uint, error) {
	if m.verifyEmailFn != nil {
		return m.verifyEmailFn(token)
	}
	return 1, 1, nil
}

func (m *mockUserServiceForVerify) FindVerifiedUserByID(id uint) (*model.User, error) {
	if m.findVerifiedUserFn != nil {
		return m.findVerifiedUserFn(id)
	}
	return &model.User{ID: id}, nil
}

func (m *mockUserServiceForVerify) GenerateResetToken(userID, appID uint) (string, []byte, error) {
	if m.generateResetTokenFn != nil {
		return m.generateResetTokenFn(userID, appID)
	}
	return "test-reset-token", []byte("hash"), nil
}

func TestVerifyEmail_TwoStep(t *testing.T) {
	tmpl := template.Must(template.New("verify_email_confirm.html").Parse("<html>confirm:token={{.Token}}|csrf={{.csrf_token}}</html>"))
	template.Must(tmpl.New("verify_email.html").Parse("<html>verify_success:needs_pwd={{.NeedsPassword}}</html>"))
	template.Must(tmpl.New("error.html").Parse("<html>error:title={{.Title}}|msg={{.Message}}</html>"))

	t.Run("GET /verify displays confirm page without consuming token", func(t *testing.T) {
		verifyCalled := false
		userSvc := &mockUserServiceForVerify{
			verifyEmailFn: func(token string) (uint, uint, error) {
				verifyCalled = true
				return 1, 1, nil
			},
		}
		ctrl := &RegisterController{UserService: userSvc}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.Use(func(c *gin.Context) {
			c.Set("csrf_token", "dummy_csrf_token_123")
			c.Next()
		})
		r.GET("/verify", ctrl.GetVerifyEmail)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/verify?token=valid_test_token_abc", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido %d: %s", w.Code, w.Body.String())
		}
		if verifyCalled {
			t.Fatalf("GET /verify no debe consumir el token de verificación")
		}
		expectedSnippet := "confirm:token=valid_test_token_abc|csrf=dummy_csrf_token_123"
		if !strings.Contains(w.Body.String(), expectedSnippet) {
			t.Errorf("respuesta no contiene el token o el csrf_token esperado: %s", w.Body.String())
		}
	})

	t.Run("GET /verify without token returns 400", func(t *testing.T) {
		ctrl := &RegisterController{UserService: &mockUserServiceForVerify{}}
		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.GET("/verify", ctrl.GetVerifyEmail)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/verify", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request, obtenido %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Token requerido") {
			t.Errorf("se esperaba mensaje de error de token requerido, obtenido: %s", w.Body.String())
		}
	})

	t.Run("POST /verify with valid token consumes token and verifies user", func(t *testing.T) {
		consumedToken := ""
		userSvc := &mockUserServiceForVerify{
			verifyEmailFn: func(token string) (uint, uint, error) {
				consumedToken = token
				return 42, 1, nil
			},
			findVerifiedUserFn: func(id uint) (*model.User, error) {
				return &model.User{ID: id}, nil
			},
		}
		ctrl := &RegisterController{UserService: userSvc}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/verify", ctrl.PostVerifyEmail)

		form := url.Values{}
		form.Set("token", "valid_verification_token_xyz")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido %d: %s", w.Code, w.Body.String())
		}
		if consumedToken != "valid_verification_token_xyz" {
			t.Errorf("se esperaba consumo del token 'valid_verification_token_xyz', consumido: %q", consumedToken)
		}
		if !strings.Contains(w.Body.String(), "verify_success:needs_pwd=true") {
			t.Errorf("se esperaba renderizado de verify_success, obtenido: %s", w.Body.String())
		}
	})

	t.Run("POST /verify without token returns 400", func(t *testing.T) {
		ctrl := &RegisterController{UserService: &mockUserServiceForVerify{}}
		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/verify", ctrl.PostVerifyEmail)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/verify", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request, obtenido %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Token requerido") {
			t.Errorf("se esperaba mensaje de error de token requerido, obtenido: %s", w.Body.String())
		}
	})

	t.Run("POST /verify with invalid/expired token returns 400", func(t *testing.T) {
		userSvc := &mockUserServiceForVerify{
			verifyEmailFn: func(token string) (uint, uint, error) {
				return 0, 0, fmt.Errorf("token inválido o expirado")
			},
		}
		ctrl := &RegisterController{UserService: userSvc}
		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/verify", ctrl.PostVerifyEmail)

		form := url.Values{}
		form.Set("token", "expired_token_123")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request, obtenido %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Verificación fallida") {
			t.Errorf("se esperaba mensaje de verificación fallida, obtenido: %s", w.Body.String())
		}
	})
}

func TestRuleController_RequestBodyLimit(t *testing.T) {
	appSvc := &mockAppAdminService{}
	ruleSvc := &mockRuleAdminService{}
	ctrl := &RuleController{
		AppService:  appSvc,
		RuleService: ruleSvc,
	}

	r := gin.New()
	r.POST("/apps/:id/rules/:code", middleware.RequestBodyLimitMiddleware(64*1024), ctrl.PostAppRule)
	r.PUT("/apps/:id/rules/:code", middleware.RequestBodyLimitMiddleware(64*1024), ctrl.PutAppRule)

	t.Run("POST /rules accepts body within 64KB", func(t *testing.T) {
		validBody := `{"token_expiration_minutes": 60, "max_failed_logins": 5}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("POST /rules rejects body exceeding 64KB with 413", func(t *testing.T) {
		oversized := `{"data":"` + strings.Repeat("a", 65*1024) + `"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("se esperaba 413 Request Entity Too Large, obtenido %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "excede el límite permitido") {
			t.Errorf("mensaje de error inesperado: %s", w.Body.String())
		}
	})

	t.Run("PUT /rules rejects body exceeding 64KB with 413", func(t *testing.T) {
		oversized := `{"data":"` + strings.Repeat("b", 65*1024) + `"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("se esperaba 413 Request Entity Too Large, obtenido %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "excede el límite permitido") {
			t.Errorf("mensaje de error inesperado: %s", w.Body.String())
		}
	})
}

func TestFinishWebAuthnRegistration_ErrorHandling(t *testing.T) {
	t.Run("Validation error returns 400 with fixed client message", func(t *testing.T) {
		mfaSvc := &mockMfaServiceForStepUp{
			finishWebAuthnRegErr: service.ErrWebAuthnValidation,
		}
		ctrl := &UserController{MfaService: mfaSvc}
		service.StoreWebAuthnSession("wa_reg_42", &webauthn.SessionData{})

		r := gin.New()
		r.POST("/api/v1/mfa/webauthn/verify", func(c *gin.Context) {
			c.Set("user_id", uint(42))
			ctrl.FinishWebAuthnRegistration(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/verify", strings.NewReader(`{}`))
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request, obtenido %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Registro WebAuthn inválido") {
			t.Errorf("respuesta inesperada: %s", w.Body.String())
		}
	})

	t.Run("Internal error masks technical details and returns 500", func(t *testing.T) {
		mfaSvc := &mockMfaServiceForStepUp{
			finishWebAuthnRegErr: fmt.Errorf("%w: pq: table mfa_credentials locked", service.ErrWebAuthnInternal),
		}
		ctrl := &UserController{MfaService: mfaSvc}
		service.StoreWebAuthnSession("wa_reg_42", &webauthn.SessionData{})

		r := gin.New()
		r.POST("/api/v1/mfa/webauthn/verify", func(c *gin.Context) {
			c.Set("user_id", uint(42))
			ctrl.FinishWebAuthnRegistration(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/verify", strings.NewReader(`{}`))
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("se esperaba 500 Internal Server Error, obtenido %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "pq:") || strings.Contains(w.Body.String(), "mfa_credentials") {
			t.Fatalf("vulnerabilidad presente: se filtró detalle interno: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "ocurrió un error procesando la solicitud") {
			t.Errorf("se esperaba mensaje genérico, obtenido: %s", w.Body.String())
		}
	})
}

func TestUserController_ListAndDeleteWebAuthnKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mfaSvc := &mockMfaServiceForStepUp{}
	ctrl := &UserController{MfaService: mfaSvc}

	r := gin.New()
	r.GET("/api/v1/mfa/webauthn/credentials", func(c *gin.Context) {
		c.Set("user_id", uint(42))
		ctrl.ListWebAuthnKeys(c)
	})
	r.DELETE("/api/v1/mfa/webauthn/credentials/:id", func(c *gin.Context) {
		c.Set("user_id", uint(42))
		ctrl.DeleteWebAuthnKey(c)
	})

	t.Run("GET /api/v1/mfa/webauthn/credentials retorna 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/mfa/webauthn/credentials", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
		}
	})

	t.Run("DELETE /api/v1/mfa/webauthn/credentials/:id retorna 200 para ID válido", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/5", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
		}
	})

	t.Run("DELETE /api/v1/mfa/webauthn/credentials/:id retorna 400 para ID no numérico", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/invalido", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("se esperaba 400 Bad Request, obtenido: %d", w.Code)
		}
	})
}

