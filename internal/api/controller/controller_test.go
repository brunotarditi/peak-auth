package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
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
	app     model.Application
	isRoot  bool
	revoked bool
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
	mfaEnabled bool
	disabled   bool
	totpCode   string
}

func (m *mockMfaServiceForStepUp) IsMfaEnabled(userID uint) bool {
	return m.mfaEnabled
}

func (m *mockMfaServiceForStepUp) DisableMFA(userID uint) error {
	m.disabled = true
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
	return &response.TOTPSetupResponse{Secret: "JBSWY3DPEHPK3PXP"}, nil
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

