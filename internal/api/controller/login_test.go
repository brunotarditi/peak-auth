package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"peak-auth/internal/api/request"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

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

type mockUserServiceForLogin struct {
	adminLoginFn func(email, password string) (string, int, bool, bool, string, error)
}

func (m *mockUserServiceForLogin) Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error) {
	return response.TokenResponse{}, nil
}
func (m *mockUserServiceForLogin) AdminLogin(email, password string) (string, int, bool, bool, string, error) {
	if m.adminLoginFn != nil {
		return m.adminLoginFn(email, password)
	}
	return "", 0, false, false, "", nil
}
func (m *mockUserServiceForLogin) CompleteLoginWithMfa(userID uint, publicAppID string, mfaCompleted bool, clientInfo ...string) (response.TokenResponse, error) {
	return response.TokenResponse{}, nil
}
func (m *mockUserServiceForLogin) CompleteAdminLoginWithMfa(userID uint) (string, int, error) {
	return "", 0, nil
}
func (m *mockUserServiceForLogin) Register(req request.RegisterRequest) (model.User, error) {
	return model.User{}, nil
}
func (m *mockUserServiceForLogin) FindAll() ([]model.User, error) {
	return nil, nil
}
func (m *mockUserServiceForLogin) FindVerifiedUser(email string) (*model.User, error) {
	return nil, nil
}
func (m *mockUserServiceForLogin) FindVerifiedUserByID(id uint) (*model.User, error) {
	return nil, nil
}
func (m *mockUserServiceForLogin) FindUserByAppID(appID string) ([]response.UserAppRow, error) {
	return nil, nil
}
func (m *mockUserServiceForLogin) FindUserByAppIDPaginated(appID model.Application, page, limit int) ([]response.UserAppRow, int64, error) {
	return nil, 0, nil
}
func (m *mockUserServiceForLogin) GenerateResetToken(userID, appID uint) (string, []byte, error) {
	return "", nil, nil
}
func (m *mockUserServiceForLogin) VerifyEmail(token string) (uint, uint, error) {
	return 0, 0, nil
}
func (m *mockUserServiceForLogin) SendResetEmail(user *model.User, appID uint) error {
	return nil
}
func (m *mockUserServiceForLogin) ResendVerification(userID uint, appID string) error {
	return nil
}
func (m *mockUserServiceForLogin) ResetPassword(token, newPassword string) error {
	return nil
}
func (m *mockUserServiceForLogin) CanRequestPasswordReset(userID uint) (bool, error) {
	return true, nil
}
func (m *mockUserServiceForLogin) Refresh(token string, clientInfo ...string) (response.TokenResponse, error) {
	return response.TokenResponse{}, nil
}
func (m *mockUserServiceForLogin) UnlockUser(userID uint) error {
	return nil
}
func (m *mockUserServiceForLogin) UpdateAvatar(userID uint, avatarURL string) error {
	return nil
}

func TestPostLoginForm_PasswordExpiredRedirectsToReset(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockUserSvc := &mockUserServiceForLogin{
		adminLoginFn: func(email, password string) (string, int, bool, bool, string, error) {
			return "", 0, false, false, "", fmt.Errorf("PASSWORD_EXPIRED:test-expired-token-xyz")
		},
	}

	loginCtrl := &LoginController{
		UserService: mockUserSvc,
	}

	r := gin.New()
	r.POST("/admin/login", loginCtrl.PostLoginForm)

	form := url.Values{}
	form.Set("email", "admin@peakauth.com")
	form.Set("password", "oldpassword")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba status 303 See Other, obtenido: %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/reset-password?required=true" {
		t.Errorf("se esperaba redirección a /reset-password?required=true, obtenido: %s", location)
	}

	// Verificar cookie reset_token
	cookies := w.Result().Cookies()
	var foundResetToken bool
	for _, c := range cookies {
		if c.Name == "reset_token" {
			foundResetToken = true
			if c.Value != "test-expired-token-xyz" {
				t.Errorf("se esperaba reset_token con valor test-expired-token-xyz, obtenido: %s", c.Value)
			}
			if c.Path != "/reset-password" {
				t.Errorf("se esperaba cookie path /reset-password, obtenido: %s", c.Path)
			}
			if !c.HttpOnly {
				t.Errorf("se esperaba cookie HttpOnly=true")
			}
		}
	}
	if !foundResetToken {
		t.Errorf("no se encontró cookie reset_token en la respuesta")
	}
}

