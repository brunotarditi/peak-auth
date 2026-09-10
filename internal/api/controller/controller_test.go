package controller

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"peak-auth/internal/api/response"
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
