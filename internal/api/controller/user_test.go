package controller

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"peak-auth/internal/store/model"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

func TestRevokeUserAccess_ProtectsRootUser(t *testing.T) {
	appSvc := &mockAppService{
		app:    model.Application{AppID: "peak-auth"},
		isRoot: true,
	}
	ctrl := &UserController{AppService: appSvc}

	r := gin.New()
	r.DELETE("/admin/apps/:id/users/:user_id", func(c *gin.Context) {
		c.Set("user_id", uint(99))
		ctrl.RevokeUserAccess(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/admin/apps/peak-auth/users/1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Esperaba 403 Forbidden para usuario ROOT, obtuvo %d", w.Code)
	}
	if appSvc.revoked {
		t.Fatal("Vulnerabilidad presente: se revocó el acceso al usuario ROOT")
	}
}

func TestRevokeUserAccess_AllowsRevokingRegularUser(t *testing.T) {
	appSvc := &mockAppService{
		app:    model.Application{AppID: "peak-auth"},
		isRoot: false,
	}
	ctrl := &UserController{AppService: appSvc}

	r := gin.New()
	r.DELETE("/admin/apps/:id/users/:user_id", func(c *gin.Context) {
		c.Set("user_id", uint(99))
		ctrl.RevokeUserAccess(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/admin/apps/peak-auth/users/42", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK para usuario normal, obtuvo %d", w.Code)
	}
	if !appSvc.revoked {
		t.Fatal("No se revocó el acceso al usuario regular")
	}
}

func TestRevokeUserAccess_UserNotInApp_ReturnsNotFound(t *testing.T) {
	appSvc := &mockAppService{
		app:        model.Application{AppID: "peak-auth"},
		isRoot:     false,
		notBelongs: true,
	}
	ctrl := &UserController{AppService: appSvc}

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

func TestDisableMFA_RequiresAuthentication(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", ctrl.DisableMFA)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"pass"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Esperaba 401 Unauthorized sin user_id en contexto, obtuvo %d", w.Code)
	}
}

func TestDisableMFA_RequiresBothPasswordAndCode(t *testing.T) {
	ctrl := &UserController{}
	r := gin.New()
	r.POST("/api/v1/mfa/totp/disable", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		ctrl.DisableMFA(c)
	})

	// 1. Falta password
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Esperaba 400 sin password, obtuvo %d", w.Code)
	}

	// 2. Falta code
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"password":"pass"}`))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("Esperaba 400 sin code, obtuvo %d", w2.Code)
	}
}

func TestDisableMFA_RejectsWrongCredentials(t *testing.T) {
	hashedPassword, _ := util.HashPassword("valid_password_123")
	user := &model.User{
		Password:   hashedPassword,
		MfaEnabled: true,
	}
	userSvc := &mockUserServiceForStepUp{user: user}

	t.Run("Contraseña incorrecta falla", func(t *testing.T) {
		mfaSvc := &mockMfaServiceForStepUp{
			mfaEnabled: true,
			totpCode:   "654321",
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

		body := `{"password":"wrong_password","code":"654321"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Esperaba 401 con contraseña incorrecta, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if mfaSvc.disabled {
			t.Fatal("Vulnerabilidad presente: MFA fue deshabilitado con contraseña incorrecta")
		}
	})

	t.Run("Código TOTP incorrecto falla", func(t *testing.T) {
		mfaSvc := &mockMfaServiceForStepUp{
			mfaEnabled: true,
			totpCode:   "654321",
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

		body := `{"password":"valid_password_123","code":"000000"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Esperaba 401 con código incorrecto, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if mfaSvc.disabled {
			t.Fatal("Vulnerabilidad presente: MFA fue deshabilitado con código TOTP incorrecto")
		}
	})
}

func TestDisableMFA_SucceedsWithBothValidCredentials(t *testing.T) {
	hashedPassword, _ := util.HashPassword("valid_password_123")
	user := &model.User{
		Password:   hashedPassword,
		MfaEnabled: true,
	}
	userSvc := &mockUserServiceForStepUp{user: user}
	mfaSvc := &mockMfaServiceForStepUp{
		mfaEnabled: true,
		totpCode:   "654321",
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

	body := `{"password":"valid_password_123","code":"654321"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Esperaba 200 OK con credenciales válidas, obtuvo %d: %s", w.Code, w.Body.String())
	}
	if !mfaSvc.disabled {
		t.Fatal("MFA debió ser deshabilitado con credenciales válidas")
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

	body := `{"password":"CorrectPassword123!","code":"123456"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(body))
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

func TestUserController_PostUpdateAccessTime(t *testing.T) {
	gin.SetMode(gin.TestMode)

	appSvc := &mockAppService{
		app: model.Application{ID: 15, AppID: "shop-app"},
	}
	ctrl := &UserController{AppService: appSvc}

	r := gin.New()
	r.POST("/admin/apps/:id/users/:user_id/access-time", ctrl.PostUpdateAccessTime)

	t.Run("invalid user_id returns 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/shop-app/users/abc/access-time", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("update to temporary 24h succeeds", func(t *testing.T) {
		form := url.Values{}
		form.Set("duration_preset", "24h")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/shop-app/users/42/access-time", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if appSvc.updatedAccessUserID != 42 || appSvc.updatedAccessAppID != "shop-app" {
			t.Errorf("expected user 42 and app shop-app, got user %d app %s", appSvc.updatedAccessUserID, appSvc.updatedAccessAppID)
		}
		if appSvc.updatedAccessExpires == nil || appSvc.updatedAccessExpires.Before(time.Now().Add(23*time.Hour)) {
			t.Errorf("expected expiration ~24h, got %v", appSvc.updatedAccessExpires)
		}
	})

	t.Run("update to permanent succeeds", func(t *testing.T) {
		form := url.Values{}
		form.Set("is_permanent", "true")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/shop-app/users/42/access-time", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if appSvc.updatedAccessExpires != nil || appSvc.updatedAccessStarts != nil {
			t.Errorf("expected nil times for permanent access, got starts=%v expires=%v", appSvc.updatedAccessStarts, appSvc.updatedAccessExpires)
		}
	})
}

