package controller

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

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
		if w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Errorf("se esperaba Referrer-Policy: same-origin, obtenido: %s", w.Header().Get("Referrer-Policy"))
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

func TestPostUsersInApp_TemporaryAccess(t *testing.T) {
	appSvc := &mockAppService{
		app: model.Application{ID: 10, AppID: "test-app", Name: "Test App"},
	}
	ctrl := &RegisterController{AppService: appSvc}

	r := gin.New()
	r.POST("/admin/apps/:id/users", ctrl.PostUsersInApp)

	// 1. Permanent access (no is_temporary)
	form := url.Values{}
	form.Set("email", "perm@test.com")
	form.Set("role", "EDITOR")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/apps/test-app/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if len(appSvc.registeredAccessTimes) != 0 {
		t.Errorf("expected 0 access times for permanent user, got %d", len(appSvc.registeredAccessTimes))
	}

	// 2. Temporary access with preset 7d
	form = url.Values{}
	form.Set("email", "temp@test.com")
	form.Set("role", "EDITOR")
	form.Set("is_temporary", "true")
	form.Set("duration_preset", "7d")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/admin/apps/test-app/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if len(appSvc.registeredAccessTimes) != 2 {
		t.Fatalf("expected 2 access times (startsAt, expiresAt) for temporary user, got %d", len(appSvc.registeredAccessTimes))
	}
	if appSvc.registeredAccessTimes[1] == nil || appSvc.registeredAccessTimes[1].Before(time.Now().Add(6*24*time.Hour)) {
		t.Errorf("expected expiration ~7 days in future, got %v", appSvc.registeredAccessTimes[1])
	}
}

