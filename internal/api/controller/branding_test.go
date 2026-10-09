package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"peak-auth/internal/service"
	"peak-auth/internal/storage"
	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

type mockOAuthServiceForBranding struct {
	service.OAuthService
	clientID    string
	redirectURI string
}

func (m *mockOAuthServiceForBranding) ValidateClientRedirect(clientID, redirectURI string) error {
	if clientID == m.clientID && redirectURI == m.redirectURI {
		return nil
	}
	return errors.New("invalid redirect")
}

// Helper mock storage para pruebas
type mockStorageServiceForTest struct {
	uploadedURL string
	err         error
}

func (m *mockStorageServiceForTest) Upload(ctx any, r any, filename, folder string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return "/static/uploads/" + folder + "/test-file.png", nil
}

func (m *mockStorageServiceForTest) Delete(ctx any, fileURL string) error {
	return nil
}

func TestApplicationController_Branding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmpl := template.Must(template.New("app_branding.html").Parse("<html>branding:app={{.App.Name}}|color={{.PrimaryColor}}|title={{.CustomTitle}}</html>"))
	template.Must(tmpl.New("error.html").Parse("<html>error:{{.Title}}-{{.Message}}</html>"))

	t.Run("GetAppBranding forbids peak-auth root app", func(t *testing.T) {
		ctrl := &ApplicationController{}
		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.GET("/admin/apps/:id/branding", func(c *gin.Context) {
			c.Set("is_root", true)
			ctrl.GetAppBranding(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/apps/peak-auth/branding", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("se esperaba 403 Forbidden para peak-auth, se obtuvo %d", w.Code)
		}
	})

	t.Run("GetAppBranding forbids non-owner non-root", func(t *testing.T) {
		ownerID := uint(10)
		appSvc := &mockAppService{
			app: model.Application{
				AppID:   "test-app",
				Name:    "Test App",
				OwnerID: &ownerID,
			},
		}

		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.GET("/admin/apps/:id/branding", func(c *gin.Context) {
			c.Set("user_id", uint(99)) // Otro usuario
			c.Set("is_root", false)
			ctrl.GetAppBranding(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/apps/test-app/branding", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("se esperaba 403 Forbidden, se obtuvo %d", w.Code)
		}
	})

	t.Run("GetAppBranding allows owner and displays default/existing theme", func(t *testing.T) {
		ownerID := uint(10)
		appSvc := &mockAppService{
			app: model.Application{
				AppID:   "test-app",
				Name:    "Test App",
				OwnerID: &ownerID,
				Theme: &model.ApplicationTheme{
					PrimaryColor: "#059669",
					CustomTitle:  "Login Personalizado",
				},
			},
		}

		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.GET("/admin/apps/:id/branding", func(c *gin.Context) {
			c.Set("user_id", ownerID)
			c.Set("is_root", false)
			ctrl.GetAppBranding(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/apps/test-app/branding", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, se obtuvo %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "#059669") || !strings.Contains(w.Body.String(), "Login Personalizado") {
			t.Errorf("respuesta no contiene valores del tema: %s", w.Body.String())
		}
	})

	t.Run("PostAppBranding saves preferences and redirects", func(t *testing.T) {
		ownerID := uint(10)
		appSvc := &mockAppService{
			app: model.Application{
				AppID:   "test-app",
				Name:    "Test App",
				OwnerID: &ownerID,
			},
		}

		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.POST("/admin/apps/:id/branding", func(c *gin.Context) {
			c.Set("user_id", ownerID)
			c.Set("is_root", false)
			ctrl.PostAppBranding(c)
		})

		form := url.Values{}
		form.Set("primary_color", "#e11d48")
		form.Set("custom_title", "Tienda Online")
		form.Set("custom_subtitle", "Ingresa con tu cuenta")
		form.Set("terms_url", "https://example.com/terms")
		form.Set("privacy_url", "https://example.com/privacy")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/test-app/branding", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other, se obtuvo %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/admin/apps/test-app/branding?saved=true" {
			t.Errorf("location inesperado: %s", loc)
		}
		if appSvc.app.Theme == nil || appSvc.app.Theme.PrimaryColor != "#e11d48" {
			t.Errorf("tema no fue actualizado correctamente: %+v", appSvc.app.Theme)
		}
	})

	t.Run("PostAppThemeReset resets theme", func(t *testing.T) {
		ownerID := uint(10)
		appSvc := &mockAppService{
			app: model.Application{
				AppID:   "test-app",
				Name:    "Test App",
				OwnerID: &ownerID,
				Theme: &model.ApplicationTheme{
					PrimaryColor: "#e11d48",
				},
			},
		}

		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.POST("/admin/apps/:id/branding/reset", func(c *gin.Context) {
			c.Set("user_id", ownerID)
			c.Set("is_root", false)
			ctrl.PostAppThemeReset(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/test-app/branding/reset", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other, se obtuvo %d", w.Code)
		}
		if appSvc.app.Theme != nil {
			t.Errorf("se esperaba tema reseteado a nil, pero tiene: %+v", appSvc.app.Theme)
		}
	})

	t.Run("PostAppUploadLogo via AJAX", func(t *testing.T) {
		tempDir := t.TempDir()
		storageSvc, err := storage.NewLocalStorageService(tempDir)
		if err != nil {
			t.Fatalf("fallo al crear storage: %v", err)
		}

		ownerID := uint(10)
		appSvc := &mockAppService{
			app: model.Application{
				AppID:   "test-app",
				Name:    "Test App",
				OwnerID: &ownerID,
			},
		}

		ctrl := &ApplicationController{
			AppService:     appSvc,
			StorageService: storageSvc,
		}

		r := gin.New()
		r.POST("/admin/apps/:id/branding/upload-logo", func(c *gin.Context) {
			c.Set("user_id", ownerID)
			c.Set("is_root", false)
			ctrl.PostAppUploadLogo(c)
		})

		// PNG válido mínimo de 1x1 píxel
		pngBytes := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
			0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
			0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
			0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
			0x42, 0x60, 0x82,
		}

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("logo", "logo.png")
		if err != nil {
			t.Fatalf("error al crear form file: %v", err)
		}
		part.Write(pngBytes)
		writer.Close()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/test-app/branding/upload-logo", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, se obtuvo %d: %s", w.Code, w.Body.String())
		}

		var res map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("error decodificando json: %v", err)
		}
		if res["success"] != true {
			t.Errorf("se esperaba success=true, se obtuvo: %v", res)
		}
		urlStr, _ := res["url"].(string)
		if !strings.HasPrefix(urlStr, "/static/uploads/logos/") {
			t.Errorf("url inesperada: %s", urlStr)
		}
	})
}

// Mock UserService para pruebas de avatar
type mockUserServiceForAvatar struct {
	service.UserService
	avatarUpdated string
	updatedUserID uint
	err           error
}

func (m *mockUserServiceForAvatar) UpdateAvatar(userID uint, avatarURL string) error {
	m.updatedUserID = userID
	m.avatarUpdated = avatarURL
	return m.err
}

func TestUserController_Avatar(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tempDir := t.TempDir()
	storageSvc, err := storage.NewLocalStorageService(tempDir)
	if err != nil {
		t.Fatalf("fallo al crear storage: %v", err)
	}

	t.Run("PostUploadAvatar rejects unauthenticated request", func(t *testing.T) {
		ctrl := &UserController{
			StorageService: storageSvc,
		}

		r := gin.New()
		r.POST("/api/v1/user/avatar", ctrl.PostUploadAvatar)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/user/avatar", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("se esperaba 401 Unauthorized, se obtuvo %d", w.Code)
		}
	})

	t.Run("PostUploadAvatar uploads valid image and updates user profile", func(t *testing.T) {
		mockUserSvc := &mockUserServiceForAvatar{}
		ctrl := &UserController{
			UserService:    mockUserSvc,
			StorageService: storageSvc,
		}

		r := gin.New()
		r.POST("/api/v1/user/avatar", func(c *gin.Context) {
			c.Set("user_id", uint(42))
			ctrl.PostUploadAvatar(c)
		})

		pngBytes := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
			0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
			0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
			0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
			0x42, 0x60, 0x82,
		}

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("avatar", "profile.png")
		part.Write(pngBytes)
		writer.Close()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/user/avatar", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, se obtuvo %d: %s", w.Code, w.Body.String())
		}

		if mockUserSvc.updatedUserID != 42 {
			t.Errorf("se esperaba userID 42, se obtuvo %d", mockUserSvc.updatedUserID)
		}
		if !strings.HasPrefix(mockUserSvc.avatarUpdated, "/static/uploads/avatars/") {
			t.Errorf("avatar URL inesperada: %s", mockUserSvc.avatarUpdated)
		}
	})

	t.Run("DeleteAvatar removes avatar", func(t *testing.T) {
		mockUserSvc := &mockUserServiceForAvatar{
			avatarUpdated: "previous-avatar.jpg",
		}
		ctrl := &UserController{
			UserService: mockUserSvc,
		}

		r := gin.New()
		r.DELETE("/api/v1/user/avatar", func(c *gin.Context) {
			c.Set("user_id", uint(42))
			ctrl.DeleteAvatar(c)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodDelete, "/api/v1/user/avatar", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, se obtuvo %d", w.Code)
		}
		if mockUserSvc.avatarUpdated != "" {
			t.Errorf("se esperaba avatar vacío tras eliminación, se obtuvo: %s", mockUserSvc.avatarUpdated)
		}
	})
}

func TestOAuthController_DynamicThemeRendering(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmpl := template.Must(template.New("oauth_login.html").Parse("<html>login:client={{.ClientID}}|title={{.CustomTitle}}|logo={{.AppLogo}}|terms={{.TermsURL}}</html>"))

	t.Run("GetPublicLogin with themed app renders custom brand attributes", func(t *testing.T) {
		appSvc := &mockAppService{
			app: model.Application{
				AppID:       "app-prueba",
				Name:        "App prueba",
				RedirectURL: "https://app.local/callback",
				Theme: &model.ApplicationTheme{
					PrimaryColor:   "#059669",
					LogoURL:        "/static/uploads/logos/app-logo.png",
					CustomTitle:    "Portal App prueba",
					CustomSubtitle: "Inicia sesión para gestionar compras",
					TermsURL:       "https://app.local/terms",
				},
			},
		}

		ctrl := &OAuthController{
			AppService: appSvc,
			OAuthService: &mockOAuthServiceForBranding{
				clientID:    "app-prueba",
				redirectURI: "https://app.local/callback",
			},
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.GET("/oauth/login", ctrl.GetPublicLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/login?client_id=app-prueba&redirect_uri=https://app.local/callback", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, se obtuvo %d: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "Portal App prueba") {
			t.Errorf("se esperaba título personalizado en el render: %s", body)
		}
		if !strings.Contains(body, "/static/uploads/logos/app-logo.png") {
			t.Errorf("se esperaba logo personalizado en el render: %s", body)
		}
		if !strings.Contains(body, "https://app.local/terms") {
			t.Errorf("se esperaba terms_url en el render: %s", body)
		}
	})
}
