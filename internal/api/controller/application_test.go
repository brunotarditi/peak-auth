package controller

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

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

	t.Run("Loopback HTTP redirect_url is allowed", func(t *testing.T) {
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
		form.Set("name", "Local Dev App")
		form.Set("redirect_url", "http://127.0.0.1:3000/callback")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("esperaba 200 OK para loopback, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "app_created:Local Dev App") {
			t.Errorf("esperaba renderizado de app_created, obtuvo: %s", w.Body.String())
		}
	})

	t.Run("Valid HTTPS redirect_url creates app", func(t *testing.T) {
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
		form.Set("redirect_url", "https://app.example.com/oauth/callback")

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

func TestPostTransferOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmpl := template.Must(template.New("error.html").Parse("<html>error:{{.error}}</html>"))

	t.Run("Successful transfer by ID redirects with 303", func(t *testing.T) {
		transferred := false
		appSvc := &mockAppAdminService{
			transferFn: func(appID string, currentUserID, newOwnerID uint) error {
				if appID == "my-app" && currentUserID == 1 && newOwnerID == 2 {
					transferred = true
					return nil
				}
				return nil
			},
		}

		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps/:id/transfer-ownership", func(c *gin.Context) {
			c.Set("user_id", uint(1))
			ctrl.PostTransferOwnership(c)
		})

		form := url.Values{}
		form.Set("new_owner_id", "2")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/my-app/transfer-ownership", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("esperaba 303 See Other, obtuvo %d", w.Code)
		}
		if !transferred {
			t.Errorf("esperaba que transferFn fuera ejecutada")
		}
		if loc := w.Header().Get("Location"); loc != "/admin/apps/my-app" {
			t.Errorf("esperaba redirección a /admin/apps/my-app, obtuvo %s", loc)
		}
	})

	t.Run("Missing new owner parameter returns 400", func(t *testing.T) {
		appSvc := &mockAppAdminService{}
		ctrl := &ApplicationController{
			AppService: appSvc,
		}

		r := gin.New()
		r.SetHTMLTemplate(tmpl)
		r.POST("/admin/apps/:id/transfer-ownership", func(c *gin.Context) {
			c.Set("user_id", uint(1))
			ctrl.PostTransferOwnership(c)
		})

		form := url.Values{} // vacío

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/apps/my-app/transfer-ownership", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("esperaba 400 Bad Request, obtuvo %d", w.Code)
		}
	})
}

