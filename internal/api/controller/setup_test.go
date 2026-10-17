package controller_test

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"peak-auth/internal/api/controller"
	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

type mockSetupServiceForController struct {
	firstRun      bool
	requiresToken bool
	validToken    string
	createdUser   model.User
	createErr     error
}

func (m *mockSetupServiceForController) CreateRootUser(email, password, token string) (model.User, error) {
	if m.createErr != nil {
		return model.User{}, m.createErr
	}
	if err := m.ValidateSetupToken(token); err != nil {
		return model.User{}, err
	}
	m.createdUser = model.User{Email: email}
	return m.createdUser, nil
}

func (m *mockSetupServiceForController) ValidateSetupToken(token string) error {
	token = strings.TrimSpace(token)
	if m.validToken != "" && token == m.validToken {
		return nil
	}
	return errors.New("token de instalación inválido")
}

func (m *mockSetupServiceForController) IsFirstRun() (bool, error) {
	return m.firstRun, nil
}

func (m *mockSetupServiceForController) InitializeSystem(port string) {}
func (m *mockSetupServiceForController) CompleteSetup(rootUser model.User) {}
func (m *mockSetupServiceForController) RequiresToken() bool {
	return m.requiresToken
}

func setupTestTemplates(r *gin.Engine) {
	tmpl := template.Must(template.New("setup_auth.html").Parse("<html>setup_auth:{{.ErrorMessage}}</html>"))
	template.Must(tmpl.New("setup.html").Parse("<html>setup_form</html>"))
	template.Must(tmpl.New("login.html").Parse("<html>login_form</html>"))
	template.Must(tmpl.New("error.html").Parse("<html>error:{{.Message}}|back:{{.BackURL}}</html>"))
	r.SetHTMLTemplate(tmpl)
}

func TestSetupController_ShowSetup_FirstRun_NoToken_ShowsAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	setupSvc := &mockSetupServiceForController{
		firstRun:      true,
		requiresToken: true,
		validToken:    "valid-setup-token-123",
	}
	ctrl := &controller.SetupController{SetupService: setupSvc}
	r.GET("/setup", ctrl.ShowSetup)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/setup", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "setup_auth") {
		t.Fatalf("se esperaba plantilla setup_auth.html, obtenido: %s", w.Body.String())
	}
}

func TestSetupController_ShowSetup_InvalidCookie_ClearsCookieAndShowsAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	setupSvc := &mockSetupServiceForController{
		firstRun:      true,
		requiresToken: true,
		validToken:    "new-server-ephemeral-token",
	}
	ctrl := &controller.SetupController{SetupService: setupSvc}
	r.GET("/setup", ctrl.ShowSetup)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/setup", nil)
	// Cookie vieja o expirada de un reinicio anterior
	req.AddCookie(&http.Cookie{Name: "setup_token", Value: "stale-token-from-previous-run"})
	r.ServeHTTP(w, req)

	// No debe devolver 403 bloqueante, sino 200 con setup_auth y la cookie limpiada
	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK con formulario de auth, obtenido: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "setup_auth") {
		t.Fatalf("se esperaba que cargara setup_auth.html para ingresar el token actual, obtenido: %s", w.Body.String())
	}

	// Comprobar que la cookie fue invalidada en la respuesta (MaxAge < 0 o Set-Cookie con expiración pasada)
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "setup_token=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Errorf("se esperaba eliminación de la cookie setup_token en cabeceras de respuesta, obtenido: %s", setCookie)
	}
}

func TestSetupController_ShowSetup_QueryToken_Valid_SetsCookieAndRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	tokenVal := "console-ephemeral-token-99"
	setupSvc := &mockSetupServiceForController{
		firstRun:      true,
		requiresToken: true,
		validToken:    tokenVal,
	}
	ctrl := &controller.SetupController{SetupService: setupSvc}
	r.GET("/setup", ctrl.ShowSetup)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/setup?token="+tokenVal, nil)
	r.ServeHTTP(w, req)

	// Debe redirigir a /setup limpio (303)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 SeeOther para limpiar query param, obtenido: %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/setup" {
		t.Fatalf("se esperaba redirección a /setup, obtenido: %s", loc)
	}

	// Debe haber seteado la cookie con el token válido
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "setup_token="+tokenVal) {
		t.Fatalf("se esperaba cookie setup_token con el token válido, obtenido: %s", setCookie)
	}
}

func TestSetupController_ShowSetup_ValidCookie_ShowsSetupForm(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	tokenVal := "active-valid-token-88"
	setupSvc := &mockSetupServiceForController{
		firstRun:      true,
		requiresToken: true,
		validToken:    tokenVal,
	}
	ctrl := &controller.SetupController{SetupService: setupSvc}
	r.GET("/setup", ctrl.ShowSetup)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/setup", nil)
	req.AddCookie(&http.Cookie{Name: "setup_token", Value: tokenVal})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK, obtenido: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "setup_form") {
		t.Fatalf("se esperaba plantilla setup.html, obtenido: %s", w.Body.String())
	}
}

func TestSetupController_ShowSetup_NotFirstRun_RedirectsToLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	setupSvc := &mockSetupServiceForController{
		firstRun: false,
	}
	ctrl := &controller.SetupController{SetupService: setupSvc}
	r.GET("/setup", ctrl.ShowSetup)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/setup", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 SeeOther, obtenido: %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/admin/login" {
		t.Fatalf("se esperaba redirección a /admin/login, obtenido: %s", loc)
	}
}

func TestLoginController_GetLoginForm_FirstRun_RedirectsToSetup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupTestTemplates(r)

	setupSvc := &mockSetupServiceForController{
		firstRun: true,
	}
	ctrl := &controller.LoginController{SetupService: setupSvc}
	r.GET("/admin/login", ctrl.GetLoginForm)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/admin/login", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 SeeOther hacia /setup en primer arranque, obtenido: %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/setup" {
		t.Fatalf("se esperaba redirección a /setup, obtenido: %s", loc)
	}
}
