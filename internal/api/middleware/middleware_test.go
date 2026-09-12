package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"peak-auth/internal/auth"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestJWTManager construye un JWTManager con una clave RSA efímera para tests.
func newTestJWTManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave RSA: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	m, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("NewJWTManager falló: %v", err)
	}
	return m
}

func csrfRouter() *gin.Engine {
	r := gin.New()
	r.Use(AdminCSRFMiddleware())
	r.GET("/form", func(c *gin.Context) { c.String(200, "ok") })
	r.POST("/do", func(c *gin.Context) { c.String(200, "done") })
	return r
}

func TestCSRF_GetIssuesCookie(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/form", nil)
	csrfRouter().ServeHTTP(w, req)
	if !strings.Contains(w.Header().Get("Set-Cookie"), "csrf_token=") {
		t.Fatalf("se esperaba cookie csrf_token, headers: %v", w.Header())
	}
}

func TestCSRF_PostNoOriginRejected(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403, se obtuvo %d", w.Code)
	}
}

func TestCSRF_PostValidPasses(t *testing.T) {
	token := "tok123ABC"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestCSRF_PostMismatchRejected(t *testing.T) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "good"})
	req.Header.Set("X-CSRF-Token", "evil")
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403, se obtuvo %d", w.Code)
	}
}

func TestCSRF_PostCrossOriginRejected(t *testing.T) {
	token := "abc"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/do", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	csrfRouter().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 por origen cruzado, se obtuvo %d", w.Code)
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.allowed.com")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("no se esperaba ACAO para origen no permitido, se obtuvo %q", got)
	}
}

func TestCORS_AllowedOriginWithCredentials(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://app.allowed.com")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://app.allowed.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.allowed.com" {
		t.Fatalf("ACAO incorrecto: %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("se esperaba credenciales true, got %q", got)
	}
}

func TestCORS_WildcardNoCredentials(t *testing.T) {
	t.Setenv("FRONTEND_URL", "")
	r := gin.New()
	r.Use(CORSMiddleware())
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/x", nil)
	req.Header.Set("Origin", "https://anything.com")
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("se esperaba '*', got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Fatal("'*' no debe combinarse con Allow-Credentials: true")
	}
}

func TestRateLimit_BlocksAfterLimit(t *testing.T) {
	r := gin.New()
	r.Use(RateLimitMiddleware(3, time.Minute))
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })

	doReq := func() int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/x", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 0; i < 3; i++ {
		if code := doReq(); code != http.StatusOK {
			t.Fatalf("petición %d debería pasar, got %d", i+1, code)
		}
	}
	if code := doReq(); code != http.StatusTooManyRequests {
		t.Fatalf("la 4ª petición debería ser 429, got %d", code)
	}
}

func TestAuthMiddleware(t *testing.T) {
	manager := newTestJWTManager(t)

	tests := []struct {
		name           string
		path           string
		setupRequest   func(*http.Request)
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "API sin token",
			path:           "/api/v1/protected",
			setupRequest:   func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Admin sin token (Redirección)",
			path:           "/admin/dashboard",
			setupRequest:   func(req *http.Request) {},
			expectedStatus: http.StatusSeeOther,
			expectRedirect: true,
		},
		{
			name: "Token inválido",
			path: "/api/v1/protected",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token_basura")
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Token válido pero MFA pendiente",
			path: "/api/v1/protected",
			setupRequest: func(req *http.Request) {
				token, _ := manager.GenerateMFAPendingToken(1, "user@test.com", util.AppIdPeakAuth)
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Token válido y MFA completado (Acceso OK)",
			path: "/api/v1/protected",
			setupRequest: func(req *http.Request) {
				token, _ := manager.GenerateToken(1, "user@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Admin con token válido (Acceso OK)",
			path: "/admin/dashboard",
			setupRequest: func(req *http.Request) {
				token, _ := manager.GenerateToken(1, "admin@test.com", util.AppIdPeakAuth, []string{"ADMIN"}, time.Hour, true)
				req.AddCookie(&http.Cookie{Name: "admin_token", Value: token})
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, engine := gin.CreateTestContext(w)

			// Configuramos la ruta con el middleware
			engine.Use(AuthMiddleware(manager))
			engine.GET(tt.path, func(ctx *gin.Context) {
				ctx.Status(http.StatusOK) // Si llega aquí, es que el middleware lo dejó pasar
			})

			req, _ := http.NewRequest(http.MethodGet, tt.path, nil)
			tt.setupRequest(req)

			engine.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Se esperaba status %d, pero se obtuvo %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				if loc := w.Header().Get("Location"); loc != "/admin/login" {
					t.Errorf("Se esperaba redirección a /admin/login, pero fue a %s", loc)
				}
			}
		})
	}
}

type mockUserRepo struct {
	user model.User
	err  error
}

func (m *mockUserRepo) FindAll() ([]model.User, error)                                   { return nil, nil }
func (m *mockUserRepo) CreateWithProfile(user *model.User, profile *model.Profile) error { return nil }
func (m *mockUserRepo) VerifyUserEmail(userID uint, verificationID uint) error          { return nil }
func (m *mockUserRepo) FindByEmail(email string) (model.User, error)                     { return m.user, m.err }
func (m *mockUserRepo) FindById(ID uint) (model.User, error)                             { return m.user, m.err }
func (m *mockUserRepo) UpdateColumn(column string, value interface{}, id uint) error    { return nil }

func TestAuthMiddleware_PasswordResetRevocation(t *testing.T) {
	manager := newTestJWTManager(t)

	// Token emitido en T0
	tokenT0, err := manager.GenerateToken(42, "user@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)
	if err != nil {
		t.Fatalf("error generando token: %v", err)
	}

	// Simulamos que el password se reseteó después de emitir el token (T0 + 10s)
	resetTime := time.Now().Add(10 * time.Second)
	repo := &mockUserRepo{
		user: model.User{
			Email:             "user@test.com",
			IsActive:          true,
			IsVerified:        true,
			PasswordChangedAt: &resetTime,
		},
	}

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(AuthMiddleware(manager, repo))
	engine.GET("/api/v1/protected", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenT0)
	engine.ServeHTTP(w, req)

	// Debe ser rechazado porque el token fue emitido antes del cambio de contraseña
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Esperaba 401 Unauthorized por token emitido previo al cambio de contraseña, obtuvo %d", w.Code)
	}
}

func TestAuthMiddleware_InactiveUserRejected(t *testing.T) {
	manager := newTestJWTManager(t)

	token, _ := manager.GenerateToken(42, "user@test.com", util.AppIdPeakAuth, []string{"ADMIN"}, time.Hour, true)

	repo := &mockUserRepo{
		user: model.User{
			Email:      "user@test.com",
			IsActive:   false, // Usuario desactivado
			IsVerified: true,
		},
	}

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(AuthMiddleware(manager, repo))
	engine.GET("/admin/dashboard", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: token})
	engine.ServeHTTP(w, req)

	// El admin desactivado debe ser redirigido/rechazado
	if w.Code != http.StatusSeeOther {
		t.Fatalf("Esperaba redirección a login (303) para admin desactivado, obtuvo %d", w.Code)
	}
}

func TestAdminGuestMiddleware(t *testing.T) {
	manager := newTestJWTManager(t)

	r := gin.New()
	r.Use(AdminGuestMiddleware(manager))
	r.GET("/admin/login", func(c *gin.Context) {
		c.String(http.StatusOK, "login-page")
	})

	t.Run("Usuario anónimo puede acceder a /admin/login", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/login", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK para anónimo, obtenido: %d", w.Code)
		}
	})

	t.Run("Usuario con admin_token válido y MFA verificado es redirigido a /admin", func(t *testing.T) {
		token, _ := manager.GenerateToken(1, "admin@peak.local", util.AppIdPeakAuth, []string{"ADMIN"}, time.Hour, true)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/login", nil)
		req.AddCookie(&http.Cookie{Name: "admin_token", Value: token})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("se esperaba 303 See Other para admin logueado, obtenido: %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/admin" {
			t.Fatalf("se esperaba redirección a /admin, obtenido: %s", loc)
		}
	})

	t.Run("Usuario con token MFA pendiente no es redirigido", func(t *testing.T) {
		token, _ := manager.GenerateMFAPendingToken(1, "admin@peak.local", util.AppIdPeakAuth)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/admin/login", nil)
		req.AddCookie(&http.Cookie{Name: "admin_token", Value: token})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK para token con MFA pendiente, obtenido: %d", w.Code)
		}
	})
}
