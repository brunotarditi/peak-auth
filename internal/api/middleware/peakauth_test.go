package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"peak-auth/internal/auth"
	"peak-auth/internal/util"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

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

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := newTestJWTManager(t)

	tests := []struct {
		name           string
		path           string
		setupRequest   func(*http.Request)
		expectedStatus int
		expectRedirect bool
	}{
		{
			name: "API sin token",
			path: "/api/v1/protected",
			setupRequest: func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Admin sin token (Redirección)",
			path: "/admin/dashboard",
			setupRequest: func(req *http.Request) {},
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
				req.Header.Set("Authorization", "Bearer " + token)
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Token válido y MFA completado (Acceso OK)",
			path: "/api/v1/protected",
			setupRequest: func(req *http.Request) {
				token, _ := manager.GenerateToken(1, "user@test.com", util.AppIdPeakAuth, []string{"USER"}, time.Hour, true)
				req.Header.Set("Authorization", "Bearer " + token)
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
