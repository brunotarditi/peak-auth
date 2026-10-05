package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"peak-auth/internal/auth"
	"peak-auth/internal/auth/broker"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type mockBrokerServiceForController struct {
	authURLFn     func(provider string, relay broker.RelayState) (string, error)
	processFn     func(ctx context.Context, provider string, code string, rawState string, expectedNonce ...string) (*service.BrokerAuthResult, error)
	isConfigured  bool
	providersList []string
}

func (m *mockBrokerServiceForController) GetAuthURL(provider string, relay broker.RelayState) (string, error) {
	if m.authURLFn != nil {
		return m.authURLFn(provider, relay)
	}
	return "https://accounts.google.com/auth?state=dummy", nil
}

func (m *mockBrokerServiceForController) ProcessCallback(ctx context.Context, provider string, code string, rawState string, expectedNonce ...string) (*service.BrokerAuthResult, error) {
	if m.processFn != nil {
		return m.processFn(ctx, provider, code, rawState, expectedNonce...)
	}
	return &service.BrokerAuthResult{
		User: &model.User{
			Model:      gorm.Model{ID: 10},
			Email:      "federated@peak.test",
			IsActive:   true,
			IsVerified: true,
		},
		Relay: &broker.RelayState{
			ClientID:    "test-app",
			RedirectURI: "https://test-app.com/callback",
			State:       "st-123",
		},
		RedirectURL: "/oauth/authorize?client_id=test-app&redirect_uri=https://test-app.com/callback&response_type=code&state=st-123",
	}, nil
}

func (m *mockBrokerServiceForController) IsProviderConfigured(provider string) bool {
	return m.isConfigured
}

func (m *mockBrokerServiceForController) ListConfiguredProviders() []string {
	return m.providersList
}

func newTestJWTManager(t *testing.T) *auth.JWTManager {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	t.Setenv("JWT_PRIVATE_KEY", string(pemBytes))
	t.Setenv("JWT_ISSUER", "peak-auth")

	tm, err := auth.NewJWTManager()
	if err != nil {
		t.Fatalf("error creating JWTManager: %v", err)
	}
	return tm
}

func TestBrokerController_AuthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBroker := &mockBrokerServiceForController{}
	ctrl := NewBrokerController(mockBroker, nil, nil, nil)

	r := gin.New()
	r.GET("/oauth/broker/:provider/auth", ctrl.AuthEndpoint)

	t.Run("Missing client_id or redirect_uri returns 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/auth", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Valid parameters redirects to provider auth URL", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/auth?client_id=test-app&redirect_uri=https://app.com/cb&state=xyz", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", w.Code)
		}
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://accounts.google.com/auth") {
			t.Errorf("expected Location to provider URL, got %s", loc)
		}
	})

	t.Run("Service error redirects to login with error param", func(t *testing.T) {
		mockBroker.authURLFn = func(provider string, relay broker.RelayState) (string, error) {
			return "", errors.New("app desactivada")
		}
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/auth?client_id=test-app&redirect_uri=https://app.com/cb", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 See Other, got %d", w.Code)
		}
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "/oauth/login?") || !strings.Contains(loc, "error=") {
			t.Errorf("expected redirect to login with error, got %s", loc)
		}
	})
}

func TestBrokerController_CallbackEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tm := newTestJWTManager(t)

	mockBroker := &mockBrokerServiceForController{}
	ctrl := NewBrokerController(mockBroker, tm, nil, nil)

	r := gin.New()
	r.GET("/oauth/broker/:provider/callback", ctrl.CallbackEndpoint)

	t.Run("Provider error redirects to login", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/callback?error=access_denied", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303, got %d", w.Code)
		}
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "/oauth/login?error=") {
			t.Errorf("expected error redirect to login, got %s", loc)
		}
	})

	t.Run("Missing code redirects to login", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/callback?state=xyz", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303, got %d", w.Code)
		}
	})

	t.Run("Missing broker_nonce cookie triggers Login CSRF block", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/callback?code=valid-code&state=valid-state", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 See Other, got %d", w.Code)
		}
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "Login+CSRF+prevenido") && !strings.Contains(loc, "Login%20CSRF%20prevenido") {
			t.Errorf("expected Login CSRF error in redirect, got %s", loc)
		}
	})

	t.Run("Successful callback sets SSO cookie and redirects to authorize", func(t *testing.T) {
		mockBroker.processFn = func(ctx context.Context, provider, code, rawState string, expectedNonce ...string) (*service.BrokerAuthResult, error) {
			return &service.BrokerAuthResult{
				User: &model.User{
					Model:        gorm.Model{ID: 5},
					Email:        "social@peak.test",
					IsActive:     true,
					IsVerified:   true,
					AuthzVersion: 1,
				},
				RedirectURL: "/oauth/authorize?client_id=test-app&redirect_uri=https://app.com/cb&response_type=code&state=123",
			}, nil
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/callback?code=valid-code&state=valid-state", nil)
		req.AddCookie(&http.Cookie{Name: "broker_nonce", Value: "valid-nonce"})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 See Other, got %d", w.Code)
		}

		loc := w.Header().Get("Location")
		if loc != "/oauth/authorize?client_id=test-app&redirect_uri=https://app.com/cb&response_type=code&state=123" {
			t.Errorf("expected redirect to authorize URL, got %s", loc)
		}

		// Verify peak_session cookie is set
		cookies := w.Result().Cookies()
		foundSession := false
		for _, cookie := range cookies {
			if cookie.Name == "peak_session" {
				foundSession = true
				if cookie.Value == "" {
					t.Error("expected non-empty peak_session cookie value")
				}
				if !cookie.HttpOnly {
					t.Error("expected peak_session cookie to be HttpOnly")
				}
			}
		}
		if !foundSession {
			t.Error("expected peak_session cookie to be set")
		}
	})

	t.Run("MFA required callback sets mfa_pending cookie and redirects to MFA challenge", func(t *testing.T) {
		mockBroker.processFn = func(ctx context.Context, provider, code, rawState string, expectedNonce ...string) (*service.BrokerAuthResult, error) {
			return &service.BrokerAuthResult{
				User: &model.User{
					Model:    gorm.Model{ID: 5},
					Email:    "mfauser@peak.test",
					IsActive: true,
				},
				MfaRequired: true,
				MfaToken:    "mfa-jwt-pending-token",
				RedirectURL: "/oauth/login/mfa?client_id=test-app&redirect_uri=https://app.com/cb",
			}, nil
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/oauth/broker/google/callback?code=valid-code&state=valid-state", nil)
		req.AddCookie(&http.Cookie{Name: "broker_nonce", Value: "valid-nonce"})
		r.ServeHTTP(w, req)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 See Other, got %d", w.Code)
		}

		loc := w.Header().Get("Location")
		if loc != "/oauth/login/mfa?client_id=test-app&redirect_uri=https://app.com/cb" {
			t.Errorf("expected redirect to MFA challenge URL, got %s", loc)
		}

		cookies := w.Result().Cookies()
		foundMfa := false
		for _, cookie := range cookies {
			if cookie.Name == "mfa_pending" && cookie.Value == "mfa-jwt-pending-token" {
				foundMfa = true
			}
		}
		if !foundMfa {
			t.Error("expected mfa_pending cookie to be set")
		}
	})
}
