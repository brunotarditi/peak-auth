package controller

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

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

func TestSanitizeForLogging(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "user@example.com"},
		{"user@example.com\r\n[audit] fake entry", "user@example.com[audit] fake entry"},
		{"null\x00byte\x1bescape", "nullbyteescape"},
		{"clean_string_123", "clean_string_123"},
	}

	for _, tt := range tests {
		got := sanitizeForLogging(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeForLogging(%q) = %q, want %q", tt.input, got, tt.expected)
		}
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

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer jwt_in_header")
	r.ServeHTTP(w, req)

	if extracted != "jwt_in_header" {
		t.Fatalf("Esperaba 'jwt_in_header', obtuvo: %q", extracted)
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

func TestMfaChallengeKey(t *testing.T) {
	// 1. Con JTI presente, usa JTI
	key := mfaChallengeKey("oauth_mfa", 1, "jti-123", "1")
	if key != "oauth_mfa_1_jti-123" {
		t.Errorf("mfaChallengeKey con JTI inesperado: %s", key)
	}

	// 2. Sin JTI, fallback a Subject
	fallbackKey := mfaChallengeKey("oauth_mfa", 1, "", "1")
	if fallbackKey != "oauth_mfa_1_1" {
		t.Errorf("mfaChallengeKey fallback inesperado: %s", fallbackKey)
	}

	// 3. Dos tokens distintos producen claves distintas para el mismo usuario
	keyA := mfaChallengeKey("oauth_mfa", 1, "tok-aaa", "1")
	keyB := mfaChallengeKey("oauth_mfa", 1, "tok-bbb", "1")
	if keyA == keyB {
		t.Errorf("claves deben ser distintas: %s == %s", keyA, keyB)
	}
}
