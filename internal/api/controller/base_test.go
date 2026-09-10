package controller

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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
