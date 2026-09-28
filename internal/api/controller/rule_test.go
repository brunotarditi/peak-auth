package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"peak-auth/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

func TestRuleController_RequestBodyLimit(t *testing.T) {
	appSvc := &mockAppAdminService{}
	ruleSvc := &mockRuleAdminService{}
	ctrl := &RuleController{
		AppService:  appSvc,
		RuleService: ruleSvc,
	}

	r := gin.New()
	r.POST("/apps/:id/rules/:code", middleware.RequestBodyLimitMiddleware(64*1024), ctrl.PostAppRule)
	r.PUT("/apps/:id/rules/:code", middleware.RequestBodyLimitMiddleware(64*1024), ctrl.PutAppRule)

	t.Run("POST /rules accepts body within 64KB", func(t *testing.T) {
		validBody := `{"token_expiration_minutes": 60, "max_failed_logins": 5}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("se esperaba 200 OK, obtenido %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("POST /rules rejects body exceeding 64KB with 413", func(t *testing.T) {
		oversized := `{"data":"` + strings.Repeat("a", 65*1024) + `"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("se esperaba 413 Request Entity Too Large, obtenido %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "excede el límite permitido") {
			t.Errorf("mensaje de error inesperado: %s", w.Body.String())
		}
	})

	t.Run("PUT /rules rejects body exceeding 64KB with 413", func(t *testing.T) {
		oversized := `{"data":"` + strings.Repeat("b", 65*1024) + `"}`
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPut, "/apps/app-1/rules/SESSION_POLICY", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("se esperaba 413 Request Entity Too Large, obtenido %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "excede el límite permitido") {
			t.Errorf("mensaje de error inesperado: %s", w.Body.String())
		}
	})
}
