package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

func TestPostSendResetPassword_RateLimitingAndAtomicity(t *testing.T) {
	t.Run("Success sends email and returns 200", func(t *testing.T) {
		userSvc := &mockUserDashboardService{}
		appSvc := &mockAppDashboardService{}
		ctrl := &DashboardController{
			UserService: userSvc,
			AppService:  appSvc,
		}

		r := gin.New()
		r.POST("/apps/:id/users/:user_id/send-reset", ctrl.PostSendResetPassword)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/users/42/send-reset", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("esperaba 200 OK, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Email de recuperación enviado correctamente") {
			t.Errorf("respuesta inesperada: %s", w.Body.String())
		}
	})

	t.Run("Rate limit error from SendResetEmail returns 429 Too Many Requests", func(t *testing.T) {
		userSvc := &mockUserDashboardService{
			sendResetEmailFn: func(user *model.User, appID uint) error {
				return fmt.Errorf("debe esperar al menos 15 minutos entre solicitudes de reset")
			},
		}
		appSvc := &mockAppDashboardService{}
		ctrl := &DashboardController{
			UserService: userSvc,
			AppService:  appSvc,
		}

		r := gin.New()
		r.POST("/apps/:id/users/:user_id/send-reset", ctrl.PostSendResetPassword)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/apps/app-1/users/42/send-reset", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("esperaba 429 Too Many Requests, obtuvo %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "debe esperar al menos 15 minutos") {
			t.Errorf("respuesta inesperada: %s", w.Body.String())
		}
	})
}
