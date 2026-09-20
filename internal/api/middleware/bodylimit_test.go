package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestBodyLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("permits body within limit", func(t *testing.T) {
		router := gin.New()
		router.Use(RequestBodyLimitMiddleware(1024))
		router.POST("/test", func(c *gin.Context) {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.String(http.StatusBadRequest, "read error: %v", err)
				return
			}
			c.String(http.StatusOK, string(body))
		})

		payload := strings.Repeat("a", 512)
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(payload))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		if w.Body.String() != payload {
			t.Fatalf("expected payload body match")
		}
	})

	t.Run("rejects body exceeding limit", func(t *testing.T) {
		router := gin.New()
		router.Use(RequestBodyLimitMiddleware(100))
		router.POST("/test", func(c *gin.Context) {
			_, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.String(http.StatusRequestEntityTooLarge, "body too large: %v", err)
				return
			}
			c.String(http.StatusOK, "ok")
		})

		payload := strings.Repeat("x", 200)
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(payload))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status 413, got %d", w.Code)
		}
	})
}
