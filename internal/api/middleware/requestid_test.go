package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestIDMiddleware_GeneratesNewID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		reqID := GetRequestID(c)
		if reqID == "" {
			t.Errorf("GetRequestID retornó cadena vacía")
		}
		c.String(http.StatusOK, "pong")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	respID := w.Header().Get(RequestIDHeader)
	if respID == "" {
		t.Fatalf("no se inyectó la cabecera %s en la respuesta", RequestIDHeader)
	}
	if len(respID) != 32 {
		t.Errorf("longitud esperada de 32 hex chars, obtenido: %d (%s)", len(respID), respID)
	}
}

func TestRequestIDMiddleware_PreservesExistingValidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	customID := "custom-trace-uuid-12345"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set(RequestIDHeader, customID)
	r.ServeHTTP(w, req)

	respID := w.Header().Get(RequestIDHeader)
	if respID != customID {
		t.Errorf("se esperaba preservar ID %s, obtenido: %s", customID, respID)
	}
}

func TestRequestIDMiddleware_ReplacesInvalidIDWithNewline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	invalidID := "malicious\r\ninjection"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set(RequestIDHeader, invalidID)
	r.ServeHTTP(w, req)

	respID := w.Header().Get(RequestIDHeader)
	if respID == invalidID || len(respID) != 32 {
		t.Errorf("se esperaba reemplazo de ID inseguro, obtenido: %s", respID)
	}
}
