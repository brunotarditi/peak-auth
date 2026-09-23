package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type mockHealthService struct {
	alive    bool
	dbOk     bool
	tmOk     bool
}

func (m *mockHealthService) CheckHealth() bool {
	return m.alive
}

func (m *mockHealthService) CheckReadiness(ctx context.Context) (bool, bool) {
	return m.dbOk, m.tmOk
}

func TestHealthController_Health(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := &HealthController{
		HealthService: &mockHealthService{alive: true},
	}

	r := gin.New()
	r.GET("/health", ctrl.Health)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK en /health, obtenido: %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error parseando JSON de /health: %v", err)
	}

	if body["status"] != "pass" {
		t.Errorf("se esperaba status pass, obtenido: %v", body["status"])
	}
	if body["timestamp"] == nil {
		t.Errorf("se esperaba campo timestamp")
	}
}

func TestHealthController_Ready_AllHealthy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := &HealthController{
		HealthService: &mockHealthService{alive: true, dbOk: true, tmOk: true},
	}

	r := gin.New()
	r.GET("/ready", ctrl.Ready)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 OK en /ready cuando todo está saludable, obtenido: %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error parseando JSON de /ready: %v", err)
	}

	if body["status"] != "pass" {
		t.Errorf("se esperaba status pass, obtenido: %v", body["status"])
	}
	checks, ok := body["checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("se esperaba objeto checks en la respuesta")
	}
	if checks["database"] != "up" {
		t.Errorf("se esperaba database up, obtenido: %v", checks["database"])
	}
	if checks["token_manager"] != "up" {
		t.Errorf("se esperaba token_manager up, obtenido: %v", checks["token_manager"])
	}
}

func TestHealthController_Ready_NilOrUnhealthyService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := &HealthController{
		HealthService: &mockHealthService{alive: true, dbOk: false, tmOk: true},
	}

	r := gin.New()
	r.GET("/ready", ctrl.Ready)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("se esperaba 503 en /ready con DB caída, obtenido: %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error parseando JSON de /ready: %v", err)
	}

	if body["status"] != "fail" {
		t.Errorf("se esperaba status fail, obtenido: %v", body["status"])
	}
	checks, ok := body["checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("se esperaba objeto checks en la respuesta")
	}
	if checks["database"] != "down" {
		t.Errorf("se esperaba database down, obtenido: %v", checks["database"])
	}
	if checks["token_manager"] != "up" {
		t.Errorf("se esperaba token_manager up, obtenido: %v", checks["token_manager"])
	}
}
