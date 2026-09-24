package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"peak-auth/internal/api/controller"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type mockSessionService struct {
	sessions []response.SessionItem
	apps     []response.AuthorizedAppItem
}

func (m *mockSessionService) ListSessions(userID uint, currentToken string, devCtx ...service.SessionDeviceContext) ([]response.SessionItem, error) {
	return m.sessions, nil
}

func (m *mockSessionService) RevokeSession(userID uint, sessionID uint) error {
	var remaining []response.SessionItem
	for _, s := range m.sessions {
		if s.ID != sessionID {
			remaining = append(remaining, s)
		}
	}
	m.sessions = remaining
	return nil
}

func (m *mockSessionService) RevokeOtherSessions(userID uint, currentToken string, currentSessionID ...uint) error {
	var remaining []response.SessionItem
	for _, s := range m.sessions {
		if s.IsCurrent {
			remaining = append(remaining, s)
		}
	}
	m.sessions = remaining
	return nil
}

func (m *mockSessionService) ListAuthorizedApps(userID uint) ([]response.AuthorizedAppItem, error) {
	return m.apps, nil
}

func (m *mockSessionService) RevokeAuthorizedApp(userID uint, clientID string) error {
	var remaining []response.AuthorizedAppItem
	for _, a := range m.apps {
		if a.ClientID != clientID {
			remaining = append(remaining, a)
		}
	}
	m.apps = remaining
	return nil
}

func setupSessionTestRouter(svc *mockSessionService, userID uint) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Auth simulation middleware
	r.Use(func(c *gin.Context) {
		if userID > 0 {
			c.Set("user_id", userID)
			c.Set("user_email", "user@example.com")
		}
		c.Next()
	})

	ctrl := controller.NewSessionController(svc)
	api := r.Group("/api/v1/user")
	{
		api.GET("/sessions", ctrl.ListSessions)
		api.DELETE("/sessions/:id", ctrl.RevokeSession)
		api.POST("/sessions/revoke-others", ctrl.RevokeOtherSessions)
		api.GET("/applications", ctrl.ListAuthorizedApps)
		api.DELETE("/applications/:client_id", ctrl.RevokeAuthorizedApp)
	}

	return r
}

func TestSessionController_ListSessions(t *testing.T) {
	svc := &mockSessionService{
		sessions: []response.SessionItem{
			{ID: 1, AppName: "App 1", DeviceType: "Desktop", LastUsedAt: time.Now()},
		},
	}
	router := setupSessionTestRouter(svc, 1)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/user/sessions", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body map[string][]response.SessionItem
	err := json.Unmarshal(w.Body.Bytes(), &body)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(body["sessions"]) != 1 {
		t.Fatalf("expected 1 session, got %d", len(body["sessions"]))
	}
	if body["sessions"][0].AppName != "App 1" {
		t.Errorf("expected App 1, got %s", body["sessions"][0].AppName)
	}
}

func TestSessionController_RevokeSession(t *testing.T) {
	svc := &mockSessionService{
		sessions: []response.SessionItem{
			{ID: 1, AppName: "App 1"},
		},
	}
	router := setupSessionTestRouter(svc, 1)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/api/v1/user/sessions/1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if len(svc.sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(svc.sessions))
	}
}

func TestSessionController_RevokeOtherSessions(t *testing.T) {
	svc := &mockSessionService{
		sessions: []response.SessionItem{
			{ID: 1, AppName: "App 1", IsCurrent: true},
			{ID: 2, AppName: "App 2", IsCurrent: false},
		},
	}
	router := setupSessionTestRouter(svc, 1)

	payload := `{"current_refresh_token": "valid-token"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/user/sessions/revoke-others", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if len(svc.sessions) != 1 {
		t.Fatalf("expected 1 session remaining, got %d", len(svc.sessions))
	}
	if svc.sessions[0].ID != 1 {
		t.Errorf("expected remaining session ID 1, got %d", svc.sessions[0].ID)
	}
}

func TestSessionController_AuthorizedApps(t *testing.T) {
	svc := &mockSessionService{
		apps: []response.AuthorizedAppItem{
			{ClientID: "client-1", AppName: "App 1"},
		},
	}
	router := setupSessionTestRouter(svc, 1)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/user/applications", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Revoke
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("DELETE", "/api/v1/user/applications/client-1", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w2.Code)
	}
	if len(svc.apps) != 0 {
		t.Errorf("expected 0 apps, got %d", len(svc.apps))
	}
}
