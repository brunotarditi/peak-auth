package controller_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"net/url"
	"peak-auth/internal/api/controller"
	"peak-auth/internal/api/request"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"

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

	ctrl := controller.NewSessionController(svc, nil, nil)
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

type mockUserServiceForSession struct {
	updateProfileCalled  bool
	changePasswordCalled bool
	changePasswordErr    error
}

func (m *mockUserServiceForSession) Login(req request.LoginRequest, publicAppID string) (response.TokenResponse, error) { return response.TokenResponse{}, nil }
func (m *mockUserServiceForSession) AdminLogin(email, password string) (string, int, bool, bool, string, error) { return "", 0, false, false, "", nil }
func (m *mockUserServiceForSession) CompleteLoginWithMfa(userID uint, publicAppID string, mfaCompleted bool, clientInfo ...string) (response.TokenResponse, error) { return response.TokenResponse{}, nil }
func (m *mockUserServiceForSession) CompleteAdminLoginWithMfa(userID uint) (string, int, error) { return "", 0, nil }
func (m *mockUserServiceForSession) Register(req request.RegisterRequest) (model.User, error) { return model.User{}, nil }
func (m *mockUserServiceForSession) FindAll() ([]model.User, error) { return nil, nil }
func (m *mockUserServiceForSession) FindVerifiedUser(email string) (*model.User, error) { return nil, nil }
func (m *mockUserServiceForSession) FindVerifiedUserByID(id uint) (*model.User, error) { return nil, nil }
func (m *mockUserServiceForSession) FindUserByAppID(appID string) ([]response.UserAppRow, error) { return nil, nil }
func (m *mockUserServiceForSession) FindUserByAppIDPaginated(appID model.Application, page, limit int) ([]response.UserAppRow, int64, error) { return nil, 0, nil }
func (m *mockUserServiceForSession) GenerateResetToken(userID, appID uint) (string, []byte, error) { return "", nil, nil }
func (m *mockUserServiceForSession) VerifyEmail(token string) (uint, uint, error) { return 0, 0, nil }
func (m *mockUserServiceForSession) SendResetEmail(user *model.User, appID uint) error { return nil }
func (m *mockUserServiceForSession) ResendVerification(userID uint, appID string) error { return nil }
func (m *mockUserServiceForSession) ResetPassword(token, newPassword string) error { return nil }
func (m *mockUserServiceForSession) CanRequestPasswordReset(userID uint) (bool, error) { return true, nil }
func (m *mockUserServiceForSession) Refresh(token string, clientInfo ...string) (response.TokenResponse, error) { return response.TokenResponse{}, nil }
func (m *mockUserServiceForSession) UnlockUser(userID uint) error { return nil }
func (m *mockUserServiceForSession) UpdateAvatar(userID uint, avatarURL string) error { return nil }
func (m *mockUserServiceForSession) UpdateProfile(userID uint, firstName, lastName string, birthDate time.Time, avatarURL string) error {
	m.updateProfileCalled = true
	return nil
}
func (m *mockUserServiceForSession) ChangePassword(userID uint, currentPassword, newPassword string) error {
	m.changePasswordCalled = true
	if m.changePasswordErr != nil {
		return m.changePasswordErr
	}
	return nil
}

func TestSessionController_PostUpdateProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userMock := &mockUserServiceForSession{}
	ctrl := controller.NewSessionController(&mockSessionService{}, userMock, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uint(42))
		c.Next()
	})
	r.POST("/settings/profile", ctrl.PostUpdateProfile)

	form := url.Values{}
	form.Set("first_name", "Jane")
	form.Set("last_name", "Doe")
	form.Set("birth_date", "1990-05-15")
	form.Set("avatar_url", "https://img.test/photo.png")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/settings/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("se esperaba status 200, obtenido: %d, body: %s", w.Code, w.Body.String())
	}
	if !userMock.updateProfileCalled {
		t.Errorf("se esperaba que UpdateProfile fuese llamado")
	}
}

func TestSessionController_PostUpdatePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userMock := &mockUserServiceForSession{}
	ctrl := controller.NewSessionController(&mockSessionService{}, userMock, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uint(42))
		c.Next()
	})
	r.POST("/settings/password", ctrl.PostUpdatePassword)

	// Caso 1: mismatch
	formMismatch := url.Values{}
	formMismatch.Set("current_password", "oldpass")
	formMismatch.Set("new_password", "newpass123")
	formMismatch.Set("confirm_password", "different123")

	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(formMismatch.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba status 400 por mismatch, obtenido: %d", w1.Code)
	}

	// Caso 2: success
	formSuccess := url.Values{}
	formSuccess.Set("current_password", "oldpass")
	formSuccess.Set("new_password", "NewPass!456")
	formSuccess.Set("confirm_password", "NewPass!456")

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(formSuccess.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("se esperaba status 200, obtenido: %d, body: %s", w2.Code, w2.Body.String())
	}
	if !userMock.changePasswordCalled {
		t.Errorf("se esperaba que ChangePassword fuese llamado")
	}

	// Caso 3: sanitización de error interno
	userMock.changePasswordErr = errors.New("gorm: fatal postgres connection error")
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(formSuccess.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba status 400 por error interno, obtenido: %d", w3.Code)
	}
	if strings.Contains(w3.Body.String(), "postgres") {
		t.Errorf("error interno de BD no sanitizado: %s", w3.Body.String())
	}
	if !strings.Contains(w3.Body.String(), "Error al actualizar la contraseña") {
		t.Errorf("se esperaba mensaje sanitizado de error, obtenido: %s", w3.Body.String())
	}
}

