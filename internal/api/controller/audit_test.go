package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"peak-auth/internal/api/controller"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"

	"github.com/gin-gonic/gin"
)

type mockAuditAppService struct {
	app model.Application
	err error
}

func (m *mockAuditAppService) CreateApp(name, description, redirectURL string, isActive bool) (model.Application, string, error) {
	return m.app, "", m.err
}
func (m *mockAuditAppService) UpdateApp(appID string, description, redirectURL string, isActive bool) error {
	return m.err
}
func (m *mockAuditAppService) ValidateAppNameUnique(name string) error                        { return nil }
func (m *mockAuditAppService) RegenerateSecret(appID string) (string, error)                 { return "", nil }
func (m *mockAuditAppService) RegisterUserInApp(userEmail, roleName string, app *model.Application) error {
	return nil
}
func (m *mockAuditAppService) RevokeUserFromApp(userID, appID uint) error { return nil }
func (m *mockAuditAppService) IsRootUser(userID, appID uint) bool         { return false }
func (m *mockAuditAppService) UserBelongsToApp(userID, appID uint) (bool, error) {
	return true, nil
}
func (m *mockAuditAppService) GetAppDetails(appID string) (model.Application, error) {
	if m.err != nil {
		return model.Application{}, m.err
	}
	return m.app, nil
}
func (m *mockAuditAppService) DeleteApp(appID string) error                                              { return nil }
func (m *mockAuditAppService) GetDashboardStats() ([]response.AppStatsResponse, error)                  { return nil, nil }
func (m *mockAuditAppService) GetDashboardStatsForUser(userID uint) ([]response.AppStatsResponse, error) {
	return nil, nil
}

type mockAuditServiceForCtrl struct {
	pageRes *response.AuditLogPageResponse
	detail  *service.AuditDetailResult
	err     error
}

func (m *mockAuditServiceForCtrl) GetAppAuditLogs(appID uint, filter repo.AuditFilter) (*response.AuditLogPageResponse, error) {
	return m.pageRes, m.err
}

func (m *mockAuditServiceForCtrl) GetAuditLogDetail(id int64, appID uint) (*service.AuditDetailResult, error) {
	return m.detail, m.err
}

func (m *mockAuditServiceForCtrl) GetAuditFilterOptions(appID uint) ([]string, []string, error) {
	return []string{"applications"}, []string{"UPDATE"}, nil
}

func TestAuditController_GetAppAuditDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	app := model.Application{
		AppID: "test-app",
		Name:  "Test App",
	}
	app.ID = 10
	appSvc := &mockAuditAppService{app: app}

	auditSvc := &mockAuditServiceForCtrl{
		detail: &service.AuditDetailResult{
			Log: &model.AuditLog{
				ID:        42,
				TableName: "applications",
				RecordID:  "10",
				Action:    "UPDATE",
				ChangedBy: "admin@example.com",
				OldData:   `{"name": "Old Name"}`,
				NewData:   `{"name": "Test App"}`,
				CreatedAt: time.Now(),
			},
			TableLabel: "Configuración de App",
			Entities:   map[string]string{"app_10": "Test App"},
		},
	}

	ctrl := controller.NewAuditController(auditSvc, appSvc)

	r := gin.New()
	r.GET("/admin/apps/:id/audit/:log_id", ctrl.GetAppAuditDetail)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/apps/test-app/audit/42", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if res["action"] != "UPDATE" {
		t.Errorf("expected action UPDATE, got %v", res["action"])
	}
	if res["changed_by"] != "admin@example.com" {
		t.Errorf("expected changed_by admin@example.com, got %v", res["changed_by"])
	}
}

func TestAuditController_GetAppAuditDetail_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := controller.NewAuditController(&mockAuditServiceForCtrl{}, &mockAuditAppService{})

	r := gin.New()
	r.GET("/admin/apps/:id/audit/:log_id", ctrl.GetAppAuditDetail)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin/apps/test-app/audit/abc", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for non-numeric log ID, got %d", w.Code)
	}
}
