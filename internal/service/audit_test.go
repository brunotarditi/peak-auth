package service_test

import (
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"testing"
	"time"

	"gorm.io/gorm"
)

type mockAuditRepo struct {
	logs    []model.AuditLog
	actions []string
	tables  []string
}

func (m *mockAuditRepo) FindAppAuditLogs(appID uint, filter repo.AuditFilter) ([]model.AuditLog, int64, error) {
	var filtered []model.AuditLog
	for _, l := range m.logs {
		if filter.TableName != "" && l.TableName != filter.TableName {
			continue
		}
		if filter.Action != "" && l.Action != filter.Action {
			continue
		}
		filtered = append(filtered, l)
	}

	total := int64(len(filtered))
	limit := filter.Limit
	if limit <= 0 {
		limit = 10
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit
	if offset >= len(filtered) {
		return []model.AuditLog{}, total, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
}

func (m *mockAuditRepo) FindByID(id int64) (*model.AuditLog, error) {
	for _, l := range m.logs {
		if l.ID == id {
			return &l, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (m *mockAuditRepo) GetDistinctActionsByApp(appID uint) ([]string, error) {
	return m.actions, nil
}

func (m *mockAuditRepo) GetDistinctTablesByApp(appID uint) ([]string, error) {
	return m.tables, nil
}

func TestAuditService_GetAppAuditLogs(t *testing.T) {
	mockRepo := &mockAuditRepo{
		logs: []model.AuditLog{
			{
				ID:        1,
				TableName: "applications",
				RecordID:  "5",
				Action:    "UPDATE",
				ChangedBy: "admin@test.com",
				CreatedAt: time.Now(),
			},
			{
				ID:        2,
				TableName: "application_rules",
				RecordID:  "12",
				Action:    "INSERT",
				ChangedBy: "admin@test.com",
				CreatedAt: time.Now(),
			},
		},
		actions: []string{"INSERT", "UPDATE"},
		tables:  []string{"applications", "application_rules"},
	}

	svc := service.NewAuditService(mockRepo, nil, nil, nil)

	res, err := svc.GetAppAuditLogs(5, repo.AuditFilter{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Total != 2 {
		t.Errorf("expected total 2, got %d", res.Total)
	}
	if len(res.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(res.Items))
	}
	if res.Items[0].TableLabel != "Configuración de App" {
		t.Errorf("expected Configuración de App, got %s", res.Items[0].TableLabel)
	}
	if res.Items[1].TableLabel != "Regla de Acceso" {
		t.Errorf("expected Regla de Acceso, got %s", res.Items[1].TableLabel)
	}
}

func TestAuditService_GetAuditLogDetail(t *testing.T) {
	mockRepo := &mockAuditRepo{
		logs: []model.AuditLog{
			{
				ID:        100,
				TableName: "applications",
				RecordID:  "5",
				Action:    "UPDATE",
				NewData:   `{"name": "App 5", "application_id": 5}`,
			},
			{
				ID:        200,
				TableName: "application_rules",
				RecordID:  "15",
				Action:    "INSERT",
				NewData:   `{"rule": "MFA", "application_id": 99}`,
			},
		},
	}

	svc := service.NewAuditService(mockRepo, nil, nil, nil)

	// Log belonging to app 5 should succeed
	detail, err := svc.GetAuditLogDetail(100, 5)
	if err != nil {
		t.Fatalf("unexpected error for matching app: %v", err)
	}
	if detail.Log.ID != 100 {
		t.Errorf("expected ID 100, got %d", detail.Log.ID)
	}

	// Log belonging to app 99 requested by app 5 should fail (anti-IDOR)
	_, err = svc.GetAuditLogDetail(200, 5)
	if err == nil {
		t.Fatalf("expected error for non-belonging app, got nil")
	}
}

func TestAuditService_GetAuditFilterOptions(t *testing.T) {
	mockRepo := &mockAuditRepo{
		actions: []string{"INSERT", "UPDATE", "DELETE"},
		tables:  []string{"applications", "application_rules"},
	}

	svc := service.NewAuditService(mockRepo, nil, nil, nil)

	tables, actions, err := svc.GetAuditFilterOptions(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tables) != 2 {
		t.Errorf("expected 2 tables, got %d", len(tables))
	}
	if len(actions) != 3 {
		t.Errorf("expected 3 actions, got %d", len(actions))
	}
}
