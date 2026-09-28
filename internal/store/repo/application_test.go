package repo

import (
	"fmt"
	"peak-auth/internal/store/model"
	"testing"
	"time"
)

func TestApplicationRepository_CRUD(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}

	repo := NewApplicationRepository(db)
	uniqueSuffix := time.Now().UnixNano()
	appID := fmt.Sprintf("test-app-%d", uniqueSuffix)
	appName := fmt.Sprintf("Test App %d", uniqueSuffix)

	app := model.Application{
		Name:        appName,
		AppID:       appID,
		SecretKey:   "secret-12345",
		RedirectURL: "http://localhost/callback",
		IsActive:    true,
	}

	// 1. Create
	if err := repo.Create(&app); err != nil {
		t.Fatalf("repo.Create failed: %v", err)
	}

	// 2. FindByID
	foundByID, err := repo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("repo.FindByID failed: %v", err)
	}
	if foundByID.AppID != appID {
		t.Errorf("expected AppID %s, got %s", appID, foundByID.AppID)
	}

	// 3. FindByAppID
	foundByAppID, err := repo.FindByAppID(appID)
	if err != nil {
		t.Fatalf("repo.FindByAppID failed: %v", err)
	}
	if foundByAppID.Name != appName {
		t.Errorf("expected Name %s, got %s", appName, foundByAppID.Name)
	}

	// 4. FindByName
	foundByName, err := repo.FindByName(appName)
	if err != nil {
		t.Fatalf("repo.FindByName failed: %v", err)
	}
	if foundByName.ID != app.ID {
		t.Errorf("expected ID %d, got %d", app.ID, foundByName.ID)
	}

	// 5. UpdateColumns
	newDesc := "Updated Description"
	if err := repo.UpdateColumns(app.ID, map[string]interface{}{"description": newDesc}); err != nil {
		t.Fatalf("repo.UpdateColumns failed: %v", err)
	}
	updated, _ := repo.FindByID(app.ID)
	if updated.Description != newDesc {
		t.Errorf("expected description %s, got %s", newDesc, updated.Description)
	}

	// 6. Delete
	if err := repo.Delete(app.ID); err != nil {
		t.Fatalf("repo.Delete failed: %v", err)
	}
}
