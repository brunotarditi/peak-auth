package repo

import (
	"fmt"
	"peak-auth/internal/store/model"
	"testing"
	"time"
)

func TestRoleRepository_CRUD(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}

	repo := NewRoleRepositoryRepository(db)
	uniqueSuffix := time.Now().UnixNano()
	roleName := fmt.Sprintf("TEST_ROLE_%d", uniqueSuffix)

	role := model.Role{
		Name:          roleName,
		ApplicationID: nil,
		IsDefault:     false,
	}

	// 1. Create
	if err := repo.Create(&role); err != nil {
		t.Fatalf("repo.Create failed: %v", err)
	}

	// 2. FindGlobalByName
	found, err := repo.FindGlobalByName(roleName)
	if err != nil {
		t.Fatalf("repo.FindGlobalByName failed: %v", err)
	}
	if found.ID != role.ID {
		t.Errorf("expected ID %d, got %d", role.ID, found.ID)
	}

	// 3. FindByID
	foundByID, err := repo.FindByID(role.ID)
	if err != nil {
		t.Fatalf("repo.FindByID failed: %v", err)
	}
	if foundByID.Name != roleName {
		t.Errorf("expected name %s, got %s", roleName, foundByID.Name)
	}

	// 4. CountUsersWithRole
	count, err := repo.CountUsersWithRole(role.ID)
	if err != nil {
		t.Fatalf("repo.CountUsersWithRole failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users with role, got %d", count)
	}

	// 5. Delete
	if err := repo.Delete(role.ID); err != nil {
		t.Fatalf("repo.Delete failed: %v", err)
	}
}
