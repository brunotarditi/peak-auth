package repo

import (
	"fmt"
	"peak-auth/internal/store/model"
	"testing"
	"time"
)

func TestUserRepository_CRUD(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}

	repo := NewUserRepositoryRepository(db)
	uniqueSuffix := time.Now().UnixNano()
	email := fmt.Sprintf("testuser%d@peak.local", uniqueSuffix)

	user := model.User{
		Email:      email,
		Password:   "hashed-pwd",
		IsActive:   true,
		IsVerified: true,
	}
	profile := model.Profile{
		FirstName: "Test",
		LastName:  "User",
		AvatarURL: "https://peak.local/avatar.png",
	}

	// 1. CreateWithProfile
	if err := repo.CreateWithProfile(&user, &profile); err != nil {
		t.Fatalf("repo.CreateWithProfile failed: %v", err)
	}

	// 2. FindByEmail
	foundByEmail, err := repo.FindByEmail(email)
	if err != nil {
		t.Fatalf("repo.FindByEmail failed: %v", err)
	}
	if foundByEmail.ID != user.ID {
		t.Errorf("expected ID %d, got %d", user.ID, foundByEmail.ID)
	}
	if foundByEmail.Profile.FirstName != "Test" {
		t.Errorf("expected Profile.FirstName Test, got %s", foundByEmail.Profile.FirstName)
	}

	// 3. FindById
	foundByID, err := repo.FindById(user.ID)
	if err != nil {
		t.Fatalf("repo.FindById failed: %v", err)
	}
	if foundByID.Email != email {
		t.Errorf("expected Email %s, got %s", email, foundByID.Email)
	}

	// 4. UpdateColumn
	if err := repo.UpdateColumn("mfa_enabled", true, user.ID); err != nil {
		t.Fatalf("repo.UpdateColumn failed: %v", err)
	}
	updated, _ := repo.FindById(user.ID)
	if !updated.MfaEnabled {
		t.Errorf("expected MfaEnabled true")
	}
}
