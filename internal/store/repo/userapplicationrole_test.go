package repo

import (
	"fmt"
	"peak-auth/internal/store/model"
	"testing"
	"time"
)

func TestUserApplicationRoleRepository_GetUsersWithRolesByApp_Deduplication(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}

	uRepo := NewUserRepositoryRepository(db)
	uarRepo := NewUserApplicationRoleRepository(db)
	appRepo := NewApplicationRepository(db)
	roleRepo := NewRoleRepositoryRepository(db)

	suffix := time.Now().UnixNano()
	email := fmt.Sprintf("multi-role-%d@peak.local", suffix)

	user := model.User{
		Email:      email,
		Password:   "pwd",
		IsActive:   true,
		IsVerified: true,
	}
	profile := model.Profile{FirstName: "Multi", LastName: "Role"}
	if err := uRepo.CreateWithProfile(&user, &profile); err != nil {
		t.Fatalf("CreateWithProfile failed: %v", err)
	}

	app := model.Application{
		Name:        fmt.Sprintf("App Test %d", suffix),
		AppID:       fmt.Sprintf("app-test-%d", suffix),
		SecretKey:   "secret",
		RedirectURL: "https://peak.local/callback",
		IsActive:    true,
	}
	if err := appRepo.Create(&app); err != nil {
		t.Fatalf("appRepo.Create failed: %v", err)
	}

	// Obtener o crear dos roles
	ownerRole, err := roleRepo.FindGlobalByName("OWNER")
	if err != nil {
		t.Fatalf("FindGlobalByName OWNER failed: %v", err)
	}
	adminRole, err := roleRepo.FindGlobalByName("ADMIN")
	if err != nil {
		t.Fatalf("FindGlobalByName ADMIN failed: %v", err)
	}

	// Asignar ambos roles al mismo usuario en la aplicación
	if err := uarRepo.AssignRole(user.ID, app.ID, ownerRole.ID); err != nil {
		t.Fatalf("AssignRole OWNER failed: %v", err)
	}
	if err := uarRepo.AssignRole(user.ID, app.ID, adminRole.ID); err != nil {
		t.Fatalf("AssignRole ADMIN failed: %v", err)
	}

	// Probar GetUsersWithRolesByApp
	users, err := uarRepo.GetUsersWithRolesByApp(app.ID)
	if err != nil {
		t.Fatalf("GetUsersWithRolesByApp failed: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("se esperaba exactamente 1 usuario único, pero se obtuvieron %d", len(users))
	}

	if users[0].ID != user.ID {
		t.Errorf("ID esperado %d, obtenido %d", user.ID, users[0].ID)
	}
}
