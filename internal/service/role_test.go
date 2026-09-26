package service

import (
	"encoding/json"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"testing"
)

func TestRoleService_FindAll(t *testing.T) {
	roleRepo := newMockRoleRepo()
	ruleRepo := &mockRuleRepo{}
	svc := NewRoleService(roleRepo, ruleRepo)

	// Global roles
	_ = roleRepo.Create(&model.Role{Name: "ROOT", ApplicationID: nil})
	_ = roleRepo.Create(&model.Role{Name: "ADMIN", ApplicationID: nil})

	// App-specific role
	appID := uint(5)
	_ = roleRepo.Create(&model.Role{Name: "MODERATOR", ApplicationID: &appID})

	roles, err := svc.FindAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(roles) != 2 {
		t.Fatalf("expected 2 global roles, got %d", len(roles))
	}
	for _, r := range roles {
		if r.ApplicationID != nil {
			t.Errorf("expected global role (nil ApplicationID), got %v", r.ApplicationID)
		}
	}
}

func TestRoleService_FindVisibleForApp(t *testing.T) {
	roleRepo := newMockRoleRepo()
	ruleRepo := &mockRuleRepo{}
	svc := NewRoleService(roleRepo, ruleRepo)

	// Global roles
	_ = roleRepo.Create(&model.Role{Name: "ADMIN", ApplicationID: nil})
	_ = roleRepo.Create(&model.Role{Name: "USER", ApplicationID: nil})

	// App 10 role
	app10 := uint(10)
	_ = roleRepo.Create(&model.Role{Name: "APP10_ROLE", ApplicationID: &app10})

	// App 20 role
	app20 := uint(20)
	_ = roleRepo.Create(&model.Role{Name: "APP20_ROLE", ApplicationID: &app20})

	visible, err := svc.FindVisibleForApp(app10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(visible) != 3 {
		t.Fatalf("expected 3 roles visible for app10, got %d", len(visible))
	}

	names := make(map[string]bool)
	for _, r := range visible {
		names[r.Name] = true
	}

	if !names["ADMIN"] || !names["USER"] || !names["APP10_ROLE"] {
		t.Errorf("missing expected role in visible list: %v", names)
	}
	if names["APP20_ROLE"] {
		t.Errorf("unexpected role from another app in visible list: APP20_ROLE")
	}
}

func TestRoleService_CreateRole(t *testing.T) {
	roleRepo := newMockRoleRepo()
	ruleRepo := &mockRuleRepo{}
	svc := NewRoleService(roleRepo, ruleRepo)

	// 1. Empty role name
	err := svc.CreateRole("   ")
	if err == nil || err.Error() != "el nombre del rol es obligatorio" {
		t.Errorf("expected 'el nombre del rol es obligatorio', got %v", err)
	}

	// 2. Successful creation
	err = svc.CreateRole("editor")
	if err != nil {
		t.Fatalf("unexpected error creating role: %v", err)
	}

	created, err := roleRepo.FindGlobalByName("EDITOR")
	if err != nil {
		t.Fatalf("expected role EDITOR to exist: %v", err)
	}
	if created.ApplicationID != nil {
		t.Errorf("expected ApplicationID to be nil, got %v", created.ApplicationID)
	}

	// 3. Duplicate role name
	err = svc.CreateRole("EDITOR")
	if err == nil || err.Error() != "el rol ya existe" {
		t.Errorf("expected 'el rol ya existe', got %v", err)
	}
}

func TestRoleService_CreateAppRole(t *testing.T) {
	appID := uint(7)

	tests := []struct {
		name        string
		roleName    string
		appID       uint
		rules       []model.ApplicationRules
		setupRoles  func(repo *mockRoleRepo)
		expectedErr string
	}{
		{
			name:        "empty role name",
			roleName:    "  ",
			appID:       appID,
			rules:       nil,
			expectedErr: "el nombre del rol es obligatorio",
		},
		{
			name:        "reserved role ROOT",
			roleName:    "ROOT",
			appID:       appID,
			rules:       nil,
			expectedErr: "el rol \"ROOT\" es un rol del sistema y no puede crearse como rol de aplicación",
		},
		{
			name:        "reserved role ADMIN",
			roleName:    "admin",
			appID:       appID,
			rules:       nil,
			expectedErr: "el rol \"ADMIN\" es un rol del sistema y no puede crearse como rol de aplicación",
		},
		{
			name:        "reserved role USER",
			roleName:    "USER",
			appID:       appID,
			rules:       nil,
			expectedErr: "el rol \"USER\" es un rol del sistema y no puede crearse como rol de aplicación",
		},
		{
			name:        "app without roles enabled (no rule)",
			roleName:    "MANAGER",
			appID:       appID,
			rules:       []model.ApplicationRules{},
			expectedErr: "esta aplicación no tiene el sistema de roles habilitado",
		},
		{
			name:     "app without roles enabled (enable_roles = false)",
			roleName: "MANAGER",
			appID:    appID,
			rules: []model.ApplicationRules{
				{
					ApplicationID: appID,
					Code:          util.AUTHZ_POLICY,
					Value:         []byte(`{"enable_roles": false}`),
				},
			},
			expectedErr: "esta aplicación no tiene el sistema de roles habilitado",
		},
		{
			name:     "duplicate role in the same app",
			roleName: "MANAGER",
			appID:    appID,
			rules: []model.ApplicationRules{
				{
					ApplicationID: appID,
					Code:          util.AUTHZ_POLICY,
					Value:         []byte(`{"enable_roles": true}`),
				},
			},
			setupRoles: func(r *mockRoleRepo) {
				_ = r.Create(&model.Role{Name: "MANAGER", ApplicationID: &appID})
			},
			expectedErr: "el rol ya existe en esta aplicación",
		},
		{
			name:     "successful creation",
			roleName: "operator",
			appID:    appID,
			rules: []model.ApplicationRules{
				{
					ApplicationID: appID,
					Code:          util.AUTHZ_POLICY,
					Value: func() []byte {
						b, _ := json.Marshal(util.AuthzPolicy{EnableRoles: true})
						return b
					}(),
				},
			},
			expectedErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleRepo := newMockRoleRepo()
			if tt.setupRoles != nil {
				tt.setupRoles(roleRepo)
			}
			ruleRepo := &mockRuleRepo{rules: tt.rules}
			svc := NewRoleService(roleRepo, ruleRepo)

			err := svc.CreateAppRole(tt.roleName, tt.appID)
			if tt.expectedErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// Verify created role
				role, err := roleRepo.FindByNameForApp(tt.roleName, tt.appID)
				if err != nil {
					t.Fatalf("role was not created: %v", err)
				}
				if role.ApplicationID == nil || *role.ApplicationID != tt.appID {
					t.Errorf("expected ApplicationID %d, got %v", tt.appID, role.ApplicationID)
				}
			} else {
				if err == nil || err.Error() != tt.expectedErr {
					t.Errorf("expected error %q, got %v", tt.expectedErr, err)
				}
			}
		})
	}
}

func TestRoleService_DeleteRole(t *testing.T) {
	t.Run("role does not exist", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteRole("NONEXISTENT")
		if err == nil || err.Error() != "el rol no existe" {
			t.Errorf("expected 'el rol no existe', got %v", err)
		}
	})

	t.Run("default protected role cannot be deleted", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		_ = roleRepo.Create(&model.Role{Name: "ROOT", IsDefault: true})
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteRole("root")
		if err == nil || err.Error() != "el rol \"ROOT\" es un rol protegido del sistema y no puede eliminarse" {
			t.Errorf("expected protected role error, got %v", err)
		}
	})

	t.Run("role with assigned users cannot be deleted", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		_ = roleRepo.Create(&model.Role{Name: "REVIEWER", IsDefault: false})
		created, _ := roleRepo.FindGlobalByName("REVIEWER")
		roleRepo.userCounts[created.ID] = 3
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteRole("reviewer")
		expected := "no se puede eliminar: 3 usuario(s) tienen asignado el rol \"REVIEWER\""
		if err == nil || err.Error() != expected {
			t.Errorf("expected %q, got %v", expected, err)
		}
	})

	t.Run("successful deletion", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		_ = roleRepo.Create(&model.Role{Name: "CUSTOM", IsDefault: false})
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteRole("custom")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = roleRepo.FindGlobalByName("CUSTOM")
		if err == nil {
			t.Errorf("expected role CUSTOM to be deleted")
		}
	})
}

func TestRoleService_DeleteAppRole(t *testing.T) {
	appID := uint(3)

	t.Run("role does not exist in app", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteAppRole("NONEXISTENT", appID)
		if err == nil || err.Error() != "el rol no existe en esta aplicación" {
			t.Errorf("expected 'el rol no existe en esta aplicación', got %v", err)
		}
	})

	t.Run("cannot delete global role via DeleteAppRole", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		// Global role visible for app
		_ = roleRepo.Create(&model.Role{Name: "GLOBAL_MEMBER", ApplicationID: nil})
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteAppRole("GLOBAL_MEMBER", appID)
		if err == nil || err.Error() != "solo pueden eliminarse los roles propios de la aplicación" {
			t.Errorf("expected 'solo pueden eliminarse los roles propios de la aplicación', got %v", err)
		}
	})

	t.Run("role with assigned users cannot be deleted", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		_ = roleRepo.Create(&model.Role{Name: "TEAM_LEAD", ApplicationID: &appID})
		created, _ := roleRepo.FindByNameForApp("TEAM_LEAD", appID)
		roleRepo.userCounts[created.ID] = 2
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteAppRole("team_lead", appID)
		expected := "no se puede eliminar: 2 usuario(s) tienen asignado el rol \"TEAM_LEAD\""
		if err == nil || err.Error() != expected {
			t.Errorf("expected %q, got %v", expected, err)
		}
	})

	t.Run("successful app role deletion", func(t *testing.T) {
		roleRepo := newMockRoleRepo()
		_ = roleRepo.Create(&model.Role{Name: "AUDITOR", ApplicationID: &appID})
		svc := NewRoleService(roleRepo, &mockRuleRepo{})

		err := svc.DeleteAppRole("auditor", appID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = roleRepo.FindByNameForApp("AUDITOR", appID)
		if err == nil {
			t.Errorf("expected role AUDITOR to be deleted")
		}
	})
}
