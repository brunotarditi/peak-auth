package service

import (
	"testing"
	"time"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
)

// --- Tests Application Service ---

func TestRevokeUserFromApp_DeletesRefreshTokens(t *testing.T) {
	refreshRepo := &mockRefreshTokenRepo{}
	uarRepo := &mockUARRepo{
		roles: map[uint][]string{1: {"USER"}},
	}
	appRepo := newMockAppRepo()
	appRepo.apps["my-app"] = &model.Application{AppID: "my-app"}

	appSvc := &applicationService{
		repo:             appRepo,
		uarRepo:          uarRepo,
		refreshTokenRepo: refreshRepo,
	}

	err := appSvc.RevokeUserFromApp(1, 10)
	if err != nil {
		t.Fatalf("error inesperado en RevokeUserFromApp: %v", err)
	}
	if !refreshRepo.deletedByUserAndApp {
		t.Fatalf("RevokeUserFromApp no eliminó los refresh tokens de la aplicación")
	}
}

func TestRevokeUserFromApp_ProtectsRootUserInPeakAuth(t *testing.T) {
	refreshRepo := &mockRefreshTokenRepo{}
	uarRepo := &mockUARRepo{
		roles: map[uint][]string{1: {"ROOT"}},
	}
	appRepo := newMockAppRepo()
	peakApp := &model.Application{AppID: util.AppIdPeakAuth}
	peakApp.ID = 1
	appRepo.apps[util.AppIdPeakAuth] = peakApp

	appSvc := &applicationService{
		repo:             appRepo,
		uarRepo:          uarRepo,
		refreshTokenRepo: refreshRepo,
	}

	err := appSvc.RevokeUserFromApp(1, 1)
	if err == nil {
		t.Fatalf("Esperaba error al intentar revocar al usuario ROOT en la app raíz")
	}
	if refreshRepo.deletedByUserAndApp {
		t.Fatalf("Los tokens no debieron eliminarse porque la operación debía fallar")
	}
}


func TestApplicationService_UpdateColumns_IndependentUpdates(t *testing.T) {
	initialSecret := "initial-secret-hash-123"
	app := &model.Application{
		ID:          1,
		AppID:       "test-client",
		Name:        "Test Client",
		Description: "Initial description",
		RedirectURL: "https://example.com/callback",
		SecretKey:   initialSecret,
		IsActive:    true,
	}

	appRepo := newMockAppRepo()
	appRepo.apps["test-client"] = app

	svc := NewApplicationService(appRepo, nil, nil, nil, nil, nil, nil, nil)

	// 1. UpdateApp: debe modificar metadata pero NO tocar el secret
	err := svc.UpdateApp("test-client", "Updated description", "https://example.com/new-callback", true)
	if err != nil {
		t.Fatalf("UpdateApp falló: %v", err)
	}
	if app.Description != "Updated description" {
		t.Errorf("se esperaba descripción actualizada, obtenido: %s", app.Description)
	}
	if app.RedirectURL != "https://example.com/new-callback" {
		t.Errorf("se esperaba redirect_url actualizada, obtenido: %s", app.RedirectURL)
	}
	if app.SecretKey != initialSecret {
		t.Errorf("UpdateApp no debió modificar SecretKey")
	}

	// 2. RegenerateSecret: debe modificar el secret pero NO tocar descripción ni redirect_url
	newPlainSecret, err := svc.RegenerateSecret("test-client")
	if err != nil {
		t.Fatalf("RegenerateSecret falló: %v", err)
	}
	if newPlainSecret == "" {
		t.Fatalf("se esperaba un plainSecret generado")
	}
	if app.SecretKey == initialSecret {
		t.Errorf("se esperaba que el secret cambiara")
	}
	if app.Description != "Updated description" {
		t.Errorf("RegenerateSecret no debió modificar la descripción")
	}
	if app.RedirectURL != "https://example.com/new-callback" {
		t.Errorf("RegenerateSecret no debió modificar la redirect_url")
	}
}

func TestApplicationService_CreateApp_WithOwnership(t *testing.T) {
	appRepo := newMockAppRepo()
	roleRepo := newMockRoleRepo()
	_ = roleRepo.Create(&model.Role{Name: "OWNER"})

	assignedRoles := make(map[uint][]uint) // userID -> roleIDs
	uarRepo := &mockUARRepo{
		roles: make(map[uint][]string),
	}

	svc := &applicationService{
		repo:     appRepo,
		roleRepo: roleRepo,
		uarRepo:  uarRepo,
	}

	creatorID := uint(55)
	app, secret, err := svc.CreateApp("Tenant One", "A new tenant", "https://tenant.com/cb", true, creatorID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Errorf("expected generated secret")
	}
	if app.OwnerID == nil || *app.OwnerID != creatorID {
		t.Errorf("expected OwnerID = %d, got %v", creatorID, app.OwnerID)
	}
	_ = assignedRoles
}

func TestApplicationService_TransferOwnership(t *testing.T) {
	currentOwnerID := uint(10)
	newOwnerID := uint(20)

	app := &model.Application{
		ID:       1,
		AppID:    "acme-app",
		Name:     "Acme App",
		OwnerID:  &currentOwnerID,
		IsActive: true,
	}

	appRepo := newMockAppRepo()
	appRepo.apps["acme-app"] = app

	userRepo := newMockUserRepo()
	userRepo.users["owner@example.com"] = &model.User{
		ID:         currentOwnerID,
		Email:      "owner@example.com",
		IsActive:   true,
		IsVerified: true,
	}
	userRepo.users["newowner@example.com"] = &model.User{
		ID:         newOwnerID,
		Email:      "newowner@example.com",
		IsActive:   true,
		IsVerified: true,
	}

	roleRepo := newMockRoleRepo()
	_ = roleRepo.Create(&model.Role{Name: "OWNER"})
	_ = roleRepo.Create(&model.Role{Name: "ADMIN"})

	uarRepo := &mockUARRepo{
		roles: map[uint][]string{
			currentOwnerID: {"OWNER"},
			newOwnerID:     {"USER"},
		},
	}

	txRepo := &mockTxRepo{
		appRepo:  appRepo,
		roleRepo: roleRepo,
		uarRepo:  uarRepo,
		userRepo: userRepo,
	}
	txMgr := &mockTxManager{txRepo: txRepo}

	svc := &applicationService{
		repo:      appRepo,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		uarRepo:   uarRepo,
		txManager: txMgr,
	}

	// 1. Error: Transfer peak-auth system app
	err := svc.TransferOwnership(util.AppIdPeakAuth, currentOwnerID, newOwnerID)
	if err == nil {
		t.Errorf("expected error transferring system app peak-auth")
	}

	// 2. Error: Caller is neither owner nor root
	err = svc.TransferOwnership("acme-app", 999, newOwnerID)
	if err == nil {
		t.Errorf("expected forbidden error for unauthorized caller")
	}

	// 3. Error: Transfer to same user
	err = svc.TransferOwnership("acme-app", currentOwnerID, currentOwnerID)
	if err == nil {
		t.Errorf("expected error transferring to same owner")
	}

	// 4. Success: Current owner transfers to new owner
	err = svc.TransferOwnership("acme-app", currentOwnerID, newOwnerID)
	if err != nil {
		t.Fatalf("unexpected error in transfer: %v", err)
	}

	if app.OwnerID == nil || *app.OwnerID != newOwnerID {
		t.Errorf("expected app.OwnerID = %d, got %v", newOwnerID, app.OwnerID)
	}
}

func TestApplicationService_RevokeUserFromApp_ProtectsOwner(t *testing.T) {
	ownerID := uint(33)
	app := &model.Application{
		ID:      5,
		AppID:   "shop-app",
		OwnerID: &ownerID,
	}

	appRepo := newMockAppRepo()
	appRepo.apps["shop-app"] = app

	svc := &applicationService{
		repo:    appRepo,
		uarRepo: &mockUARRepo{},
	}

	err := svc.RevokeUserFromApp(ownerID, 5)
	if err == nil {
		t.Fatalf("expected error revoking owner from their own app")
	}
}

func TestApplicationService_RegisterUserInApp_BlocksDirectOwnerRole(t *testing.T) {
	svc := &applicationService{}
	app := &model.Application{ID: 1, Name: "App"}

	err := svc.RegisterUserInApp("user@test.com", "OWNER", app)
	if err == nil {
		t.Fatalf("expected error when attempting to assign OWNER role directly")
	}
}

func TestApplicationService_UpdateUserAccessTime(t *testing.T) {
	appRepo := newMockAppRepo()
	appRepo.apps["test-app"] = &model.Application{
		ID:    10,
		AppID: "test-app",
	}

	userRepo := newMockUserRepo()
	userRepo.usersByID[42] = &model.User{
		ID:           42,
		AuthzVersion: 1,
	}

	uarRepo := &mockUARRepo{}

	svc := &applicationService{
		repo:     appRepo,
		userRepo: userRepo,
		uarRepo:  uarRepo,
	}

	// 1. App not found
	err := svc.UpdateUserAccessTime("non-existent", 42, nil, nil)
	if err == nil {
		t.Fatalf("expected error for non-existent app")
	}

	// 2. Success: updates access time and bumps authz_version
	now := time.Now()
	expires := now.Add(7 * 24 * time.Hour)
	err = svc.UpdateUserAccessTime("test-app", 42, &now, &expires)
	if err != nil {
		t.Fatalf("unexpected error updating access time: %v", err)
	}

	if uarRepo.updatedUserID != 42 || uarRepo.updatedAppID != 10 {
		t.Errorf("expected uar update for user 42 and app 10, got user %d app %d", uarRepo.updatedUserID, uarRepo.updatedAppID)
	}
	if uarRepo.updatedAccessStarts != &now || uarRepo.updatedAccessExpires != &expires {
		t.Errorf("expected access times passed to uarRepo")
	}
	if v, ok := userRepo.updatedColumns["authz_version"]; !ok || v != uint(2) {
		t.Errorf("expected authz_version bumped to 2, got %v", v)
	}
}




