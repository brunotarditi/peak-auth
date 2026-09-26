package service

import (
	"testing"
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


