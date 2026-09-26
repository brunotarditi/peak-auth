package service

import (
	"testing"
	"time"

	"peak-auth/internal/store/model"
)


func TestSetupService_EphemeralToken(t *testing.T) {
	repo := &mockSetupRepo{firstRun: true}
	svc := NewSetupService(repo, "", nil)

	// Antes de InitializeSystem no hay token efímero ni configurado
	if err := svc.ValidateSetupToken("random-token"); err == nil {
		t.Fatalf("se esperaba error cuando no hay token configurado ni efímero")
	}

	// Inicializar sistema sin SETUP_TOKEN -> debe generar token efímero
	svc.InitializeSystem("8080")

	if !svc.RequiresToken() {
		t.Fatalf("se esperaba que RequiresToken() retornara true con token efímero activo")
	}

	concrete := svc.(*setupService)
	ephemeralToken := concrete.ephemeralToken
	if ephemeralToken == "" {
		t.Fatalf("se esperaba que ephemeralToken no estuviera vacío")
	}

	// Token erróneo debe fallar
	if err := svc.ValidateSetupToken("token-incorrecto"); err == nil {
		t.Fatalf("se esperaba error con token incorrecto")
	}

	// Token correcto debe ser válido
	if err := svc.ValidateSetupToken(ephemeralToken); err != nil {
		t.Fatalf("se esperaba validación exitosa con token efímero correcto: %v", err)
	}

	// Token expirado debe fallar
	concrete.tokenExpiry = time.Now().Add(-1 * time.Minute)
	if err := svc.ValidateSetupToken(ephemeralToken); err == nil {
		t.Fatalf("se esperaba error cuando el token efímero está expirado")
	}

	// Resetear expiry y completar setup
	concrete.tokenExpiry = time.Now().Add(1 * time.Hour)
	svc.CompleteSetup(model.User{Email: "root@peak.local"})

	if concrete.ephemeralToken != "" {
		t.Fatalf("CompleteSetup debió limpiar el token efímero")
	}
}

func TestSetupService_ConfiguredToken(t *testing.T) {
	repo := &mockSetupRepo{firstRun: true}
	configuredToken := "super-secret-setup-token-42"
	svc := NewSetupService(repo, configuredToken, nil)

	if !svc.RequiresToken() {
		t.Fatalf("se esperaba RequiresToken() == true con SETUP_TOKEN configurado")
	}

	if err := svc.ValidateSetupToken("wrong-token"); err == nil {
		t.Fatalf("se esperaba error con token no coincidente")
	}

	if err := svc.ValidateSetupToken(configuredToken); err != nil {
		t.Fatalf("se esperaba éxito con token coincidente: %v", err)
	}
}


