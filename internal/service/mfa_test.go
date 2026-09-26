package service

import (
	"errors"
	"peak-auth/internal/store/model"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

type mockMultiMfaRepo struct {
	creds         []model.UserMfaCredential
	recoveryCodes []model.UserRecoveryCode
}

func (m *mockMultiMfaRepo) CreateCredential(cred *model.UserMfaCredential) error {
	m.creds = append(m.creds, *cred)
	return nil
}

func (m *mockMultiMfaRepo) FindActiveCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	var result []model.UserMfaCredential
	for _, c := range m.creds {
		if c.UserID == userID && c.IsActive {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *mockMultiMfaRepo) FindActiveCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error) {
	for _, c := range m.creds {
		if c.UserID == userID && c.Type == credType && c.IsActive {
			return &c, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *mockMultiMfaRepo) FindPendingCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error) {
	for _, c := range m.creds {
		if c.UserID == userID && c.Type == credType && !c.IsActive {
			return &c, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *mockMultiMfaRepo) FindAllCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	return m.creds, nil
}

func (m *mockMultiMfaRepo) ActivateCredential(credID uint) error {
	for i := range m.creds {
		if m.creds[i].ID == credID {
			m.creds[i].IsActive = true
			return nil
		}
	}
	return nil
}

func (m *mockMultiMfaRepo) UpdateCredentialSecret(credID uint, secret string) error {
	for i := range m.creds {
		if m.creds[i].ID == credID {
			m.creds[i].Secret = secret
			return nil
		}
	}
	return nil
}

func (m *mockMultiMfaRepo) UpdateCredentialSecretAtomic(credID uint, oldSecret string, newSecret string) error {
	for i := range m.creds {
		if m.creds[i].ID == credID && m.creds[i].Secret == oldSecret {
			m.creds[i].Secret = newSecret
			return nil
		}
	}
	return errors.New("concurrent modification")
}

func (m *mockMultiMfaRepo) DeleteCredentialsByUser(userID uint) error {
	m.creds = nil
	return nil
}

func (m *mockMultiMfaRepo) DeleteCredential(credID uint) error { return nil }

func (m *mockMultiMfaRepo) DeleteCredentialByIDAndUser(credID uint, userID uint) error {
	var updated []model.UserMfaCredential
	for _, c := range m.creds {
		if c.ID == credID && c.UserID == userID {
			continue
		}
		updated = append(updated, c)
	}
	m.creds = updated
	return nil
}

func (m *mockMultiMfaRepo) FindActiveWebAuthnCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	var result []model.UserMfaCredential
	for _, c := range m.creds {
		if c.UserID == userID && c.Type == "WEBAUTHN" && c.IsActive {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *mockMultiMfaRepo) CreateRecoveryCodes(codes []model.UserRecoveryCode) error {
	m.recoveryCodes = append(m.recoveryCodes, codes...)
	return nil
}

func (m *mockMultiMfaRepo) FindUnusedRecoveryCodesByUser(userID uint) ([]model.UserRecoveryCode, error) {
	var result []model.UserRecoveryCode
	for _, rc := range m.recoveryCodes {
		if rc.UserID == userID && !rc.IsUsed {
			result = append(result, rc)
		}
	}
	return result, nil
}

func (m *mockMultiMfaRepo) MarkRecoveryCodeUsed(codeID uint) error {
	for i := range m.recoveryCodes {
		if m.recoveryCodes[i].ID == codeID {
			m.recoveryCodes[i].IsUsed = true
			return nil
		}
	}
	return nil
}

func (m *mockMultiMfaRepo) DeleteRecoveryCodesByUser(userID uint) error {
	var remaining []model.UserRecoveryCode
	for _, rc := range m.recoveryCodes {
		if rc.UserID != userID {
			remaining = append(remaining, rc)
		}
	}
	m.recoveryCodes = remaining
	return nil
}

func (m *mockMultiMfaRepo) CountActiveCredentials(userID uint) (int64, error) {
	count := int64(0)
	for _, c := range m.creds {
		if c.UserID == userID && c.IsActive {
			count++
		}
	}
	return count, nil
}

type mockUserRepoForMfa struct {
	mfaEnabled bool
}

func (m *mockUserRepoForMfa) FindById(id uint) (model.User, error) {
	return model.User{
		MfaEnabled: m.mfaEnabled,
	}, nil
}

func (m *mockUserRepoForMfa) UpdateColumn(column string, value interface{}, id uint) error {
	if column == "mfa_enabled" {
		if b, ok := value.(bool); ok {
			m.mfaEnabled = b
		}
	}
	return nil
}

func (m *mockUserRepoForMfa) FindByEmail(email string) (model.User, error) { return model.User{}, nil }
func (m *mockUserRepoForMfa) FindAll() ([]model.User, error)             { return nil, nil }
func (m *mockUserRepoForMfa) CreateWithProfile(user *model.User, profile *model.Profile) error {
	return nil
}
func (m *mockUserRepoForMfa) VerifyUserEmail(userID uint, verificationID uint) error { return nil }
func (m *mockUserRepoForMfa) VerifyUserEmailByToken(tokenHash []byte) (uint, uint, error) {
	return 0, 0, nil
}
func (m *mockUserRepoForMfa) LockUserForUpdate(userID uint) error { return nil }

// --- Tests WebAuthn / Multi-Key ---

func TestMfaService_MultiWebAuthnKeys(t *testing.T) {
	repo := &mockMultiMfaRepo{
		creds: []model.UserMfaCredential{
			{ID: 1, UserID: 10, Type: "WEBAUTHN", Name: "YubiKey 5C", IsActive: true, CreatedAt: time.Now()},
			{ID: 2, UserID: 10, Type: "WEBAUTHN", Name: "MacBook TouchID", IsActive: true, CreatedAt: time.Now()},
			{ID: 3, UserID: 10, Type: "TOTP", Name: "Google Authenticator", IsActive: true, CreatedAt: time.Now()},
		},
	}
	userRepo := &mockUserRepoForMfa{mfaEnabled: true}
	svc := NewMfaService(repo, userRepo)

	t.Run("ListWebAuthnCredentials lista solo llaves WebAuthn activas", func(t *testing.T) {
		keys, err := svc.ListWebAuthnCredentials(10)
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("se esperaban 2 llaves WebAuthn, obtenidas: %d", len(keys))
		}
		if keys[0].Name != "YubiKey 5C" || keys[1].Name != "MacBook TouchID" {
			t.Errorf("nombres de llaves inesperados: %v", keys)
		}
	})

	t.Run("DeleteWebAuthnCredential elimina una llave pero preserva mfaEnabled si queda TOTP", func(t *testing.T) {
		err := svc.DeleteWebAuthnCredential(10, 1)
		if err != nil {
			t.Fatalf("error borrando llave 1: %v", err)
		}

		keys, _ := svc.ListWebAuthnCredentials(10)
		if len(keys) != 1 {
			t.Fatalf("se esperaba 1 llave restante, obtenidas: %d", len(keys))
		}
		if !userRepo.mfaEnabled {
			t.Errorf("mfaEnabled no debió desactivarse porque aún tiene TOTP y otra llave")
		}
	})

	t.Run("GetMfaStatus devuelve tanto TOTP como lista de WebAuthn", func(t *testing.T) {
		status, err := svc.GetMfaStatus(10)
		if err != nil {
			t.Fatalf("error obteniendo status: %v", err)
		}
		if !status.TOTPConfigured {
			t.Errorf("se esperaba TOTPConfigured=true")
		}
		if !status.WebAuthnConfigured {
			t.Errorf("se esperaba WebAuthnConfigured=true")
		}
		if len(status.WebAuthnKeys) != 1 {
			t.Errorf("se esperaba 1 llave en status, obtenidas: %d", len(status.WebAuthnKeys))
		}
	})
}

// --- Tests Recovery Codes ---

func TestRecoveryCodeHashingAndVerification(t *testing.T) {
	code := "ABCD-1234"

	hash := hashRecoveryCode(code)
	if len(hash) <= 7 || hash[:7] != "sha256:" {
		t.Fatalf("se esperaba prefijo sha256:, obtenido: %s", hash)
	}

	testCases := []string{
		"ABCD-1234",
		"abcd-1234",
		"ABCD1234",
		"abcd1234",
		"  ABCD-1234  ",
	}
	for _, tc := range testCases {
		if !verifyRecoveryCodeHash(tc, hash) {
			t.Errorf("falló verificación de código válido con formato: %s", tc)
		}
	}

	if verifyRecoveryCodeHash("WXYZ-9999", hash) {
		t.Errorf("código incorrecto fue aceptado")
	}
	if verifyRecoveryCodeHash("", hash) {
		t.Errorf("código vacío fue aceptado")
	}
}

func TestApiMfaToken_AtomicConsumptionAndReplayPrevention(t *testing.T) {
	mockRepo := &mockMfaAttemptRepo{
		consumed: make(map[string]bool),
		locked:   make(map[string]bool),
	}
	InitMfaAttemptTracking(mockRepo)

	tokenKey := "api_mfa_1_test_token"

	if IsApiMfaTokenConsumed(tokenKey) {
		t.Fatalf("se esperaba que el token no estuviera consumido inicialmente")
	}

	if err := ConsumeApiMfaToken(tokenKey, 1); err != nil {
		t.Fatalf("primer ConsumeApiMfaToken debió tener éxito: %v", err)
	}

	if !IsApiMfaTokenConsumed(tokenKey) {
		t.Fatalf("se esperaba que el token estuviera marcado como consumido")
	}

	if err := ConsumeApiMfaToken(tokenKey, 1); err == nil {
		t.Fatalf("se esperaba que el segundo intento de consumo fallara")
	}
}

// --- Tests TOTP Service Flow ---

func TestMfaService_TOTPFlow(t *testing.T) {
	t.Setenv("MFA_ENCRYPTION_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")

	repo := &mockMultiMfaRepo{}
	userRepo := &mockUserRepoForMfa{mfaEnabled: false}
	svc := NewMfaService(repo, userRepo)

	t.Run("SetupTOTP genera secreto y QR", func(t *testing.T) {
		res, err := svc.SetupTOTP(1, "test@peak.local")
		if err != nil {
			t.Fatalf("error configurando TOTP: %v", err)
		}
		if res.Secret == "" {
			t.Errorf("se esperaba secreto TOTP no vacío")
		}
		if res.QRCode == "" {
			t.Errorf("se esperaba código QR en base64 no vacío")
		}

		// Validar código TOTP en tiempo real usando otp/totp
		code, err := totp.GenerateCode(res.Secret, time.Now())
		if err != nil {
			t.Fatalf("error generando código TOTP con el secreto: %v", err)
		}

		// Activar TOTP
		recoveryCodes, err := svc.VerifyAndActivateTOTP(1, code)
		if err != nil {
			t.Fatalf("error activando TOTP con código válido: %v", err)
		}
		if len(recoveryCodes) != 10 {
			t.Errorf("se esperaban 10 códigos de recuperación, obtenidos: %d", len(recoveryCodes))
		}
		if !userRepo.mfaEnabled {
			t.Errorf("se esperaba mfaEnabled=true tras activación")
		}

		// Validar código TOTP con ValidateTOTPCode
		if err := svc.ValidateTOTPCode(1, code); err != nil {
			t.Errorf("ValidateTOTPCode falló con código válido: %v", err)
		}

		// Código incorrecto debe fallar
		if err := svc.ValidateTOTPCode(1, "000000"); err == nil {
			t.Errorf("se esperaba error con código TOTP incorrecto")
		}
	})

	t.Run("DisableMFA desactiva credenciales y mfaEnabled", func(t *testing.T) {
		err := svc.DisableMFA(1)
		if err != nil {
			t.Fatalf("error desactivando MFA: %v", err)
		}
		if userRepo.mfaEnabled {
			t.Errorf("se esperaba mfaEnabled=false tras desactivación")
		}
	})
}
