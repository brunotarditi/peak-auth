package service

import (
	"errors"
	"peak-auth/internal/store/model"
	"testing"
	"time"
)

type mockMultiMfaRepo struct {
	creds []model.UserMfaCredential
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
	return nil, errors.New("not found")
}

func (m *mockMultiMfaRepo) FindAllCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	return m.creds, nil
}

func (m *mockMultiMfaRepo) ActivateCredential(credID uint) error { return nil }
func (m *mockMultiMfaRepo) UpdateCredentialSecret(credID uint, secret string) error { return nil }
func (m *mockMultiMfaRepo) UpdateCredentialSecretAtomic(credID uint, oldSecret string, newSecret string) error { return nil }
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

func (m *mockMultiMfaRepo) CreateRecoveryCodes(codes []model.UserRecoveryCode) error { return nil }
func (m *mockMultiMfaRepo) FindUnusedRecoveryCodesByUser(userID uint) ([]model.UserRecoveryCode, error) {
	return nil, nil
}
func (m *mockMultiMfaRepo) MarkRecoveryCodeUsed(codeID uint) error { return nil }
func (m *mockMultiMfaRepo) DeleteRecoveryCodesByUser(userID uint) error { return nil }

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
func (m *mockUserRepoForMfa) FindAll() ([]model.User, error) { return nil, nil }
func (m *mockUserRepoForMfa) CreateWithProfile(user *model.User, profile *model.Profile) error { return nil }
func (m *mockUserRepoForMfa) VerifyUserEmail(userID uint, verificationID uint) error { return nil }
func (m *mockUserRepoForMfa) VerifyUserEmailByToken(tokenHash []byte) (uint, uint, error) { return 0, 0, nil }
func (m *mockUserRepoForMfa) LockUserForUpdate(userID uint) error { return nil }

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
