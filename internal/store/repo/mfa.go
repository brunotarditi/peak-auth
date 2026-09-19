package repo

import (
	"peak-auth/internal/store/model"

	"gorm.io/gorm"
)

type MfaRepository interface {
	// Credenciales MFA
	CreateCredential(cred *model.UserMfaCredential) error
	FindActiveCredentialsByUser(userID uint) ([]model.UserMfaCredential, error)
	FindActiveCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error)
	FindPendingCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error)
	FindAllCredentialsByUser(userID uint) ([]model.UserMfaCredential, error)
	ActivateCredential(credID uint) error
	UpdateCredentialSecret(credID uint, secret string) error
	UpdateCredentialSecretAtomic(credID uint, oldSecret string, newSecret string) error
	DeleteCredentialsByUser(userID uint) error
	DeleteCredential(credID uint) error

	// Códigos de recuperación
	CreateRecoveryCodes(codes []model.UserRecoveryCode) error
	FindUnusedRecoveryCodesByUser(userID uint) ([]model.UserRecoveryCode, error)
	MarkRecoveryCodeUsed(codeID uint) error
	DeleteRecoveryCodesByUser(userID uint) error

	// Contar credenciales activas (para saber si hay que desactivar MFA global)
	CountActiveCredentials(userID uint) (int64, error)
}

type mfaRepository struct {
	db *gorm.DB
}

func NewMfaRepository(db *gorm.DB) MfaRepository {
	return &mfaRepository{db: db}
}

func (r *mfaRepository) CreateCredential(cred *model.UserMfaCredential) error {
	return r.db.Create(cred).Error
}

func (r *mfaRepository) FindActiveCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	var creds []model.UserMfaCredential
	err := r.db.Where("user_id = ? AND is_active = ?", userID, true).Find(&creds).Error
	return creds, err
}

func (r *mfaRepository) FindActiveCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error) {
	var cred model.UserMfaCredential
	err := r.db.Where("user_id = ? AND type = ? AND is_active = ?", userID, credType, true).First(&cred).Error
	if err != nil {
		return nil, err
	}
	return &cred, nil
}
func (r *mfaRepository) FindPendingCredentialByUserAndType(userID uint, credType string) (*model.UserMfaCredential, error) {
	var cred model.UserMfaCredential
	err := r.db.Where("user_id = ? AND type = ? AND is_active = ?", userID, credType, false).First(&cred).Error
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *mfaRepository) FindAllCredentialsByUser(userID uint) ([]model.UserMfaCredential, error) {
	var creds []model.UserMfaCredential
	err := r.db.Where("user_id = ?", userID).Find(&creds).Error
	return creds, err
}

func (r *mfaRepository) ActivateCredential(credID uint) error {
	return r.db.Model(&model.UserMfaCredential{}).Where("id = ?", credID).Update("is_active", true).Error
}

func (r *mfaRepository) UpdateCredentialSecret(credID uint, secret string) error {
	return r.db.Model(&model.UserMfaCredential{}).Where("id = ?", credID).Update("secret", secret).Error
}

// UpdateCredentialSecretAtomic realiza una actualización atómica compare-and-swap del secret de la credencial.
// Solo actualiza si el secret actual coincide con oldSecret, evitando condiciones de carrera donde
// autenticaciones concurrentes pudieran sobrescribir un contador más nuevo con un estado viejo.
func (r *mfaRepository) UpdateCredentialSecretAtomic(credID uint, oldSecret string, newSecret string) error {
	result := r.db.Model(&model.UserMfaCredential{}).
		Where("id = ? AND secret = ?", credID, oldSecret).
		Update("secret", newSecret)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *mfaRepository) DeleteCredentialsByUser(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.UserMfaCredential{}).Error
}

func (r *mfaRepository) DeleteCredential(credID uint) error {
	return r.db.Delete(&model.UserMfaCredential{}, credID).Error
}

func (r *mfaRepository) CreateRecoveryCodes(codes []model.UserRecoveryCode) error {
	return r.db.Create(&codes).Error
}

func (r *mfaRepository) FindUnusedRecoveryCodesByUser(userID uint) ([]model.UserRecoveryCode, error) {
	var codes []model.UserRecoveryCode
	err := r.db.Where("user_id = ? AND is_used = ?", userID, false).Find(&codes).Error
	return codes, err
}

func (r *mfaRepository) MarkRecoveryCodeUsed(codeID uint) error {
	result := r.db.Model(&model.UserRecoveryCode{}).Where("id = ? AND is_used = ?", codeID, false).Update("is_used", true)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *mfaRepository) DeleteRecoveryCodesByUser(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.UserRecoveryCode{}).Error
}

func (r *mfaRepository) CountActiveCredentials(userID uint) (int64, error) {
	var count int64
	err := r.db.Model(&model.UserMfaCredential{}).Where("user_id = ? AND is_active = ?", userID, true).Count(&count).Error
	return count, err
}
