package repo

import (
	"errors"
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type OAuthRepository interface {
	CreateCode(code *model.OAuthCode) error
	GetAndConsumeCode(codeStr string) (*model.OAuthCode, error)
	DeleteExpiredCodes() error
	HasValidConsent(userID uint, clientID string) (bool, error)
	CreateConsent(consent *model.UserConsent) error
	RevokeConsent(userID uint, clientID string) error
}

type oauthRepository struct {
	db *gorm.DB
}

func NewOAuthRepository(db *gorm.DB) OAuthRepository {
	return &oauthRepository{db: db}
}

func (r *oauthRepository) CreateCode(code *model.OAuthCode) error {
	return r.db.Create(code).Error
}

func (r *oauthRepository) GetAndConsumeCode(codeStr string) (*model.OAuthCode, error) {
	var code model.OAuthCode
	
	// Utilizar una transacción con bloqueo a nivel de fila para asegurar que el uso sea estrictamente ONE-TIME
	err := r.db.Transaction(func(tx *gorm.DB) error {
		// Bloquear la fila con SELECT ... FOR UPDATE para evitar lecturas concurrentes
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("code = ?", codeStr).
			First(&code).Error; err != nil {
			return err
		}
		
		// Eliminar el código y verificar que exactamente una fila fue afectada
		result := tx.Where("code = ?", codeStr).Delete(&model.OAuthCode{})
		if result.Error != nil {
			return result.Error
		}
		
		if result.RowsAffected != 1 {
			return errors.New("el código de autorización ya fue consumido")
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return &code, nil
}

func (r *oauthRepository) DeleteExpiredCodes() error {
	return r.db.Where("expires_at < CURRENT_TIMESTAMP").Delete(&model.OAuthCode{}).Error
}

func (r *oauthRepository) HasValidConsent(userID uint, clientID string) (bool, error) {
	var consent model.UserConsent
	err := r.db.Where("user_id = ? AND client_id = ?", userID, clientID).First(&consent).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}

	// Check if consent has expired
	if consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt) {
		return false, nil
	}

	return true, nil
}

func (r *oauthRepository) CreateConsent(consent *model.UserConsent) error {
	return r.db.Create(consent).Error
}

func (r *oauthRepository) RevokeConsent(userID uint, clientID string) error {
	return r.db.Where("user_id = ? AND client_id = ?", userID, clientID).Delete(&model.UserConsent{}).Error
}
