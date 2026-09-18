package repo

import (
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
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
	
	// Utilizar una transacción para asegurar que el uso sea verdaderamente ONE-TIME
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("code = ?", codeStr).First(&code).Error; err != nil {
			return err
		}
		if err := tx.Where("code = ?", codeStr).Delete(&model.OAuthCode{}).Error; err != nil {
			return err
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
