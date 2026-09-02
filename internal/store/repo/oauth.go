package repo

import (
	"peak-auth/internal/store/model"

	"gorm.io/gorm"
)

type OAuthRepository interface {
	CreateCode(code *model.OAuthCode) error
	GetAndConsumeCode(codeStr string) (*model.OAuthCode, error)
	DeleteExpiredCodes() error
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
