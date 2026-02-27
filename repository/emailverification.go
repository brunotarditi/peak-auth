package repository

import (
	"peak-auth/model"
	"peak-auth/utils"
	"time"

	"gorm.io/gorm"
)

type EmailVerificationRepository interface {
	CreateEmailVerification(verification *model.EmailVerification) error
	FindEmailVerification(token string) (*model.EmailVerification, error)
	UpdateUsedAt(verification *model.EmailVerification, usedAt time.Time) error
}

type emailVerification struct {
	db *gorm.DB
}

func NewEmailVerificationRepositoryRepository(db *gorm.DB) EmailVerificationRepository {
	return &emailVerification{db: db}
}

func (r *emailVerification) CreateEmailVerification(verification *model.EmailVerification) error {
	return r.db.Create(verification).Error
}

func (r *emailVerification) FindEmailVerification(plainToken string) (*model.EmailVerification, error) {
	var verifications []model.EmailVerification

	if err := r.db.Where("used_at IS NULL AND expires_at > ?", time.Now()).Find(&verifications).Error; err != nil {
		return nil, err
	}
	for _, verification := range verifications {
		if verification.ExpiresAt.Before(time.Now()) {
			continue
		}

		if utils.CheckTokenSHA256(plainToken, verification.TokenHash) {
			return &verification, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (r *emailVerification) UpdateUsedAt(verification *model.EmailVerification, usedAt time.Time) error {
	return r.db.Model(verification).Update("used_at", usedAt).Error
}
