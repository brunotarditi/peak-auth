package repository

import (
	"crypto/sha256"
	"peak-auth/model"
	"time"

	"gorm.io/gorm"
)

type EmailVerificationRepository interface {
	CreateEmailVerification(verification *model.EmailVerification) error
	FindEmailVerification(token string) (*model.EmailVerification, error)
	UpdateUsedAt(verification *model.EmailVerification, usedAt time.Time) error
	FindLatestByUserIDAndAppID(userID, appID uint) (*model.EmailVerification, error)
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
	// 1. Calculamos el hash del token recibido una sola vez
	hashedToken := sha256.Sum256([]byte(plainToken))

	var verification model.EmailVerification
	// 2. Buscamos directamente por el hash en la base de datos (O(1) con índice)
	err := r.db.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", hashedToken[:], time.Now()).First(&verification).Error
	if err != nil {
		return nil, err
	}

	return &verification, nil
}

func (r *emailVerification) UpdateUsedAt(verification *model.EmailVerification, usedAt time.Time) error {
	return r.db.Model(verification).Update("used_at", usedAt).Error
}

func (r *emailVerification) FindLatestByUserIDAndAppID(userID, appID uint) (*model.EmailVerification, error) {
	var verification model.EmailVerification
	err := r.db.Where("user_id = ? AND application_id = ?", userID, appID).Order("created_at desc").First(&verification).Error
	return &verification, err
}
