package repository

import (
	"peak-auth/model"
	"peak-auth/utils"
	"time"

	"gorm.io/gorm"
)

type PasswordResetRepository interface {
	CheckLastTimeTokenReset(userId uint) (time.Time, error)
	FindValidPasswordReset(token string) (*model.PasswordReset, error)
	UpdatePassword(userID uint, hashed string) error
	MarkPasswordResetUsed(resetID uint, usedAt time.Time) error
	CreatePasswordReset(reset *model.PasswordReset) error
}

type passwordReset struct {
	db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) PasswordResetRepository {
	return &passwordReset{db: db}
}

func (r *passwordReset) CheckLastTimeTokenReset(userId uint) (time.Time, error) {
	var lastReset model.PasswordReset
	err := r.db.Where("user_id = ? AND used_at IS NULL AND expires_at > ?", userId, time.Now()).Order("created_at desc").First(&lastReset).Error
	return lastReset.CreatedAt, err
}

func (r *passwordReset) FindValidPasswordReset(plainToken string) (*model.PasswordReset, error) {
	var resets []model.PasswordReset
	if err := r.db.Where("used_at IS NULL AND expires_at > ?", time.Now()).Find(&resets).Error; err != nil {
		return nil, err
	}

	for _, reset := range resets {
		if reset.ExpiresAt.Before(time.Now()) {
			continue
		}
		if utils.CheckTokenSHA256(plainToken, reset.TokenHash) {
			return &reset, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (r *passwordReset) UpdatePassword(userID uint, hashed string) error {
	return r.db.Model(&model.User{}).Where("id = ?", userID).UpdateColumn("password", hashed).Error
}

func (r *passwordReset) MarkPasswordResetUsed(resetID uint, usedAt time.Time) error {
	return r.db.Model(&model.PasswordReset{}).Where("id = ? AND used_at IS NULL", resetID).UpdateColumn("used_at", usedAt).Error
}

func (r *passwordReset) CreatePasswordReset(reset *model.PasswordReset) error {
	return r.db.Create(reset).Error
}
