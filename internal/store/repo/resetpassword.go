package repo

import (
	"crypto/sha256"
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
)

type PasswordResetRepository interface {
	CheckLastTimeTokenReset(userId uint) (time.Time, error)
	FindValidPasswordReset(token string) (*model.PasswordReset, error)
	UpdatePassword(userID uint, hashed string) error
	MarkPasswordResetUsed(resetID uint, usedAt time.Time) error
	CreatePasswordReset(reset *model.PasswordReset) error
	CountResetsThisMonth(userID uint) (int64, error)
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
	// 1. Calculamos el hash del token recibido una sola vez
	hashedToken := sha256.Sum256([]byte(plainToken))

	var reset model.PasswordReset
	// 2. Buscamos directamente por el hash en la base de datos (O(1) con índice)
	err := r.db.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", hashedToken[:], time.Now()).First(&reset).Error
	if err != nil {
		return nil, err
	}

	return &reset, nil
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

func (r *passwordReset) CountResetsThisMonth(userID uint) (int64, error) {
	var count int64
	startOfMonth := time.Now().AddDate(0, 0, -time.Now().Day()+1)
	startOfDay := time.Date(startOfMonth.Year(), startOfMonth.Month(), startOfMonth.Day(), 0, 0, 0, 0, startOfMonth.Location())
	err := r.db.Model(&model.PasswordReset{}).
		Where("user_id = ? AND created_at >= ?", userID, startOfDay).
		Count(&count).Error
	return count, err
}
