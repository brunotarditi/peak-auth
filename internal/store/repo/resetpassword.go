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
	FindValidPasswordResetWithLock(token string) (*model.PasswordReset, error)
	UpdatePassword(userID uint, hashed string) error
	MarkPasswordResetUsed(resetID uint, usedAt time.Time) error
	CreatePasswordReset(reset *model.PasswordReset) error
	CountResetsThisMonth(userID uint) (int64, error)
	InvalidateAllUserTokens(userID uint) error
	InvalidateAllUserTokensAndCreate(userID uint, reset *model.PasswordReset) error
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

// FindValidPasswordResetWithLock finds a valid password reset token and locks the row
// using SELECT FOR UPDATE to prevent concurrent redemptions of the same or different tokens
// for the same user. This method should only be called within a transaction.
func (r *passwordReset) FindValidPasswordResetWithLock(plainToken string) (*model.PasswordReset, error) {
	// 1. Calculate the hash of the received token
	hashedToken := sha256.Sum256([]byte(plainToken))

	var reset model.PasswordReset
	// 2. Find the token with row-level lock (SELECT FOR UPDATE)
	// This prevents concurrent transactions from reading/modifying this row
	err := r.db.Clauses(gorm.Locking{Strength: "UPDATE"}).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", hashedToken[:], time.Now()).
		First(&reset).Error
	if err != nil {
		return nil, err
	}

	return &reset, nil
}

func (r *passwordReset) UpdatePassword(userID uint, hashed string) error {
	now := time.Now()
	return r.db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"password":            hashed,
		"password_changed_at": &now,
	}).Error
}

func (r *passwordReset) MarkPasswordResetUsed(resetID uint, usedAt time.Time) error {
	result := r.db.Model(&model.PasswordReset{}).Where("id = ? AND used_at IS NULL", resetID).UpdateColumn("used_at", usedAt)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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

func (r *passwordReset) InvalidateAllUserTokens(userID uint) error {
	now := time.Now()
	return r.db.Model(&model.PasswordReset{}).
		Where("user_id = ? AND used_at IS NULL AND expires_at > ?", userID, now).
		UpdateColumn("used_at", now).Error
}

// InvalidateAllUserTokensAndCreate atomically invalidates all existing tokens for a user
// and creates a new one within a single transaction with row-level locking to prevent race conditions.
// This ensures the single-active-token invariant is maintained even under concurrent requests.
func (r *passwordReset) InvalidateAllUserTokensAndCreate(userID uint, reset *model.PasswordReset) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		
		// 1. Lock all password reset rows for this user to prevent concurrent token generation
		// SELECT ... FOR UPDATE ensures no other transaction can read or modify these rows
		// until this transaction completes
		var existingResets []model.PasswordReset
		if err := tx.Clauses(gorm.Locking{Strength: "UPDATE"}).
			Where("user_id = ?", userID).
			Find(&existingResets).Error; err != nil {
			return err
		}
		
		// 2. Invalidate all existing unused tokens for this user
		if err := tx.Model(&model.PasswordReset{}).
			Where("user_id = ? AND used_at IS NULL AND expires_at > ?", userID, now).
			UpdateColumn("used_at", now).Error; err != nil {
			return err
		}
		
		// 3. Create the new token (now guaranteed to be the only active one)
		if err := tx.Create(reset).Error; err != nil {
			return err
		}
		
		return nil
	})
}
