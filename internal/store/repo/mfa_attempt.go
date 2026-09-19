package repo

import (
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MfaAttemptRepository interface {
	// RecordFailedAttempt increments the failed attempt counter for a challenge
	// Returns true if the challenge should be locked (exceeded max attempts)
	RecordFailedAttempt(challengeKey string, userID uint, maxAttempts int) (bool, error)
	
	// IsLocked checks if a challenge is locked due to excessive failures
	IsLocked(challengeKey string) (bool, error)
	
	// ClearAttempts removes the attempt tracker (called on successful validation)
	ClearAttempts(challengeKey string) error
	
	// CleanupExpired removes expired attempt trackers
	CleanupExpired() error
	
	// MarkConsumed atomically marks a challenge as consumed (locked) to prevent replay
	// Returns an error if the challenge was already consumed or locked
	MarkConsumed(challengeKey string, userID uint) error
	
	// IsConsumed checks if a challenge has been consumed
	IsConsumed(challengeKey string) (bool, error)
}

type mfaAttemptRepository struct {
	db *gorm.DB
}

func NewMfaAttemptRepository(db *gorm.DB) MfaAttemptRepository {
	return &mfaAttemptRepository{db: db}
}

// RecordFailedAttempt increments the failed attempt counter and locks if threshold exceeded
func (r *mfaAttemptRepository) RecordFailedAttempt(challengeKey string, userID uint, maxAttempts int) (bool, error) {
	// Use upsert to atomically increment or create the tracker
	tracker := model.MfaAttemptTracker{
		ChallengeKey:   challengeKey,
		UserID:         userID,
		FailedAttempts: 1,
		Locked:         false,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	// Upsert: if exists, increment FailedAttempts; if not, insert
	err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "challenge_key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"failed_attempts": gorm.Expr("mfa_attempt_trackers.failed_attempts + 1"),
			"updated_at":      time.Now(),
		}),
	}).Create(&tracker).Error

	if err != nil {
		return false, err
	}

	// Fetch the current state to check if we should lock
	var current model.MfaAttemptTracker
	if err := r.db.Where("challenge_key = ?", challengeKey).First(&current).Error; err != nil {
		return false, err
	}

	// Lock if threshold exceeded
	if current.FailedAttempts >= maxAttempts && !current.Locked {
		current.Locked = true
		if err := r.db.Save(&current).Error; err != nil {
			return false, err
		}
		return true, nil
	}

	return current.Locked, nil
}

// IsLocked checks if a challenge is currently locked
func (r *mfaAttemptRepository) IsLocked(challengeKey string) (bool, error) {
	var tracker model.MfaAttemptTracker
	err := r.db.Where("challenge_key = ? AND locked = ? AND expires_at > ?", 
		challengeKey, true, time.Now()).First(&tracker).Error
	
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	return tracker.Locked, nil
}

// ClearAttempts removes the attempt tracker for a challenge
func (r *mfaAttemptRepository) ClearAttempts(challengeKey string) error {
	return r.db.Where("challenge_key = ?", challengeKey).Delete(&model.MfaAttemptTracker{}).Error
}

// CleanupExpired removes expired attempt trackers
func (r *mfaAttemptRepository) CleanupExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&model.MfaAttemptTracker{}).Error
}

// MarkConsumed atomically marks a challenge as consumed to prevent replay attacks
// Returns an error if the challenge was already consumed/locked
func (r *mfaAttemptRepository) MarkConsumed(challengeKey string, userID uint) error {
	// Attempt to insert a locked tracker atomically
	// If it already exists, the unique constraint will prevent insertion
	tracker := model.MfaAttemptTracker{
		ChallengeKey:   challengeKey,
		UserID:         userID,
		FailedAttempts: 0,
		Locked:         true,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}
	
	// Use a transaction to ensure atomicity
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Check if already exists and is locked
		var existing model.MfaAttemptTracker
		err := tx.Where("challenge_key = ?", challengeKey).First(&existing).Error
		
		if err == nil {
			// Record exists - check if already consumed/locked
			if existing.Locked {
				return gorm.ErrDuplicatedKey // Token already consumed
			}
			// Update to locked
			return tx.Model(&existing).Update("locked", true).Error
		}
		
		if err != gorm.ErrRecordNotFound {
			return err
		}
		
		// Record doesn't exist - create it as locked
		return tx.Create(&tracker).Error
	})
}

// IsConsumed checks if a challenge has been consumed (marked as locked for replay prevention)
func (r *mfaAttemptRepository) IsConsumed(challengeKey string) (bool, error) {
	var tracker model.MfaAttemptTracker
	err := r.db.Where("challenge_key = ? AND locked = ? AND expires_at > ?", 
		challengeKey, true, time.Now()).First(&tracker).Error
	
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	return true, nil
}
