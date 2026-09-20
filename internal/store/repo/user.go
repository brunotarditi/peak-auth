package repo

import (
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
)

type UserRepository interface {
	FindAll() ([]model.User, error)
	CreateWithProfile(user *model.User, profile *model.Profile) error
	VerifyUserEmail(userID uint, verificationID uint) error
	VerifyUserEmailByToken(tokenHash []byte) (uint, uint, error)
	FindByEmail(email string) (model.User, error)
	FindById(ID uint) (model.User, error)
	UpdateColumn(column string, value interface{}, id uint) error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepositoryRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

// FindAll devuelve todas los usuarios con sus perfiles.
func (r *userRepository) FindAll() ([]model.User, error) {
	var users []model.User
	err := r.db.Preload("Profile").Order("created_at DESC").Find(&users).Error
	return users, err
}

// FindByEmail devuelve el usuario a través de email.
func (r *userRepository) FindByEmail(email string) (model.User, error) {
	var user model.User
	err := r.db.Where("email = ?", email).First(&user).Error
	return user, err
}

// FindById devuelve el usuario a través de ID.
func (r *userRepository) FindById(id uint) (model.User, error) {
	var user model.User
	err := r.db.Preload("Profile").First(&user, id).Error
	return user, err
}

// UpdateColumn actualiza una columna de un usuario en BD.
func (r *userRepository) UpdateColumn(column string, value interface{}, id uint) error {
	return r.db.Model(&model.User{}).Where("id = ? AND is_active = ?", id, true).Update(column, value).Error
}

// Create inserta un nuevo usuario con su perfil en BD.
func (r *userRepository) CreateWithProfile(user *model.User, profile *model.Profile) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		profile.UserID = user.ID
		return tx.Create(profile).Error
	})
}

// VerifyUserEmail verifica que el usuario recibe el email para completar el registro.
// Atomically claims the verification token with a conditional update to prevent concurrent replay.
func (r *userRepository) VerifyUserEmail(userID uint, verificationID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Atomically claim the verification token with a conditional update.
		// Only succeed if the token is unused and not expired.
		result := tx.Model(&model.EmailVerification{}).
			Where("id = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?", verificationID, userID, time.Now()).
			Update("used_at", time.Now())

		if result.Error != nil {
			return result.Error
		}

		// Check that exactly one row was updated (token was successfully claimed)
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound // Token already used, expired, or doesn't exist
		}

		// Only update user verification status if token claim succeeded
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Update("is_verified", true).Error; err != nil {
			return err
		}

		return nil
	})
}

// VerifyUserEmailByToken atomically validates and consumes an email verification token.
// Returns userID and applicationID on success, or an error if the token is invalid, expired, or already used.
// This method prevents concurrent replay by using a conditional update with RowsAffected validation.
func (r *userRepository) VerifyUserEmailByToken(tokenHash []byte) (uint, uint, error) {
	var userID, appID uint

	err := r.db.Transaction(func(tx *gorm.DB) error {
		// First, atomically claim the verification token with a conditional update.
		// Only succeed if the token is unused and not expired.
		var verification model.EmailVerification
		result := tx.Model(&model.EmailVerification{}).
			Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
			First(&verification)

		if result.Error != nil {
			return result.Error
		}

		// Now update the same row, but only if it's still unused
		updateResult := tx.Model(&model.EmailVerification{}).
			Where("id = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?", verification.ID, verification.UserID, time.Now()).
			Update("used_at", time.Now())

		if updateResult.Error != nil {
			return updateResult.Error
		}

		// Check that exactly one row was updated (token was successfully claimed)
		if updateResult.RowsAffected != 1 {
			return gorm.ErrRecordNotFound // Token already used by concurrent request
		}

		// Only update user verification status if token claim succeeded
		if err := tx.Model(&model.User{}).Where("id = ?", verification.UserID).Update("is_verified", true).Error; err != nil {
			return err
		}

		userID = verification.UserID
		appID = verification.ApplicationID
		return nil
	})

	if err != nil {
		return 0, 0, err
	}

	return userID, appID, nil
}
