package repository

import (
	"peak-auth/model"
	"time"

	"gorm.io/gorm"
)

type UserRepository interface {
	FindAll() ([]model.User, error)
	CreateWithProfile(user *model.User, profile *model.Profile) error
	VerifyUserEmail(userID uint, verificationID uint) error
	FindByEmail(email string) (model.User, error)
	FindById(ID uint) (model.User, error)
	Update(user *model.User) error
	UpdateColumn(column string, value interface{}, id uint) error
	ExistsByEmail(email string) (bool, error)
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

// Update actualiza un usuario en BD.
func (r *userRepository) Update(user *model.User) error {
	return r.db.Save(user).Error
}

// UpdateColumn actualiza una columna de un usuario en BD.
func (r *userRepository) UpdateColumn(column string, value interface{}, id uint) error {
	return r.db.Model(&model.User{}).Where("id = ? AND is_active = ?", id, true).Update(column, value).Error
}

// ExistsByEmail verifica si ese email ya existe.
func (r *userRepository) ExistsByEmail(email string) (bool, error) {
	var count int64
	err := r.db.Model(&model.User{}).Where("email = ?", email).Count(&count).Error
	return count > 0, err
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

// VerifyUserEmail verifica que el usuario recibe el email para completar el registro
func (r *userRepository) VerifyUserEmail(userID uint, verificationID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// 1. Marcar usuario como verificado
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Update("is_verified", true).Error; err != nil {
			return err
		}
		// 2. Marcar el token de verificación como usado
		return tx.Model(&model.EmailVerification{}).Where("id = ?", verificationID).Update("used_at", time.Now()).Error
	})
}
