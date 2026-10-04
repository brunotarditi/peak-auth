package repo

import (
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
)

type UserIdentityRepository interface {
	FindByProviderAndUID(provider, uid string) (*model.UserIdentity, error)
	FindByUserID(userID uint) ([]model.UserIdentity, error)
	Create(identity *model.UserIdentity) error
	UpdateLastLogin(id uint) error
	Delete(id uint) error
}

type userIdentityRepository struct {
	db *gorm.DB
}

func NewUserIdentityRepository(db *gorm.DB) UserIdentityRepository {
	return &userIdentityRepository{db: db}
}

func (r *userIdentityRepository) FindByProviderAndUID(provider, uid string) (*model.UserIdentity, error) {
	var identity model.UserIdentity
	err := r.db.Preload("User").Preload("User.Profile").
		Where("provider = ? AND provider_user_id = ?", provider, uid).
		First(&identity).Error
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func (r *userIdentityRepository) FindByUserID(userID uint) ([]model.UserIdentity, error) {
	var identities []model.UserIdentity
	err := r.db.Where("user_id = ?", userID).Order("created_at ASC").Find(&identities).Error
	return identities, err
}

func (r *userIdentityRepository) Create(identity *model.UserIdentity) error {
	return r.db.Create(identity).Error
}

func (r *userIdentityRepository) UpdateLastLogin(id uint) error {
	return r.db.Model(&model.UserIdentity{}).Where("id = ?", id).Update("last_login_at", time.Now()).Error
}

func (r *userIdentityRepository) Delete(id uint) error {
	return r.db.Delete(&model.UserIdentity{}, id).Error
}
