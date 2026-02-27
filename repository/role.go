package repository

import (
	"peak-auth/model"
	"strings"

	"gorm.io/gorm"
)

type RoleRepository interface {
	FindByRoleName(roleName string) (model.Role, error)
	Create(role *model.Role) error
	FindAll() ([]model.Role, error)
}

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepositoryRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) FindAll() ([]model.Role, error) {
	var roles []model.Role
	err := r.db.Find(&roles).Error
	return roles, err
}

func (r *roleRepository) FindByRoleName(roleName string) (model.Role, error) {
	var role model.Role
	err := r.db.Where("name = ?", strings.ToUpper(roleName)).First(&role).Error
	return role, err
}

func (r *roleRepository) Create(role *model.Role) error {
	return r.db.Create(role).Error
}
