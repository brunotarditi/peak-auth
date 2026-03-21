package repository

import (
	"peak-auth/model"
	"strings"
	"time"

	"gorm.io/gorm"
)

type RoleRepository interface {
	FindByRoleName(roleName string) (model.Role, error)
	Create(role *model.Role) error
	FindAll() ([]model.Role, error)
	CountUsersWithRole(roleID uint) (int64, error)
	Delete(roleID uint) error
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

// CountUsersWithRole cuenta cuántos usuarios tienen este rol asignado.
func (r *roleRepository) CountUsersWithRole(roleID uint) (int64, error) {
	var count int64
	err := r.db.Model(&model.UserApplicationRole{}).
		Where("role_id = ? AND deleted_at IS NULL", roleID).
		Count(&count).Error
	return count, err
}

// Delete elimina de forma lógica un rol.
func (r *roleRepository) Delete(roleID uint) error {
	return r.db.Model(&model.Role{}).Where("id = ?", roleID).Updates(map[string]interface{}{
		"deleted_at": time.Now(),
	}).Error
}
