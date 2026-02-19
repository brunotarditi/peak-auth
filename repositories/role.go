package repositories

import (
	"peak-auth/models"
	"strings"

	"gorm.io/gorm"
)

type RoleRepository interface {
	FindByRoleName(roleName string) (models.Role, error)
	Create(role *models.Role) error
}

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepositoryRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{db: db}
}

// Busca el rol por el nombre del rol
func (r *roleRepository) FindByRoleName(roleName string) (models.Role, error) {
	var role models.Role
	err := r.db.Where("name = ?", strings.ToUpper(roleName)).First(&role).Error
	return role, err
}

// Crea un registro de rol en la BD
func (r *roleRepository) Create(role *models.Role) error {
	return r.db.Create(role).Error
}
