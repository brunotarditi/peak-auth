package repo

import (
	"peak-auth/internal/store/model"
	"strings"
	"time"

	"gorm.io/gorm"
)

type RoleRepository interface {
	FindByRoleName(roleName string) (model.Role, error)
	FindGlobalByName(roleName string) (model.Role, error)
	FindByNameForApp(roleName string, appID uint) (model.Role, error)
	Create(role *model.Role) error
	FindAll() ([]model.Role, error)
	FindVisibleForApp(appID uint) ([]model.Role, error)
	CountUsersWithRole(roleID uint) (int64, error)
	Delete(roleID uint) error
}

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepositoryRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{db: db}
}

// FindAll devuelve únicamente los roles GLOBALES del sistema (application_id IS NULL).
// Se usa en contextos que no están asociados a una app específica.
func (r *roleRepository) FindAll() ([]model.Role, error) {
	var roles []model.Role
	err := r.db.Where("application_id IS NULL").Find(&roles).Error
	return roles, err
}

// FindVisibleForApp devuelve los roles que aplican a una aplicación:
// los roles GLOBALES del sistema + los roles propios de esa app.
func (r *roleRepository) FindVisibleForApp(appID uint) ([]model.Role, error) {
	var roles []model.Role
	err := r.db.Where("application_id IS NULL OR application_id = ?", appID).
		Order("application_id NULLS FIRST, name ASC").
		Find(&roles).Error
	return roles, err
}

// FindByRoleName mantiene compatibilidad: resuelve un rol GLOBAL del sistema por nombre.
func (r *roleRepository) FindByRoleName(roleName string) (model.Role, error) {
	return r.FindGlobalByName(roleName)
}

// FindGlobalByName busca un rol global del sistema (application_id IS NULL).
func (r *roleRepository) FindGlobalByName(roleName string) (model.Role, error) {
	var role model.Role
	err := r.db.Where("name = ? AND application_id IS NULL", strings.ToUpper(roleName)).First(&role).Error
	return role, err
}

// FindByNameForApp resuelve el rol asignable para una app a partir de un nombre.
// Prioriza el rol PROPIO de la app; si no existe, cae al rol GLOBAL del sistema.
func (r *roleRepository) FindByNameForApp(roleName string, appID uint) (model.Role, error) {
	name := strings.ToUpper(roleName)
	var role model.Role
	// 1) Rol propio de la app
	err := r.db.Where("name = ? AND application_id = ?", name, appID).First(&role).Error
	if err == nil {
		return role, nil
	}
	// 2) Rol global del sistema
	err = r.db.Where("name = ? AND application_id IS NULL", name).First(&role).Error
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
