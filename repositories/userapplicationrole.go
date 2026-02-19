package repositories

import (
	"fmt"
	"peak-auth/models"

	"gorm.io/gorm"
)

type UserApplicationRoleRepository interface {
	AssignRole(userID, appID, roleID uint) error
	FindRolesByUserAndApp(userID, appID uint) ([]models.Role, error)
	CountUsersByApp(appID uint) (int64, error)
	HasRole(userID uint, roleName string) (bool, error)
	GetUsersByApp(appID uint) ([]models.User, error)
	GetUserRolesInApp(userID, appID uint) ([]string, error)
}

type userApplicationRoleRepository struct {
	db *gorm.DB
}

// NewUserApplicationRoleRepository crea el repositorio para user-application-role.
func NewUserApplicationRoleRepository(db *gorm.DB) UserApplicationRoleRepository {
	return &userApplicationRoleRepository{db: db}
}

// AssignRole asigna el `roleID` al `userID` dentro de la `appID`, evitando duplicados.
func (r *userApplicationRoleRepository) AssignRole(userID, appID, roleID uint) error {
	var existing models.UserApplicationRole
	// Evitamos duplicados: misma app, mismo usuario, mismo rol
	err := r.db.Where("user_id = ? AND application_id = ? AND role_id = ?", userID, appID, roleID).
		First(&existing).Error

	if err == nil {
		return fmt.Errorf("el usuario ya tiene este rol en esta aplicación")
	}

	uar := models.UserApplicationRole{
		UserID:        userID,
		ApplicationID: appID,
		RoleID:        roleID,
	}
	return r.db.Create(&uar).Error
}

// FindRolesByUserAndApp obtiene los roles que tiene un usuario en una aplicación.
func (r *userApplicationRoleRepository) FindRolesByUserAndApp(userID, appID uint) ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Table("roles").
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ?", userID, appID).
		Find(&roles).Error
	return roles, err
}

// CountUsersByApp cuenta usuarios únicos asociados a la aplicación (para bootstrapping).
func (r *userApplicationRoleRepository) CountUsersByApp(appID uint) (int64, error) {
	var count int64
	err := r.db.Model(&models.UserApplicationRole{}).Where("application_id = ?", appID).Distinct("user_id").Count(&count).Error
	return count, err
}

// HasRole verifica si el usuario tiene un rol con nombre `roleName` en alguna aplicación.
func (r *userApplicationRoleRepository) HasRole(userID uint, roleName string) (bool, error) {
	var count int64
	err := r.db.Model(&models.UserApplicationRole{}).
		Joins("JOIN roles r ON r.id = uar.role_id").
		Where("uar.user_id = ? AND r.name = ?", userID, roleName).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetUsersByApp devuelve los usuarios asociados a una aplicación (sin duplicados) y precarga el perfil.
func (r *userApplicationRoleRepository) GetUsersByApp(appID uint) ([]models.User, error) {
	var users []models.User
	err := r.db.Model(&models.User{}).
		Preload("Profile").
		Joins("JOIN user_application_roles uar ON uar.user_id = users.id").
		Where("uar.application_id = ?", appID).
		Group("users.id").
		Find(&users).Error
	return users, err
}

func (r *userApplicationRoleRepository) GetUserRolesInApp(userID, appID uint) ([]string, error) {
	var roles []string
	err := r.db.Model(&models.Role{}).
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ?", userID, appID).
		Pluck("roles.name", &roles).Error
	return roles, err
}
