package repository

import (
	"fmt"
	"peak-auth/model"
	"peak-auth/response"

	"gorm.io/gorm"
)

type UserApplicationRoleRepository interface {
	AssignRole(userID, appID, roleID uint) error
	FindRolesByUserAndApp(userID, appID uint) ([]model.Role, error)
	CountUsersByApp(appID uint) (int64, error)
	HasRole(userID uint, roleName string) (bool, error)
	GetUsersByApp(appID uint) ([]model.User, error)
	GetUserRolesInApp(userID, appID uint) ([]string, error)
	GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error)
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
	var existing model.UserApplicationRole
	// Evitamos duplicados: misma app, mismo usuario, mismo rol
	err := r.db.Where("user_id = ? AND application_id = ? AND role_id = ?", userID, appID, roleID).
		First(&existing).Error

	if err == nil {
		return fmt.Errorf("el usuario ya tiene este rol en esta aplicación")
	}

	uar := model.UserApplicationRole{
		UserID:        userID,
		ApplicationID: appID,
		RoleID:        roleID,
	}
	return r.db.Create(&uar).Error
}

// FindRolesByUserAndApp obtiene los roles que tiene un usuario en una aplicación.
func (r *userApplicationRoleRepository) FindRolesByUserAndApp(userID, appID uint) ([]model.Role, error) {
	var roles []model.Role
	err := r.db.Table("roles").
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ?", userID, appID).
		Find(&roles).Error
	return roles, err
}

// CountUsersByApp cuenta usuarios únicos asociados a la aplicación (para bootstrapping).
func (r *userApplicationRoleRepository) CountUsersByApp(appID uint) (int64, error) {
	var count int64
	err := r.db.Model(&model.UserApplicationRole{}).Where("application_id = ?", appID).Distinct("user_id").Count(&count).Error
	return count, err
}

// HasRole verifica si el usuario tiene un rol con nombre `roleName` en alguna aplicación.
func (r *userApplicationRoleRepository) HasRole(userID uint, roleName string) (bool, error) {
	var count int64
	err := r.db.Model(&model.UserApplicationRole{}).
		Joins("JOIN roles r ON r.id = user_application_roles.role_id").
		Where("user_application_roles.user_id = ? AND r.name = ?", userID, roleName).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *userApplicationRoleRepository) GetUsersByApp(appID uint) ([]model.User, error) {
	var users []model.User
	err := r.db.Model(&model.User{}).
		Preload("Profile").
		Joins("JOIN user_application_roles uar ON uar.user_id = users.id").
		Where("uar.application_id = ?", appID).
		Group("users.id").
		Find(&users).Error
	return users, err
}

func (r *userApplicationRoleRepository) GetUserRolesInApp(userID, appID uint) ([]string, error) {
	var roles []string
	err := r.db.Model(&model.Role{}).
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ?", userID, appID).
		Pluck("roles.name", &roles).Error
	return roles, err
}

func (r *userApplicationRoleRepository) GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error) {
	var rows []response.UserAppRow

	err := r.db.Table("users").
		Select("users.id, users.email, users.is_verified, users.is_active, profiles.first_name, profiles.last_name, roles.name as role_name").
		Joins("JOIN profiles ON profiles.user_id = users.id").
		Joins("JOIN user_application_roles uar ON uar.user_id = users.id").
		Joins("JOIN roles ON roles.id = uar.role_id").
		Where("uar.application_id = ? AND uar.deleted_at IS NULL", appID).
		Scan(&rows).Error

	return rows, err
}
