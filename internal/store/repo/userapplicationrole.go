package repo

import (
	"fmt"
	"peak-auth/internal/api/response"
	"peak-auth/internal/store/model"
	"time"

	"gorm.io/gorm"
)

type UserApplicationRoleRepository interface {
	AssignRole(userID, appID, roleID uint, accessTime ...*time.Time) error
	RevokeRole(userID, appID, roleID uint) error
	RevokeAccess(userID, appID uint) error
	UpdateAccessTime(userID, appID uint, startsAt, expiresAt *time.Time) error
	FindRolesByUserAndApp(userID, appID uint) ([]model.Role, error)
	//CountUsersByApp(appID uint) (int64, error)
	//HasRole(userID uint, roleName string) (bool, error)
	//GetUsersByApp(appID uint) ([]model.User, error)
	GetUserRolesInApp(userID, appID uint) ([]string, error)
	GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error)
	GetUsersWithRolesByAppPaginated(appID uint, page, limit int) ([]response.UserAppRow, int64, error)
	BelongsToApp(userID, appID uint) (bool, error)
	IsAppAdmin(userID, appID uint) (bool, error)
	HasAdminRoleInAnyApp(userID uint) (bool, error)
}

type userApplicationRoleRepository struct {
	db *gorm.DB
}

// NewUserApplicationRoleRepository crea el repositorio para user-application-role.
func NewUserApplicationRoleRepository(db *gorm.DB) UserApplicationRoleRepository {
	return &userApplicationRoleRepository{db: db}
}

// AssignRole asigna el `roleID` al `userID` dentro de la `appID`, evitando duplicados.
// Opcionalmente recibe startsAt y expiresAt para accesos temporales.
func (r *userApplicationRoleRepository) AssignRole(userID, appID, roleID uint, accessTime ...*time.Time) error {
	var startsAt, expiresAt *time.Time
	if len(accessTime) > 0 {
		startsAt = accessTime[0]
	}
	if len(accessTime) > 1 {
		expiresAt = accessTime[1]
	}

	var existing model.UserApplicationRole
	// Buscamos duplicados incluyendo registros eliminados lógicamente (soft-deleted)
	err := r.db.Unscoped().Where("user_id = ? AND application_id = ? AND role_id = ?", userID, appID, roleID).
		First(&existing).Error

	if err == nil {
		// Si el registro existe pero está borrado (deleted_at no es null), lo restauramos
		if existing.DeletedAt.Valid {
			updates := map[string]interface{}{
				"deleted_at":        nil,
				"access_starts_at":  startsAt,
				"access_expires_at": expiresAt,
			}
			return r.db.Unscoped().Model(&existing).Updates(updates).Error
		}
		// Si el registro ya existe activo, actualizamos las fechas de acceso si se enviaron
		if startsAt != nil || expiresAt != nil {
			updates := map[string]interface{}{
				"access_starts_at":  startsAt,
				"access_expires_at": expiresAt,
			}
			return r.db.Model(&existing).Updates(updates).Error
		}
		return fmt.Errorf("el usuario ya tiene este rol en esta aplicación")
	}

	uar := model.UserApplicationRole{
		UserID:          userID,
		ApplicationID:   appID,
		RoleID:          roleID,
		AccessStartsAt:  startsAt,
		AccessExpiresAt: expiresAt,
	}
	return r.db.Create(&uar).Error
}

// UpdateAccessTime actualiza las fechas de inicio y expiración de acceso para un usuario en una aplicación.
func (r *userApplicationRoleRepository) UpdateAccessTime(userID, appID uint, startsAt, expiresAt *time.Time) error {
	updates := map[string]interface{}{
		"access_starts_at":  startsAt,
		"access_expires_at": expiresAt,
	}
	return r.db.Model(&model.UserApplicationRole{}).
		Where("user_id = ? AND application_id = ? AND deleted_at IS NULL", userID, appID).
		Updates(updates).Error
}

// RevokeRole elimina lógicamente un rol específico del usuario en la app.
func (r *userApplicationRoleRepository) RevokeRole(userID, appID, roleID uint) error {
	return r.db.Model(&model.UserApplicationRole{}).
		Where("user_id = ? AND application_id = ? AND role_id = ? AND deleted_at IS NULL", userID, appID, roleID).
		Update("deleted_at", time.Now()).Error
}

// RevokeAccess elimina lógicamente todos los roles del usuario en la app.
func (r *userApplicationRoleRepository) RevokeAccess(userID, appID uint) error {
	result := r.db.Model(&model.UserApplicationRole{}).
		Where("user_id = ? AND application_id = ? AND deleted_at IS NULL", userID, appID).
		Updates(map[string]interface{}{
			"deleted_at": time.Now(),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no se encontró vinculación activa para este usuario")
	}
	return nil
}

// FindRolesByUserAndApp obtiene los roles que tiene un usuario en una aplicación respetando ventanas de acceso temporal.
func (r *userApplicationRoleRepository) FindRolesByUserAndApp(userID, appID uint) ([]model.Role, error) {
	now := time.Now()
	var roles []model.Role
	err := r.db.Table("roles").
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ? AND uar.deleted_at IS NULL", userID, appID).
		Where("(uar.access_expires_at IS NULL OR uar.access_expires_at > ?)", now).
		Where("(uar.access_starts_at IS NULL OR uar.access_starts_at <= ?)", now).
		Find(&roles).Error
	return roles, err
}

func (r *userApplicationRoleRepository) GetUserRolesInApp(userID, appID uint) ([]string, error) {
	now := time.Now()
	var roles []string
	err := r.db.Model(&model.Role{}).
		Joins("JOIN user_application_roles uar ON uar.role_id = roles.id").
		Where("uar.user_id = ? AND uar.application_id = ? AND uar.deleted_at IS NULL", userID, appID).
		Where("(uar.access_expires_at IS NULL OR uar.access_expires_at > ?)", now).
		Where("(uar.access_starts_at IS NULL OR uar.access_starts_at <= ?)", now).
		Pluck("roles.name", &roles).Error
	return roles, err
}

func (r *userApplicationRoleRepository) GetUsersWithRolesByApp(appID uint) ([]response.UserAppRow, error) {
	var rows []response.UserAppRow

	err := r.db.Table("users").
		Select("users.id, users.email, users.is_verified, users.is_active, users.mfa_enabled, profiles.first_name, profiles.last_name, roles.name as role_name, uar.access_starts_at, uar.access_expires_at").
		Joins("JOIN profiles ON profiles.user_id = users.id").
		Joins("JOIN user_application_roles uar ON uar.user_id = users.id").
		Joins("JOIN roles ON roles.id = uar.role_id").
		Where("uar.application_id = ? AND uar.deleted_at IS NULL", appID).
		Scan(&rows).Error

	now := time.Now()
	for i := range rows {
		if rows[i].AccessExpiresAt != nil && now.After(*rows[i].AccessExpiresAt) {
			rows[i].AccessStatus = "expired"
		} else if rows[i].AccessStartsAt != nil && now.Before(*rows[i].AccessStartsAt) {
			rows[i].AccessStatus = "scheduled"
		} else {
			rows[i].AccessStatus = "active"
		}
	}

	return rows, err
}

// GetUsersWithRolesByAppPaginated devuelve los usuarios con roles de forma paginada para una aplicación.
func (r *userApplicationRoleRepository) GetUsersWithRolesByAppPaginated(appID uint, page, limit int) ([]response.UserAppRow, int64, error) {
	var rows []response.UserAppRow
	var total int64

	baseQuery := r.db.Table("users").
		Joins("JOIN profiles ON profiles.user_id = users.id").
		Joins("JOIN user_application_roles uar ON uar.user_id = users.id").
		Joins("JOIN roles ON roles.id = uar.role_id").
		Where("uar.application_id = ? AND uar.deleted_at IS NULL", appID)

	// Contar el total de registros (usuarios únicos) para esta consulta
	if err := baseQuery.Distinct("users.id").Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * limit

	// Realizar la consulta con paginación agrupando por usuario para juntar sus roles
	err := baseQuery.
		Select("users.id, users.email, users.is_verified, users.is_active, users.failed_logins, users.mfa_enabled, profiles.first_name, profiles.last_name, string_agg(roles.name, ', ') as role_name, MIN(uar.access_starts_at) as access_starts_at, MAX(uar.access_expires_at) as access_expires_at").
		Group("users.id, users.email, users.is_verified, users.is_active, users.failed_logins, users.mfa_enabled, profiles.first_name, profiles.last_name").
		Order("users.email ASC").
		Offset(offset).
		Limit(limit).
		Scan(&rows).Error

	now := time.Now()
	for i := range rows {
		if rows[i].AccessExpiresAt != nil && now.After(*rows[i].AccessExpiresAt) {
			rows[i].AccessStatus = "expired"
		} else if rows[i].AccessStartsAt != nil && now.Before(*rows[i].AccessStartsAt) {
			rows[i].AccessStatus = "scheduled"
		} else {
			rows[i].AccessStatus = "active"
		}
	}

	return rows, total, err
}

func (r *userApplicationRoleRepository) HasAdminRoleInAnyApp(userID uint) (bool, error) {
	now := time.Now()
	var count int64
	err := r.db.Table("user_application_roles").
		Joins("JOIN roles ON roles.id = user_application_roles.role_id").
		Where("user_application_roles.user_id = ? AND roles.name IN ('ADMIN', 'OWNER') AND user_application_roles.deleted_at IS NULL", userID).
		Where("(user_application_roles.access_expires_at IS NULL OR user_application_roles.access_expires_at > ?)", now).
		Where("(user_application_roles.access_starts_at IS NULL OR user_application_roles.access_starts_at <= ?)", now).
		Count(&count).Error
	return count > 0, err
}

// BelongsToApp indica si el usuario pertenece a la aplicación (tiene al menos un
// rol activo y no expirado en ella), independientemente de cuál sea ese rol. Es la primera
// barrera de autorización: si no perteneces o tu acceso expiró, no ves ni accedes a la app.
func (r *userApplicationRoleRepository) BelongsToApp(userID, appID uint) (bool, error) {
	now := time.Now()
	var count int64
	err := r.db.Model(&model.UserApplicationRole{}).
		Where("user_id = ? AND application_id = ? AND deleted_at IS NULL", userID, appID).
		Where("(access_expires_at IS NULL OR access_expires_at > ?)", now).
		Where("(access_starts_at IS NULL OR access_starts_at <= ?)", now).
		Count(&count).Error
	return count > 0, err
}

// IsAppAdmin indica si el usuario tiene el rol ADMIN o OWNER activo y no expirado dentro de la aplicación
func (r *userApplicationRoleRepository) IsAppAdmin(userID, appID uint) (bool, error) {
	now := time.Now()
	var count int64
	err := r.db.Table("user_application_roles uar").
		Joins("JOIN roles ON roles.id = uar.role_id").
		Where("uar.user_id = ? AND uar.application_id = ? AND uar.deleted_at IS NULL AND roles.name IN ('ADMIN', 'OWNER')", userID, appID).
		Where("(uar.access_expires_at IS NULL OR uar.access_expires_at > ?)", now).
		Where("(uar.access_starts_at IS NULL OR uar.access_starts_at <= ?)", now).
		Count(&count).Error
	return count > 0, err
}
