package repository

import (
	"peak-auth/model"

	"gorm.io/gorm"
)

type ApplicationRuleRepository interface {
	GetByCode(appID uint, code string) (model.ApplicationRules, error)
	GetRulesByAppID(appID uint) ([]model.ApplicationRules, error)
	CreateDefaultRules(appID uint) error
	CreateRule(appID uint, code string, value []byte) error
	UpdateRuleValue(appID uint, code string, value []byte) error
	DeleteRule(appID uint, code string) error
}

type applicationRuleRepository struct {
	db *gorm.DB
}

func NewApplicationRuleRepository(db *gorm.DB) ApplicationRuleRepository {
	return &applicationRuleRepository{db: db}
}

// GetByCode devuelve la regla activa de una aplicación por su código (p.ej. "PWD_STRENGTH").
func (r *applicationRuleRepository) GetByCode(appID uint, code string) (model.ApplicationRules, error) {
	var rule model.ApplicationRules
	err := r.db.Where("application_id = ? AND code = ? AND is_active = ?", appID, code, true).First(&rule).Error
	return rule, err
}

// GetRulesByAppID devuelve todas las reglas activas asociadas a una aplicación.
func (r *applicationRuleRepository) GetRulesByAppID(appID uint) ([]model.ApplicationRules, error) {
	var rules []model.ApplicationRules
	err := r.db.Where("application_id = ? AND is_active = ?", appID, true).Find(&rules).Error
	return rules, err
}

func (r *applicationRuleRepository) CreateDefaultRules(appID uint) error {
	// STARTER PACK de reglas para una nueva aplicación
	defs := []model.ApplicationRules{
		{ApplicationID: appID, Code: "REGISTRATION_POLICY", Value: []byte(`{"mode": "public", "require_email_verification": true, "default_role": "USER"}`), IsActive: true},
		{ApplicationID: appID, Code: "PWD_POLICY", Value: []byte(`{"min_length": 8, "require_uppercase": true, "require_numbers": true, "require_symbols": true}`), IsActive: true},
		{ApplicationID: appID, Code: "SESSION_POLICY", Value: []byte(`{"token_expiration_minutes": 1440, "max_failed_logins": 5}`), IsActive: true},
		{ApplicationID: appID, Code: "AUTHZ_POLICY", Value: []byte(`{"enable_roles": true}`), IsActive: true},
	}
	for _, d := range defs {
		if err := r.db.Create(&d).Error; err != nil {
			return err
		}
	}
	return nil
}

// CreateRule crea una nueva regla para la app, verificando que no exista el código
func (r *applicationRuleRepository) CreateRule(appID uint, code string, value []byte) error {
	var rule model.ApplicationRules
	// Comprobar si ya existe una regla activa con ese código
	err := r.db.Where("application_id = ? AND code = ? AND is_active = ?", appID, code, true).First(&rule).Error
	if err == nil {
		return gorm.ErrDuplicatedKey // Ya existe
	}

	newRule := model.ApplicationRules{
		ApplicationID: appID,
		Code:          code,
		Value:         value,
		IsActive:      true,
	}
	return r.db.Create(&newRule).Error
}

// UpdateRuleValue actualiza solo el valor de una regla existente
func (r *applicationRuleRepository) UpdateRuleValue(appID uint, code string, value []byte) error {
	result := r.db.Model(&model.ApplicationRules{}).
		Where("application_id = ? AND code = ? AND is_active = ?", appID, code, true).
		Updates(map[string]interface{}{
			"value": value,
		})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// DeleteRule hace un soft delete
func (r *applicationRuleRepository) DeleteRule(appID uint, code string) error {
	// Gorm soft delete con deleted_at y también bajamos el flag is_active
	return r.db.Model(&model.ApplicationRules{}).
		Where("application_id = ? AND code = ? AND is_active = ?", appID, code, true).
		Updates(map[string]interface{}{
			"is_active": false,
		}).Delete(&model.ApplicationRules{}).Error
}
