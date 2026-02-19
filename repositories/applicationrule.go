package repositories

import (
	"peak-auth/models"

	"gorm.io/gorm"
)

type ApplicationRuleRepository interface {
	GetByCode(appID uint, code string) (models.ApplicationRules, error)
	GetRulesByAppID(appID uint) ([]models.ApplicationRules, error)
	CreateDefaultRules(appID uint) error
}

type applicationRuleRepository struct {
	db *gorm.DB
}

func NewApplicationRuleRepository(db *gorm.DB) ApplicationRuleRepository {
	return &applicationRuleRepository{db: db}
}

// GetByCode devuelve la regla activa de una aplicación por su código (p.ej. "PWD_STRENGTH").
func (r *applicationRuleRepository) GetByCode(appID uint, code string) (models.ApplicationRules, error) {
	var rule models.ApplicationRules
	err := r.db.Where("application_id = ? AND code = ? AND is_active = ?", appID, code, true).First(&rule).Error
	return rule, err
}

// GetRulesByAppID devuelve todas las reglas activas asociadas a una aplicación.
func (r *applicationRuleRepository) GetRulesByAppID(appID uint) ([]models.ApplicationRules, error) {
	var rules []models.ApplicationRules
	err := r.db.Where("application_id = ? AND is_active = ?", appID, true).Find(&rules).Error
	return rules, err
}

// CreateDefaultRules inserta reglas por defecto al crear una nueva aplicación.
// Para que al crear una App ya nazca con reglas base
func (r *applicationRuleRepository) CreateDefaultRules(appID uint) error {
	// Crear algunas reglas por defecto (SELF_REGISTER = allow true, no pwd strength)
	defs := []models.ApplicationRules{
		{ApplicationID: appID, Code: "SELF_REGISTER", Value: []byte(`{"allow": true}`), IsActive: true},
	}
	for _, d := range defs {
		if err := r.db.Create(&d).Error; err != nil {
			return err
		}
	}
	return nil
}
