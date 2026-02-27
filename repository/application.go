package repository

import (
	"peak-auth/model"
	"peak-auth/response"

	"peak-auth/utils"

	"gorm.io/gorm"
)

type ApplicationRepository interface {
	Create(app *model.Application) error
	FindByID(id uint) (model.Application, error)
	FindByAppID(appID string) (model.Application, error)
	ValidateSecret(appID string, secret string) (model.Application, error)
	FindAll() ([]model.Application, error)
	Update(app *model.Application) error
	GetAppsWithUserCount() ([]response.AppStatsResponse, error)
}

type applicationRepository struct {
	db *gorm.DB
}

// NewApplicationRepository construye el repositorio de aplicaciones.
func NewApplicationRepository(db *gorm.DB) ApplicationRepository {
	return &applicationRepository{db: db}
}

// Create inserta una nueva App en BD.
func (r *applicationRepository) Create(app *model.Application) error {
	return r.db.Create(app).Error
}

// FindByID devuelve una aplicación por su ID numérico.
func (r *applicationRepository) FindByAppID(appID string) (model.Application, error) {
	var app model.Application
	err := r.db.Where("app_id = ? AND is_active = ?", appID, true).First(&app).Error
	return app, err
}

// ValidateSecret comprueba el secret proporcionado para la app pública y
// devuelve la aplicación si la credencial es válida.
func (r *applicationRepository) ValidateSecret(appID string, secret string) (model.Application, error) {
	app, err := r.FindByAppID(appID)
	if err != nil {
		return model.Application{}, err
	}
	// SecretKey stores the hashed secret
	if !utils.CheckPasswordHash(secret, app.SecretKey) {
		return model.Application{}, gorm.ErrRecordNotFound
	}
	return app, nil
}

// FindAll devuelve todas las aplicaciones.
func (r *applicationRepository) FindAll() ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Find(&apps).Error
	return apps, err
}

// FindByAppID busca una aplicación pública por su AppID (string).
func (r *applicationRepository) FindByID(id uint) (model.Application, error) {
	var app model.Application
	err := r.db.First(&app, id).Error
	return app, err
}

// Update guarda cambios en una Application existente.
func (r *applicationRepository) Update(app *model.Application) error {
	return r.db.Save(app).Error
}

// Agrupamos por aplicación y contamos usuarios únicos en UserApplicationRole
func (r *applicationRepository) GetAppsWithUserCount() ([]response.AppStatsResponse, error) {
	var stats []response.AppStatsResponse
	err := r.db.Table("applications").
		Select("applications.id, applications.name, applications.app_id, applications.description, COUNT(DISTINCT uar.user_id) as user_count").
		Joins("LEFT JOIN user_application_roles uar ON uar.application_id = applications.id").
		Where("applications.deleted_at IS NULL"). // Importante si usas gorm.Model (Soft Delete)
		Group("applications.id, applications.name, applications.app_id, applications.description").
		Scan(&stats).Error
	return stats, err
}
