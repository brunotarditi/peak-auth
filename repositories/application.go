package repositories

import (
	"peak-auth/models"
	"peak-auth/responses"

	"peak-auth/utils"

	"gorm.io/gorm"
)

type ApplicationRepository interface {
	Create(app *models.Application) error
	FindByID(id uint) (models.Application, error)
	FindByAppID(appID string) (models.Application, error)
	ValidateSecret(appID string, secret string) (models.Application, error)
	FindAll() ([]models.Application, error)
	Update(app *models.Application) error
	GetAppsWithUserCount() ([]responses.AppStatsResponse, error)
}

type applicationRepository struct {
	db *gorm.DB
}

// NewApplicationRepository construye el repositorio de aplicaciones.
func NewApplicationRepository(db *gorm.DB) ApplicationRepository {
	return &applicationRepository{db: db}
}

// Create inserta una nueva App en BD.
func (r *applicationRepository) Create(app *models.Application) error {
	return r.db.Create(app).Error
}

// FindByID devuelve una aplicación por su ID numérico.
func (r *applicationRepository) FindByAppID(appID string) (models.Application, error) {
	var app models.Application
	err := r.db.Where("app_id = ? AND is_active = ?", appID, true).First(&app).Error
	return app, err
}

// ValidateSecret comprueba el secret proporcionado para la app pública y
// devuelve la aplicación si la credencial es válida.
func (r *applicationRepository) ValidateSecret(appID string, secret string) (models.Application, error) {
	app, err := r.FindByAppID(appID)
	if err != nil {
		return models.Application{}, err
	}
	// SecretKey stores the hashed secret
	if !utils.CheckPasswordHash(secret, app.SecretKey) {
		return models.Application{}, gorm.ErrRecordNotFound
	}
	return app, nil
}

// FindAll devuelve todas las aplicaciones.
func (r *applicationRepository) FindAll() ([]models.Application, error) {
	var apps []models.Application
	err := r.db.Find(&apps).Error
	return apps, err
}

// FindByAppID busca una aplicación pública por su AppID (string).
func (r *applicationRepository) FindByID(id uint) (models.Application, error) {
	var app models.Application
	err := r.db.First(&app, id).Error
	return app, err
}

// Update guarda cambios en una Application existente.
func (r *applicationRepository) Update(app *models.Application) error {
	return r.db.Save(app).Error
}

// Agrupamos por aplicación y contamos usuarios únicos en UserApplicationRole
func (r *applicationRepository) GetAppsWithUserCount() ([]responses.AppStatsResponse, error) {
	var stats []responses.AppStatsResponse
	err := r.db.Table("applications").
		Select("applications.id, applications.name, applications.app_id, applications.description, COUNT(DISTINCT uar.user_id) as user_count").
		Joins("LEFT JOIN user_application_roles uar ON uar.application_id = applications.id").
		Where("applications.deleted_at IS NULL"). // Importante si usas gorm.Model (Soft Delete)
		Group("applications.id, applications.name, applications.app_id, applications.description").
		Scan(&stats).Error
	return stats, err
}
