package repository

import (
	"peak-auth/model"
	"peak-auth/response"
	"time"

	"peak-auth/utils"

	"gorm.io/gorm"
)

type ApplicationRepository interface {
	Create(app *model.Application) error
	FindByID(id uint) (model.Application, error)
	FindByAppID(appID string) (model.Application, error)
	FindByName(name string) (model.Application, error)
	ValidateSecret(appID string, secret string) (model.Application, error)
	FindAll() ([]model.Application, error)
	Update(app *model.Application) error
	Delete(id uint) error
	GetAppsWithUserCount() ([]response.AppStatsResponse, error)
	GetAppsForUser(userID uint) ([]response.AppStatsResponse, error)
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
func (r *applicationRepository) FindByID(id uint) (model.Application, error) {
	var app model.Application
	err := r.db.First(&app, id).Error
	return app, err
}

// FindByAppID devuelve una aplicación por su ID público (app_id).
func (r *applicationRepository) FindByAppID(appID string) (model.Application, error) {
	var app model.Application
	err := r.db.Where("app_id = ?", appID).First(&app).Error
	return app, err
}

// FindByName busca una aplicación activa por su nombre exacto.
func (r *applicationRepository) FindByName(name string) (model.Application, error) {
	var app model.Application
	err := r.db.Where("name = ? AND deleted_at IS NULL", name).First(&app).Error
	return app, err
}

// ValidateSecret comprueba el secret proporcionado para la app pública y
// devuelve la aplicación si la credencial es válida.
func (r *applicationRepository) ValidateSecret(appID string, secret string) (model.Application, error) {
	app, err := r.FindByAppID(appID)
	if err != nil {
		return model.Application{}, err
	}
	if !utils.CheckTokenSHA256(secret, []byte(app.SecretKey)) {
		return model.Application{}, gorm.ErrRecordNotFound
	}
	return app, nil
}

// FindAll devuelve todas las aplicaciones activas.
func (r *applicationRepository) FindAll() ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Where("deleted_at IS NULL").Find(&apps).Error
	return apps, err
}

// Update actualiza una aplicación.
func (r *applicationRepository) Update(app *model.Application) error {
	return r.db.Save(app).Error
}

// Delete hace un soft delete de la aplicación.
func (r *applicationRepository) Delete(id uint) error {
	return r.db.Model(&model.Application{}).Where("id = ?", id).Update("deleted_at", time.Now()).Error
}

// GetAppsWithUserCount devuelve estadísticas de uso por aplicación.
// Agrupamos por aplicación y contamos usuarios únicos en UserApplicationRole
func (r *applicationRepository) GetAppsWithUserCount() ([]response.AppStatsResponse, error) {
	var stats []response.AppStatsResponse
	err := r.db.Table("applications").
		Select("applications.id, applications.name, applications.app_id, applications.description, COUNT(DISTINCT uar.user_id) as user_count").
		Joins("LEFT JOIN user_application_roles uar ON uar.application_id = applications.id AND uar.deleted_at IS NULL").
		Where("applications.deleted_at IS NULL").
		Group("applications.id, applications.name, applications.app_id, applications.description").
		Scan(&stats).Error
	return stats, err
}

// GetAppsForUser devuelve solo las apps donde el usuario tiene roles asignados.
func (r *applicationRepository) GetAppsForUser(userID uint) ([]response.AppStatsResponse, error) {
	var stats []response.AppStatsResponse
	err := r.db.Table("applications").
		Select("applications.id, applications.name, applications.app_id, applications.description, (SELECT COUNT(DISTINCT u2.user_id) FROM user_application_roles u2 WHERE u2.application_id = applications.id AND u2.deleted_at IS NULL) as user_count").
		Joins("JOIN user_application_roles uar ON uar.application_id = applications.id AND uar.deleted_at IS NULL").
		Where("uar.user_id = ? AND applications.deleted_at IS NULL", userID).
		Group("applications.id, applications.name, applications.app_id, applications.description").
		Scan(&stats).Error
	return stats, err
}
