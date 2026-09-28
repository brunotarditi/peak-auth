package repo

import (
	"errors"
	"peak-auth/internal/store/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ApplicationThemeRepository interface {
	FindByAppID(appID uint) (*model.ApplicationTheme, error)
	Upsert(theme *model.ApplicationTheme) error
	DeleteByAppID(appID uint) error
}

type applicationThemeRepository struct {
	db *gorm.DB
}

func NewApplicationThemeRepository(db *gorm.DB) ApplicationThemeRepository {
	return &applicationThemeRepository{db: db}
}

func (r *applicationThemeRepository) FindByAppID(appID uint) (*model.ApplicationTheme, error) {
	var theme model.ApplicationTheme
	err := r.db.Where("application_id = ?", appID).First(&theme).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Sin tema personalizado (usa default)
		}
		return nil, err
	}
	return &theme, nil
}

func (r *applicationThemeRepository) Upsert(theme *model.ApplicationTheme) error {
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "application_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"logo_url",
			"favicon_url",
			"primary_color",
			"custom_title",
			"custom_subtitle",
			"terms_url",
			"privacy_url",
			"updated_at",
		}),
	}).Create(theme).Error
}

func (r *applicationThemeRepository) DeleteByAppID(appID uint) error {
	return r.db.Where("application_id = ?", appID).Delete(&model.ApplicationTheme{}).Error
}
