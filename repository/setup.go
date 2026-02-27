package repository

import (
	"peak-auth/model"

	"gorm.io/gorm"
)

type SetupRepository interface {
	IsFirstRun() (bool, error)
}

type setupRepository struct {
	db *gorm.DB
}

func NewSetupRepository(db *gorm.DB) SetupRepository {
	return &setupRepository{db: db}
}

// Verifica si la PEAK AUTH se corre por primera vez
func (r *setupRepository) IsFirstRun() (bool, error) {
	var count int64
	// Si no hay usuarios en la tabla central, es el primer inicio
	err := r.db.Model(&model.User{}).Count(&count).Error
	return count == 0, err
}
