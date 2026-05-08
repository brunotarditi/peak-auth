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

func (r *setupRepository) IsFirstRun() (bool, error) {
	var count int64
	err := r.db.Model(&model.User{}).Count(&count).Error
	return count == 0, err
}
