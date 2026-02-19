package models

import (
	"gorm.io/gorm"
)

type Application struct {
	gorm.Model
	Name        string `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	Description string `gorm:"type:varchar(255)" json:"description"`
	AppID       string `gorm:"type:varchar(255);uniqueIndex;not null" json:"app_id"`
	SecretKey   string `gorm:"type:varchar(255);not null" json:"-"`
	RedirectURL string `gorm:"type:varchar(255)" json:"redirect_url"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`
}
