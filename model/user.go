package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Password     string    `gorm:"type:varchar(255);not null" json:"-"`
	Email        string    `gorm:"type:varchar(100);not null;unique" json:"email"`
	IsActive     bool      `gorm:"default:true" json:"is_active"`
	IsVerified   bool      `gorm:"default:false" json:"is_verified"`
	FailedLogins uint      `gorm:"default:0" json:"failed_logins"`
	LastLogin    time.Time `json:"last_login"`
	Profile      Profile   `gorm:"foreignKey:UserID"`
}
