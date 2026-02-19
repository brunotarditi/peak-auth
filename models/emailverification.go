package models

import (
	"time"

	"gorm.io/gorm"
)

type EmailVerification struct {
	gorm.Model
	UserID        uint
	ApplicationID uint
	User          User        `gorm:"foreignKey:UserID"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	TokenHash     []byte
	ExpiresAt     time.Time
	UsedAt        *time.Time
}
