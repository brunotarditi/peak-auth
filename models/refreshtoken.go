package models

import (
	"time"

	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	UserID        uint
	ApplicationID uint
	Token         string `gorm:"uniqueIndex;not null"`
	ExpiresAt     time.Time
}
