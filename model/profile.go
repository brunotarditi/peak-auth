package model

import (
	"time"

	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID    uint      `gorm:"uniqueIndex"`
	FirstName string    `gorm:"type:varchar(50)" json:"first_name"`
	LastName  string    `gorm:"type:varchar(50)" json:"last_name"`
	BirthDate time.Time `json:"birth_date"`
	AvatarURL string    `gorm:"type:varchar(255)" json:"avatar_url"`
}
