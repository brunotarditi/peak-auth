package model

import "gorm.io/gorm"

type UserApplicationRole struct {
	gorm.Model
	UserID        uint        `gorm:"not null;index"`
	ApplicationID uint        `gorm:"not null;index"`
	RoleID        uint        `gorm:"not null;index"`
	User          User        `gorm:"foreignKey:UserID"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	Role          Role        `gorm:"foreignKey:RoleID"`
}
