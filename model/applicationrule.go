package model

import "gorm.io/gorm"

type ApplicationRules struct {
	gorm.Model
	ApplicationID uint        `gorm:"index;not null"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	Code          string      `gorm:"type:varchar(50);index"` // ej: "SELF_REGISTER", "PWD_STRENGTH"
	Value         []byte      `gorm:"type:jsonb"`             // Configuración de la regla
	IsActive      bool        `gorm:"default:true"`
}
