package model

import (
	"time"

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

type ApplicationRules struct {
	gorm.Model
	ApplicationID uint        `gorm:"index;not null"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	Code          string      `gorm:"type:varchar(50);index"` // ej: "SELF_REGISTER", "PWD_STRENGTH"
	Value         []byte      `gorm:"type:jsonb"`             // Configuración de la regla
	IsActive      bool        `gorm:"default:true"`
}

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

type PasswordReset struct {
	gorm.Model
	UserID        uint
	ApplicationID uint
	User          User        `gorm:"foreignKey:UserID"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	TokenHash     []byte
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

type Profile struct {
	gorm.Model
	UserID    uint      `gorm:"uniqueIndex"`
	FirstName string    `gorm:"type:varchar(50)" json:"first_name"`
	LastName  string    `gorm:"type:varchar(50)" json:"last_name"`
	BirthDate time.Time `json:"birth_date"`
	AvatarURL string    `gorm:"type:varchar(255)" json:"avatar_url"`
}

type RefreshToken struct {
	gorm.Model
	UserID        uint
	ApplicationID uint
	Token         string `gorm:"uniqueIndex;not null"`
	ExpiresAt     time.Time
}

type Role struct {
	gorm.Model
	Name string `gorm:"type:varchar(100);index:idx_role_name_app,unique;not null"`
	// ApplicationID define el alcance del rol:
	//   - nil  -> rol GLOBAL del sistema (ROOT, ADMIN, USER), visible para todas las apps.
	//   - !nil -> rol PROPIO de una aplicación, visible/asignable solo dentro de esa app.
	ApplicationID *uint        `gorm:"index:idx_role_name_app,unique"`
	Application   *Application `gorm:"foreignKey:ApplicationID"`
	IsDefault     bool         `gorm:"default:false"`
}

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

type UserApplicationRole struct {
	gorm.Model
	UserID        uint        `gorm:"not null;index:idx_uar_unique,unique"`
	ApplicationID uint        `gorm:"not null;index:idx_uar_unique,unique"`
	RoleID        uint        `gorm:"not null;index:idx_uar_unique,unique"`
	User          User        `gorm:"foreignKey:UserID"`
	Application   Application `gorm:"foreignKey:ApplicationID"`
	Role          Role        `gorm:"foreignKey:RoleID"`
}
