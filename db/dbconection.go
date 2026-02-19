package db

import (
	"fmt"
	"log"
	"os"
	"peak-auth/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var postgresqlDB *gorm.DB

func ConnectDB() (db *gorm.DB) {

	// Validar variables de entorno
	requiredEnvVars := []string{"DB_USER", "DB_PASSWORD", "DB_HOST", "DB_PORT", "DB_NAME"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("Error: la variable de entorno %s no está definida", envVar)
		}
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=America/Argentina/Buenos_Aires",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Error conectando a la base de datos:", err)
	}

	postgresqlDB = db
	return postgresqlDB
}

func AutoMigrate() {
	if postgresqlDB == nil {
		log.Fatal("La base de datos no está inicializada")
	}
	postgresqlDB.AutoMigrate(
		&models.Application{},
		&models.Role{},
		&models.User{},
		&models.Profile{},
		&models.UserApplicationRole{},
		&models.EmailVerification{},
		&models.PasswordReset{},
		&models.RefreshToken{},
		&models.ApplicationRules{},
	)
}

func DisconnectDB() {
	if postgresqlDB == nil {
		log.Fatal("La base de datos no está inicializada")
	}
	connect, err := postgresqlDB.DB()
	if err != nil {
		log.Fatal("Error al obtener la conexión de la base de datos:", err)
	}
	if err := connect.Close(); err != nil {
		log.Fatal("Error al cerrar la conexión:", err)
	}
}

func GetDatabasePostgreSQL() *gorm.DB {
	if postgresqlDB == nil {
		log.Fatal("La base de datos no está inicializada")
	}
	return postgresqlDB
}
