package repo

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"peak-auth/internal/store/model"
)

// getTestDB retorna una conexión a la base de datos de pruebas si PostgreSQL está disponible,
// o salta la prueba limpiamente si no hay una instancia en ejecución en el entorno actual.
func getTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}

	// Verificar si el puerto de PostgreSQL responde rápidamente
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 400*time.Millisecond)
	if err != nil {
		t.Skipf("Saltando prueba de integración: PostgreSQL no disponible en %s:%s", host, port)
		return nil
	}
	_ = conn.Close()

	user := os.Getenv("DB_USER")
	if user == "" {
		user = "postgres"
	}
	pass := os.Getenv("DB_PASSWORD")
	if pass == "" {
		pass = "password"
	}
	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		dbname = "peak_auth_local"
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		host, user, pass, dbname, port,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Skipf("Saltando prueba de integración: error conectando a PostgreSQL (%s): %v", dsn, err)
		return nil
	}

	_ = db.AutoMigrate(
		&model.Application{},
		&model.Role{},
		&model.User{},
		&model.Profile{},
		&model.UserApplicationRole{},
	)

	return db
}
