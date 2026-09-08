package db

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"
	"sort"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var postgresqlDB *gorm.DB

func ConnectDB() (db *gorm.DB) {

	// Validar variables requeridas
	required := []string{"DB_USER", "DB_PASSWORD", "DB_HOST", "DB_PORT", "DB_NAME"}
	for _, v := range required {
		if os.Getenv(v) == "" {
			log.Fatalf("Error: la variable de entorno %s no está definida", v)
		}
	}

	sslMode := getSSLMode()

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		sslMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Error conectando a PostgreSQL: %v", err)
	}

	// Pool de conexiones
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Error obteniendo el pool de conexiones:", err)
	}

	sqlDB.SetMaxOpenConns(30)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(1 * time.Hour)
	sqlDB.SetConnMaxIdleTime(15 * time.Minute)

	postgresqlDB = db
	log.Printf("✅ PostgreSQL conectado correctamente (SSLMode: %s)", sslMode)
	return db
}

// AutoMigrate realiza la migración de todas las tablas
func AutoMigrate() {
	if postgresqlDB == nil {
		log.Fatal("La base de datos no está inicializada antes de AutoMigrate")
	}

	err := postgresqlDB.AutoMigrate(
		&model.Application{},
		&model.Role{},
		&model.User{},
		&model.Profile{},
		&model.UserApplicationRole{},
		&model.EmailVerification{},
		&model.PasswordReset{},
		&model.RefreshToken{},
		&model.ApplicationRules{},
		&model.UserMfaCredential{},
		&model.UserRecoveryCode{},
		&model.OAuthCode{},
	)
	if err != nil {
		log.Printf("⚠️ Error durante AutoMigrate: %v", err)
	} else {
		log.Println("✅ AutoMigrate completado correctamente")
	}

	// Índice único parcial para roles globales (solo se crea una vez)
	if err := postgresqlDB.Exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_role_name_global 
        ON roles (name) 
        WHERE application_id IS NULL AND deleted_at IS NULL
    `).Error; err != nil {
		log.Printf("⚠️ No se pudo crear el índice idx_role_name_global: %v", err)
	}

	// Índice único parcial para vinculación de roles de usuario (evita duplicados activos)
	if err := postgresqlDB.Exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_uar_unique
        ON user_application_roles (user_id, application_id, role_id)
        WHERE deleted_at IS NULL
    `).Error; err != nil {
		log.Printf("⚠️ No se pudo crear el índice idx_uar_unique: %v", err)
	}

	RunSQLMigrations()
}

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration model para la auditoría de scripts ejecutados
type Migration struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	CreatedAt time.Time
}

// RunSQLMigrations lee y ejecuta los scripts SQL embebidos en migrations/
func RunSQLMigrations() {
	if err := postgresqlDB.AutoMigrate(&Migration{}); err != nil {
		log.Printf("⚠️ Error migrando tabla de migrations: %v", err)
		return
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		log.Printf("ℹ️ Carpeta de migraciones no encontrada en binario: %v. Saltando.", err)
		return
	}

	// Ordenamos alfanuméricamente de forma determinista (001, 002...)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}

		var count int64
		postgresqlDB.Model(&Migration{}).Where("name = ?", entry.Name()).Count(&count)

		if count > 0 {
			continue // Ya ejecutado previamente
		}

		log.Printf("Ejecutando script de BD: %s...", entry.Name())
		content, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			log.Printf("⚠️ Error leyendo script embebido %s: %v", entry.Name(), err)
			continue
		}

		// Ejecutamos en una transacción para atomicidad
		err = postgresqlDB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(string(content)).Error; err != nil {
				return err
			}
			return tx.Create(&Migration{Name: entry.Name()}).Error
		})

		if err != nil {
			log.Printf("⚠️ Error ejecutando %s: %v", entry.Name(), err)
		} else {
			log.Printf("✅ Script %s aplicado con éxito.", entry.Name())
		}
	}
}

// DisconnectDB cierra la conexión con la base de datos
func DisconnectDB() {
	if postgresqlDB == nil {
		return
	}

	sqlDB, err := postgresqlDB.DB()
	if err != nil {
		log.Printf("Error al obtener sql.DB para cerrar: %v", err)
		return
	}

	if err := sqlDB.Close(); err != nil {
		log.Printf("Error al cerrar la conexión con PostgreSQL: %v", err)
	} else {
		log.Println("✅ Conexión con PostgreSQL cerrada correctamente")
	}
}

// getSSLMode devuelve el modo SSL según la variable de entorno o el entorno actual
func getSSLMode() string {
	if mode := os.Getenv("DB_SSLMODE"); mode != "" {
		return mode
	}

	if util.IsProduction() {
		return "require"
	}
	return "disable"
}
