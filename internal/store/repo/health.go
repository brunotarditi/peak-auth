package repo

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// HealthRepository define las operaciones de comprobación a nivel de capa de datos.
type HealthRepository interface {
	Ping(ctx context.Context) error
}

type healthRepository struct {
	db *gorm.DB
}

// NewHealthRepository instancia el repositorio de salud de base de datos.
func NewHealthRepository(db *gorm.DB) HealthRepository {
	return &healthRepository{db: db}
}

// Ping comprueba la conectividad activa contra el motor PostgreSQL respetando el contexto.
func (r *healthRepository) Ping(ctx context.Context) error {
	if r.db == nil {
		return errors.New("db instance is nil")
	}
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
