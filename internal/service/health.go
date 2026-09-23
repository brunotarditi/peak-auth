package service

import (
	"context"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/repo"
	"time"
)

// HealthService define la lógica de negocio para comprobaciones de liveness y readiness.
type HealthService interface {
	CheckHealth() bool
	CheckReadiness(ctx context.Context) (dbHealthy bool, tokenManagerHealthy bool)
}

type healthService struct {
	healthRepo   repo.HealthRepository
	tokenManager *auth.JWTManager
}

// NewHealthService instancia el servicio de observabilidad inyectando sus dependencias.
func NewHealthService(healthRepo repo.HealthRepository, tokenManager *auth.JWTManager) HealthService {
	return &healthService{
		healthRepo:   healthRepo,
		tokenManager: tokenManager,
	}
}

// CheckHealth comprueba que la capa de servicio esté viva y despachando operaciones.
func (s *healthService) CheckHealth() bool {
	return true
}

// CheckReadiness valida la operatividad de los componentes críticos: PostgreSQL y TokenManager.
func (s *healthService) CheckReadiness(ctx context.Context) (bool, bool) {
	dbHealthy := false
	tokenManagerHealthy := false

	// 1. Validar conexión a PostgreSQL con timeout acotado
	if s.healthRepo != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := s.healthRepo.Ping(pingCtx); err == nil {
			dbHealthy = true
		}
	}

	// 2. Validar gestor criptográfico JWT
	if s.tokenManager != nil && s.tokenManager.ActiveKeyID() != "" {
		tokenManagerHealthy = true
	}

	return dbHealthy, tokenManagerHealthy
}
