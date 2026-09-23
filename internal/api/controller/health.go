package controller

import (
	"net/http"
	"peak-auth/internal/service"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthController provee endpoints de liveness (/health) y readiness (/ready)
// desacoplados de la base de datos mediante la capa de servicio HealthService.
type HealthController struct {
	HealthService service.HealthService
}

// Health maneja la comprobación básica de vida (Liveness probe).
// Responde 200 OK inmediatamente si la capa de aplicación y servidor HTTP despachan solicitudes.
// GET /health
func (ctrl *HealthController) Health(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	isAlive := true
	if ctrl.HealthService != nil {
		isAlive = ctrl.HealthService.CheckHealth()
	}

	status := "pass"
	code := http.StatusOK
	if !isAlive {
		status = "fail"
		code = http.StatusServiceUnavailable
	}

	c.JSON(code, gin.H{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Ready maneja la comprobación de disponibilidad operativa (Readiness probe).
// Delega en HealthService la verificación de conectividad con la base de datos y la disponibilidad de claves JWT.
// GET /ready
func (ctrl *HealthController) Ready(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	dbHealthy := false
	tokenManagerHealthy := false

	if ctrl.HealthService != nil {
		dbHealthy, tokenManagerHealthy = ctrl.HealthService.CheckReadiness(c.Request.Context())
	}

	checks := gin.H{
		"database":      "down",
		"token_manager": "down",
	}
	if dbHealthy {
		checks["database"] = "up"
	}
	if tokenManagerHealthy {
		checks["token_manager"] = "up"
	}

	allHealthy := dbHealthy && tokenManagerHealthy

	statusCode := http.StatusOK
	statusText := "pass"
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
		statusText = "fail"
	}

	c.JSON(statusCode, gin.H{
		"status":    statusText,
		"checks":    checks,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
