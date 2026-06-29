package controller

import (
	"fmt"
	"log"
	"net/http"
	"peak-auth/internal/api/middleware"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type DashboardController struct {
	BaseController
	UserService service.UserService
	AppService  service.ApplicationService
}

// Dashboard renderiza el dashboard
func (ctrl *DashboardController) Dashboard(c *gin.Context) {
	scopeVal, exists := c.Get("platform_scope")
	if !exists {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Error al obtener privilegios",
		})
		return
	}

	scope := scopeVal.(middleware.PlatformScope)

	var stats []response.AppStatsResponse
	var err error

	if scope.IsRoot || scope.IsPlatformAdmin {
		stats, err = ctrl.AppService.GetDashboardStats()
	} else {
		userID := c.MustGet("user_id").(uint)
		stats, err = ctrl.AppService.GetDashboardStatsForUser(userID)
	}

	if err != nil {
		log.Printf("[error] Dashboard stats: %v", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "No se pudieron cargar las estadísticas"})
		return
	}

	ctrl.renderAdmin(c, "dashboard.html", gin.H{
		"Applications": stats,
		"IsPlatform":   scope.IsRoot || scope.IsPlatformAdmin,
		"Breadcrumbs":  nil,
		"Title":        "Dashboard",
	})
}

// PostResendVerification reenvía el email de activación
func (ctrl *DashboardController) PostResendVerification(c *gin.Context) {
	appID := c.Param("id")
	userIDStr := c.Param("user_id")
	var userID uint
	fmt.Sscanf(userIDStr, "%d", &userID)

	if err := ctrl.UserService.ResendVerification(userID, appID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No se pudo reenviar el email de verificación"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email de activación reenviado correctamente"})
}

// PostSendResetPassword envía un email de recuperación manualmente
func (ctrl *DashboardController) PostSendResetPassword(c *gin.Context) {
	userIDStr := c.Param("user_id")
	var userID uint
	fmt.Sscanf(userIDStr, "%d", &userID)

	user, err := ctrl.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	// Rate limit de reset
	canReset, err := ctrl.UserService.CanRequestPasswordReset(userID)
	if err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Debe esperar antes de solicitar un nuevo reset de contraseña"})
		return
	}

	if !canReset {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Debe esperar al menos 15 minutos entre solicitudes de reset"})
		return
	}

	appIDParam := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	if err := ctrl.UserService.SendResetEmail(user, app.ID); err != nil {
		internalErrorJSON(c, "SendResetEmail", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email de recuperación enviado correctamente"})
}
