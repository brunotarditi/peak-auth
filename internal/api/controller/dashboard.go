package controller

import (
	"net/http"
	"peak-auth/internal/api/middleware"
	"peak-auth/internal/api/response"
	"peak-auth/internal/service"
	"strings"

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
		ctrl.renderError(c, http.StatusInternalServerError, "Error", "Error al obtener privilegios.")
		return
	}

	scope := scopeVal.(middleware.PlatformScope)

	var stats []response.AppStatsResponse
	var err error

	if scope.IsRoot || scope.IsPlatformAdmin {
		stats, err = ctrl.AppService.GetDashboardStats()
	} else {
		userID, ok := authenticatedUserID(c)
		if !ok {
			ctrl.renderError(c, http.StatusUnauthorized, "No autenticado", "La sesión de usuario no es válida.")
			return
		}
		stats, err = ctrl.AppService.GetDashboardStatsForUser(userID)
	}

	if err != nil {
		ctrl.internalErrorHTML(c, "Dashboard.GetDashboardStats", err, "No se pudieron cargar las estadísticas.")
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
func (ctrl *DashboardController) PostSendVerification(c *gin.Context) {
	appID := c.Param("id")
	userID, err := parsePathUint(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de usuario inválido"})
		return
	}

	// Verificar que la aplicación existe
	app, err := ctrl.AppService.GetAppDetails(appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	// Verificar que el usuario pertenece a la aplicación
	belongs, err := ctrl.AppService.UserBelongsToApp(userID, app.ID)
	if err != nil || !belongs {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario no pertenece a esta aplicación"})
		return
	}

	if err := ctrl.UserService.SendVerification(userID, &app); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No se pudo reenviar el email de verificación"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email de activación reenviado correctamente"})
}

// PostSendResetPassword envía un email de recuperación manualmente
func (ctrl *DashboardController) PostSendResetPassword(c *gin.Context) {
	userID, err := parsePathUint(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID de usuario inválido"})
		return
	}

	user, err := ctrl.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	appIDParam := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(appIDParam)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Aplicación no encontrada"})
		return
	}

	// Verificar que el usuario pertenece a la aplicación
	belongs, err := ctrl.AppService.UserBelongsToApp(userID, app.ID)
	if err != nil || !belongs {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario no pertenece a esta aplicación"})
		return
	}

	// SendResetEmail verifica la elegibilidad atómicamente dentro de la transacción y crea el token
	if err := ctrl.UserService.SendResetEmail(user, app.ID); err != nil {
		if strings.Contains(err.Error(), "debe esperar") || strings.Contains(err.Error(), "límite mensual") {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
			return
		}
		internalErrorJSON(c, "SendResetEmail", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email de recuperación enviado correctamente"})
}
