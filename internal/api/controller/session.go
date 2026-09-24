package controller

import (
	"errors"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type SessionController struct {
	BaseController
	SessionService service.SessionService
}

func NewSessionController(sessionService service.SessionService) *SessionController {
	return &SessionController{
		SessionService: sessionService,
	}
}

// ListSessions devuelve la lista de sesiones activas del usuario autenticado.
func (c *SessionController) ListSessions(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	currentToken := ctx.GetHeader("X-Refresh-Token")
	if currentToken == "" {
		currentToken = ctx.Query("current_token")
	}

	sessions, err := c.SessionService.ListSessions(userID, currentToken, service.SessionDeviceContext{
		IPAddress: ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		internalErrorJSON(ctx, "ListSessions", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

// RevokeSession revoca una sesión específica del usuario autenticado.
func (c *SessionController) RevokeSession(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	idParam := ctx.Param("id")
	sessionID, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil || sessionID == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "ID de sesión inválido"})
		return
	}

	if err := c.SessionService.RevokeSession(userID, uint(sessionID)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Sesión no encontrada"})
			return
		}
		internalErrorJSON(ctx, "RevokeSession", err)
		return
	}

	audit.Event(ctx, "session.revoke", "Revocación de sesión ID "+idParam)
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Sesión revocada exitosamente",
	})
}

type RevokeOthersRequest struct {
	CurrentRefreshToken string `json:"current_refresh_token"`
	CurrentSessionID    uint   `json:"current_session_id"`
}

// RevokeOtherSessions revoca todas las sesiones activas excepto la sesión actual.
func (c *SessionController) RevokeOtherSessions(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	var req RevokeOthersRequest
	_ = ctx.ShouldBindJSON(&req)

	currentToken := req.CurrentRefreshToken
	if currentToken == "" {
		currentToken = ctx.GetHeader("X-Refresh-Token")
	}

	if err := c.SessionService.RevokeOtherSessions(userID, currentToken, req.CurrentSessionID); err != nil {
		internalErrorJSON(ctx, "RevokeOtherSessions", err)
		return
	}

	audit.Event(ctx, "session.revoke_others", "Revocación de todas las demás sesiones")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Todas las demás sesiones han sido revocadas exitosamente",
	})
}

// ListAuthorizedApps devuelve la lista de aplicaciones OAuth consentidas por el usuario.
func (c *SessionController) ListAuthorizedApps(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	apps, err := c.SessionService.ListAuthorizedApps(userID)
	if err != nil {
		internalErrorJSON(ctx, "ListAuthorizedApps", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"applications": apps,
	})
}

// RevokeAuthorizedApp revoca el consentimiento y acceso de una aplicación OAuth.
func (c *SessionController) RevokeAuthorizedApp(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	clientID := strings.TrimSpace(ctx.Param("client_id"))
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "client_id requerido"})
		return
	}

	if err := c.SessionService.RevokeAuthorizedApp(userID, clientID); err != nil {
		internalErrorJSON(ctx, "RevokeAuthorizedApp", err)
		return
	}

	audit.Event(ctx, "oauth.consent.revoke", "Revocación de aplicación cliente: "+clientID)
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Autorización de aplicación revocada exitosamente",
	})
}

// GetSettingsPage renderiza la página completa de ajustes (Perfil, Seguridad/MFA, Sesiones y Apps).
func (c *SessionController) GetSettingsPage(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}
	userID := val.(uint)

	sessions, _ := c.SessionService.ListSessions(userID, "", service.SessionDeviceContext{
		IPAddress: ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	apps, _ := c.SessionService.ListAuthorizedApps(userID)

	c.renderAdmin(ctx, "settings.html", gin.H{
		"Title":        "Ajustes de Cuenta",
		"Sessions":     sessions,
		"Applications": apps,
		"Breadcrumbs": []gin.H{
			{"Label": "Ajustes", "URL": ""},
		},
	})
}

