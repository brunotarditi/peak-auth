package controller

import (
	"errors"
	"net/http"
	"fmt"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type SessionController struct {
	BaseController
	SessionService service.SessionService
	UserService    service.UserService
	UserRepo       repo.UserRepository
}

func NewSessionController(sessionService service.SessionService, userService service.UserService, userRepo repo.UserRepository) *SessionController {
	return &SessionController{
		SessionService: sessionService,
		UserService:    userService,
		UserRepo:       userRepo,
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

	var user model.User
	if c.UserRepo != nil {
		user, _ = c.UserRepo.FindById(userID)
	}

	c.renderAdmin(ctx, "settings.html", gin.H{
		"Title":        "Ajustes de Cuenta",
		"User":         user,
		"Sessions":     sessions,
		"Applications": apps,
		"Breadcrumbs": []gin.H{
			{"Label": "Ajustes", "URL": ""},
		},
	})
}

// PostUpdateProfile actualiza los datos informativos del perfil del usuario (nombre, apellido, fecha, avatar).
func (c *SessionController) PostUpdateProfile(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	firstName := strings.TrimSpace(ctx.PostForm("first_name"))
	lastName := strings.TrimSpace(ctx.PostForm("last_name"))
	birthDateStr := strings.TrimSpace(ctx.PostForm("birth_date"))
	avatarURL := strings.TrimSpace(ctx.PostForm("avatar_url"))

	var birthDate time.Time
	if birthDateStr != "" {
		if t, err := time.Parse("2006-01-02", birthDateStr); err == nil {
			birthDate = t
		}
	}

	if c.UserService == nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Servicio de usuario no disponible"})
		return
	}

	if err := c.UserService.UpdateProfile(userID, firstName, lastName, birthDate, avatarURL); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	audit.Event(ctx, "user.profile_update", fmt.Sprintf("user_id=%d", userID))
	ctx.JSON(http.StatusOK, gin.H{"message": "Perfil actualizado exitosamente"})
}

// PostUpdatePassword actualiza la contraseña del usuario tras validar la actual.
func (c *SessionController) PostUpdatePassword(ctx *gin.Context) {
	val, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}
	userID := val.(uint)

	currentPassword := ctx.PostForm("current_password")
	newPassword := ctx.PostForm("new_password")
	confirmPassword := ctx.PostForm("confirm_password")

	if currentPassword == "" || newPassword == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Las contraseñas no pueden estar vacías"})
		return
	}

	if newPassword != confirmPassword {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "La nueva contraseña y su confirmación no coinciden"})
		return
	}

	if c.UserService == nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Servicio de usuario no disponible"})
		return
	}

	if err := c.UserService.ChangePassword(userID, currentPassword, newPassword); err != nil {
		errMsg := err.Error()
		// Solo exponer mensajes de validación conocidos, sanitizar errores internos
		if !strings.Contains(errMsg, "contraseña") && !strings.Contains(errMsg, "usuario") {
			errMsg = "Error al actualizar la contraseña"
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	audit.Event(ctx, "user.password_change", fmt.Sprintf("user_id=%d", userID))
	ctx.JSON(http.StatusOK, gin.H{"message": "Contraseña actualizada exitosamente"})
}


