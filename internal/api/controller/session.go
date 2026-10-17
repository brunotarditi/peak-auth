package controller

import (
	"errors"
	"fmt"
	"net/http"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/store/repo"
	"strconv"
	"strings"
	"time"

	"peak-auth/internal/storage"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type SessionController struct {
	BaseController
	SessionService service.SessionService
	UserService    service.UserService
	UserRepo       repo.UserRepository
	StorageService storage.StorageService
	IdentityRepo   repo.UserIdentityRepository
}

func NewSessionController(sessionService service.SessionService, userService service.UserService, userRepo repo.UserRepository, extras ...any) *SessionController {
	var st storage.StorageService
	var idRepo repo.UserIdentityRepository
	for _, extra := range extras {
		if s, ok := extra.(storage.StorageService); ok {
			st = s
		} else if id, ok := extra.(repo.UserIdentityRepository); ok {
			idRepo = id
		}
	}
	return &SessionController{
		SessionService: sessionService,
		UserService:    userService,
		UserRepo:       userRepo,
		StorageService: st,
		IdentityRepo:   idRepo,
	}
}

// ListSessions devuelve la lista de sesiones activas del usuario autenticado.
func (c *SessionController) ListSessions(ctx *gin.Context) {
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	sessions, err := c.SessionService.ListSessions(userID, "", service.SessionDeviceContext{
		IPAddress: ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		c.internalErrorHTML(ctx, "GetSettingsPage.ListSessions", err, "No se pudieron cargar tus sesiones.")
		return
	}
	apps, err := c.SessionService.ListAuthorizedApps(userID)
	if err != nil {
		c.internalErrorHTML(ctx, "GetSettingsPage.ListAuthorizedApps", err, "No se pudieron cargar tus aplicaciones autorizadas.")
		return
	}

	hasOtherSessions := false
	for _, s := range sessions {
		if !s.IsCurrent {
			hasOtherSessions = true
			break
		}
	}

	var user model.User
	if c.UserRepo != nil {
		user, err = c.UserRepo.FindById(userID)
		if err != nil {
			c.internalErrorHTML(ctx, "GetSettingsPage.FindUser", err, "No se pudo cargar tu perfil.")
			return
		}
	}

	var identities []model.UserIdentity
	hasGoogle := false
	hasGithub := false
	if c.IdentityRepo != nil {
		identities, err = c.IdentityRepo.FindByUserID(userID)
		if err != nil {
			c.internalErrorHTML(ctx, "GetSettingsPage.FindIdentities", err, "No se pudieron cargar tus identidades vinculadas.")
			return
		}
		for _, idn := range identities {
			if strings.EqualFold(idn.Provider, "google") {
				hasGoogle = true
			} else if strings.EqualFold(idn.Provider, "github") {
				hasGithub = true
			}
		}
	}

	c.renderAdmin(ctx, "settings.html", gin.H{
		"Title":            "Ajustes de cuenta",
		"User":             user,
		"Sessions":         sessions,
		"HasOtherSessions": hasOtherSessions,
		"Applications":     apps,
		"HasGoogle":        hasGoogle,
		"HasGitHub":        hasGithub,
		"Identities":       identities,
		"Breadcrumbs": []gin.H{
			{"Label": "Ajustes", "URL": ""},
		},
	})
}

// PostUpdateProfile actualiza los datos informativos del perfil del usuario (nombre, apellido, fecha, avatar).
func (c *SessionController) PostUpdateProfile(ctx *gin.Context) {
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

	firstName := strings.TrimSpace(ctx.PostForm("first_name"))
	lastName := strings.TrimSpace(ctx.PostForm("last_name"))
	birthDateStr := strings.TrimSpace(ctx.PostForm("birth_date"))
	avatarURL := strings.TrimSpace(ctx.PostForm("avatar_url"))

	// Soporte para subida directa de archivo de imagen desde el formulario
	if file, header, err := ctx.Request.FormFile("avatar_file"); err == nil && file != nil && c.StorageService != nil {
		defer file.Close()
		uploadedURL, uploadErr := c.StorageService.Upload(ctx.Request.Context(), file, header.Filename, storage.FolderAvatars)
		if uploadErr != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": uploadErr.Error()})
			return
		}
		avatarURL = uploadedURL
	}

	var birthDate time.Time
	if birthDateStr != "" {
		if t, err := time.Parse("2006-01-02", birthDateStr); err == nil {
			birthDate = time.Date(t.Year(), t.Month(), t.Day(), 12, 0, 0, 0, time.UTC)
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
	ctx.JSON(http.StatusOK, gin.H{
		"message":    "Perfil actualizado exitosamente",
		"avatar_url": avatarURL,
	})
}

// PostUpdatePassword actualiza la contraseña del usuario tras validar la actual.
func (c *SessionController) PostUpdatePassword(ctx *gin.Context) {
	userID, ok := authenticatedUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "No autenticado"})
		return
	}

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
