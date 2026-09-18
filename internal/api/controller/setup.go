package controller

import (
	"net/http"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"time"

	"github.com/gin-gonic/gin"
)

type SetupController struct {
	BaseController
	SetupService service.SetupService
	TokenManager *auth.JWTManager
}

// AuthenticateSetup accepts the setup token via POST body and sets it in a secure cookie
func (ctrl *SetupController) AuthenticateSetup(c *gin.Context) {
	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.JSON(http.StatusForbidden, gin.H{"error": "El sistema ya ha sido configurado"})
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token requerido"})
		return
	}

	// Validate token before setting cookie
	if err := ctrl.SetupService.ValidateSetupToken(token); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Token de instalación inválido"})
		return
	}

	// Set token in secure, HttpOnly cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("setup_token", token, 7200, "/", "", util.IsProduction(), true) // 2 hours

	c.JSON(http.StatusOK, gin.H{"success": true, "redirect": "/setup"})
}

func (ctrl *SetupController) ShowSetup(c *gin.Context) {
	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(303, "/admin/login")
		return
	}

	// Only accept token from cookie (never from query string to prevent URL logging)
	token := ""
	if cookie, err := c.Cookie("setup_token"); err == nil {
		token = cookie
	}

	// If SETUP_TOKEN is required but not provided, show auth page
	if ctrl.SetupService.RequiresToken() && token == "" {
		// Apply no-store cache control
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		csrf, _ := c.Get("csrf_token")
		c.HTML(200, "setup_auth.html", gin.H{"CSRFToken": csrf})
		return
	}

	// Validate token but don't pass it to the template
	if err := ctrl.SetupService.ValidateSetupToken(token); err != nil {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "El token de inicialización (setup) es inválido o el sistema ya ha sido configurado.")
		return
	}

	// Apply no-store cache control to prevent caching of setup page
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	csrf, _ := c.Get("csrf_token")
	// Do NOT pass SetupToken to template - validation is server-side only
	c.HTML(200, "setup.html", gin.H{"CSRFToken": csrf})
}

func (ctrl *SetupController) ProcessSetup(c *gin.Context) {

	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	email := c.PostForm("email")
	password := c.PostForm("password")

	// Only accept token from cookie (never from POST form to prevent logging)
	token := ""
	if cookie, err := c.Cookie("setup_token"); err == nil {
		token = cookie
	}

	if email == "" || password == "" {
		ctrl.renderError(c, http.StatusBadRequest, "Datos Incompletos", "Email y contraseña son requeridos para completar la configuración inicial.")
		return
	}

	user, err := ctrl.SetupService.CreateRootUser(email, password, token)
	if err != nil {
		ctrl.renderError(c, http.StatusBadRequest, "Error de Configuración", "No se pudo crear el usuario administrador inicial. Verifique los datos ingresados.")
		return
	}

	tokenString, err := ctrl.TokenManager.GenerateToken(user.ID, "System Root", util.AppIdPeakAuth, []string{"ROOT"}, 24*time.Hour, true, user.AuthzVersion)
	if err != nil {
		ctrl.renderError(c, http.StatusInternalServerError, "Error del Sistema", "No se pudo generar la sesión administrativa.")
		return
	}

	ctrl.setAdminCookie(c, tokenString, 86400) // 1 día
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("setup_token", "", -1, "/", "", util.IsProduction(), true)

	c.Redirect(http.StatusSeeOther, "/admin/login")
}
