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
	MfaService   service.MfaService
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

	// Borrar setup_token inmediatamente tras la creación del usuario
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("setup_token", "", -1, "/", "", util.IsProduction(), true)

	// Paso 2: Si MfaService está configurado, generar enrolamiento TOTP y redirigir a /setup/mfa
	if ctrl.MfaService != nil && ctrl.TokenManager != nil {
		mfaToken, err := ctrl.TokenManager.GenerateToken(user.ID, user.Email, "setup-mfa", []string{"SETUP_MFA"}, 15*time.Minute, false, user.AuthzVersion)
		if err == nil {
			c.SetCookie("setup_root_mfa", mfaToken, 900, "/", "", util.IsProduction(), true)
			c.Redirect(http.StatusSeeOther, "/setup/mfa")
			return
		}
	}

	// Fallback si no hay MFA service
	tokenString, err := ctrl.TokenManager.GenerateToken(user.ID, user.Email, util.AppIdPeakAuth, []string{"ROOT"}, 24*time.Hour, true, user.AuthzVersion)
	if err != nil {
		ctrl.renderError(c, http.StatusInternalServerError, "Error del Sistema", "No se pudo generar la sesión administrativa.")
		return
	}

	ctrl.setAdminCookie(c, tokenString, 86400) // 1 día
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// ShowSetupMFA renderiza el paso 2 de setup: configuración obligatoria de TOTP
func (ctrl *SetupController) ShowSetupMFA(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	mfaCookie, err := c.Cookie("setup_root_mfa")
	if err != nil || mfaCookie == "" {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	claims, err := ctrl.TokenManager.VerifyTokenForApp(mfaCookie, "setup-mfa")
	if err != nil || claims == nil {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	if ctrl.MfaService == nil {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	totpResp, err := ctrl.MfaService.SetupTOTP(userID, claims.Username)
	if err != nil {
		// Si ya está activo o hubo error, verificar si ya tiene mfa o mostrar error
		ctrl.renderError(c, http.StatusBadRequest, "Error MFA", "No se pudo iniciar la configuración de MFA: "+err.Error())
		return
	}

	csrf, _ := c.Get("csrf_token")
	c.HTML(http.StatusOK, "setup_mfa.html", gin.H{
		"QRCode":    totpResp.QRCode,
		"Secret":    totpResp.Secret,
		"CSRFToken": csrf,
	})
}

// ProcessSetupMFAVerify verifica el código TOTP, activa el 2FA del Root y devuelve los códigos de recuperación
func (ctrl *SetupController) ProcessSetupMFAVerify(c *gin.Context) {
	mfaCookie, err := c.Cookie("setup_root_mfa")
	if err != nil || mfaCookie == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión de setup expirada"})
		return
	}

	claims, err := ctrl.TokenManager.VerifyTokenForApp(mfaCookie, "setup-mfa")
	if err != nil || claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión de setup inválida o expirada"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión de setup inválida"})
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Código TOTP requerido"})
		return
	}

	if ctrl.MfaService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Servicio de MFA no disponible"})
		return
	}

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Código TOTP incorrecto. Verifica la sincronización horaria de tu dispositivo"})
		return
	}

	// Generar sesión administrativa definitiva para el superusuario Root
	tokenString, err := ctrl.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"ROOT"}, 24*time.Hour, true, claims.AuthzVersion)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al generar sesión administrativa"})
		return
	}

	ctrl.setAdminCookie(c, tokenString, 86400) // 1 día
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("setup_root_mfa", "", -1, "/", "", util.IsProduction(), true)

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"recovery_codes": recoveryCodes,
	})
}
