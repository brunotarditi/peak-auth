package controller

import (

	"net/http"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"strings"
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

	token := strings.TrimSpace(c.PostForm("token"))
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
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	// 1. Si el token viene por query param (ej: copiado o clickeado desde la consola):
	queryToken := strings.TrimSpace(c.Query("token"))
	if queryToken != "" {
		if err := ctrl.SetupService.ValidateSetupToken(queryToken); err == nil {
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie("setup_token", queryToken, 7200, "/", "", util.IsProduction(), true)
			// Redirigir a /setup limpio para no dejar el token sensible en la URL ni en el historial
			c.Redirect(http.StatusSeeOther, "/setup")
			return
		}

		// Si el token provisto en query es inválido, limpiar cookie y mostrar formulario de auth con error
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("setup_token", "", -1, "/", "", util.IsProduction(), true)

		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		csrf, _ := c.Get("csrf_token")
		c.HTML(http.StatusOK, "setup_auth.html", gin.H{
			"CSRFToken":    csrf,
			"ErrorMessage": "El token de instalación proporcionado en la URL es inválido o ha expirado.",
		})
		return
	}

	// 2. Extraer token de cookie
	token := ""
	if cookie, err := c.Cookie("setup_token"); err == nil {
		token = strings.TrimSpace(cookie)
	}

	// 3. Si se requiere token y no hay cookie, mostrar página de autenticación
	if ctrl.SetupService.RequiresToken() && token == "" {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		csrf, _ := c.Get("csrf_token")
		c.HTML(http.StatusOK, "setup_auth.html", gin.H{"CSRFToken": csrf})
		return
	}

	// 4. Si hay token en la cookie, validar su vigencia
	if err := ctrl.SetupService.ValidateSetupToken(token); err != nil {
		// La cookie contenía un token viejo, inválido o expirado.
		// Borrar inmediatamente la cookie para no atrapar al usuario en un bucle 403.
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("setup_token", "", -1, "/", "", util.IsProduction(), true)

		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		csrf, _ := c.Get("csrf_token")
		c.HTML(http.StatusOK, "setup_auth.html", gin.H{
			"CSRFToken":    csrf,
			"ErrorMessage": "El token de instalación anterior ha expirado o no es válido. Ingrese el token actual.",
		})
		return
	}

	// 5. Token válido: mostrar formulario de configuración de ROOT
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	csrf, _ := c.Get("csrf_token")
	c.HTML(http.StatusOK, "setup.html", gin.H{"CSRFToken": csrf})
}

func (ctrl *SetupController) ProcessSetup(c *gin.Context) {
	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	email := strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")

	// Only accept token from cookie (never from POST form to prevent logging)
	token := ""
	if cookie, err := c.Cookie("setup_token"); err == nil {
		token = strings.TrimSpace(cookie)
	}

	c.Set("is_setup", true)
	c.Set("error_back_url", "/setup")
	c.Set("error_back_label", "Volver a la instalación")

	if email == "" || password == "" {
		ctrl.renderError(c, http.StatusBadRequest, "Datos incompletos", "Email y contraseña son requeridos para completar la configuración inicial.")
		return
	}

	user, err := ctrl.SetupService.CreateRootUser(email, password, token)
	if err != nil {
		ctrl.renderError(c, http.StatusBadRequest, "Error de configuración", "No se pudo crear el usuario administrador inicial. Verifique los datos ingresados: "+err.Error())
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
		c.Set("is_setup", true)
		c.Set("error_back_url", "/setup")
		c.Set("error_back_label", "Volver a la instalación")
		ctrl.renderError(c, http.StatusBadRequest, "Error de MFA", "No se pudo iniciar la configuración de MFA: "+err.Error())
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
