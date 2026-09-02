package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/api/request"
	"peak-auth/internal/audit"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"strings"

	"github.com/gin-gonic/gin"
)

type LoginController struct {
	UserService  service.UserService
	MfaService   service.MfaService
	TokenManager *auth.JWTManager
}

// Login maneja el endpoint de login. Espera el header X-App-Id con el AppID público.
func (c *LoginController) Login(ctx *gin.Context) {
	var req request.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": "Formato inválido"})
		return
	}

	// El app_id lo podemos recibir por Header o QueryParam
	appID := ctx.GetHeader("X-App-ID")
	if appID == "" {
		ctx.JSON(400, gin.H{"error": "X-App-ID es requerido"})
		return
	}

	response, err := c.UserService.Login(req, appID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// GetLoginForm renderiza el formulario de login
func (ctrl *LoginController) GetLoginForm(c *gin.Context) {
	csrf, _ := c.Get("csrf_token")
	c.HTML(http.StatusOK, "login.html", gin.H{
		"Error":     c.Query("error"),
		"CSRFToken": csrf,
	})
}

// PostLoginForm procesa el login
func (ctrl *LoginController) PostLoginForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	token, expireMinutes, mfaRequired, mfaSetupRequired, mfaToken, err := ctrl.UserService.AdminLogin(email, password)
	if err != nil {
		audit.EventResult(c, "admin.login", "email="+email, false, err.Error())
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape(err.Error()))
		return
	}

	if mfaRequired {
		if mfaSetupRequired {
			c.Redirect(http.StatusSeeOther, "/admin/login/mfa/setup?mfa_token="+url.QueryEscape(mfaToken))
		} else {
			c.Redirect(http.StatusSeeOther, "/admin/login/mfa?mfa_token="+url.QueryEscape(mfaToken))
		}
		return
	}

	audit.EventResult(c, "admin.login", "email="+email, true, "")

	// Configuración de cookie segura
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()

	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// PostLogout cierra la sesión
func (ctrl *LoginController) PostLogout(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", "", -1, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// GetAdminMfaForm renderiza la vista para que el administrador valide su MFA
func (ctrl *LoginController) GetAdminMfaForm(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.Redirect(http.StatusSeeOther, "/admin/login?error=" + url.QueryEscape("Acceso no autorizado"))
		return
	}

	csrf, _ := c.Get("csrf_token")
	
	// Verificar si tiene WebAuthn configurado
	hasWebAuthn := false
	if claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, ""); err == nil {
		var userID uint
		if _, err := fmt.Sscanf(claims.Subject, "%d", &userID); err == nil {
			if status, err := ctrl.MfaService.GetMfaStatus(userID); err == nil {
				hasWebAuthn = status.WebAuthnConfigured
			}
		}
	}

	c.HTML(http.StatusOK, "login_mfa.html", gin.H{
		"MfaToken":    mfaToken,
		"CSRFToken":   csrf,
		"Error":       c.Query("error"),
		"HasWebAuthn": hasWebAuthn,
	})
}

// GetAdminMfaSetupForm renderiza la vista para configurar forzosamente el MFA
func (ctrl *LoginController) GetAdminMfaSetupForm(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.Redirect(http.StatusSeeOther, "/admin/login?error=" + url.QueryEscape("Acceso no autorizado"))
		return
	}

	csrf, _ := c.Get("csrf_token")

	c.HTML(http.StatusOK, "login_mfa_setup.html", gin.H{
		"MfaToken":  mfaToken,
		"CSRFToken": csrf,
	})
}

// PostAdminMfa valida el código MFA (TOTP o de recuperación) para acceso administrativo
func (ctrl *LoginController) PostAdminMfa(c *gin.Context) {
	mfaToken := c.PostForm("mfa_token")
	code := strings.TrimSpace(c.PostForm("code"))

	if mfaToken == "" || code == "" {
		c.Redirect(http.StatusSeeOther, "/admin/login?error=" + url.QueryEscape("Acceso no autorizado"))
		return
	}

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/login?error=" + url.QueryEscape("Sesión expirada. Inicie sesión nuevamente"))
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	// Determinar el tipo de código: TOTP (6 dígitos) o Código de recuperación
	isRecovery := len(strings.ReplaceAll(code, "-", "")) != 6

	var mfaErr error
	if isRecovery {
		mfaErr = ctrl.MfaService.ValidateRecoveryCode(userID, code)
	} else {
		mfaErr = ctrl.MfaService.ValidateTOTPCode(userID, code)
	}

	if mfaErr != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", userID), false, mfaErr.Error())
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/admin/login/mfa?mfa_token=%s&error=%s", url.QueryEscape(mfaToken), url.QueryEscape(mfaErr.Error())))
		return
	}

	// Completar login
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(userID)
	if err != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.Redirect(http.StatusSeeOther, "/admin/login?error=" + url.QueryEscape(err.Error()))
		return
	}

	audit.EventResult(c, "admin.login.mfa_success", fmt.Sprintf("userID=%d", userID), true, "")

	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()

	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// BeginWebAuthnLogin inicia el login WebAuthn (Admin o API)
func (ctrl *LoginController) BeginWebAuthnLogin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	options, sessionData, err := ctrl.MfaService.BeginWebAuthnLogin(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sessionKey := fmt.Sprintf("wa_login_%s", mfaToken)
	service.StoreWebAuthnSession(sessionKey, sessionData)

	c.JSON(http.StatusOK, options)
}

// FinishWebAuthnLoginAdmin finaliza el login WebAuthn para el panel de administración
func (ctrl *LoginController) FinishWebAuthnLoginAdmin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	sessionKey := fmt.Sprintf("wa_login_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := ctrl.MfaService.FinishWebAuthnLogin(userID, sessionData, c.Request); err != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Completar login admin
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)

	c.JSON(http.StatusOK, gin.H{"message": "Login exitoso", "redirect": "/admin"})
}

// VerifyTOTPSetupAdmin valida el código TOTP enviado para activar el factor durante el login del admin
func (ctrl *LoginController) VerifyTOTPSetupAdmin(c *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(req.MfaToken, "")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Login is complete, generate final token
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)

	c.JSON(http.StatusOK, gin.H{
		"message":        "TOTP activado con éxito",
		"recovery_codes": recoveryCodes,
		"redirect":       "/admin",
	})
}

// FinishWebAuthnSetupAdmin finaliza el registro de WebAuthn durante el login del admin
func (ctrl *LoginController) FinishWebAuthnSetupAdmin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	sessionKey := fmt.Sprintf("wa_reg_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := ctrl.MfaService.FinishWebAuthnRegistration(userID, sessionData, c.Request); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Delete session from cache
	service.DeleteWebAuthnSession(sessionKey)

	// Login is complete, generate final token
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Llave de seguridad vinculada con éxito",
		"redirect": "/admin",
	})
}

// VerifyMfaTotp valida el código TOTP para acceso API
func (ctrl *LoginController) VerifyMfaTotp(c *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token y code son requeridos"})
		return
	}

	appID := c.GetHeader("X-App-ID")

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(req.MfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	if err := ctrl.MfaService.ValidateTOTPCode(userID, req.Code); err != nil {
		audit.EventResult(c, "api.login.mfa_totp_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	audit.EventResult(c, "api.login.mfa_totp_success", fmt.Sprintf("userID=%d", userID), true, "")
	c.JSON(http.StatusOK, response)
}

// VerifyMfaRecovery valida el código de recuperación para acceso API
func (ctrl *LoginController) VerifyMfaRecovery(c *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token y code son requeridos"})
		return
	}

	appID := c.GetHeader("X-App-ID")

	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(req.MfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	if err := ctrl.MfaService.ValidateRecoveryCode(userID, req.Code); err != nil {
		audit.EventResult(c, "api.login.mfa_recovery_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// SetupTOTPLogin permite configurar TOTP durante el login forzoso
func (ctrl *LoginController) SetupTOTPLogin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	appID := c.GetHeader("X-App-ID")
	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	resp, err := ctrl.MfaService.SetupTOTP(userID, claims.Username)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyTOTPLogin valida el código TOTP enviado para activar el factor durante el login
func (ctrl *LoginController) VerifyTOTPLogin(c *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	appID := c.GetHeader("X-App-ID")
	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(req.MfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Login is complete, generate final token
	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "TOTP activado con éxito",
		"recovery_codes": recoveryCodes,
		"auth":           response,
	})
}

// BeginWebAuthnRegistrationLogin inicia el registro de WebAuthn durante el login forzoso
func (ctrl *LoginController) BeginWebAuthnRegistrationLogin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	appID := c.GetHeader("X-App-ID")
	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	options, sessionData, err := ctrl.MfaService.BeginWebAuthnRegistration(userID, claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Guardar sesión en caché (usando mfa_token como key)
	sessionKey := fmt.Sprintf("wa_reg_%s", mfaToken)
	service.StoreWebAuthnSession(sessionKey, sessionData)

	c.JSON(http.StatusOK, options)
}

// FinishWebAuthnRegistrationLogin finaliza el registro de WebAuthn durante el login forzoso
func (ctrl *LoginController) FinishWebAuthnRegistrationLogin(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_token es requerido"})
		return
	}

	appID := c.GetHeader("X-App-ID")
	claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, appID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	sessionKey := fmt.Sprintf("wa_reg_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := ctrl.MfaService.FinishWebAuthnRegistration(userID, sessionData, c.Request); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Delete session from cache
	service.DeleteWebAuthnSession(sessionKey)

	// Login is complete, generate final token
	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Llave de seguridad vinculada con éxito",
		"auth":    response,
	})
}
