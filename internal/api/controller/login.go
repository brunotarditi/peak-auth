package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/api/request"
	"peak-auth/internal/audit"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"strings"

	"github.com/gin-gonic/gin"
)

type LoginController struct {
	BaseController
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
		// Sanitizar mensaje para el usuario evitando filtrar detalles internos
		userErrMsg := "Credenciales inválidas"
		if strings.Contains(strings.ToLower(err.Error()), "inactiva") || strings.Contains(strings.ToLower(err.Error()), "bloqueada") {
			userErrMsg = err.Error()
		}
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape(userErrMsg))
		return
	}

	if mfaRequired {
		// Extract user ID from the mfaToken to create server-side transaction
		claims, err := ctrl.TokenManager.VerifyMFAPendingToken(mfaToken, "")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Error en autenticación MFA"))
			return
		}
		userID, err := parseUserIDFromSubject(claims.Subject)
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Error en autenticación MFA"))
			return
		}

		// Create server-side MFA transaction instead of exposing JWT
		sessionID := ctrl.getMfaSessionIdentifier(c)
		transactionID, err := service.StoreMfaTransaction(mfaToken, userID, claims.Username, claims.AppID, sessionID)
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Error en autenticación MFA"))
			return
		}

		// Store only the opaque transaction ID in cookie, not the JWT
		ctrl.setMfaTransactionCookie(c, transactionID)
		ctrl.clearMfaCookie(c) // Clear any old JWT cookie
		
		if mfaSetupRequired {
			c.Redirect(http.StatusSeeOther, "/admin/login/mfa/setup")
		} else {
			c.Redirect(http.StatusSeeOther, "/admin/login/mfa")
		}
		return
	}

	audit.EventResult(c, "admin.login", "email="+email, true, "")

	ctrl.setAdminCookie(c, token, expireMinutes*60)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// PostLogout cierra la sesión
func (ctrl *LoginController) PostLogout(c *gin.Context) {
	ctrl.clearAdminCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.clearMfaTransactionCookie(c)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// GetAdminMfaForm renderiza la vista para que el administrador valide su MFA
func (ctrl *LoginController) GetAdminMfaForm(c *gin.Context) {
	ctrl.setNoCacheHeaders(c)
	
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		ctrl.clearMfaTransactionCookie(c)
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Acceso no autorizado o sesión MFA expirada"))
		return
	}

	csrf, _ := c.Get("csrf_token")

	// Verificar si tiene WebAuthn configurado
	hasWebAuthn := false
	if status, err := ctrl.MfaService.GetMfaStatus(txn.UserID); err == nil {
		hasWebAuthn = status.WebAuthnConfigured
	}

	// Do NOT pass the MFA token to the template - keep it server-side only
	c.HTML(http.StatusOK, "login_mfa.html", gin.H{
		"CSRFToken":   csrf,
		"Error":       c.Query("error"),
		"HasWebAuthn": hasWebAuthn,
	})
}

// GetAdminMfaSetupForm renderiza la vista para configurar forzosamente el MFA
func (ctrl *LoginController) GetAdminMfaSetupForm(c *gin.Context) {
	ctrl.setNoCacheHeaders(c)
	
	// Get MFA transaction from server-side store
	_, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		ctrl.clearMfaTransactionCookie(c)
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Acceso no autorizado o sesión MFA expirada"))
		return
	}

	csrf, _ := c.Get("csrf_token")

	// Do NOT pass the MFA token to the template - keep it server-side only
	c.HTML(http.StatusOK, "login_mfa_setup.html", gin.H{
		"CSRFToken": csrf,
	})
}

// PostAdminMfa valida el código MFA (TOTP o de recuperación) para acceso administrativo
func (ctrl *LoginController) PostAdminMfa(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		ctrl.clearMfaTransactionCookie(c)
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Sesión MFA expirada. Inicie sesión nuevamente"))
		return
	}

	code := strings.TrimSpace(c.PostForm("code"))
	if code == "" {
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Código requerido"))
		return
	}

	// Determinar el tipo de código: TOTP (6 dígitos) o Código de recuperación
	isRecovery := len(strings.ReplaceAll(code, "-", "")) != 6

	var mfaErr error
	if isRecovery {
		mfaErr = ctrl.MfaService.ValidateRecoveryCode(txn.UserID, code)
	} else {
		mfaErr = ctrl.MfaService.ValidateTOTPCode(txn.UserID, code)
	}

	if mfaErr != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", txn.UserID), false, mfaErr.Error())
		c.Redirect(http.StatusSeeOther, "/admin/login/mfa?error="+url.QueryEscape("Código de verificación inválido"))
		return
	}

	// Consume the MFA transaction (one-time use)
	transactionID := ctrl.extractMfaTransactionID(c)
	if err := service.ConsumeMfaTransaction(transactionID); err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("Error al completar autenticación"))
		return
	}

	// Completar login
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(txn.UserID)
	if err != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", txn.UserID), false, err.Error())
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape("No se pudo completar el inicio de sesión"))
		return
	}

	audit.EventResult(c, "admin.login.mfa_success", fmt.Sprintf("userID=%d", txn.UserID), true, "")

	ctrl.clearMfaTransactionCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.setAdminCookie(c, token, expireMinutes*60)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// BeginWebAuthnLogin inicia el login WebAuthn (Admin o API)
func (ctrl *LoginController) BeginWebAuthnLogin(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	options, sessionData, err := ctrl.MfaService.BeginWebAuthnLogin(txn.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Use transaction ID for WebAuthn session key instead of the JWT
	transactionID := ctrl.extractMfaTransactionID(c)
	sessionKey := fmt.Sprintf("wa_login_%s", transactionID)
	service.StoreWebAuthnSession(sessionKey, sessionData)

	c.JSON(http.StatusOK, options)
}

// FinishWebAuthnLoginAdmin finaliza el login WebAuthn para el panel de administración
func (ctrl *LoginController) FinishWebAuthnLoginAdmin(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	transactionID := ctrl.extractMfaTransactionID(c)
	sessionKey := fmt.Sprintf("wa_login_%s", transactionID)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := ctrl.MfaService.FinishWebAuthnLogin(txn.UserID, sessionData, c.Request); err != nil {
		audit.EventResult(c, "admin.login.mfa_failed", fmt.Sprintf("userID=%d", txn.UserID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Invalida el desafío WebAuthn para prevenir reuso (single-use challenge)
	service.DeleteWebAuthnSession(sessionKey)

	// Consume the MFA transaction (one-time use)
	if err := service.ConsumeMfaTransaction(transactionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al completar autenticación"})
		return
	}

	// Completar login admin
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(txn.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctrl.clearMfaTransactionCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.setAdminCookie(c, token, expireMinutes*60)

	c.JSON(http.StatusOK, gin.H{"message": "Login exitoso", "redirect": "/admin"})
}

// VerifyTOTPSetupAdmin valida el código TOTP enviado para activar el factor durante el login del admin
func (ctrl *LoginController) VerifyTOTPSetupAdmin(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(txn.UserID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Consume the MFA transaction (one-time use)
	transactionID := ctrl.extractMfaTransactionID(c)
	if err := service.ConsumeMfaTransaction(transactionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al completar autenticación"})
		return
	}

	// Login is complete, generate final token
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(txn.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctrl.clearMfaTransactionCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.setAdminCookie(c, token, expireMinutes*60)

	c.JSON(http.StatusOK, gin.H{
		"message":        "TOTP activado con éxito",
		"recovery_codes": recoveryCodes,
		"redirect":       "/admin",
	})
}

// FinishWebAuthnSetupAdmin finaliza el registro de WebAuthn durante el login del admin
func (ctrl *LoginController) FinishWebAuthnSetupAdmin(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	transactionID := ctrl.extractMfaTransactionID(c)
	sessionKey := fmt.Sprintf("wa_reg_%s", transactionID)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := ctrl.MfaService.FinishWebAuthnRegistration(txn.UserID, sessionData, c.Request); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Delete session from cache
	service.DeleteWebAuthnSession(sessionKey)

	// Consume the MFA transaction (one-time use)
	if err := service.ConsumeMfaTransaction(transactionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al completar autenticación"})
		return
	}

	// Login is complete, generate final token
	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(txn.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctrl.clearMfaTransactionCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.setAdminCookie(c, token, expireMinutes*60)

	c.JSON(http.StatusOK, gin.H{
		"message":  "Llave de seguridad vinculada con éxito",
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if err := ctrl.MfaService.ValidateTOTPCode(userID, req.Code); err != nil {
		audit.EventResult(c, "api.login.mfa_totp_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID, true)
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if err := ctrl.MfaService.ValidateRecoveryCode(userID, req.Code); err != nil {
		audit.EventResult(c, "api.login.mfa_recovery_failed", fmt.Sprintf("userID=%d", userID), false, err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// SetupTOTPLogin permite configurar TOTP durante el login forzoso
func (ctrl *LoginController) SetupTOTPLogin(c *gin.Context) {
	mfaToken := ctrl.extractMfaToken(c)
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado; debe autenticarse con su factor existente"})
		return
	}

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
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = ctrl.extractMfaToken(c)
	}
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado"})
		return
	}

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Login is complete, generate final token
	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID, true)
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
	mfaToken := ctrl.extractMfaToken(c)
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado; debe autenticarse con su factor existente"})
		return
	}

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
	mfaToken := ctrl.extractMfaToken(c)
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

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado"})
		return
	}

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
	response, err := ctrl.UserService.CompleteLoginWithMfa(userID, claims.AppID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Llave de seguridad vinculada con éxito",
		"auth":    response,
	})
}

// PostAdminMfaSetup genera el QR para configurar TOTP forzosamente en el panel admin
func (ctrl *LoginController) PostAdminMfaSetup(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(txn.UserID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado; debe autenticarse con su factor existente"})
		return
	}

	resp, err := ctrl.MfaService.SetupTOTP(txn.UserID, txn.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// PostAdminMfaVerifySetup verifica y activa TOTP forzosamente en el panel admin
func (ctrl *LoginController) PostAdminMfaVerifySetup(c *gin.Context) {
	// Get MFA transaction from server-side store
	txn, err := ctrl.getMfaTransactionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	if ctrl.MfaService.IsMfaEnabled(txn.UserID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado"})
		return
	}

	recoveryCodes, err := ctrl.MfaService.VerifyAndActivateTOTP(txn.UserID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Consume the MFA transaction (one-time use)
	transactionID := ctrl.extractMfaTransactionID(c)
	if err := service.ConsumeMfaTransaction(transactionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al completar autenticación"})
		return
	}

	token, expireMinutes, err := ctrl.UserService.CompleteAdminLoginWithMfa(txn.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctrl.clearMfaTransactionCookie(c)
	ctrl.clearMfaCookie(c)
	ctrl.setAdminCookie(c, token, expireMinutes*60)

	c.JSON(http.StatusOK, gin.H{"message": "TOTP activado", "recovery_codes": recoveryCodes})
}
