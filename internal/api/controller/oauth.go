package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/api/request"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type OAuthController struct {
	BaseController
	OAuthService service.OAuthService
	UserService  service.UserService
	MfaService   service.MfaService
	TokenManager *auth.JWTManager
}

// AuthorizeEndpoint maneja GET /oauth/authorize
func (c *OAuthController) AuthorizeEndpoint(ctx *gin.Context) {
	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	responseType := ctx.Query("response_type")
	state := ctx.Query("state")
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" || responseType != "code" {
		// No podemos redirigir a un lugar seguro si faltan parámetros clave
		c.renderError(ctx, http.StatusBadRequest, "Parámetros Inválidos", "Parámetros de autorización OAuth inválidos o incompletos.")
		return
	}

	// 0. Validar de antemano que la aplicación exista y que redirect_uri coincida con la registrada (prevención Open Redirect)
	if err := c.OAuthService.ValidateClientRedirect(clientID, redirectURI); err != nil {
		c.renderError(ctx, http.StatusBadRequest, "Solicitud No Permitida", "Redirect URI o Client ID inválidos.")
		return
	}

	// 1. Validar sesión SSO exclusiva de Peak Auth (prevención de Cross-App Session Hijacking)
	cookie, err := ctx.Cookie("peak_session")
	var claims *auth.CustomClaims

	if err == nil && cookie != "" {
		claims, err = c.TokenManager.VerifyTokenForApp(cookie, util.AppIdPeakAuth)
	}

	if err != nil || claims == nil {
		// No hay sesión, redirigir a la pantalla de login público de OAuth propagando PKCE si vino
		url := url.URL{Path: "/oauth/login"}
		query := url.Query()
		query.Set("client_id", clientID)
		query.Set("redirect_uri", redirectURI)
		query.Set("state", state)

		if codeChallenge != "" {
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", codeChallengeMethod)
		}
		url.RawQuery = query.Encode()
		ctx.Redirect(http.StatusFound, url.String())
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		url := url.URL{Path: "/oauth/login"}
		query := url.Query()
		query.Set("client_id", clientID)
		query.Set("redirect_uri", redirectURI)
		query.Set("state", state)

		if codeChallenge != "" {
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", codeChallengeMethod)
		}
		url.RawQuery = query.Encode()
		ctx.Redirect(http.StatusFound, url.String())
		return
	}

	// 2. Generar Authorization Code (con soporte PKCE)
	code, err := c.OAuthService.GenerateAuthorizationCode(userID, clientID, redirectURI, codeChallenge, codeChallengeMethod)
	if err != nil {
		// Por seguridad, si el redirectURI no es válido según BD, no redirigir
		if err.Error() == "redirect_uri no coincide con la registrada" {
			ctx.String(http.StatusBadRequest, "Redirect URI inválida")
			return
		}
		// Redirigir con error a la URI validada
		errRedirect := fmt.Sprintf("%s?error=server_error&state=%s", redirectURI, url.QueryEscape(state))
		ctx.Redirect(http.StatusFound, errRedirect)
		return
	}

	// 3. Redirigir de vuelta a la aplicación cliente con el código
	finalRedirect := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, url.QueryEscape(code), url.QueryEscape(state))
	ctx.Redirect(http.StatusFound, finalRedirect)
}

// TokenEndpoint maneja POST /oauth/token
func (c *OAuthController) TokenEndpoint(ctx *gin.Context) {
	// Soporta tanto Form Data como JSON
	var req struct {
		ClientID     string `json:"client_id" form:"client_id"`
		ClientSecret string `json:"client_secret" form:"client_secret"`
		Code         string `json:"code" form:"code"`
		GrantType    string `json:"grant_type" form:"grant_type"`
		RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
		CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	}

	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	if req.GrantType != "authorization_code" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	if req.ClientID == "" || req.ClientSecret == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Intercambiar código por Token validando client, secret, redirect_uri y PKCE code_verifier
	userID, err := c.OAuthService.ExchangeCodeForToken(req.ClientID, req.ClientSecret, req.Code, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	// El token final se genera emulando un login completo (incluyendo roles para ese client_id)
	// Para ello utilizamos CompleteLoginWithMfa (que simplemente expide un token JWT para el usuario en la app)
	response, err := c.UserService.CompleteLoginWithMfa(userID, req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	// OAuth2 response standard
	ctx.JSON(http.StatusOK, gin.H{
		"access_token": response.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   response.ExpiresIn,
	})
}

// GetPublicLogin renderiza la vista pública de login para el flujo OAuth2
func (c *OAuthController) GetPublicLogin(ctx *gin.Context) {
	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	state := ctx.Query("state")
	codeChallenge := ctx.Query("code_challenge")
	codeChallengeMethod := ctx.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" {
		ctx.String(http.StatusBadRequest, "Parámetros inválidos")
		return
	}

	if err := c.OAuthService.ValidateClientRedirect(clientID, redirectURI); err != nil {
		ctx.String(http.StatusBadRequest, "Redirect URI o client_id inválidos")
		return
	}

	csrf, _ := ctx.Get("csrf_token")
	ctx.HTML(http.StatusOK, "oauth_login.html", gin.H{
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"CSRFToken":           csrf,
		"Error":               ctx.Query("error"),
	})
}

// PostPublicLogin procesa las credenciales públicas de login
func (c *OAuthController) PostPublicLogin(ctx *gin.Context) {
	clientID := ctx.PostForm("client_id")
	redirectURI := ctx.PostForm("redirect_uri")
	state := ctx.PostForm("state")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")
	codeChallenge := ctx.PostForm("code_challenge")
	codeChallengeMethod := ctx.PostForm("code_challenge_method")

	if err := c.OAuthService.ValidateClientRedirect(clientID, redirectURI); err != nil {
		ctx.String(http.StatusBadRequest, "Redirect URI o client_id inválidos")
		return
	}

	// Usamos Login (para usuarios finales) en lugar de AdminLogin
	response, err := c.UserService.Login(request.LoginRequest{
		Email:    email,
		Password: password,
	}, clientID)

	if err != nil {
		userErrMsg := "Credenciales inválidas"
		if strings.Contains(strings.ToLower(err.Error()), "inactiva") || strings.Contains(strings.ToLower(err.Error()), "bloqueada") {
			userErrMsg = err.Error()
		}
		redirectURL := fmt.Sprintf("/oauth/login?client_id=%s&redirect_uri=%s&state=%s&error=%s",
			url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state), url.QueryEscape(userErrMsg))
		if codeChallenge != "" {
			redirectURL += fmt.Sprintf("&code_challenge=%s&code_challenge_method=%s",
				url.QueryEscape(codeChallenge), url.QueryEscape(codeChallengeMethod))
		}
		ctx.Redirect(http.StatusSeeOther, redirectURL)
		return
	}

	if response.MfaRequired {
		c.setMfaCookie(ctx, response.MfaToken)
		targetURL := "/oauth/login/mfa"
		if response.MfaSetupRequired {
			targetURL = "/oauth/login/mfa/setup"
		}
		mfaRedirect := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s",
			targetURL, url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state))
		if codeChallenge != "" {
			mfaRedirect += fmt.Sprintf("&code_challenge=%s&code_challenge_method=%s",
				url.QueryEscape(codeChallenge), url.QueryEscape(codeChallengeMethod))
		}
		ctx.Redirect(http.StatusSeeOther, mfaRedirect)
		return
	}

	// Login exitoso sin MFA. Separación de cookie: emitir sesión interactiva SSO para Peak Auth (M4)
	claims, err := c.TokenManager.VerifyToken(response.AccessToken)
	if err != nil || claims == nil {
		c.renderError(ctx, http.StatusInternalServerError, "Error de Servidor", "No se pudo iniciar la sesión SSO.")
		return
	}
	uid, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.renderError(ctx, http.StatusInternalServerError, "Error de Servidor", "Identificador de usuario inválido.")
		return
	}
	ssoJWT, err := c.TokenManager.GenerateToken(uid, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		c.renderError(ctx, http.StatusInternalServerError, "Error de Servidor", "No se pudo generar la sesión SSO.")
		return
	}

	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	authURL := fmt.Sprintf("/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
		url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state))
	if codeChallenge != "" {
		authURL += fmt.Sprintf("&code_challenge=%s&code_challenge_method=%s",
			url.QueryEscape(codeChallenge), url.QueryEscape(codeChallengeMethod))
	}
	ctx.Redirect(http.StatusSeeOther, authURL)
}

// GetPublicLoginMfa renderiza la vista de verificación MFA pública
func (c *OAuthController) GetPublicLoginMfa(ctx *gin.Context) {
	mfaToken := c.extractMfaToken(ctx)
	if mfaToken == "" {
		ctx.Redirect(http.StatusSeeOther, "/oauth/login?error="+url.QueryEscape("Acceso no autorizado o sesión MFA expirada"))
		return
	}

	ctx.HTML(http.StatusOK, "oauth_login_mfa.html", gin.H{
		"MfaToken":    mfaToken,
		"ClientID":    ctx.Query("client_id"),
		"RedirectURI": ctx.Query("redirect_uri"),
		"State":       ctx.Query("state"),
	})
}

// GetPublicLoginMfaSetup renderiza la vista de setup MFA forzoso pública
func (c *OAuthController) GetPublicLoginMfaSetup(ctx *gin.Context) {
	mfaToken := c.extractMfaToken(ctx)
	if mfaToken == "" {
		ctx.Redirect(http.StatusSeeOther, "/oauth/login?error="+url.QueryEscape("Acceso no autorizado o sesión MFA expirada"))
		return
	}

	ctx.HTML(http.StatusOK, "oauth_login_mfa_setup.html", gin.H{
		"MfaToken":    mfaToken,
		"ClientID":    ctx.Query("client_id"),
		"RedirectURI": ctx.Query("redirect_uri"),
		"State":       ctx.Query("state"),
	})
}

// PostPublicLoginMfaTotp valida TOTP y establece la cookie de sesión SSO HttpOnly
func (c *OAuthController) PostPublicLoginMfaTotp(ctx *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Código requerido"})
		return
	}

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = c.extractMfaToken(ctx)
	}
	if mfaToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if err := c.MfaService.ValidateTOTPCode(userID, req.Code); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Código incorrecto"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar sesión SSO"})
		return
	}

	c.clearMfaCookie(ctx)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

// PostPublicLoginMfaRecovery valida código de recuperación y establece la cookie de sesión SSO HttpOnly
func (c *OAuthController) PostPublicLoginMfaRecovery(ctx *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Código de recuperación requerido"})
		return
	}

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = c.extractMfaToken(ctx)
	}
	if mfaToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA expirada o no encontrada"})
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	if err := c.MfaService.ValidateRecoveryCode(userID, req.Code); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Código de recuperación inválido"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar sesión SSO"})
		return
	}

	c.clearMfaCookie(ctx)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

// PostPublicLoginMfaWebAuthnFinish valida el desafío WebAuthn y establece la sesión SSO HttpOnly
func (c *OAuthController) PostPublicLoginMfaWebAuthnFinish(ctx *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token"`
	}
	_ = ctx.ShouldBindBodyWithJSON(&req)

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = c.extractMfaToken(ctx)
	}
	if mfaToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "mfa_token requerido"})
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	sessionKey := fmt.Sprintf("wa_login_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := c.MfaService.FinishWebAuthnLogin(userID, sessionData, ctx.Request); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	service.DeleteWebAuthnSession(sessionKey)

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar sesión SSO"})
		return
	}

	c.clearMfaCookie(ctx)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

// PostPublicLoginMfaSetupVerify activa TOTP en el setup obligatorio y establece la sesión SSO
func (c *OAuthController) PostPublicLoginMfaSetupVerify(ctx *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Código requerido"})
		return
	}

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = c.extractMfaToken(ctx)
	}
	if mfaToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Sesión MFA requerida"})
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido o expirado"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
		return
	}

	recoveryCodes, err := c.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar sesión SSO"})
		return
	}

	c.clearMfaCookie(ctx)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	ctx.JSON(http.StatusOK, gin.H{
		"message":        "MFA activado con éxito",
		"recovery_codes": recoveryCodes,
		"success":        true,
	})
}

// PostPublicLoginMfaSetupWebAuthnFinish activa WebAuthn en el setup obligatorio y establece la sesión SSO
func (c *OAuthController) PostPublicLoginMfaSetupWebAuthnFinish(ctx *gin.Context) {
	var req struct {
		MfaToken string `json:"mfa_token"`
	}
	_ = ctx.ShouldBindBodyWithJSON(&req)

	mfaToken := req.MfaToken
	if mfaToken == "" {
		mfaToken = c.extractMfaToken(ctx)
	}
	if mfaToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "mfa_token requerido"})
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido o expirado"})
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Token MFA inválido"})
		return
	}

	sessionKey := fmt.Sprintf("wa_reg_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := c.MfaService.FinishWebAuthnRegistration(userID, sessionData, ctx.Request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	service.DeleteWebAuthnSession(sessionKey)

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo generar sesión SSO"})
		return
	}

	c.clearMfaCookie(ctx)
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", ssoJWT, 86400, "/", "", util.IsProduction(), true)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Passkey registrada con éxito",
		"success": true,
	})
}
