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
	RuleService  service.ApplicationRuleService
	AppService   service.ApplicationService
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
		c.redirectToOAuthLogin(ctx, "/oauth/login", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
		return
	}

	userID, err := parseUserIDFromSubject(claims.Subject)
	if err != nil {
		c.redirectToOAuthLogin(ctx, "/oauth/login", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
		return
	}

	// Validar que el token no haya sido invalidado por cambio de contraseña o revocación
	if c.UserService != nil {
		user, err := c.UserService.FindVerifiedUserByID(userID)
		if err != nil || user == nil || !user.IsActive {
			// Usuario no encontrado, inactivo o no verificado - redirigir a login
			c.redirectToOAuthLogin(ctx, "/oauth/login", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
			return
		}

		// Si la contraseña fue restablecida con posterioridad a la emisión del token, invalidarlo
		if user.PasswordChangedAt != nil && claims.IssuedAt != nil && claims.IssuedAt.Time.Before(*user.PasswordChangedAt) {
			c.redirectToOAuthLogin(ctx, "/oauth/login", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
			return
		}

		// Verificar que el token no haya sido revocado (authz_version mismatch)
		if claims.AuthzVersion != user.AuthzVersion {
			c.redirectToOAuthLogin(ctx, "/oauth/login", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
			return
		}
	}

	// Validar si la app destino exige MFA_POLICY
	if c.AppService != nil && c.RuleService != nil {
		targetApp, err := c.AppService.GetAppDetails(clientID)
		if err == nil {
			rules, _ := c.RuleService.FindRulesByAppID(targetApp.ID)
			for _, r := range rules {
				if r.Code == "MFA_POLICY" {
					policy, err := util.ParseMfaPolicy(r.Value)
					if err == nil && policy.Mode == "REQUIRED" {
						if !c.MfaService.IsMfaEnabled(userID) {
							mfaToken, _ := c.TokenManager.GenerateMFAPendingToken(userID, claims.Username, clientID)
							c.setMfaCookie(ctx, mfaToken)
							c.redirectToOAuthLogin(ctx, "/oauth/login/mfa/setup", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
							return
						}
						if !claims.MfaVerified {
							mfaToken, _ := c.TokenManager.GenerateMFAPendingToken(userID, claims.Username, clientID)
							c.setMfaCookie(ctx, mfaToken)
							c.redirectToOAuthLogin(ctx, "/oauth/login/mfa", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
							return
						}
					}
				}
			}
		}
	}

	// 2. Generar Authorization Code (con soporte PKCE)
	mfaCompleted := claims.MfaVerified
	code, err := c.OAuthService.GenerateAuthorizationCode(userID, clientID, redirectURI, codeChallenge, codeChallengeMethod, mfaCompleted)
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

// TokenEndpoint maneja POST y OPTIONS /oauth/token (RFC 6749, RFC 7636)
func (c *OAuthController) TokenEndpoint(ctx *gin.Context) {
	// Soporte CORS para clientes SPA
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	ctx.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if ctx.Request.Method == http.MethodOptions {
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}

	// Directivas de no almacenamiento en caché conforme a RFC 6749 §5.1
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")

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

	// Soporte client_secret_basic (RFC 6749 §2.3.1): si client_id o client_secret faltan en el cuerpo,
	// intentar extraerlos del encabezado Authorization: Basic <base64(client_id:client_secret)>
	if basicUser, basicPass, ok := ctx.Request.BasicAuth(); ok {
		if unescapedUser, err := url.QueryUnescape(basicUser); err == nil {
			basicUser = unescapedUser
		}
		if unescapedPass, err := url.QueryUnescape(basicPass); err == nil {
			basicPass = unescapedPass
		}
		if req.ClientID == "" {
			req.ClientID = basicUser
		}
		if req.ClientSecret == "" {
			req.ClientSecret = basicPass
		}
	}

	if req.GrantType != "authorization_code" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	if req.ClientID == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	// Intercambiar código por Token validando client, secret, redirect_uri y PKCE code_verifier
	userID, mfaCompleted, err := c.OAuthService.ExchangeCodeForToken(req.ClientID, req.ClientSecret, req.Code, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	// El token final se genera emulando un login completo (incluyendo roles para ese client_id)
	// Para ello utilizamos CompleteLoginWithMfa (que simplemente expide un token JWT para el usuario en la app)
	response, err := c.UserService.CompleteLoginWithMfa(userID, req.ClientID, mfaCompleted)
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
		redirectURL := url.URL{Path: "/oauth/login"}
		query := redirectURL.Query()
		query.Set("client_id", clientID)
		query.Set("redirect_uri", redirectURI)
		query.Set("state", state)
		query.Set("error", userErrMsg)
		if codeChallenge != "" {
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", codeChallengeMethod)
		}
		redirectURL.RawQuery = query.Encode()
		ctx.Redirect(http.StatusSeeOther, redirectURL.String())
		return
	}

	if response.MfaRequired {
		c.setMfaCookie(ctx, response.MfaToken)
		targetURL := "/oauth/login/mfa"
		if response.MfaSetupRequired {
			targetURL = "/oauth/login/mfa/setup"
		}
		url := url.URL{Path: targetURL}
		query := url.Query()
		query.Set("client_id", clientID)
		query.Set("redirect_uri", redirectURI)
		query.Set("state", state)
		if codeChallenge != "" {
			query.Set("code_challenge", codeChallenge)
			query.Set("code_challenge_method", codeChallengeMethod)
		}
		url.RawQuery = query.Encode()
		ctx.Redirect(http.StatusSeeOther, url.String())
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
	ssoJWT, err := c.TokenManager.GenerateToken(uid, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, false, claims.AuthzVersion)
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

	csrf, _ := ctx.Get("csrf_token")
	ctx.HTML(http.StatusOK, "oauth_login_mfa.html", gin.H{
		"MfaToken":    mfaToken,
		"ClientID":    ctx.Query("client_id"),
		"RedirectURI": ctx.Query("redirect_uri"),
		"State":       ctx.Query("state"),
		"CSRFToken":   csrf,
	})
}

// GetPublicLoginMfaSetup renderiza la vista de setup MFA forzoso pública
func (c *OAuthController) GetPublicLoginMfaSetup(ctx *gin.Context) {
	mfaToken := c.extractMfaToken(ctx)
	if mfaToken == "" {
		ctx.Redirect(http.StatusSeeOther, "/oauth/login?error="+url.QueryEscape("Acceso no autorizado o sesión MFA expirada"))
		return
	}

	claims, err := c.TokenManager.VerifyMFAPendingToken(mfaToken, "")
	if err == nil {
		if userID, err := parseUserIDFromSubject(claims.Subject); err == nil {
			if c.MfaService.IsMfaEnabled(userID) {
				ctx.Redirect(http.StatusSeeOther, fmt.Sprintf("/oauth/login/mfa?client_id=%s&redirect_uri=%s&state=%s",
					url.QueryEscape(ctx.Query("client_id")), url.QueryEscape(ctx.Query("redirect_uri")), url.QueryEscape(ctx.Query("state"))))
				return
			}
		}
	}

	csrf, _ := ctx.Get("csrf_token")
	ctx.HTML(http.StatusOK, "oauth_login_mfa_setup.html", gin.H{
		"MfaToken":    mfaToken,
		"ClientID":    ctx.Query("client_id"),
		"RedirectURI": ctx.Query("redirect_uri"),
		"State":       ctx.Query("state"),
		"CSRFToken":   csrf,
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

	// Create a unique key for this MFA token to track attempts
	tokenKey := fmt.Sprintf("oauth_mfa_%d_%s", userID, claims.Subject)

	// Check if token is already locked
	if service.IsApiMfaTokenLocked(tokenKey) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
		return
	}

	if err := c.MfaService.ValidateTOTPCode(userID, req.Code); err != nil {
		// Record failed attempt and check if token should be locked
		if lockErr := service.RecordApiMfaFailedAttempt(tokenKey, userID); lockErr != nil {
			// Token is now locked due to excessive failures
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Código incorrecto"})
		return
	}

	// Clear attempt tracker on successful validation
	service.DeleteApiMfaAttemptTracker(tokenKey)

	// Fetch user to get current authz_version
	user, err := c.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el usuario"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, true, user.AuthzVersion)
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

	// Create a unique key for this MFA token to track attempts
	tokenKey := fmt.Sprintf("oauth_mfa_%d_%s", userID, claims.Subject)

	// Check if token is already locked
	if service.IsApiMfaTokenLocked(tokenKey) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
		return
	}

	if err := c.MfaService.ValidateRecoveryCode(userID, req.Code); err != nil {
		// Record failed attempt and check if token should be locked
		if lockErr := service.RecordApiMfaFailedAttempt(tokenKey, userID); lockErr != nil {
			// Token is now locked due to excessive failures
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Código de recuperación inválido"})
		return
	}

	// Clear attempt tracker on successful validation
	service.DeleteApiMfaAttemptTracker(tokenKey)

	// Fetch user to get current authz_version
	user, err := c.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el usuario"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, true, user.AuthzVersion)
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

	// Create a unique key for this MFA token to track attempts
	tokenKey := fmt.Sprintf("oauth_mfa_%d_%s", userID, claims.Subject)

	// Check if token is already locked
	if service.IsApiMfaTokenLocked(tokenKey) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
		return
	}

	sessionKey := fmt.Sprintf("wa_login_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := c.MfaService.FinishWebAuthnLogin(userID, sessionData, ctx.Request); err != nil {
		// Record failed attempt and check if token should be locked
		if lockErr := service.RecordApiMfaFailedAttempt(tokenKey, userID); lockErr != nil {
			// Token is now locked due to excessive failures
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
			return
		}
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Clear attempt tracker on successful validation
	service.DeleteApiMfaAttemptTracker(tokenKey)

	service.DeleteWebAuthnSession(sessionKey)

	// Fetch user to get current authz_version
	user, err := c.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el usuario"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, true, user.AuthzVersion)
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

	if c.MfaService.IsMfaEnabled(userID) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado"})
		return
	}

	// Create a unique key for this MFA token to track attempts
	tokenKey := fmt.Sprintf("oauth_mfa_setup_%d_%s", userID, claims.Subject)

	// Check if token is already locked
	if service.IsApiMfaTokenLocked(tokenKey) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
		return
	}

	recoveryCodes, err := c.MfaService.VerifyAndActivateTOTP(userID, req.Code)
	if err != nil {
		// Record failed attempt and check if token should be locked
		if lockErr := service.RecordApiMfaFailedAttempt(tokenKey, userID); lockErr != nil {
			// Token is now locked due to excessive failures
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Clear attempt tracker on successful validation
	service.DeleteApiMfaAttemptTracker(tokenKey)

	// Fetch user to get current authz_version
	user, err := c.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el usuario"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, true, user.AuthzVersion)
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

	if c.MfaService.IsMfaEnabled(userID) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "El usuario ya tiene MFA configurado"})
		return
	}

	// Create a unique key for this MFA token to track attempts
	tokenKey := fmt.Sprintf("oauth_mfa_setup_%d_%s", userID, claims.Subject)

	// Check if token is already locked
	if service.IsApiMfaTokenLocked(tokenKey) {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
		return
	}

	sessionKey := fmt.Sprintf("wa_reg_%s", mfaToken)
	sessionData, exists := service.GetWebAuthnSession(sessionKey)
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Sesión WebAuthn expirada o no encontrada"})
		return
	}

	if err := c.MfaService.FinishWebAuthnRegistration(userID, sessionData, ctx.Request); err != nil {
		// Record failed attempt and check if token should be locked
		if lockErr := service.RecordApiMfaFailedAttempt(tokenKey, userID); lockErr != nil {
			// Token is now locked due to excessive failures
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Demasiados intentos fallidos. Inicie sesión nuevamente"})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Clear attempt tracker on successful validation
	service.DeleteApiMfaAttemptTracker(tokenKey)

	service.DeleteWebAuthnSession(sessionKey)

	// Fetch user to get current authz_version
	user, err := c.UserService.FindVerifiedUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo verificar el usuario"})
		return
	}

	ssoJWT, err := c.TokenManager.GenerateToken(userID, claims.Username, util.AppIdPeakAuth, []string{"SSO_SESSION"}, 24*time.Hour, true, user.AuthzVersion)
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

// LogoutEndpoint maneja el Federated Logout (Single Logout) de OAuth2/OIDC.
// Borra la cookie de sesión central (peak_session) y redirige al usuario de vuelta a la aplicación tras validar el destino.
func (c *OAuthController) LogoutEndpoint(ctx *gin.Context) {
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("peak_session", "", -1, "/", "", util.IsProduction(), true)

	redirectURI := ctx.Query("post_logout_redirect_uri")
	if redirectURI == "" {
		redirectURI = ctx.Query("redirect_uri")
	}
	if redirectURI == "" {
		redirectURI = ctx.PostForm("post_logout_redirect_uri")
	}
	if redirectURI == "" {
		redirectURI = ctx.PostForm("redirect_uri")
	}

	if redirectURI != "" {
		clientID := ctx.Query("client_id")
		if clientID == "" {
			clientID = ctx.PostForm("client_id")
		}

		if clientID == "" {
			c.renderError(ctx, http.StatusBadRequest, "Solicitud Inválida", "client_id es requerido cuando se especifica una URL de redirección.")
			return
		}

		if err := c.OAuthService.ValidateClientRedirect(clientID, redirectURI); err != nil {
			c.renderError(ctx, http.StatusBadRequest, "Solicitud No Permitida", "Redirect URI o Client ID inválidos.")
			return
		}

		ctx.Redirect(http.StatusSeeOther, redirectURI)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Sesión cerrada correctamente"})
}

func (c *OAuthController) redirectToOAuthLogin(ctx *gin.Context, path, clientID, redirectURI, state, codeChallenge, codeChallengeMethod string) {
	redirectURL := url.URL{Path: path}
	query := redirectURL.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)

	if codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", codeChallengeMethod)
	}
	redirectURL.RawQuery = query.Encode()
	ctx.Redirect(http.StatusFound, redirectURL.String())
}
