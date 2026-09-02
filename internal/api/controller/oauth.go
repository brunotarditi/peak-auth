package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"peak-auth/internal/api/request"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type OAuthController struct {
	OAuthService service.OAuthService
	UserService  service.UserService
	TokenManager *auth.JWTManager
}

// AuthorizeEndpoint maneja GET /oauth/authorize
func (c *OAuthController) AuthorizeEndpoint(ctx *gin.Context) {
	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	responseType := ctx.Query("response_type")
	state := ctx.Query("state")

	if clientID == "" || redirectURI == "" || responseType != "code" {
		// No podemos redirigir a un lugar seguro si faltan parámetros clave
		ctx.String(http.StatusBadRequest, "Parámetros de autorización inválidos")
		return
	}

	// 1. Validar sesión del usuario final
	cookie, err := ctx.Cookie("peak_session")
	var claims *auth.CustomClaims

	if err == nil && cookie != "" {
		claims, err = c.TokenManager.VerifyToken(cookie)
	}

	if err != nil || claims == nil {
		// No hay sesión, redirigir a la pantalla de login público de OAuth
		loginURL := fmt.Sprintf("/oauth/login?client_id=%s&redirect_uri=%s&state=%s",
			url.QueryEscape(clientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape(state))
		ctx.Redirect(http.StatusFound, loginURL)
		return
	}

	var userID uint
	_, _ = fmt.Sscanf(claims.Subject, "%d", &userID)

	// 2. Generar Authorization Code
	code, err := c.OAuthService.GenerateAuthorizationCode(userID, clientID, redirectURI)
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

	// Intercambiar código por Token
	userID, err := c.OAuthService.ExchangeCodeForToken(req.ClientID, req.ClientSecret, req.Code)
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

	if clientID == "" || redirectURI == "" {
		ctx.String(http.StatusBadRequest, "Parámetros inválidos")
		return
	}

	csrf, _ := ctx.Get("csrf_token")
	ctx.HTML(http.StatusOK, "oauth_login.html", gin.H{
		"ClientID":    clientID,
		"RedirectURI": redirectURI,
		"State":       state,
		"CSRFToken":   csrf,
		"Error":       ctx.Query("error"),
	})
}

// PostPublicLogin procesa las credenciales públicas de login
func (c *OAuthController) PostPublicLogin(ctx *gin.Context) {
	clientID := ctx.PostForm("client_id")
	redirectURI := ctx.PostForm("redirect_uri")
	state := ctx.PostForm("state")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	// Usamos Login (para usuarios finales) en lugar de AdminLogin
	response, err := c.UserService.Login(request.LoginRequest{
		Email:    email,
		Password: password,
	}, clientID)

	if err != nil {
		ctx.Redirect(http.StatusSeeOther, fmt.Sprintf("/oauth/login?client_id=%s&redirect_uri=%s&state=%s&error=%s",
			url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state), url.QueryEscape(err.Error())))
		return
	}

	if response.MfaRequired {
		if response.MfaSetupRequired {
			ctx.Redirect(http.StatusSeeOther, fmt.Sprintf("/oauth/login/mfa/setup?client_id=%s&redirect_uri=%s&state=%s&mfa_token=%s",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state), url.QueryEscape(response.MfaToken)))
		} else {
			ctx.Redirect(http.StatusSeeOther, fmt.Sprintf("/oauth/login/mfa?client_id=%s&redirect_uri=%s&state=%s&mfa_token=%s",
				url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state), url.QueryEscape(response.MfaToken)))
		}
		return
	}

	// Login exitoso sin MFA. Setear cookie y redirigir a authorize
	isSecure := ctx.Request.TLS != nil || ctx.GetHeader("X-Forwarded-Proto") == "https"
	// 5 mins para la cookie temporal de sesión pública (o 24hs)
	ctx.SetCookie("peak_session", response.AccessToken, response.ExpiresIn*60, "/", "", isSecure, true)

	authURL := fmt.Sprintf("/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
		url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(state))
	ctx.Redirect(http.StatusSeeOther, authURL)
}

// GetPublicLoginMfa renderiza la vista de verificación MFA pública
func (c *OAuthController) GetPublicLoginMfa(ctx *gin.Context) {
	mfaToken := ctx.Query("mfa_token")
	if mfaToken == "" {
		ctx.String(http.StatusBadRequest, "mfa_token faltante")
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
	mfaToken := ctx.Query("mfa_token")
	if mfaToken == "" {
		ctx.String(http.StatusBadRequest, "mfa_token faltante")
		return
	}

	ctx.HTML(http.StatusOK, "oauth_login_mfa_setup.html", gin.H{
		"MfaToken":    mfaToken,
		"ClientID":    ctx.Query("client_id"),
		"RedirectURI": ctx.Query("redirect_uri"),
		"State":       ctx.Query("state"),
	})
}
