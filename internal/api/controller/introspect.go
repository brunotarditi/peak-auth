package controller

import (
	"net/http"
	"peak-auth/internal/auth"
	"peak-auth/internal/store/repo"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type IntrospectController struct {
	TokenManager *auth.JWTManager
	UserRepo     repo.UserRepository
	UarRepo      repo.UserApplicationRoleRepository
}

// IntrospectRequest representa la solicitud de introspección de token
type IntrospectRequest struct {
	Token string `json:"token" binding:"required"`
}

// IntrospectResponse representa la respuesta de introspección según RFC 7662
type IntrospectResponse struct {
	Active     bool     `json:"active"`
	Sub        string   `json:"sub,omitempty"`
	Username   string   `json:"username,omitempty"`
	Aud        string   `json:"aud,omitempty"`
	Iss        string   `json:"iss,omitempty"`
	Exp        int64    `json:"exp,omitempty"`
	Iat        int64    `json:"iat,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	TokenType  string   `json:"token_type,omitempty"`
	MfaVerified bool    `json:"mfa_verified,omitempty"`
	Roles      []string `json:"roles,omitempty"`
}

// Introspect valida un token y devuelve su estado actual, incluyendo verificación
// de revocación mediante authz_version. Este endpoint permite a las aplicaciones
// relying party verificar tokens en tiempo real en lugar de confiar únicamente
// en la validación offline mediante JWKS.
//
// POST /api/v1/introspect
// Requiere autenticación de aplicación mediante X-App-Id y X-App-Secret
func (ctrl *IntrospectController) Introspect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token es requerido"})
		return
	}

	// Verificar firma, expiración y claims estándar
	claims, err := ctrl.TokenManager.VerifyToken(req.Token)
	if err != nil {
		// Token inválido, expirado o con firma incorrecta
		c.JSON(http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	// Extraer userID del subject
	userID, err := strconv.ParseUint(claims.Subject, 10, 32)
	if err != nil {
		c.JSON(http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	// Verificar estado del usuario y authz_version para detectar revocación
	user, err := ctrl.UserRepo.FindById(uint(userID))
	if err != nil || !user.IsActive || !user.IsVerified {
		c.JSON(http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	// Verificar que el token no haya sido revocado (authz_version mismatch)
	if claims.AuthzVersion != user.AuthzVersion {
		c.JSON(http.StatusOK, IntrospectResponse{Active: false})
		return
	}

	// Verificar que el usuario aún tenga acceso a la aplicación
	// (esto es opcional pero recomendado para mayor seguridad)
	if claims.AppID != "" && ctrl.UarRepo != nil {
		// Obtener la aplicación desde el contexto (inyectada por AppAuthMiddleware)
		appID, exists := c.Get("app_id")
		if exists {
			appIDUint, ok := appID.(uint)
			if ok {
				belongs, err := ctrl.UarRepo.BelongsToApp(uint(userID), appIDUint)
				if err != nil || !belongs {
					c.JSON(http.StatusOK, IntrospectResponse{Active: false})
					return
				}
			}
		}
	}

	// Token válido y activo
	response := IntrospectResponse{
		Active:      true,
		Sub:         claims.Subject,
		Username:    claims.Username,
		Aud:         claims.AppID,
		TokenType:   claims.TokenType,
		MfaVerified: claims.MfaVerified,
		Roles:       claims.Roles,
	}

	if claims.Issuer != "" {
		response.Iss = claims.Issuer
	}
	if claims.ExpiresAt != nil {
		response.Exp = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		response.Iat = claims.IssuedAt.Unix()
	}
	if claims.AppID != "" {
		response.ClientID = claims.AppID
	}
	if len(claims.Roles) > 0 {
		response.Scope = strings.Join(claims.Roles, " ")
	}

	c.JSON(http.StatusOK, response)
}
