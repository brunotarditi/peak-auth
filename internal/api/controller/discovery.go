package controller

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"peak-auth/internal/auth"

	"github.com/gin-gonic/gin"
)

// DiscoveryController gestiona los endpoints públicos de descubrimiento OIDC y claves JWKS.
type DiscoveryController struct {
	BaseController
	TokenManager *auth.JWTManager
}

// JWKS maneja GET y OPTIONS en /.well-known/jwks.json (RFC 7517)
func (c *DiscoveryController) JWKS(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	ctx.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
	ctx.Header("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")

	if ctx.Request.Method == http.MethodOptions {
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}

	ctx.JSON(http.StatusOK, c.TokenManager.GetJWKS())
}

// OpenIDConfiguration maneja GET y OPTIONS en /.well-known/openid-configuration (RFC 8414)
func (c *DiscoveryController) OpenIDConfiguration(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	ctx.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
	ctx.Header("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")

	if ctx.Request.Method == http.MethodOptions {
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}

	baseURL := strings.TrimRight(os.Getenv("APP_BASE_URL"), "/")
	if baseURL == "" {
		scheme := "http"
		if ctx.Request.TLS != nil || ctx.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		baseURL = fmt.Sprintf("%s://%s", scheme, ctx.Request.Host)
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "peak-auth"
	}

	ctx.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
	})
}
