package peakauthgin

import (
	"net/http"
	"strings"

	"github.com/brunotarditi/peak-auth/sdk/go"
	"github.com/gin-gonic/gin"
)

// Middleware retorna un middleware para Gin que valida tokens JWT contra Peak Auth.
// Si se especifican requiredRoles, valida que el usuario posea al menos uno de ellos.
// Guarda las claims en el contexto con las claves "claims" y "user".
func Middleware(client *peakauth.Client, requiredRoles ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Bearer token es requerido",
			})
			return
		}

		tokenStr := strings.TrimSpace(authHeader[7:])
		claims, err := client.VerifyTokenWithContext(ctx.Request.Context(), tokenStr)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": err.Error(),
			})
			return
		}

		if len(requiredRoles) > 0 {
			hasRole := false
			for _, required := range requiredRoles {
				for _, userRole := range claims.Roles {
					if userRole == required {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "Permisos insuficientes para acceder a este recurso",
				})
				return
			}
		}

		ctx.Set("claims", claims)
		ctx.Set("user", claims)
		ctx.Next()
	}
}

// ClaimsFromContext recupera los Claims almacenados por el middleware de Gin.
func ClaimsFromContext(c *gin.Context) (*peakauth.Claims, bool) {
	val, exists := c.Get("claims")
	if !exists {
		return nil, false
	}
	claims, ok := val.(*peakauth.Claims)
	return claims, ok
}
