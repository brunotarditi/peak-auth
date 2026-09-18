package peakauthgin

import (
	"net/http"
	"strings"

	"github.com/brunotarditi/peak-auth/sdk/go"
	"github.com/gin-gonic/gin"
)

// MiddlewareOptions configura el comportamiento del middleware de autenticación.
type MiddlewareOptions struct {
	// RequiredRoles especifica los roles necesarios para acceder al recurso.
	RequiredRoles []string
	// UseIntrospection controla el modo de validación del token:
	//   - nil (por defecto): usa introspección automáticamente si ClientSecret está configurado
	//   - true: fuerza validación online vía /api/v1/introspect (requiere ClientSecret)
	//   - false: fuerza validación offline (solo firma/expiración, NO detecta revocación)
	//
	// ADVERTENCIA: La validación offline (false) NO verifica revocación de tokens.
	// Los tokens emitidos antes de revocar acceso seguirán siendo aceptados hasta su expiración.
	// Solo use validación offline si comprende las implicaciones de seguridad.
	UseIntrospection *bool
}

// Middleware retorna un middleware para Gin que valida tokens JWT contra Peak Auth.
// Si se especifican requiredRoles, valida que el usuario posea al menos uno de ellos.
// Guarda las claims en el contexto con las claves "claims" y "user".
func Middleware(client *peakauth.Client, requiredRoles ...string) gin.HandlerFunc {
	return MiddlewareWithOptions(client, MiddlewareOptions{
		RequiredRoles: requiredRoles,
	})
}

// MiddlewareWithOptions retorna un middleware con opciones avanzadas de configuración.
func MiddlewareWithOptions(client *peakauth.Client, opts MiddlewareOptions) gin.HandlerFunc {
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

		var userRoles []string

		// Determinar modo de validación: por defecto usa introspección si ClientSecret está disponible
		useIntrospection := false
		if opts.UseIntrospection != nil {
			useIntrospection = *opts.UseIntrospection
		} else {
			// Modo automático: usar introspección si el cliente tiene ClientSecret configurado
			useIntrospection = client.HasClientSecret()
		}

		if useIntrospection {
			// Validación online con verificación de revocación
			introspection, err := client.IntrospectToken(ctx.Request.Context(), tokenStr)
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "invalid_token",
					"message": err.Error(),
				})
				return
			}
			if !introspection.Active {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "invalid_token",
					"message": "Token revocado o inválido",
				})
				return
			}
			userRoles = introspection.Roles
			// Guardar información de introspección en el contexto
			ctx.Set("introspection", introspection)
			ctx.Set("user", introspection)
		} else {
			// Validación offline tradicional (solo firma y expiración, NO verifica revocación)
			claims, err := client.VerifyTokenWithContext(ctx.Request.Context(), tokenStr)
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "invalid_token",
					"message": err.Error(),
				})
				return
			}
			userRoles = claims.Roles
			ctx.Set("claims", claims)
			ctx.Set("user", claims)
		}

		if len(opts.RequiredRoles) > 0 {
			hasRole := false
			for _, required := range opts.RequiredRoles {
				for _, userRole := range userRoles {
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
