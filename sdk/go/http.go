package peakauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "peakauth.claims"

// HTTPMiddlewareOptions configura el comportamiento del middleware de autenticación.
type HTTPMiddlewareOptions struct {
	// RequiredRoles especifica los roles necesarios para acceder al recurso.
	RequiredRoles []string
	// UseIntrospection si es true, utiliza validación online vía /api/v1/introspect
	// para verificar revocación inmediata. Requiere ClientSecret configurado.
	// Por defecto: false (validación offline).
	UseIntrospection bool
}

// HTTPMiddleware retorna un middleware estándar net/http para validar tokens JWT.
func (c *Client) HTTPMiddleware(requiredRoles ...string) func(http.Handler) http.Handler {
	return c.HTTPMiddlewareWithOptions(HTTPMiddlewareOptions{
		RequiredRoles: requiredRoles,
	})
}

// HTTPMiddlewareWithOptions retorna un middleware con opciones avanzadas de configuración.
func (c *Client) HTTPMiddlewareWithOptions(opts HTTPMiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				respondJSON(w, http.StatusUnauthorized, map[string]string{
					"error":   "unauthorized",
					"message": "Bearer token es requerido",
				})
				return
			}

			tokenStr := strings.TrimSpace(authHeader[7:])

			var userRoles []string
			var ctx context.Context

			if opts.UseIntrospection {
				// Validación online con verificación de revocación
				introspection, err := c.IntrospectToken(r.Context(), tokenStr)
				if err != nil {
					respondJSON(w, http.StatusUnauthorized, map[string]string{
						"error":   "invalid_token",
						"message": err.Error(),
					})
					return
				}
				if !introspection.Active {
					respondJSON(w, http.StatusUnauthorized, map[string]string{
						"error":   "invalid_token",
						"message": "Token revocado o inválido",
					})
					return
				}
				userRoles = introspection.Roles
				ctx = context.WithValue(r.Context(), claimsContextKey, introspection)
			} else {
				// Validación offline tradicional (solo firma y expiración)
				claims, err := c.VerifyToken(tokenStr)
				if err != nil {
					respondJSON(w, http.StatusUnauthorized, map[string]string{
						"error":   "invalid_token",
						"message": err.Error(),
					})
					return
				}
				userRoles = claims.Roles
				ctx = context.WithValue(r.Context(), claimsContextKey, claims)
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
					respondJSON(w, http.StatusForbidden, map[string]string{
						"error":   "forbidden",
						"message": "Permisos insuficientes para acceder a este recurso",
					})
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext recupera los Claims inyectados en context.Context por HTTPMiddleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	val := ctx.Value(claimsContextKey)
	if val == nil {
		return nil, false
	}
	claims, ok := val.(*Claims)
	return claims, ok
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
