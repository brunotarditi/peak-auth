package peakauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "peakauth.claims"

// HTTPMiddleware retorna un middleware estándar net/http para validar tokens JWT.
func (c *Client) HTTPMiddleware(requiredRoles ...string) func(http.Handler) http.Handler {
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
			claims, err := c.VerifyToken(tokenStr)
			if err != nil {
				respondJSON(w, http.StatusUnauthorized, map[string]string{
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
					respondJSON(w, http.StatusForbidden, map[string]string{
						"error":   "forbidden",
						"message": "Permisos insuficientes para acceder a este recurso",
					})
					return
				}
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
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
