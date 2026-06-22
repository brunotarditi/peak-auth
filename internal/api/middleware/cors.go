package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware configura CORS para la API v1 de integraciones.
//
// Reglas de seguridad:
//   - FRONTEND_URL define la allowlist de orígenes (separados por coma).
//   - Si FRONTEND_URL está vacío, NO se habilitan credenciales y se usa "*"
//     (modo público sin cookies, válido para APIs stateless con Bearer token).
//   - Si hay allowlist, se refleja el Origin SOLO si está permitido y se
//     habilitan credenciales. Nunca se combina "*" con credenciales.
func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := parseAllowedOrigins(os.Getenv("FRONTEND_URL"))

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if len(allowedOrigins) == 0 {
			// Modo público (API completamente abierta)
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" && originAllowed(origin, allowedOrigins) {
			// Modo restringido (frontend + credenciales)
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Add("Vary", "Origin")
		} else if origin != "" {
			// Origen no permitido → no seteamos Allow-Origin (seguridad)
			c.Writer.Header().Set("Access-Control-Allow-Origin", "")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, "+
				"accept, origin, Cache-Control, X-Requested-With, X-App-Id, X-App-Secret")
		c.Writer.Header().Set("Access-Control-Max-Age", "7200") // 2 horas de cache preflight

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func parseAllowedOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, strings.TrimRight(p, "/"))
		}
	}
	return out
}

func originAllowed(origin string, allowed []string) bool {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	for _, a := range allowed {
		if strings.EqualFold(origin, strings.TrimRight(strings.TrimSpace(a), "/")) {
			return true
		}
	}
	return false
}
