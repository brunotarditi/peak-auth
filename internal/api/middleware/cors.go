package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CorsOriginChecker define el contrato para validar orígenes según la aplicación
type CorsOriginChecker interface {
	IsOriginAllowed(appID string, origin string) bool
}

// CORSMiddleware configura CORS para la API v1 e integraciones externas.
//
// Reglas de resolución:
//  1. Si se provee un CorsOriginChecker y la petición contiene App ID o Client ID,
//     se valida contra las políticas CORS de esa aplicación.
//  2. Si no coincide o no hay App ID, se consulta la variable global FRONTEND_URL.
//  3. Si FRONTEND_URL está vacío y no hay app restringida, permite "*" (modo público sin cookies).
//  4. Si el origen es validado explícitamente, se refleja el Origin y se habilitan credenciales.
func CORSMiddleware(checker ...CorsOriginChecker) gin.HandlerFunc {
	allowedOrigins := parseAllowedOrigins(os.Getenv("FRONTEND_URL"))

	var originChecker CorsOriginChecker
	if len(checker) > 0 && checker[0] != nil {
		originChecker = checker[0]
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin == "" {
			c.Next()
			return
		}

		appID := c.GetHeader("X-App-ID")
		if appID == "" {
			appID = c.GetHeader("X-App-Id")
		}
		if appID == "" {
			appID = c.Query("client_id")
		}
		if appID == "" {
			appID = c.Query("app_id")
		}

		allowedByApp := false
		if originChecker != nil && appID != "" {
			allowedByApp = originChecker.IsOriginAllowed(appID, origin)
		}

		if allowedByApp {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Add("Vary", "Origin")
		} else if len(allowedOrigins) == 0 {
			// Modo público (API abierta o pruebas sin FRONTEND_URL restrictivo)
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else if originAllowed(origin, allowedOrigins) {
			// Modo restringido por FRONTEND_URL
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Add("Vary", "Origin")
		} else {
			// Origen no permitido → no seteamos Allow-Origin
			c.Writer.Header().Set("Access-Control-Allow-Origin", "")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, "+
				"accept, origin, Cache-Control, X-Requested-With, X-App-Id, X-App-ID, X-App-Secret, X-Request-ID")
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
