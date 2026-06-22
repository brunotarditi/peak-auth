package middleware

import (
	"crypto/subtle"
	"net/http"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfMaxAge     = 3600 * 12 // 12 horas
)

// AdminCSRFMiddleware implementa protección CSRF con el patrón "double-submit cookie":
//
//  1. En toda petición segura (GET/HEAD/OPTIONS) garantiza que exista una cookie
//     csrf_token legible por JS. El front la reenvía en el header X-CSRF-Token.
//  2. En métodos mutadores (POST/PUT/PATCH/DELETE) exige que:
//     a) el header X-CSRF-Token coincida con la cookie csrf_token (comparación
//     en tiempo constante), y
//     b) el Origin/Referer pertenezca al mismo host. A diferencia de la versión
//     anterior, si Origin y Referer están AUSENTES la petición se RECHAZA.
func AdminCSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := getOrCreateCSRFToken(c)

		// Exponer token para plantillas
		c.Set("csrf_token", token)

		// Métodos seguros: solo aseguramos que exista la cookie
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		// === Validaciones para métodos mutadores ===

		// 1. Validación de origen (defensa fuerte)
		if !validateOrigin(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origen no válido o ausente"})
			return
		}

		// 2. Double-submit validation
		if !validateCSRFToken(c, token) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token CSRF inválido o ausente"})
			return
		}

		c.Next()
	}
}

func getOrCreateCSRFToken(c *gin.Context) string {
	token, err := c.Cookie(csrfCookieName)
	if err == nil && token != "" {
		return token
	}

	// Generar nuevo token
	plain, _, err := util.GenerateToken(32)
	if err != nil {
		// En producción deberías loguear el error
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error de seguridad"})
		return ""
	}

	secure := util.IsProduction()
	c.SetCookie(csrfCookieName, plain, csrfMaxAge, "/", "", secure, false) // HttpOnly=false
	return plain
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func validateOrigin(c *gin.Context) bool {
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = c.GetHeader("Referer")
	}
	if origin == "" {
		return false // Rechazamos si no hay ni Origin ni Referer
	}
	return util.SameOriginRequest(origin, c.Request.Host)
}

func validateCSRFToken(c *gin.Context, cookieToken string) bool {
	headerToken := c.GetHeader(csrfHeaderName)
	if headerToken == "" {
		headerToken = c.PostForm("csrf_token")
	}

	if headerToken == "" || cookieToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieToken)) == 1
}
