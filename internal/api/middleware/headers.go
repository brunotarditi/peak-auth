package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaderMiddleware añade cabeceras de seguridad y previene caché en rutas administrativas
func SecurityHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevenir que el navegador cachee contenido sensible (Soluciona el problema de "atrás" en logout)
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		// Cabeceras de seguridad estándar
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	}
}
