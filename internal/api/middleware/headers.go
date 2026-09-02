package middleware

import (
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

// contentSecurityPolicy define la CSP de la aplicación.
//
// Nota: se permite 'unsafe-inline' en scripts y estilos porque la UI actual usa
// manejadores inline (onclick=...) y estilos inline de Tailwind. Endurecer esto
// a nonces requeriría refactorizar todas las plantillas. Aun así, se restringe
// default-src, object-src y frame-ancestors para mitigar clickjacking e inyección.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src 'self' https://fonts.gstatic.com data:; " +
	"img-src 'self' data: https:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"upgrade-insecure-requests"

// BaseSecurityHeaders aplica cabeceras de seguridad a TODAS las respuestas
// (incluidas las páginas públicas de login, setup y reset).
func BaseSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", contentSecurityPolicy)
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")
		c.Header("X-Permitted-Cross-Domain-Policies", "none")

		// HSTS solo en producción (requiere HTTPS para tener sentido y no romper dev).
		if util.IsProduction() {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// SecurityHeaderMiddleware añade, además de las cabeceras base, política de no-caché
// para las rutas administrativas que muestran contenido sensible (evita que el
// botón "atrás" reexponga páginas tras el logout).
func SecurityHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}
