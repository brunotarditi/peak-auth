package middleware

import (
	"os"

	"github.com/gin-gonic/gin"
)

func AdminCSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			origin := c.GetHeader("Origin")
			if origin == "" {
				origin = c.GetHeader("Referer")
			}
			host := "http://" + c.Request.Host
			if os.Getenv("ENV") == "production" {
				host = "https://" + c.Request.Host
			}
			// Verificar si el origen coincide con nuestro host
			if origin != "" && len(origin) >= len(host) && origin[:len(host)] != host {
				c.AbortWithStatusJSON(403, gin.H{"error": "CSRF token mismatch o Origin inválido"})
				return
			}
		}
		c.Next()
	}
}
