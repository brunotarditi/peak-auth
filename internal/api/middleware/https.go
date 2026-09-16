package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"

	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

// RequireHTTPSMiddleware enforces HTTPS for sensitive endpoints in production.
// It checks if the request arrived over a secure transport by examining:
// 1. c.Request.TLS (direct TLS termination in the application)
// 2. X-Forwarded-Proto header (TLS termination at a trusted reverse proxy)
//
// In production mode, if neither condition is met, the request is rejected with 403.
// In development mode, this middleware allows HTTP to facilitate local testing.
func RequireHTTPSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In development, allow HTTP for local testing
		if !util.IsProduction() {
			c.Next()
			return
		}

		// Check if request arrived over TLS
		if c.Request.TLS != nil {
			c.Next()
			return
		}

		// Check X-Forwarded-Proto from trusted proxy
		// Only trust this header if TRUSTED_PROXIES is configured
		if os.Getenv("TRUSTED_PROXIES") != "" {
			proto := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")))
			if proto == "https" {
				c.Next()
				return
			}
		}

		// Neither direct TLS nor trusted proxy HTTPS - reject the request
		log.Printf("SECURITY: Rejected insecure HTTP request to %s from %s in production mode", c.Request.URL.Path, c.ClientIP())
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "This endpoint requires HTTPS in production. Please access this service through a secure connection.",
		})
	}
}
