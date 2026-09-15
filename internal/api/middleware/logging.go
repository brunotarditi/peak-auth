package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SafeLoggerMiddleware logs requests but redacts sensitive query parameters
// to prevent bearer tokens and other credentials from appearing in logs
func SafeLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Redact sensitive query parameters
		if raw != "" {
			raw = redactSensitiveParams(raw)
		}

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		statusCode := c.Writer.Status()

		// Log with redacted query string
		if raw != "" {
			fmt.Printf("[GIN] %v | %3d | %13v | %15s | %-7s %s?%s\n",
				start.Format("2006/01/02 - 15:04:05"),
				statusCode,
				latency,
				c.ClientIP(),
				c.Request.Method,
				path,
				raw,
			)
		} else {
			fmt.Printf("[GIN] %v | %3d | %13v | %15s | %-7s %s\n",
				start.Format("2006/01/02 - 15:04:05"),
				statusCode,
				latency,
				c.ClientIP(),
				c.Request.Method,
				path,
			)
		}
	}
}

// redactSensitiveParams replaces values of sensitive query parameters with [REDACTED]
func redactSensitiveParams(rawQuery string) string {
	// List of sensitive parameter names that should be redacted
	sensitiveParams := []string{
		"token",
		"setup_token",
		"password",
		"secret",
		"api_key",
		"apikey",
		"access_token",
		"refresh_token",
		"authorization",
		"auth",
		"key",
	}

	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.ToLower(kv[0])
			for _, sensitive := range sensitiveParams {
				if key == sensitive || strings.Contains(key, sensitive) {
					parts[i] = kv[0] + "=[REDACTED]"
					break
				}
			}
		}
	}
	return strings.Join(parts, "&")
}
