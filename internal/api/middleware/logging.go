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
		statusColor := statusCodeColor(statusCode)
		mColor := methodColor(c.Request.Method)

		targetPath := path
		if raw != "" {
			targetPath = path + "?" + raw
		}

		fmt.Printf("[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %s\n",
			start.Format("2006/01/02 - 15:04:05"),
			statusColor, statusCode, reset,
			latency,
			c.ClientIP(),
			mColor, c.Request.Method, reset,
			targetPath,
		)
	}
}

const (
	green   = "\033[97;42m"
	white   = "\033[90;47m"
	yellow  = "\033[90;43m"
	red     = "\033[97;41m"
	blue    = "\033[97;44m"
	magenta = "\033[97;45m"
	cyan    = "\033[97;46m"
	reset   = "\033[0m"
)

func statusCodeColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return white
	case code >= 400 && code < 500:
		return yellow
	default:
		return red
	}
}

func methodColor(method string) string {
	switch method {
	case "GET":
		return blue
	case "POST":
		return cyan
	case "PUT":
		return yellow
	case "DELETE":
		return red
	case "PATCH":
		return green
	case "HEAD":
		return magenta
	case "OPTIONS":
		return white
	default:
		return reset
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
