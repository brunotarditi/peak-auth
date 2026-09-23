package middleware

import (
	"log/slog"
	"os"
	"peak-auth/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	appLogger     *slog.Logger
	initLoggerOnce sync.Once
)

func getLogger() *slog.Logger {
	initLoggerOnce.Do(func() {
		if util.IsProduction() {
			appLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		} else {
			appLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
		}
	})
	return appLogger
}

// SafeLoggerMiddleware registra las solicitudes HTTP mediante log/slog estructurado,
// censurando automáticamente parámetros sensibles de query string para evitar fugas de credenciales.
func SafeLoggerMiddleware() gin.HandlerFunc {
	logger := getLogger()

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		if raw != "" {
			raw = redactSensitiveParams(raw)
			path = path + "?" + raw
		}

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		reqID := GetRequestID(c)

		attrs := []slog.Attr{
			slog.Int("status", status),
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Int64("latency_ms", latency.Milliseconds()),
			slog.String("ip", c.ClientIP()),
		}

		if reqID != "" {
			attrs = append(attrs, slog.String("request_id", reqID))
		}

		msg := "http_request"
		ctx := c.Request.Context()

		switch {
		case status >= 500:
			logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
		case status >= 400:
			logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
		default:
			logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
		}
	}
}

// redactSensitiveParams replaces values of sensitive query parameters with [REDACTED]
func redactSensitiveParams(rawQuery string) string {
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
