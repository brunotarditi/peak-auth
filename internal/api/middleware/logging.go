package middleware

import (
	"fmt"
	"log/slog"
	"os"
	"peak-auth/internal/util"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	appLogger      *slog.Logger
	initLoggerOnce sync.Once
)

func getLogger() *slog.Logger {
	initLoggerOnce.Do(func() {
		appLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	})
	return appLogger
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

// SafeLoggerMiddleware registra las solicitudes HTTP censurando parámetros sensibles.
// En producción utiliza JSON estructurado (slog) para observabilidad e ingesta en agregadores.
// En desarrollo preserva la salida formateada con colores ANSI para legibilidad inmediata.
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

		// En producción emitir JSON estructurado vía log/slog
		if util.IsProduction() {
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
			return
		}

		// En desarrollo: salida formateada con colores ANSI y badge de RequestID
		statusColor := statusCodeColor(status)
		mColor := methodColor(c.Request.Method)

		reqBadge := ""
		if reqID != "" {
			// Mostrar los primeros 8 caracteres del RequestID
			shortID := reqID
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}
			reqBadge = fmt.Sprintf(" | %s#%s%s", cyan, shortID, reset)
		}

		fmt.Printf("[GIN] %v |%s %3d %s| %13v | %15s |%s %-7s %s %s%s\n",
			start.Format("2006/01/02 - 15:04:05"),
			statusColor, status, reset,
			latency,
			c.ClientIP(),
			mColor, c.Request.Method, reset,
			path,
			reqBadge,
		)
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
