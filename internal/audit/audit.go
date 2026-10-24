package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"peak-auth/internal/util"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	auditLogger   *slog.Logger
	initAuditOnce sync.Once
)

func getLogger() *slog.Logger {
	initAuditOnce.Do(func() {
		if util.IsProduction() {
			auditLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		} else {
			auditLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		}
	})
	return auditLogger
}

func getReqID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if v, ok := c.Get("request_id"); ok {
		if id, ok := v.(string); ok && id != "" {
			return id
		}
	}
	return ""
}

// Event registra una acción administrativa sensible en un formato estructurado
// y consistente, para trazabilidad y respuesta ante incidentes (SIEM-ready).
//
//	action: verbo de la acción (ej. "app.create", "secret.regenerate")
//	target: recurso afectado (ej. "app=mi-app", "user=42")
func Event(c *gin.Context, action, target string) {
	EventResult(c, action, target, true, "")
}

// EventResult registra una acción incluyendo su resultado (ok/falla) y un detalle con log/slog.
func EventResult(c *gin.Context, action, target string, success bool, detail string) {
	status := "ok"
	level := slog.LevelInfo
	if !success {
		status = "fail"
		level = slog.LevelWarn
	}

	actor := actorEmail(c)
	ip := ""
	var ctx context.Context = context.Background()
	if c != nil {
		ip = c.ClientIP()
		if c.Request != nil && c.Request.Context() != nil {
			ctx = c.Request.Context()
		}
	}

	attrs := []slog.Attr{
		slog.String("event_type", "audit"),
		slog.String("action", action),
		slog.String("actor", actor),
		slog.String("ip", ip),
		slog.String("target", target),
		slog.String("status", status),
	}

	if reqID := getReqID(c); reqID != "" {
		attrs = append(attrs, slog.String("request_id", reqID))
	}
	if detail != "" {
		attrs = append(attrs, slog.String("detail", detail))
	}

	getLogger().LogAttrs(ctx, level, "audit_event", attrs...)
}

func actorEmail(c *gin.Context) string {
	if c == nil {
		return "anónimo"
	}
	if v, ok := c.Get("user_email"); ok {
		if email, ok := v.(string); ok && email != "" {
			return email
		}
	}
	if v, ok := c.Get("user_id"); ok {
		return fmt.Sprintf("uid:%v", v)
	}
	return "anónimo"
}
