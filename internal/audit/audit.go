package audit

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

// Event registra una acción administrativa sensible en un formato estructurado
// y consistente, para trazabilidad y respuesta ante incidentes.
//
// No reemplaza un SIEM, pero deja un rastro homogéneo en los logs de la app.
//
//	action: verbo de la acción (ej. "app.create", "secret.regenerate")
//	target: recurso afectado (ej. "app=mi-app", "user=42")
func Event(c *gin.Context, action, target string) {
	log.Printf("[audit] action=%s actor=%q ip=%s target=%s", action, actorEmail(c), c.ClientIP(), target)
}

// EventResult registra una acción incluyendo su resultado (ok/falla) y un detalle.
func EventResult(c *gin.Context, action, target string, success bool, detail string) {
	status := "ok"
	if !success {
		status = "fail"
	}
	log.Printf("[audit] action=%s actor=%q ip=%s target=%s status=%s detail=%q",
		action, actorEmail(c), c.ClientIP(), target, status, detail)
}

func actorEmail(c *gin.Context) string {
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
