package controller

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type BaseController struct{}

// internalErrorJSON loguea el error real (para diagnóstico) y devuelve al cliente
// un mensaje genérico, evitando filtrar detalles internos (GORM, infraestructura).
func internalErrorJSON(c *gin.Context, context string, err error) {
	log.Printf("[error] %s: %v", context, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "ocurrió un error procesando la solicitud"})
}

func (ctrl *BaseController) renderAdmin(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}
	if token, exists := c.Get("csrf_token"); exists {
		data["CSRFToken"] = token
	}

	if data["Title"] == nil {
		data["Title"] = "Panel"
	}

	c.HTML(http.StatusOK, templateName, data)
}

// renderError renderiza la plantilla error.html con el layout admin completo
// (inyecta UserEmail, CSRFToken, Title) y el código de estado HTTP indicado.
func (ctrl *BaseController) renderError(c *gin.Context, status int, title, message string) {
	data := gin.H{
		"Title":   title,
		"Message": message,
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}
	if token, exists := c.Get("csrf_token"); exists {
		data["CSRFToken"] = token
	}
	c.HTML(status, "error.html", data)
}

// internalErrorHTML loguea el error real y muestra una página de error genérica,
// evitando filtrar detalles internos (queries GORM, stack traces, etc.).
func (ctrl *BaseController) internalErrorHTML(c *gin.Context, context string, err error, userMessage string) {
	log.Printf("[error] %s: %v", context, err)
	ctrl.renderError(c, http.StatusInternalServerError, "Error", userMessage)
}
