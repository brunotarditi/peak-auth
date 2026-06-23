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
