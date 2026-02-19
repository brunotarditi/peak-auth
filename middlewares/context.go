package middlewares

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AppContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		appIDStr := c.Param("id")
		if appIDStr == "" {
			// Si no hay ID en la URL, quizás estamos en la raíz del admin (Peak)
			// Aquí podrías setear el ID de Peak por defecto o dejarlo pasar
			c.Next()
			return
		}

		var appID uint
		_, err := fmt.Sscanf(appIDStr, "%d", &appID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "ID de aplicación malformado"})
			return
		}

		// Guardamos el ID real como uint para que los servicios/repos no tengan que castear
		c.Set("current_app_id", appID)
		c.Next()
	}
}
