package middleware

import (
	"log"
	"net/http"
	"peak-auth/repository"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func AppAuthMiddleware(appRepo repository.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.GetHeader("X-App-Id")
		secret := c.GetHeader("X-App-Secret")

		if appID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "X-App-Id header requerido"})
			return
		}
		if secret == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "X-App-Secret header requerido"})
			return
		}

		app, err := appRepo.ValidateSecret(appID, secret)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				log.Printf("intento de autenticación con app_id=%s fallido: credenciales inválidas", appID)
			} else {
				log.Printf("error validando app_id=%s: %v", appID, err)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "credenciales de aplicación inválidas"})
			return
		}

		if !app.IsActive {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "aplicación desactivada"})
			return
		}

		c.Set("app_id", app.ID)
		c.Set("app", app)
		c.Next()
	}
}

func GetAppFromContext(c *gin.Context) (uint, bool) {
	val, exists := c.Get("app_id")
	if !exists {
		return 0, false
	}
	id, ok := val.(uint)
	return id, ok
}

func GetAppIDParam(c *gin.Context) (uint, error) {
	idStr := c.Param("app_id")
	if idStr == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}
