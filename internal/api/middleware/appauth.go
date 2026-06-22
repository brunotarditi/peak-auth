package middleware

import (
	"errors"
	"log"
	"net/http"
	"peak-auth/internal/store/repo"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func AppAuthMiddleware(appRepo repo.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.GetHeader("X-App-Id")
		secret := c.GetHeader("X-App-Secret")

		if appID == "" || secret == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "se requieren headers X-App-Id y X-App-Secret",
			})
			return
		}

		app, err := appRepo.ValidateSecret(appID, secret)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("Intento de auth fallido - AppID: %s", appID)
			} else {
				log.Printf("Error validando AppID %s: %v", appID, err)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
			return
		}

		if !app.IsActive {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "la aplicación está desactivada"})
			return
		}

		c.Set("app_id", app.ID)
		c.Set("app", app)
		c.Set("is_app_authenticated", true)

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
