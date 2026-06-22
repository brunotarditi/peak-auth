package middleware

import (
	"errors"
	"net/http"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func AppContextMiddleware(appRepo repo.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		slug := c.Param("id") // o c.Param("slug") si cambias el nombre
		if slug == "" {
			c.Next()
			return
		}

		if !util.IsValidSlug(slug) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "slug de aplicación inválido"})
			return
		}

		app, err := appRepo.FindByAppID(slug)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "aplicación no encontrada"})
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error interno"})
			}
			return
		}

		c.Set("current_app", app)
		c.Set("current_app_id", app.ID)
		c.Set("current_app_slug", app.AppID)

		c.Next()
	}
}
