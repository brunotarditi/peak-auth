package middlewares

import (
	"log"
	"net/http"
	"peak-auth/repositories"

	"github.com/gin-gonic/gin"
)

func RoleMiddleware(uarRepo repositories.UserApplicationRoleRepository, requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredRoles) == 0 {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "se requiere al menos un rol"})
			return
		}

		valUser, exists := c.Get("user_id")
		if !exists || valUser == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuario no autenticado"})
			return
		}
		userID, ok := valUser.(uint)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "ID de usuario inválido"})
			return
		}

		valApp, exists := c.Get("current_app_id")
		if !exists || valApp == nil {
			c.Set("current_app_id", uint(1))
			valApp = uint(1)
		}
		appID, ok := valApp.(uint)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "ID de aplicación inválido"})
			return
		}

		roles, err := uarRepo.GetUserRolesInApp(userID, appID)
		if err != nil {
			log.Printf("error obteniendo roles para usuario %d en app %d: %v", userID, appID, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error al verificar permisos"})
			return
		}

		if len(roles) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no tienes roles asignados en esta aplicación"})
			return
		}

		roleSet := make(map[string]bool, len(roles))
		for _, r := range roles {
			roleSet[r] = true
		}

		for _, rr := range requiredRoles {
			if roleSet[rr] {
				c.Next()
				return
			}
		}

		adminRole := "admin"
		if roleSet[adminRole] {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no tienes los permisos necesarios para esta acción"})
	}
}
