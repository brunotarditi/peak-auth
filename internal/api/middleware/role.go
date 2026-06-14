package middleware

import (
	"net/http"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

func RoleMiddleware(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository, requiredRoles ...string) gin.HandlerFunc {
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
		userID := valUser.(uint)

		// 1. Identifica la APP de destino
		appSlug := c.Param("id")
		var targetAppID uint = 1 // Por defecto Peak Auth Admin
		if appSlug != "" {
			app, err := appRepo.FindByAppID(appSlug)
			if err == nil {
				targetAppID = app.ID
			}
		}

		// 2. Identifica si el usuario es ROOT a nivel global (en Peak Auth Admin)
		masterApp, err := appRepo.FindByAppID(util.AppIdPeakAuth)
		isRoot := false
		if err == nil {
			globalRoles, _ := uarRepo.GetUserRolesInApp(userID, masterApp.ID)
			for _, r := range globalRoles {
				if r == "ROOT" {
					isRoot = true
					c.Set("user_roles", globalRoles)
					break
				}
			}
		}

		// Si es ROOT, pasa directo (bypass)
		if isRoot {
			c.Set("is_root", true)
			c.Next()
			return
		}

		// Si es el panel de administración principal y el usuario tiene el rol ADMIN en cualquier aplicación, le dejamos pasar
		if err == nil && targetAppID == masterApp.ID {
			hasLocalAdmin, err := uarRepo.HasAdminRoleInAnyApp(userID)
			if err == nil && hasLocalAdmin {
				c.Set("user_roles", []string{"ADMIN"})
				c.Next()
				return
			}
		}

		// 3. Si no es ROOT, validamos roles en la APP destino
		roles, err := uarRepo.GetUserRolesInApp(userID, targetAppID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no tienes permisos en esta aplicación"})
			return
		}

		roleSet := make(map[string]bool, len(roles))
		for _, r := range roles {
			roleSet[r] = true
		}
		c.Set("user_roles", roles)

		// Verificar si tiene rol requerido
		for _, rr := range requiredRoles {
			if roleSet[rr] {
				c.Next()
				return
			}
		}

		// Fallback: Si es ADMIN de la app destino, también le dejamos pasar
		if roleSet["ADMIN"] || roleSet["admin"] {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no tienes los privilegios necesarios"})
	}
}
