package middleware

import (
	"fmt"
	"net/http"
	"peak-auth/internal/store/repo"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

// PlatformScope contiene los privilegios de alto nivel del usuario
type PlatformScope struct {
	IsRoot          bool
	IsPlatformAdmin bool
}

// RoleMiddleware autoriza el acceso a una aplicación concreta identificada por el
// parámetro de ruta :id. Reglas (de mayor a menor privilegio):
//  1. ROOT o ADMIN en la app raíz (peak-auth) -> acceso concedido (plataforma).
//  2. Sobre la app destino: el usuario debe PERTENECER a ella y además tener
//     alguno de los roles requeridos (típicamente ADMIN). Si pertenece pero no
//     tiene el rol -> 403 privilegios insuficientes. Si no pertenece -> 403.
func RoleMiddleware(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository, requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredRoles) == 0 {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "configuración inválida: se requiere al menos un rol"})
			return
		}

		userID, ok := currentUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuario no autenticado"})
			return
		}

		// 1. Verificar privilegios de plataforma (ROOT o ADMIN global)
		scope := resolvePlatformScope(uarRepo, appRepo, userID)

		if scope.IsRoot {
			c.Set("is_root", true)
			c.Set("is_platform_admin", true)
			c.Next()
			return
		}

		if scope.IsPlatformAdmin {
			c.Set("is_platform_admin", true)
			c.Next()
			return
		}

		// 2. Verificar acceso a la aplicación específica
		appID, err := getTargetAppID(c, appRepo)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		// 3. ¿Pertenece el usuario a esta aplicación?
		belongs, err := uarRepo.BelongsToApp(userID, appID)
		if err != nil || !belongs {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no tienes acceso a esta aplicación"})
			return
		}

		// 4. ¿Tiene alguno de los roles requeridos?
		roles, err := uarRepo.GetUserRolesInApp(userID, appID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "error al obtener roles"})
			return
		}

		c.Set("user_roles", roles)

		roleSet := make(map[string]struct{}, len(roles))
		for _, r := range roles {
			roleSet[r] = struct{}{}
		}

		for _, required := range requiredRoles {
			if _, hasRole := roleSet[required]; hasRole {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "privilegios insuficientes"})
	}
}

// PlatformAdminMiddleware restringe una ruta a ROOT o ADMIN de la app raíz.
// Se usa para acciones globales: crear/eliminar aplicaciones y gestionar el
// catálogo de roles globales del sistema.
func PlatformAdminMiddleware(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuario no autenticado"})
			return
		}

		scope := resolvePlatformScope(uarRepo, appRepo, userID)

		if !scope.IsRoot && !scope.IsPlatformAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "se requieren privilegios de administrador de plataforma"})
			return
		}

		c.Set("is_root", scope.IsRoot)
		c.Set("is_platform_admin", true)
		c.Next()
	}
}

// RootOnlyMiddleware restringe una ruta exclusivamente al rol ROOT (operaciones
// destructivas a nivel plataforma).
func RootOnlyMiddleware(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuario no autenticado"})
			return
		}

		scope := resolvePlatformScope(uarRepo, appRepo, userID)
		if !scope.IsRoot {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "se requiere rol ROOT"})
			return
		}

		c.Set("is_root", true)
		c.Set("is_platform_admin", true)
		c.Next()
	}
}

// PlatformScopeMiddleware inyecta los privilegios de plataforma en el contexto
func PlatformScopeMiddleware(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := currentUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuario no autenticado"})
			return
		}

		scope := resolvePlatformScope(uarRepo, appRepo, userID)

		c.Set("is_root", scope.IsRoot)
		c.Set("is_platform_admin", scope.IsPlatformAdmin)
		c.Set("platform_scope", scope)

		c.Next()
	}
}

// resolvePlatformScope determina el alcance del usuario a nivel plataforma:
//   - isRoot:          rol ROOT en la app raíz (peak-auth) -> superusuario, bypass total.
//   - isPlatformAdmin: rol ADMIN en la app raíz (peak-auth) -> administra todo el panel.
//
// Estas son las ÚNICAS dos formas de obtener privilegios sobre toda la plataforma.
// Tener ADMIN en una app externa NO otorga ningún privilegio de plataforma.
func resolvePlatformScope(uarRepo repo.UserApplicationRoleRepository, appRepo repo.ApplicationRepository, userID uint) PlatformScope {
	masterApp, err := appRepo.FindByAppID(util.AppIdPeakAuth)
	if err != nil {
		return PlatformScope{}
	}

	roles, err := uarRepo.GetUserRolesInApp(userID, masterApp.ID)
	if err != nil {
		return PlatformScope{}
	}

	var scope PlatformScope
	for _, r := range roles {
		switch r {
		case "ROOT":
			scope.IsRoot = true
			scope.IsPlatformAdmin = true
			return scope
		case "ADMIN":
			scope.IsPlatformAdmin = true
		}
	}
	return scope
}

// currentUserID extrae y valida el user_id inyectado por AuthMiddleware.
func currentUserID(c *gin.Context) (uint, bool) {
	val, exists := c.Get("user_id")
	if !exists || val == nil {
		return 0, false
	}
	id, ok := val.(uint)
	return id, ok
}

func getTargetAppID(c *gin.Context, appRepo repo.ApplicationRepository) (uint, error) {
	slug := c.Param("id")
	if !util.IsValidSlug(slug) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "formato de slug inválido"})
		return 0, fmt.Errorf("invalid app slug")
	}

	app, err := appRepo.FindByAppID(slug)
	if err != nil {
		return 0, err
	}
	return app.ID, nil
}
