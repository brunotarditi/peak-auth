package controller

import (
	"net/http"
	"peak-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type RoleController struct {
	RoleService service.RoleService
	AppService  service.ApplicationService
}

// PostRole crea un nuevo rol GLOBAL del sistema (solo plataforma).
func (ctrl *RoleController) PostRole(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	if err := ctrl.RoleService.CreateRole(req.Name); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol global creado con éxito"})
}

// DeleteRole elimina un rol GLOBAL del sistema (solo plataforma).
func (ctrl *RoleController) DeleteRole(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	if err := ctrl.RoleService.DeleteRole(req.Name); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol eliminado con éxito"})
}

// PostAppRole crea un rol PROPIO de la aplicación (requiere sistema de roles activo).
func (ctrl *RoleController) PostAppRole(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	if err := ctrl.RoleService.CreateAppRole(req.Name, app.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol de aplicación creado con éxito"})
}

// DeleteAppRole elimina un rol propio de la aplicación.
func (ctrl *RoleController) DeleteAppRole(c *gin.Context) {
	id := c.Param("id")
	roleName := c.Param("code")

	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App no encontrada"})
		return
	}

	if err := ctrl.RoleService.DeleteAppRole(roleName, app.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol de aplicación eliminado"})
}
