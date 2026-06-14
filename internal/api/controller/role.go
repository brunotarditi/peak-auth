package controller

import (
	"net/http"
	"peak-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type RoleController struct {
	RoleService service.RoleService
}

// PostRole crea un nuevo rol
func (ctrl *RoleController) PostRole(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	// Usar el servicio para crear el rol
	err := ctrl.RoleService.CreateRole(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol creado con éxito"})
}

// DeleteRole elimina un rol (lógicamente) si ningún usuario lo tiene asignado
func (ctrl *RoleController) DeleteRole(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre de rol requerido"})
		return
	}

	err := ctrl.RoleService.DeleteRole(req.Name)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rol eliminado con éxito"})
}
