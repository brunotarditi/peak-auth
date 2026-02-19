package controllers

import (
	"peak-auth/models"
	"peak-auth/requests"
	"peak-auth/services"

	"github.com/gin-gonic/gin"
)

type UserController struct {
	UserService services.UserService
}

// Login maneja el endpoint de login. Espera el header X-App-Id con el AppID público.
func (c *UserController) Login(ctx *gin.Context) {
	var req requests.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": "Formato inválido"})
		return
	}

	// El app_id lo podemos recibir por Header o QueryParam
	appID := ctx.GetHeader("X-App-ID")
	if appID == "" {
		ctx.JSON(400, gin.H{"error": "X-App-ID es requerido"})
		return
	}

	response, err := c.UserService.Login(req, appID)
	if err != nil {
		ctx.JSON(401, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(200, response)
}

// Register maneja el endpoint de registro.
func (c *UserController) Register(ctx *gin.Context) {
	app := ctx.MustGet("app").(models.Application)
	var req requests.RegisterRequest

	// Bind del JSON
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validación de seguridad: el AppID del body debe ser el del middleware
	if req.AppID != app.AppID { // Suponiendo que AppCode es el ID externo string
		ctx.JSON(403, gin.H{"error": "App ID mismatch"})
		return
	}

	user, err := c.UserService.Register(req)
	if err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(201, gin.H{"message": "Usuario creado, verifique su email", "id": user.ID})
}
