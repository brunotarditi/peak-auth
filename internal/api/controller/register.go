package controller

import (
	"net/http"
	"peak-auth/internal/api/request"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

type RegisterController struct {
	UserService service.UserService
	AppService  service.ApplicationService
}

// Register maneja el endpoint de registro.
func (c *RegisterController) Register(ctx *gin.Context) {
	app := ctx.MustGet("app").(model.Application)
	var req request.RegisterRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validación de seguridad: el AppID del body debe ser el del middleware
	if req.AppID != app.AppID { // Suponiendo que AppCode es el ID externo string
		ctx.JSON(http.StatusForbidden, gin.H{"error": "App ID mismatch"})
		return
	}

	user, err := c.UserService.Register(req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "Usuario creado, verifique su email", "id": user.ID})
}

// PostUsersInApp registra un usuario en una aplicación
func (ctrl *RegisterController) PostUsersInApp(c *gin.Context) {
	id := c.Param("id")
	app, err := ctrl.AppService.GetAppDetails(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "aplicación no encontrada"})
		return
	}
	email := c.PostForm("email")
	role := c.PostForm("role")
	if email == "" || role == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y role requeridos"})
		return
	}
	if err := ctrl.AppService.RegisterUserInApp(email, role, &app); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	audit.Event(c, "user.assign", "app="+app.AppID+" email="+email+" role="+role)
	c.JSON(http.StatusOK, gin.H{"message": "Usuario vinculado con éxito"})
}

// GetVerifyEmail shows the verification landing page that extracts token from URL fragment
func (c *RegisterController) GetVerifyEmail(ctx *gin.Context) {
	// Apply defensive headers to prevent token leakage
	ctx.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("Referrer-Policy", "no-referrer")
	
	// Render landing page that will extract token from fragment and POST it
	ctx.HTML(200, "verify_landing.html", gin.H{})
}

// PostVerifyEmail handles the actual verification via POST (token in body, not URL)
func (c *RegisterController) PostVerifyEmail(ctx *gin.Context) {
	// Apply defensive headers
	ctx.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("Referrer-Policy", "no-referrer")
	
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Token requerido"})
		return
	}

	userID, appID, err := c.UserService.VerifyEmail(req.Token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "El enlace de verificación es inválido o ha expirado"})
		return
	}

	// Lógica inteligente: Si el usuario fue invitado (onboarding),
	// generamos un token de reset pero lo devolvemos en la respuesta JSON
	// para que el frontend lo maneje sin exponerlo en la URL
	needsPassword := false
	resetToken := ""

	if user, err := c.UserService.FindVerifiedUserByID(userID); err == nil {
		// Si el usuario no tiene login previo, necesita establecer contraseña
		if user.LastLogin.IsZero() {
			needsPassword = true
			// Generar token de reset al vuelo
			plainReset, _, _ := c.UserService.GenerateResetToken(userID, appID)
			resetToken = plainReset
		}
	}

	ctx.JSON(200, gin.H{
		"success":       true,
		"needsPassword": needsPassword,
		"resetToken":    resetToken,
	})
}
