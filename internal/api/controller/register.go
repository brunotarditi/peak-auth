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

// GetVerifyEmail maneja la verificación de email vía GET
func (c *RegisterController) GetVerifyEmail(ctx *gin.Context) {
	token := ctx.Query("token")
	if token == "" {
		ctx.String(400, "Token requerido")
		return
	}

	userID, appID, err := c.UserService.VerifyEmail(token)
	if err != nil {
		ctx.String(400, "El enlace de verificación es inválido o ha expirado")
		return
	}

	// Lógica inteligente: Si el usuario fue invitado (onboarding),
	// le generamos un token de reset para que ponga su pass ahora mismo.
	resetToken := ""
	needsPassword := false

	// Si logramos generar un token de reset, es porque queremos que lo use
	if user, err := c.UserService.FindVerifiedUserByID(userID); err == nil {
		// Si el usuario no tiene login previo o marcamos que necesita pass
		if user.LastLogin.IsZero() {
			needsPassword = true
			// Generar token de reset al vuelo
			plainReset, _, _ := c.UserService.GenerateResetToken(userID, appID)
			resetToken = plainReset
		}
	}

	ctx.HTML(200, "verify_email.html", gin.H{
		"NeedsPassword": needsPassword,
		"ResetToken":    resetToken,
	})
}
