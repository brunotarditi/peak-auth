package controller

import (
	"net/http"
	"peak-auth/internal/api/request"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/store/model"
	"peak-auth/internal/util"

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

// GetVerifyEmail muestra la página de confirmación previa a la verificación de email (GET no mutador)
func (c *RegisterController) GetVerifyEmail(ctx *gin.Context) {
	token := ctx.Query("token")
	if token == "" {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{
			"Title":   "Token requerido",
			"Message": "El token de verificación es requerido.",
		})
		return
	}

	// Cabeceras defensivas para evitar almacenamiento en caché o fugas por Referer
	ctx.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("Expires", "0")
	ctx.Header("Referrer-Policy", "no-referrer")

	// Validate the token without consuming it
	exists, isValid, err := c.UserService.CheckEmailVerificationToken(token)
	if err != nil {
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Title":   "Error del servidor",
			"Message": "Ocurrió un error al validar el token. Por favor, intenta nuevamente.",
		})
		return
	}

	// If token doesn't exist or is invalid (expired/used), show error with resend option
	if !exists || !isValid {
		ctx.HTML(http.StatusBadRequest, "verify_email_error.html", gin.H{
			"Title":   "Token inválido",
			"Message": "El enlace de verificación es inválido, ha expirado o ya fue utilizado.",
		})
		return
	}

	csrfToken, _ := ctx.Get("csrf_token")

	// Muestra la pantalla de confirmación sin consumir el token
	ctx.HTML(http.StatusOK, "verify_email_confirm.html", gin.H{
		"Token":      token,
		"csrf_token": csrfToken,
	})
}

// PostVerifyEmail procesa la verificación real del email consumiendo el token (POST mutador)
func (c *RegisterController) PostVerifyEmail(ctx *gin.Context) {
	token := ctx.PostForm("token")
	if token == "" {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{
			"Title":   "Token requerido",
			"Message": "El token de verificación es requerido.",
		})
		return
	}

	userID, appID, err := c.UserService.VerifyEmail(token)
	if err != nil {
		ctx.HTML(http.StatusBadRequest, "verify_email_error.html", gin.H{
			"Title":   "Verificación fallida",
			"Message": "El enlace de verificación es inválido, ha expirado o ya fue utilizado.",
		})
		return
	}

	// Lógica inteligente: Si el usuario fue invitado (onboarding),
	// le generamos un token de reset para que ponga su pass ahora mismo.
	needsPassword := false

	// Si logramos generar un token de reset, es porque queremos que lo use
	if user, err := c.UserService.FindVerifiedUserByID(userID); err == nil {
		// Si el usuario no tiene login previo o marcamos que necesita pass
		if user.LastLogin.IsZero() {
			needsPassword = true
			// Generar token de reset al vuelo y almacenarlo en cookie segura
			plainReset, _, _ := c.UserService.GenerateResetToken(userID, appID)
			ctx.SetSameSite(http.SameSiteStrictMode)
			ctx.SetCookie(
				"reset_token",
				plainReset,
				3600,
				"/reset-password",
				"",
				util.IsProduction(),
				true,
			)
		}
	}

	// Cabeceras defensivas para evitar almacenamiento en caché o fugas por Referer
	ctx.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("Expires", "0")
	ctx.Header("Referrer-Policy", "no-referrer")

	ctx.HTML(http.StatusOK, "verify_email.html", gin.H{
		"NeedsPassword": needsPassword,
	})
}

// GetResendVerification muestra el formulario para solicitar un nuevo email de verificación
func (c *RegisterController) GetResendVerification(ctx *gin.Context) {
	csrfToken, _ := ctx.Get("csrf_token")
	ctx.HTML(http.StatusOK, "resend_verification.html", gin.H{
		"csrf_token": csrfToken,
	})
}

// PostResendVerification procesa la solicitud de reenvío de email de verificación
func (c *RegisterController) PostResendVerification(ctx *gin.Context) {
	email := ctx.PostForm("email")
	if email == "" {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{
			"Title":   "Email requerido",
			"Message": "Debes proporcionar tu dirección de correo electrónico.",
		})
		return
	}

	err := c.UserService.ResendVerificationEmail(email)
	if err != nil {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{
			"Title":   "Error al reenviar",
			"Message": err.Error(),
		})
		return
	}

	ctx.HTML(http.StatusOK, "resend_verification_success.html", gin.H{
		"Email": email,
	})
}

