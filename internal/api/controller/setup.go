package controller

import (
	"net/http"
	"peak-auth/internal/auth"
	"peak-auth/internal/service"
	"peak-auth/internal/util"
	"time"

	"github.com/gin-gonic/gin"
)

type SetupController struct {
	BaseController
	SetupService service.SetupService
	TokenManager *auth.JWTManager
}

func (ctrl *SetupController) ShowSetup(c *gin.Context) {
	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(303, "/admin/login")
		return
	}

	token := c.Query("token")
	if err := ctrl.SetupService.ValidateSetupToken(token); err != nil {
		ctrl.renderError(c, http.StatusForbidden, "Acceso Denegado", "El token de inicialización (setup) es inválido o ha expirado.")
		return
	}
	csrf, _ := c.Get("csrf_token")
	c.HTML(200, "setup.html", gin.H{"SetupToken": token, "CSRFToken": csrf})
}

func (ctrl *SetupController) ProcessSetup(c *gin.Context) {

	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(http.StatusSeeOther, "/admin/login")
		return
	}

	email := c.PostForm("email")
	password := c.PostForm("password")
	token := c.PostForm("token")

	if email == "" || password == "" || token == "" {
		ctrl.renderError(c, http.StatusBadRequest, "Datos Incompletos", "Email, contraseña y token son requeridos para completar la configuración inicial.")
		return
	}

	user, err := ctrl.SetupService.CreateRootUser(email, password, token)
	if err != nil {
		ctrl.renderError(c, http.StatusBadRequest, "Error de Configuración", "No se pudo crear el usuario administrador inicial. Verifique los datos ingresados.")
		return
	}

	tokenString, err := ctrl.TokenManager.GenerateToken(user.ID, "System Root", util.AppIdPeakAuth, []string{"ROOT"}, 24*time.Hour)
	if err != nil {
		ctrl.renderError(c, http.StatusInternalServerError, "Error del Sistema", "No se pudo generar la sesión administrativa.")
		return
	}

	ctrl.setAdminCookie(c, tokenString, 86400) // 1 día

	c.Redirect(http.StatusSeeOther, "/admin/login")
}
