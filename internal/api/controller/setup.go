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
		c.String(403, "Token de setup inválido")
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
		c.String(http.StatusBadRequest, "email, password y token son requeridos")
		return
	}

	user, err := ctrl.SetupService.CreateRootUser(email, password, token)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	tokenString, err := ctrl.TokenManager.GenerateToken(user.ID, "System Root", util.AppIdPeakAuth, []string{"ROOT"}, 24*time.Hour)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error al generar sesión")
		return
	}

	isSecure := util.IsProduction()
	c.SetCookie(
		"admin_token", // Nombre
		tokenString,   // Valor (JWT)
		86400,         // MaxAge en segundos (1 día)
		"/",           // Path
		"",            // Domain
		isSecure,      // Secure: En true solo con HTTPS (importante en prod)
		true,          // HttpOnly: TRUE para que JS no pueda robarlo (XSS)
	)

	c.Redirect(http.StatusSeeOther, "/admin/login")
}
