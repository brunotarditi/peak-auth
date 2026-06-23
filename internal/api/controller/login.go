package controller

import (
	"net/http"
	"net/url"
	"peak-auth/internal/api/request"
	"peak-auth/internal/audit"
	"peak-auth/internal/service"
	"peak-auth/internal/util"

	"github.com/gin-gonic/gin"
)

type LoginController struct {
	UserService service.UserService
}

// Login maneja el endpoint de login. Espera el header X-App-Id con el AppID público.
func (c *LoginController) Login(ctx *gin.Context) {
	var req request.LoginRequest
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
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// GetLoginForm renderiza el formulario de login
func (ctrl *LoginController) GetLoginForm(c *gin.Context) {
	csrf, _ := c.Get("csrf_token")
	c.HTML(http.StatusOK, "login.html", gin.H{
		"Error":     c.Query("error"),
		"CSRFToken": csrf,
	})
}

// PostLoginForm procesa el login
func (ctrl *LoginController) PostLoginForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	token, expireMinutes, err := ctrl.UserService.AdminLogin(email, password)
	if err != nil {
		audit.EventResult(c, "admin.login", "email="+email, false, err.Error())
		// El mensaje proviene de errores de dominio controlados; se URL-encodea
		// para evitar cualquier inyección en la query string.
		c.Redirect(http.StatusSeeOther, "/admin/login?error="+url.QueryEscape(err.Error()))
		return
	}

	audit.EventResult(c, "admin.login", "email="+email, true, "")

	// Configuración de cookie segura
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()

	c.SetCookie("admin_token", token, expireMinutes*60, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// PostLogout cierra la sesión
func (ctrl *LoginController) PostLogout(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	isSecure := util.IsProduction()
	c.SetCookie("admin_token", "", -1, "/", "", isSecure, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}
