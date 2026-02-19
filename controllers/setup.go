package controllers

import (
	"net/http"
	"peak-auth/services"

	"github.com/gin-gonic/gin"
)

type SetupController struct {
	SetupService services.SetupService
}

func (ctrl *SetupController) ShowSetup(c *gin.Context) {
	first, _ := ctrl.SetupService.IsFirstRun()
	if !first {
		c.Redirect(303, "/admin/login")
		return
	}

	token := c.Query("token")
	if !ctrl.SetupService.ValidateSetupToken(token) {
		c.String(403, "Token de setup inválido")
		return
	}
	c.HTML(200, "setup.html", gin.H{"SetupToken": token})
}

func (ctrl *SetupController) ProcessSetup(c *gin.Context) {

	email := c.PostForm("email")
	password := c.PostForm("password")
	token := c.PostForm("token")

	if email == "" || password == "" || token == "" {
		c.String(http.StatusBadRequest, "email, password y token son requeridos")
		return
	}

	if err := ctrl.SetupService.CreateRootUser(email, password, token); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin")
}
