package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type BaseController struct{}

func (ctrl *BaseController) renderAdmin(c *gin.Context, templateName string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	if email, exists := c.Get("user_email"); exists {
		data["UserEmail"] = email
	}

	if data["Title"] == nil {
		data["Title"] = "Panel"
	}

	c.HTML(http.StatusOK, templateName, data)
}
