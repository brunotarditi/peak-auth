package controller

import "github.com/gin-gonic/gin"

type DocsController struct{}

func (ctrl *DocsController) ShowDocs(c *gin.Context) {
	c.HTML(200, "docs.html", gin.H{})
}

func (ctrl *DocsController) ShowAPI(c *gin.Context) {
	c.HTML(200, "api.html", gin.H{})
}
