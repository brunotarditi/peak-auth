package controller

import "github.com/gin-gonic/gin"

type DocsController struct{}

func (ctrl *DocsController) ShowDocs(c *gin.Context) {
	c.HTML(200, "docs.html", gin.H{
		"Title": "Documentación",
		"Breadcrumbs": []gin.H{
			{"Label": "Documentación", "URL": ""},
		},
	})
}

func (ctrl *DocsController) ShowAPI(c *gin.Context) {
	c.HTML(200, "api.html", gin.H{
		"Title": "Referencia de API",
		"Breadcrumbs": []gin.H{
			{"Label": "Documentación", "URL": "/admin/docs"},
			{"Label": "API", "URL": ""},
		},
	})
}

func (ctrl *DocsController) ShowTerms(c *gin.Context) {
	c.HTML(200, "terms.html", gin.H{
		"Title": "Términos y condiciones",
		"Breadcrumbs": []gin.H{
			{"Label": "Términos y condiciones", "URL": ""},
		},
	})
}

func (ctrl *DocsController) ShowPrivacy(c *gin.Context) {
	c.HTML(200, "privacy.html", gin.H{
		"Title": "Políticas de privacidad",
		"Breadcrumbs": []gin.H{
			{"Label": "Políticas de privacidad", "URL": ""},
		},
	})
}
